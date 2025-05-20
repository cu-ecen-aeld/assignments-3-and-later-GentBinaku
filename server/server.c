#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "queue.h"

// #define DEBUG    /* un-comment this line to redirect output to stdout */
#ifdef DEBUG
#define SYSLOG_OPTIONS          (LOG_PERROR | LOG_NDELAY)
#else
#define SYSLOG_OPTIONS          (LOG_NDELAY)
#endif

#define PORT 9000
#define MAX_BACKLOG 5
#define RECV_BUF_SIZE 1024
#define TIMER_THREAD_PERIOD 10
#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define DATA_FILE "/var/tmp/aesdsocketdata"

struct node {
    pthread_t tid;
    int connfd;
    pthread_mutex_t *mutex;
    int thread_complete_success;
    SLIST_ENTRY(node) nodes;
};

volatile sig_atomic_t exit_requested = 0;

void signal_handler(int signum) {
    syslog(LOG_INFO, "Caught signal, exiting");
    exit_requested = 1;
}

ssize_t send_all(int fd, const void *buf, size_t len) {
  size_t total = 0;
  const char *data = buf;
  while (total < len) {
    ssize_t sent = send(fd, data + total, len - total, 0);
    if (sent <= 0) {
      return -1;
    }
    total += sent;
  }
  return total;
}

static ssize_t process_msg(const char *buffer, size_t buf_size, int fd, pthread_mutex_t *mutex)
{
    size_t processed = 0;
    char *newline = NULL;

    while ((newline = memchr(buffer + processed, '\n', buf_size - processed)) != NULL) {
        size_t packet_len = newline - (buffer + processed) + 1;

        // Write packet to file
        if (pthread_mutex_lock(mutex) != 0) {
            syslog(LOG_ERR, "failed to lock mutex before writing");
            return -1;
        }

        FILE *fp = fopen(DATA_FILE, "a+");
        if (!fp) {
            pthread_mutex_unlock(mutex);
            syslog(LOG_ERR, "failed to open %s", DATA_FILE);
            return -1;
        }

        if (fwrite(buffer + processed, 1, packet_len, fp) != packet_len) {
            fclose(fp);
            pthread_mutex_unlock(mutex);
            syslog(LOG_ERR, "fwrite failed");
            return -1;
        }

        fclose(fp);
        pthread_mutex_unlock(mutex);

        // Send full file back to client
        fp = fopen(DATA_FILE, "r");
        if (fp) {
            char file_buf[RECV_BUF_SIZE];
            size_t n;
            while ((n = fread(file_buf, 1, sizeof(file_buf), fp)) > 0) {
                if (send_all(fd, file_buf, n) < 0) {
                    fclose(fp);
                    syslog(LOG_ERR, "send_all failed");
                    return -1;
                }
            }
            fclose(fp);
        }

        processed += packet_len;
    }

    return processed;  // Return how much was processed
}


void* thread_func(void *thread_param)
{
    ssize_t read_len = -1;
    size_t buf_size = 0;
    char *buffer = NULL;
    char recv_buf[RECV_BUF_SIZE] = {};
    struct node *n = NULL;

    if (thread_param == NULL)
        return NULL;

    n = (struct node *) thread_param;

    while ((read_len = recv(n->connfd, recv_buf, RECV_BUF_SIZE, 0)) > 0 && !exit_requested)
    {
        // Append recv_buf to buffer
        char *new_buffer = realloc(buffer, buf_size + read_len);
        if (new_buffer == NULL) {
            syslog(LOG_ERR, "failed to realloc buffer");
            free(buffer);
            break;
        }

        buffer = new_buffer;
        memcpy(buffer + buf_size, recv_buf, read_len);
        buf_size += read_len;

        // Check for newline and process complete messages
        if (memchr(buffer, '\n', buf_size)) {
            syslog(LOG_INFO, "Received data with newline from client");

            ssize_t processed = process_msg(buffer, buf_size, n->connfd, n->mutex);
            syslog(LOG_INFO, "Processed %zd bytes, remaining %zu", processed, buf_size - processed);

            if (processed < 0) {
                syslog(LOG_ERR, "process_msg failed");
                break;
            }

            if (processed > 0) {
                if ((size_t)processed < buf_size) {
                    memmove(buffer, buffer + processed, buf_size - processed);
                    buf_size -= processed;
                } else {
                    free(buffer);
                    buffer = NULL;
                    buf_size = 0;
                }
            }


        }
    }

    if (read_len < 0) {
        syslog(LOG_ERR, "recv() failed: %s", strerror(errno));
    } else if (read_len == 0) {
        syslog(LOG_INFO, "Client disconnected");
    }

    free(buffer);
    close(n->connfd);
    n->thread_complete_success = 1;

    printf("Thread ID: %lu exiting, closed client fd: %d\n", n->tid, n->connfd);

    return NULL;
}

void *timer_thread_func(void *thread_param)
{
    struct node *n = NULL;
    struct tm *tmp;
    struct timespec ts;
    time_t t;
    char outstr[RECV_BUF_SIZE] = {};
    int fd;

    if (thread_param == NULL)
        return NULL;

    n = (struct node *) thread_param;

    while (!exit_requested) {

        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            syslog(LOG_ERR, "failed to retrieve time");
            break;
        }

        ts.tv_sec += TIMER_THREAD_PERIOD;   /* 10 seconds */
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) != 0) {
            syslog(LOG_ERR, "failed to sleep");
            break;
        }

        t = time(NULL);
        if (t == ((time_t) -1)) {
            syslog(LOG_ERR, "failed to retrieve the seconds since epoch");
            break;
        }

        tmp = localtime(&t);
        if (tmp == NULL) {
            syslog(LOG_ERR, "failed to retrieve localtime");
            break;
        }

        strftime(outstr, sizeof(outstr), "timestamp: %Y, %b, %d, %H:%M:%S\n", tmp);
        fd = open(DATA_FILE, (O_CREAT | O_APPEND | O_RDWR), FILE_MODE);
        if (fd == -1) {
            syslog(LOG_ERR, "failed to open %s", DATA_FILE);
            break;
        }

        if (pthread_mutex_lock(n->mutex) != 0) {
            close(fd);
            syslog(LOG_ERR, "failed to lock mutex object before writing timestamp");
            break;
        }

        if (write(fd, outstr, strlen(outstr)) == -1)
            syslog(LOG_ERR, "failed to write timestamp to %s", DATA_FILE);

        if (pthread_mutex_unlock(n->mutex) != 0) {
            close(fd);
            syslog(LOG_ERR, "failed to unlock mutex object after writing timestamp");
            break;
        }

        close(fd);
    }

    /* we set this flag to make the parent process to join the thread */
    n->thread_complete_success = 1;

    return NULL;
}

static int create_server_socket(int* sock)
{
    int optval = 1;
    struct sockaddr_in serv_addr;

    if((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
        return -1;
    }
    if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        syslog(LOG_ERR, "setsockopt() failed: %s", strerror(errno));
        close(*sock);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT);

    if (bind(*sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        syslog(LOG_ERR, "bind() on port %d failed: %s", PORT,
            strerror(errno));
        close(*sock);
        return -1;
    }

    if (listen(*sock, MAX_BACKLOG) < 0) {
        syslog(LOG_ERR, "listen() failed: %s", strerror(errno));
        close(*sock);
        return -1;
    }

    syslog(LOG_INFO, "Listening on port %d", PORT);
    return 0;
}

static int create_server(int *mode)
{
    int rc = -1;
    int newfd = -1;
    int socket = -1;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    struct node *n = NULL;
    struct node *n_tmp = NULL;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    /* init linked-list */
    SLIST_HEAD(head_s, node) head;
    SLIST_INIT(&head);

    rc = create_server_socket(&socket);
    if (rc == -1)
        goto error;

    if (*mode)
    {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
            close(socket);
            closelog();
            return EXIT_FAILURE;
        }
        if (pid > 0) {
            /* Parent exits */
            close(socket);
            closelog();
            exit(EXIT_SUCCESS);
        }
        /* Child continues */
        if (setsid() < 0) {
            syslog(LOG_ERR, "setsid() failed: %s", strerror(errno));
            close(socket);
            closelog();
            return EXIT_FAILURE;
        }
        /* Redirect standard file descriptors to /dev/null */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    /* timer thread to write timestamp to *log_file */
    n = (struct node *) calloc(1, sizeof(struct node));
    if (n == NULL) {
        syslog(LOG_ERR, "failed to allocate memory for timer node: %s", strerror(errno));
        rc = -1;
        goto error;
    }
    n->mutex = &mutex;
    n->thread_complete_success = 0;
    rc = pthread_create(&n->tid, NULL, timer_thread_func, n);

    if (rc != 0) {
        syslog(LOG_ERR, "failed to create timer thread: %s", strerror(errno));
        goto error;
    }
    SLIST_INSERT_HEAD(&head, n, nodes);

    while (!exit_requested) {

        newfd = accept(socket, (struct sockaddr *) &addr, &addrlen);
        if (newfd == -1) {
            rc = -1;
            goto join_threads;
        }

        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(addr.sin_addr));

        /* thread per client connection */
        n = (struct node *) calloc(1, sizeof(struct node));
        if (n == NULL) {
            syslog(LOG_ERR, "failed to allocate memory for client node: %s", strerror(errno));
            rc = -1;
            goto error;
        }
        n->connfd = newfd;
        n->mutex = &mutex;
        n->thread_complete_success = 0;
        rc = pthread_create(&n->tid, NULL, thread_func, n);
        printf("Created Thread ID: %lu\n", n->tid);
        if (rc != 0) {
            syslog(LOG_ERR, "failed to create client thread: %s", strerror(errno));
            goto error;
        }
        SLIST_INSERT_HEAD(&head, n, nodes);
join_threads:
        /* remove all thread from linked-list, if threads have completed execution */
        n = NULL;
        SLIST_FOREACH_SAFE(n, &head, nodes, n_tmp) {
            if (n->thread_complete_success) {
                pthread_join(n->tid, NULL);
                SLIST_REMOVE(&head, n, node, nodes);
                free(n);
            }
        }
    }
error:
    if (socket != -1) {
        shutdown(socket, SHUT_RDWR);
        close(socket);
    }

    /* delete linked-list */
    n = NULL;
    while (!SLIST_EMPTY(&head)) {
        n = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, nodes);
        free(n);
    }
    SLIST_INIT(&head);

    pthread_mutex_destroy(&mutex);

    return rc;
}


int main(int argc, char *argv[])
{
    int rc, opt;
    int daemon_mode = 0;
    struct sigaction sa;

    openlog(NULL, SYSLOG_OPTIONS, LOG_USER);

    /* parse command-line arguments */
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
        case 'd':
            daemon_mode = 1;
            syslog(LOG_INFO, "running %s in daemon mode", argv[0]);
            break;
        }
    }

    /* set-up signal handler for SIGINT & SIGTERM */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;

    rc = sigaction(SIGINT, &sa, NULL);
    if (rc != 0) {
        syslog(LOG_ERR, "failed to setup signal handler for SIGINT");
        goto exit;
    }

    rc = sigaction(SIGTERM, &sa, NULL);
    if (rc != 0) {
        syslog(LOG_ERR, "failed to setup signal handler for SIGTERM");
        goto exit;
    }

    /* we are all set to run aesdsocket server */
    syslog(LOG_INFO, "Starting aesdsocket server");
    printf("Starting aesdsocket server\n");
    rc = create_server(&daemon_mode);

exit:
    syslog(LOG_INFO, "Exiting aesdsocket!");
    remove(DATA_FILE);
    closelog();
    return rc;
}
