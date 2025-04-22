#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#define SERVER_PORT 9000
#define BACKLOG 5
#define RECV_BUF_SIZE 1024
#define DATA_FILE "/var/tmp/aesdsocketdata"

volatile sig_atomic_t exit_requested = 0;

void signal_handler(int signum) {
  syslog(LOG_INFO, "Caught signal, exiting");
  exit_requested = 1;
}

/**
 * Sends all data in buf over fd, handling partial sends.
 * Returns total bytes sent, or -1 on error.
 */
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

int open_server_socket(void) {
  int sockfd;
  int opt = 1;
  struct sockaddr_in serv_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
    return -1;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    syslog(LOG_ERR, "setsockopt() failed: %s", strerror(errno));
    close(sockfd);
    return -1;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(SERVER_PORT);

  if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    syslog(LOG_ERR, "bind() on port %d failed: %s", SERVER_PORT,
           strerror(errno));
    close(sockfd);
    return -1;
  }

  return sockfd;
}

int handle_client(int client_fd) {
  char recv_buf[RECV_BUF_SIZE];
  size_t buf_size = 0;
  char *buffer = NULL;
  ssize_t read_len;

  while ((read_len = recv(client_fd, recv_buf, sizeof(recv_buf), 0)) > 0) {
    char *new_buffer = realloc(buffer, buf_size + read_len);
    if (!new_buffer) {
      syslog(LOG_ERR, "realloc() failed: %s", strerror(errno));
      free(buffer);
      buffer = NULL;
      buf_size = 0;
      continue;
    }
    buffer = new_buffer;
    memcpy(buffer + buf_size, recv_buf, read_len);
    buf_size += read_len;

    size_t processed = 0;
    char *newline;
    while ((newline = memchr(buffer + processed, '\n', buf_size - processed))) {
      size_t packet_len = newline - (buffer + processed) + 1;

      FILE *fp = fopen(DATA_FILE, "a");
      if (!fp) {
        syslog(LOG_ERR, "fopen() failed: %s", strerror(errno));
        free(buffer);
        return -1;
      }
      if (fwrite(buffer + processed, 1, packet_len, fp) != packet_len) {
        syslog(LOG_ERR, "fwrite() failed: %s", strerror(errno));
        fclose(fp);
        free(buffer);
        return -1;
      }
      fclose(fp);

      /* Send full file content back to client */
      fp = fopen(DATA_FILE, "r");
      if (fp) {
        char file_buf[RECV_BUF_SIZE];
        size_t n;
        while ((n = fread(file_buf, 1, sizeof(file_buf), fp)) > 0) {
          if (send_all(client_fd, file_buf, n) < 0) {
            syslog(LOG_ERR, "send() failed: %s", strerror(errno));
            fclose(fp);
            free(buffer);
            return -1;
          }
        }
        fclose(fp);
      }

      processed += packet_len;
    }

    if (processed > 0) {
      if (processed < buf_size) {
        memmove(buffer, buffer + processed, buf_size - processed);
        buf_size -= processed;
        char *shrink_buf = realloc(buffer, buf_size);
        if (shrink_buf || buf_size == 0) {
          buffer = shrink_buf;
        }
      } else {
        free(buffer);
        buffer = NULL;
        buf_size = 0;
      }
    }
  }

  if (read_len < 0) {
    syslog(LOG_ERR, "recv() failed: %s", strerror(errno));
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}

int main(int argc, char *argv[]) {
  int server_fd, client_fd;
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  char client_ip[INET_ADDRSTRLEN];
  int daemon_mode = 0;
  int opt;

  /* Parse command-line options */
  while ((opt = getopt(argc, argv, "d")) != -1) {
    switch (opt) {
    case 'd':
      daemon_mode = 1;
      break;
    default:
      fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  /* Set up signal handlers */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_DAEMON);

  /* Open and bind socket */
  server_fd = open_server_socket();
  if (server_fd < 0) {
    syslog(LOG_ERR, "Failed to open server socket");
    closelog();
    return EXIT_FAILURE;
  }

  /* Daemonize after successful bind */
  if (daemon_mode) {
    pid_t pid = fork();
    if (pid < 0) {
      syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
      close(server_fd);
      closelog();
      return EXIT_FAILURE;
    }
    if (pid > 0) {
      /* Parent exits */
      close(server_fd);
      closelog();
      exit(EXIT_SUCCESS);
    }
    /* Child continues */
    if (setsid() < 0) {
      syslog(LOG_ERR, "setsid() failed: %s", strerror(errno));
      close(server_fd);
      closelog();
      return EXIT_FAILURE;
    }
    /* Redirect standard file descriptors to /dev/null */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
  }

  if (listen(server_fd, BACKLOG) < 0) {
    syslog(LOG_ERR, "listen() failed: %s", strerror(errno));
    close(server_fd);
    closelog();
    return EXIT_FAILURE;
  }

  syslog(LOG_INFO, "Server listening on port %d", SERVER_PORT);

  /* Main accept loop */
  while (!exit_requested) {
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
      if (errno == EINTR && exit_requested) {
        break;
      }
      syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
      continue;
    }

    if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
                  sizeof(client_ip))) {
      syslog(LOG_INFO, "Accepted connection from %s", client_ip);
    } else {
      syslog(LOG_INFO, "Accepted connection from unknown client");
    }

    if (handle_client(client_fd) < 0) {
      close(client_fd);
      continue;
    }

    close(client_fd);
    if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
                  sizeof(client_ip))) {
      syslog(LOG_INFO, "Closed connection from %s", client_ip);
    } else {
      syslog(LOG_INFO, "Closed connection from unknown client");
    }
  }

  /* Cleanup */
  close(server_fd);
  unlink(DATA_FILE);
  closelog();

  return EXIT_SUCCESS;
}
