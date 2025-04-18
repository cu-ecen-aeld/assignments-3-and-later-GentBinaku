#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
    // Wait for the specified time before attempting to lock the mutex
    usleep(thread_func_args->wait_to_obtain_ms * 1000);

    // Attempt to lock the mutex
    if (pthread_mutex_lock(thread_func_args->mutex) != 0) {
        thread_func_args->thread_complete_success = false;
        return thread_param;
    }

    // Wait for the specified time while holding the mutex
    usleep(thread_func_args->wait_to_release_ms * 1000);

    // Unlock the mutex
    if (pthread_mutex_unlock(thread_func_args->mutex) != 0) {
        thread_func_args->thread_complete_success = false;
        return thread_param;
    }
    // Indicate successful completion
    thread_func_args->thread_complete_success = true;

    return thread_param;
}

bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,
                                  int wait_to_obtain_ms, int wait_to_release_ms)
{
    // Allocate memory for thread data
    struct thread_data *thread_args = malloc(sizeof(struct thread_data));
    if (thread_args == NULL) {
        return false;
    }

    // Initialize the thread_data fields
    thread_args->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_args->wait_to_release_ms = wait_to_release_ms;
    thread_args->mutex = mutex;
    thread_args->thread_complete_success = false;  // default; will be set by the thread

    // Create the thread
    int rc = pthread_create(thread, NULL, threadfunc, thread_args);
    if (rc != 0) {
        free(thread_args);
        return false;
    }

    return true;
}
