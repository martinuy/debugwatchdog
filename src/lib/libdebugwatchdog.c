/*
 *   Martin Balao (martin.uy) - © Copyright 2017
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define DWDRIVER_FROM_USER
#include "debugwatchdogdriver.h"
#undef DWDRIVER_FROM_USER

#include "debugwatchdoglib.h"

extern int init_module(void* module_image, unsigned long len, const char* param_values);
extern int delete_module(const char* name, int flags);

typedef enum lib_state_t { UNINITIALIZED = 0, INITIALIZED, STOPPING } lib_state_t;

static lib_state_t lib_state = UNINITIALIZED;
static unsigned int module_loaded = 0U;
static int debugwatchdogdriver_fd = -1;
static dwlib_process_stopped_callback_t registered_process_stopped_callback = NULL;
static char* path_to_library_directory = NULL;
static char* path_to_driver_image = NULL;
static sem_t stopped_process_notification_thread_stop_ack;
static pthread_mutex_t global_library_mutex;
static sigset_t stopped_process_actions_set;
static pthread_t stopped_process_notification_thread_id;
static unsigned int currently_watched_processes = 0U;
static void(*fatal_error_handler_ptr)(int) = NULL;

static char* get_path_to_file_with_base(const char* file);
static char* get_path_to_library_directory(void);
static void initialize_once(void);
static void finalize_once(void);
static void* stopped_process_notification_thread(void* arg);
static void flush_signals(void);
static void fatal_error_common(void);
static void fatal_error(int status);
static void handable_fatal_error(int status);
static pid_t pids_buffer[sizeof(pid_t)*10];

static void* stopped_process_notification_thread(void* arg) {
    int ret = -1;
    int cret = -1;
    int old_cancel_state = -1;

    if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) != 0) {
        fatal_error(-1);
    }

    while(1) {
        siginfo_t signal_info;

        while((cret = sigwaitinfo(&stopped_process_actions_set, &signal_info)) == -1 && errno == EINTR);
        if (cret == -1) {
            fatal_error(-1);
        }

        if (pthread_mutex_lock(&global_library_mutex) != 0) {
            fatal_error(-1);
        }

        if (lib_state == STOPPING || lib_state == INITIALIZED) {
            dwdriver_stopped_pids_t stopped_pids = { 0x0 };
            unsigned int stopped_pids_length = 0U;
            do {
                stopped_pids_length = sizeof(pids_buffer);
                stopped_pids.pids_buffer = pids_buffer;
                stopped_pids.pids_buffer_length = &stopped_pids_length;
                if (ioctl(debugwatchdogdriver_fd, DWDRIVER_IOCTL_GET_STOPPED_PIDS, (unsigned long)&stopped_pids) != DWDRIVER_SUCCESS) {
                    fatal_error(-1);
                }
                const unsigned int stopped_pids_count = *(stopped_pids.pids_buffer_length) / sizeof(pid_t);
                for (unsigned int i = 0; i < stopped_pids_count; i++) {
                    if (registered_process_stopped_callback != NULL) {
                        (*registered_process_stopped_callback)(*(pids_buffer + i));
                    }
                }
            } while (*(stopped_pids.pids_buffer_length) == sizeof(pids_buffer));

            if (lib_state == STOPPING) {
                flush_signals();
                if (sem_post(&stopped_process_notification_thread_stop_ack) != 0) {
                    fatal_error(-1);
                }
            }
        }
        if (pthread_mutex_unlock(&global_library_mutex) != 0) {
            fatal_error(-1);
        }
    }
}

long dwlib_initialize(dwlib_process_stopped_callback_t process_stopped_callback) {
    if (pthread_mutex_lock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }

    long ret = DWLIB_ERROR;
    int cret = -1;
    int debugwatchdogdriver_image_fd = -1;
    void* debugwatchdogdriver_image_buf = NULL;
    struct stat debugwatchdogdriver_image_sb = {0x0};

    if (lib_state == INITIALIZED || lib_state == STOPPING) {
        goto cleanup;
    }

    while((debugwatchdogdriver_image_fd = open(path_to_driver_image, 0, O_RDONLY)) == -1 && errno == EINTR);
    if (debugwatchdogdriver_image_fd < 0) {
        handable_fatal_error(-1);
        goto cleanup;
    }

    if (fstat(debugwatchdogdriver_image_fd, &debugwatchdogdriver_image_sb) == -1) {
        fatal_error(-1);
    }

    debugwatchdogdriver_image_buf = mmap(0, debugwatchdogdriver_image_sb.st_size, PROT_READ|PROT_EXEC, MAP_PRIVATE, debugwatchdogdriver_image_fd, 0);
    if (debugwatchdogdriver_image_buf == NULL) {
        handable_fatal_error(-1);
        goto cleanup;
    }

    if (init_module(debugwatchdogdriver_image_buf, debugwatchdogdriver_image_sb.st_size, "") != 0 && errno != EEXIST) {
        handable_fatal_error(-1);
        goto cleanup;
    }
    module_loaded = 1U;

    while((debugwatchdogdriver_fd = open(DWDRIVER_DEVICE_PATH, O_RDWR)) == -1 && errno == EINTR);
    if (debugwatchdogdriver_fd < 0) {
        fatal_error(-1);
    }

    registered_process_stopped_callback = process_stopped_callback;
    currently_watched_processes = 0;

    if (ioctl(debugwatchdogdriver_fd, DWDRIVER_IOCTL_ENABLE_WATCHDOG, DWDRIVER_WATCH) != DWDRIVER_SUCCESS) {
        handable_fatal_error(-1);
        goto cleanup;
    }

    lib_state = INITIALIZED;
    ret = DWLIB_SUCCESS;

cleanup:
    if (debugwatchdogdriver_image_buf != NULL) {
        if (munmap(debugwatchdogdriver_image_buf, debugwatchdogdriver_image_sb.st_size) == -1) {
            fatal_error(-1);
        }
        debugwatchdogdriver_image_buf = NULL;
    }

    if (debugwatchdogdriver_image_fd >= 0) {
        while((cret = close(debugwatchdogdriver_image_fd)) == -1 && errno == EINTR);
        if (cret == -1) {
            fatal_error(-1);
        }
        debugwatchdogdriver_image_fd = -1;
    }

    if (pthread_mutex_unlock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
    return ret;
}

long dwlib_watch(const char* const executable_binary_path) {
    if (pthread_mutex_lock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }

    long ret = DWLIB_ERROR;

    if (lib_state == UNINITIALIZED || lib_state == STOPPING) {
        goto cleanup;
    }

    if (currently_watched_processes == DWDRIVER_MAX_WATCHED_PROCESSES) {
        goto cleanup;
    }

    if (executable_binary_path == NULL) {
        goto cleanup;
    }

    {
        const unsigned int executable_binary_path_length = strlen(executable_binary_path);
        if (executable_binary_path_length > PATH_MAX) {
            goto cleanup;
        }
        dwdriver_watch_process_t watch_process;
        watch_process.state = STATE_WATCH;
        watch_process.process_name = executable_binary_path;
        watch_process.process_name_length = executable_binary_path_length;
        if (ioctl(debugwatchdogdriver_fd, DWDRIVER_IOCTL_WATCH_PROCESS, (unsigned long)&watch_process) != DWDRIVER_SUCCESS) {
            goto cleanup;
        }
    }
    currently_watched_processes++;
    ret = DWLIB_SUCCESS;

cleanup:
    if (pthread_mutex_unlock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
    return ret;
}

long dwlib_unwatch(const char* const executable_binary_path) {
    if (pthread_mutex_lock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }

    long ret = DWLIB_ERROR;

    if (lib_state == UNINITIALIZED || lib_state == STOPPING) {
        goto cleanup;
    }

    if (executable_binary_path == NULL) {
        goto cleanup;
    }

    {
        const unsigned int executable_binary_path_length = strlen(executable_binary_path);
        if (executable_binary_path_length > PATH_MAX) {
            goto cleanup;
        }
        dwdriver_watch_process_t watch_process;
        watch_process.state = STATE_UNWATCH;
        watch_process.process_name = executable_binary_path;
        watch_process.process_name_length = executable_binary_path_length;
        if (ioctl(debugwatchdogdriver_fd, DWDRIVER_IOCTL_WATCH_PROCESS, (unsigned long)&watch_process) != DWDRIVER_SUCCESS) {
            goto cleanup;
        }
    }
    currently_watched_processes--;
    ret = DWLIB_SUCCESS;

cleanup:
    if (pthread_mutex_unlock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
    return ret;
}

long dwlib_finalize(void) {
    if (pthread_mutex_lock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }

    long ret = DWLIB_ERROR;
    int cret = -1;

    if (lib_state == UNINITIALIZED || lib_state == STOPPING) {
        goto cleanup;
    }

    lib_state = STOPPING;

    if (ioctl(debugwatchdogdriver_fd, DWDRIVER_IOCTL_ENABLE_WATCHDOG, DWDRIVER_UNWATCH) != DWDRIVER_SUCCESS) {
        fatal_error(-1);
    }

    {
        // Driver was disabled, no more signals are going to be
        // queued. We need to flush existing signals.
        flush_signals();
        // No queued signals at this point. Notification Thread may have
        // obtained a signal to process or not. We need him to flush it and
        // ack. We will send a signal to unlock him.
        {
            union sigval val;
            val.sival_int = -1;
            if (sigqueue(getpid(), SIGUSR1, val) != 0) {
                fatal_error(-1);
            }
        }

        if (pthread_mutex_unlock(&global_library_mutex) != 0) {
            fatal_error(-1);
        }

        while((cret = sem_wait(&stopped_process_notification_thread_stop_ack)) == -1 && errno == EINTR);
        if (cret == -1) {
            fatal_error(-1);
        }

        if (pthread_mutex_lock(&global_library_mutex) != 0) {
            fatal_error(-1);
        }
    }

    while((cret = close(debugwatchdogdriver_fd)) == -1 && errno == EINTR);
    if (cret == -1) {
        fatal_error(-1);
    }
    debugwatchdogdriver_fd = -1;

    {
        unsigned int remaining_tries = 5;
        while ((cret = delete_module(DWDRIVER_NAME, O_NONBLOCK)) != 0 && (errno == EAGAIN || errno == EBUSY)
                && remaining_tries-- != 0U) {
            sleep(1);
        }
        module_loaded = 0U;
        if (cret != 0 && errno != EWOULDBLOCK) {
            fatal_error(-1);
        }
    }

    registered_process_stopped_callback = NULL;
    currently_watched_processes = 0;

    lib_state = UNINITIALIZED;

    ret = DWLIB_SUCCESS;

cleanup:
    if (pthread_mutex_unlock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
    return ret;
}

void dwlib_set_fatal_error_handler(void(*fatal_error_handler)(int)) {
    if (pthread_mutex_lock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
    fatal_error_handler_ptr = fatal_error_handler;
    if (pthread_mutex_unlock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
}

static void flush_signals(void) {
    int cret = -1;
    unsigned int signals_flushed = 0U;
    const struct timespec t = {0x0};
    siginfo_t info;
    while (signals_flushed == 0U) {
        while((cret = sigtimedwait(&stopped_process_actions_set, &info, &t)) == -1 && errno == EINTR);
        if (cret == -1) {
            if (errno == EAGAIN) {
                signals_flushed = 1U;
            } else {
                fatal_error(-1);
            }
        }
    }
}

// This is not Thread-Safe
__attribute__((constructor))
static void initialize_once(void) {

    path_to_library_directory = get_path_to_library_directory();
    if (path_to_library_directory == NULL) {
        fatal_error(-1);
    }

    path_to_driver_image = get_path_to_file_with_base(DWDRIVER_IMAGE);
    if (path_to_driver_image == NULL) {
        fatal_error(-1);
    }

    {
        pthread_mutexattr_t attr;
        if (pthread_mutexattr_init(&attr) != 0) {
            fatal_error(-1);
        }

        if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
            fatal_error(-1);
        }

        if (pthread_mutex_init(&global_library_mutex, &attr) != 0) {
            fatal_error(-1);
        }

        if (pthread_mutexattr_destroy(&attr) != 0) {
            fatal_error(-1);
        }
    }

    if (sem_init(&stopped_process_notification_thread_stop_ack, 0, 0) != 0) {
        fatal_error(-1);
    }

    if (sigemptyset(&stopped_process_actions_set) != 0){
        fatal_error(-1);
    }

    if (sigaddset(&stopped_process_actions_set, SIGUSR1) == -1){
        fatal_error(-1);
    }

    if (pthread_sigmask(SIG_BLOCK, &stopped_process_actions_set, NULL) != 0) {
        fatal_error(-1);
    }

    {
        pthread_attr_t attr;

        if (pthread_attr_init(&attr) != 0) {
            fatal_error(-1);
        }

        if (pthread_create(&stopped_process_notification_thread_id, &attr,
                           &stopped_process_notification_thread, NULL) != 0) {
            fatal_error(-1);
        }

        if (pthread_attr_destroy(&attr) != 0) {
            fatal_error(-1);
        }
    }

    return;
}

// This is not Thread-Safe
__attribute__((destructor))
static void finalize_once(void) {

    dwlib_finalize();

    if (pthread_mutex_lock(&global_library_mutex) != 0) {
        fatal_error(-1);
    }

    if (lib_state != UNINITIALIZED) {
        fatal_error(-1);
    }

    if (path_to_library_directory != NULL) {
        free(path_to_library_directory);
        path_to_library_directory = NULL;
    }

    if (path_to_driver_image != NULL) {
        free(path_to_driver_image);
        path_to_driver_image = NULL;
    }

    if (stopped_process_notification_thread_id != 0) {
        if (pthread_cancel(stopped_process_notification_thread_id) != 0) {
            fatal_error(-1);
        }
        if (pthread_join(stopped_process_notification_thread_id, NULL) != 0) {
            fatal_error(-1);
        }
        stopped_process_notification_thread_id = 0;
    }

    if (pthread_sigmask(SIG_UNBLOCK, &stopped_process_actions_set, NULL) != 0) {
        fatal_error(-1);
    }

    if (sigemptyset(&stopped_process_actions_set) != 0) {
        fatal_error(-1);
    }

    if (sem_destroy(&stopped_process_notification_thread_stop_ack) != 0) {
        fatal_error(-1);
    }

    if (pthread_mutex_destroy(&global_library_mutex) != 0) {
        fatal_error(-1);
    }
}

static void fatal_error_common(void) {
    int cret = -1;
    if (module_loaded == 1U) {
        unsigned int remaining_tries = 5U;
        while ((cret = delete_module(DWDRIVER_NAME, O_NONBLOCK)) != 0 && (errno == EAGAIN || errno == EBUSY) &&
                remaining_tries-- != 0U) {
            sleep(1);
        }
        module_loaded = 0U;
    }
}

static void fatal_error(int status) {
    fatal_error_common();
    _exit(status);
}

static void handable_fatal_error(int status) {
    fatal_error_common();
    if (fatal_error_handler_ptr != NULL) {
        (*fatal_error_handler_ptr)(status);
    } else {
        fatal_error(status);
    }
}

static char* get_path_to_file_with_base(const char* file) {
    const size_t path_to_file_with_base_length = strlen(path_to_library_directory) + 1 + strlen(file) + 1;
    char* path_to_file_with_base = (char*)malloc(path_to_file_with_base_length);
    if (path_to_file_with_base == NULL) {
        goto end;
    }
    path_to_file_with_base[0] = 0;
    strcat(path_to_file_with_base, path_to_library_directory);
    strcat(path_to_file_with_base, "/");
    strcat(path_to_file_with_base, file);
    path_to_file_with_base[path_to_file_with_base_length-1] = 0;
end:
    return path_to_file_with_base;
}

static char* get_path_to_library_directory(void) {
    char* ret = NULL;
    char* executable_full_path_ptr = NULL;
    unsigned int executable_directory_length = 0;
    ssize_t count = -1;
    char* executable_full_path = (char*)malloc(PATH_MAX);
    if (executable_full_path == NULL) {
        goto cleanup;
    }
    count = readlink("/proc/self/exe", executable_full_path, PATH_MAX);
    /* Fail if we cannot read the link or if the name is too long
     * and it was truncated by readlink */
    if (count == -1 || count == PATH_MAX) {
        goto cleanup;
    }
    /* man page readlink(2) says
     *  "readlink() does not append a null byte to buf"
     * So we put an explict 0 here to be sure that we will not
     * overrun the buffer later
     * */
    executable_full_path[count] = 0;

    executable_full_path_ptr = dirname(executable_full_path);
    executable_directory_length = strlen(executable_full_path_ptr);
    ret = (char*)malloc(executable_directory_length + 1);
    if (ret == NULL) {
        goto cleanup;
    }
    memcpy(ret, executable_full_path_ptr, executable_directory_length);
    ret[executable_directory_length] = 0;
cleanup:
    if (executable_full_path != NULL) {
        free(executable_full_path);
        executable_full_path = NULL;
    }
    return ret;
}
