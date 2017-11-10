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
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#include "debugwatchdoglib.h"

#define TEST_EXECUTABLE_BINARY_PATH "/usr/bin/ls"
#define TEST_SUCCESS 0
#define TEST_ERROR -1

static void process_stopped_callback(pid_t p);
static sem_t stopped_process_notification;
static unsigned int process_was_stopped = 0U;
static pid_t child_pid = 0;

int main(void) {
    int ret = -1;
    int cret = -1;
    unsigned int process_wait_verified = 0U;

    if (sem_init(&stopped_process_notification, 0, 0) != 0) {
		goto error;
	}

	if (dwlib_initialize(&process_stopped_callback) == DWLIB_ERROR) {
        goto error;
    }

    if (dwlib_watch(TEST_EXECUTABLE_BINARY_PATH) == DWLIB_ERROR) {
        goto error;
    }

    child_pid = fork();
    if (child_pid == 0) {
    	char *const argv[] = { "", 0x0 };
    	char *const envp[] = { "", 0x0 };
    	execve(TEST_EXECUTABLE_BINARY_PATH, argv, envp);
    	exit(-1);
    }

    struct timespec t = { 0x0 };
    if (clock_gettime(CLOCK_REALTIME, &t) != 0) {
    	goto error;
    }
    t.tv_sec += 5;
    while((cret = sem_timedwait(&stopped_process_notification, &t)) == -1 && errno == EINTR);
	if (cret == -1) {
		goto error;
	}

	if (process_was_stopped == 0U) {
		goto error;
	}

	if (dwlib_unwatch(TEST_EXECUTABLE_BINARY_PATH) == DWLIB_ERROR) {
		goto error;
	}

	unsigned int remaining_waiting_tries = 5U;
	int waitpid_status = 0;
	while (remaining_waiting_tries-- != 0U) {

		if (waitpid(child_pid, &waitpid_status, WNOHANG | WUNTRACED) == -1) {
			goto error;
		}

		if (WIFSTOPPED(waitpid_status) && WSTOPSIG(waitpid_status) == SIGSTOP) {
			process_wait_verified = 1U;
		}

		sleep(1);
	}

	if (process_wait_verified != 1U) {
		goto error;
	}

    goto success;
    
error:
    printf("TEST FAILED\n");
	ret = TEST_ERROR;
    goto cleanup;

success:
    printf("TEST PASSED\n");
    ret = TEST_SUCCESS;
    goto cleanup;

cleanup:
    if (child_pid != 0) {
    	kill(child_pid, SIGKILL);
    }
    dwlib_finalize();
    sem_destroy(&stopped_process_notification);
    return ret;
}

static void process_stopped_callback(pid_t p) {
	if (p == child_pid) {
		process_was_stopped = 1U;
		if (sem_post(&stopped_process_notification) != 0) {
			exit(-1);
		}
	}
}
