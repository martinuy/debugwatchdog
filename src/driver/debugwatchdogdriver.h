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

#ifndef DEBUGWATCHDOGDRIVER_H
#define DEBUGWATCHDOGDRIVER_H

#ifdef DWDRIVER_FROM_USER
#include <unistd.h>
#else
#include <linux/unistd.h>
#endif // DWDRIVER_FROM_USER

#define DWDRIVER_NAME "debugwatchdogdriver"
#define DWDRIVER_IMAGE "debugwatchdogdriver.ko"
#define DWDRIVER_DEVICE_PATH "/dev/debugwatchdogdriver_dev"

#define DWDRIVER_SUCCESS 0L
#define DWDRIVER_ERROR -1L

#define DWDRIVER_UNWATCH 0U
#define DWDRIVER_WATCH   1U

#define DWDRIVER_MAX_WATCHED_PROCESSES 10U
#define DWDRIVER_MAX_PENDING_STOPPED_NOTIFICATIONS 10U

typedef enum dwdriver_watch_state_t {
	STATE_UNWATCH = DWDRIVER_UNWATCH,
	STATE_WATCH = DWDRIVER_WATCH
} dwdriver_watch_state_t;

typedef struct dwdriver_watch_process_t {
	dwdriver_watch_state_t state;
	const char* process_name;
	unsigned int process_name_length;
} dwdriver_watch_process_t;

typedef struct dwdriver_stopped_pids_t {
	pid_t* pids_buffer;
	unsigned int* pids_buffer_length;
} dwdriver_stopped_pids_t;

// IOCTLs
#define DWDRIVER_IOCTL_ENABLE_WATCHDOG 1U
#define DWDRIVER_IOCTL_WATCH_PROCESS 3U
#define DWDRIVER_IOCTL_GET_STOPPED_PIDS 5U

#endif // DEBUGWATCHDOGDRIVER_H
