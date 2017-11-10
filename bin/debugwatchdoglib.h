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

//
// NOTES:
//
// 1) This library will handle SIGUSR1 signal. This signal has to be
//    blocked in all of your process threads. This can be achieved by
//    statically linking this library or by dynamically loading it
//    from the process main thread. Do not enable SIGUSR1 handling in
//    any thread nor wait for the signal.
//
// 2) This library will terminate the process immediately if an error
//    that leaves the library in an undefined state occurs (i.e. during
//    initialization or finalization). Some failures are handable. If
//    setting a custom fatal error handler, it's your responsability not
//    to do further calls on any library method.
//

#ifndef DEBUGWATCHDOGLIB_H
#define DEBUGWATCHDOGLIB_H

#include <unistd.h>

#define DWLIB_SUCCESS 0L
#define DWLIB_ERROR -1L

typedef void(*dwlib_process_stopped_callback_t)(pid_t p);

extern long dwlib_initialize(dwlib_process_stopped_callback_t process_stopped_callback);
extern long dwlib_finalize(void);

extern long dwlib_watch(const char* const executable_binary_path);
extern long dwlib_unwatch(const char* const executable_binary_path);

extern void dwlib_set_fatal_error_handler(void(*fatal_error_handler)(int));

#endif //DEBUGWATCHDOGLIB_H
