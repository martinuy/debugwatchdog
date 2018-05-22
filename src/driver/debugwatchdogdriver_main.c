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

#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

#include "debugwatchdogdriver.h"

/////////////////////
//     Defines     //
/////////////////////
#define ENABLE_WRITE_MEMORY write_cr0 (read_cr0 () & (~ 0x10000))
#define DISABLE_WRITE_MEMORY write_cr0 (read_cr0 () | 0x10000)

typedef enum debugwatchdog_state { UNWATCHING = 0, WATCHING } debugwatchdog_state_t;

typedef struct stopped_pids_list_node_t {
	struct list_head list;
	pid_t pid;
} stopped_pids_list_node_t;

typedef struct watch_process_list_node_t {
	struct list_head list;
	char* process_name;
} watch_process_list_node_t;

/////////////////////////
// Function prototypes //
/////////////////////////
extern void sys_execve_stub_ptregs_64_hook(void);
extern long sys_execve_hook(const char __user* filename, const char __user* const __user* argv, const char __user* const __user* envp);
static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg);
static void unwatch(void);
static void debugwatchdog_cleanup(void);

///////////////////////
// Global variables  //
///////////////////////
static pid_t authoritative_task_pid;
static int debugwatchdog_major = -1;
static struct cdev debugwatchdog_cdev;
static struct class* debugwatchdog_class = NULL;
static unsigned int device_created = 0U;
static DEFINE_MUTEX(global_lock);
static debugwatchdog_state_t global_state = UNWATCHING;
static LIST_HEAD(stopped_pids_list);
static LIST_HEAD(watched_processes_list);
static unsigned int currently_watched_processes = 0U;
static unsigned int currently_pending_stopped_notifications = 0U;
static const struct file_operations fops = {
	.unlocked_ioctl = unlocked_ioctl,
	.owner = THIS_MODULE,
};

void* sys_execve_hook_ptr;
void* stub_ptregs_64_ptr;
static void** sys_execve_ptr_in_sys_call_table;
static long(*sys_execve_ptr)(const char __user*, const char __user* const __user* , const char __user* const __user*);
static struct filename *(*getname_ptr)(const char __user*);
static void(*putname_ptr)(struct filename*);
static int (*group_send_sig_info_ptr)(int, struct siginfo*, struct task_struct*);
static void* sys_execve_stub_ptregs_64_ptr;

/////////////////////
//    Functions    //
/////////////////////
long sys_execve_hook(const char __user* filename, const char __user* const __user* argv, const char __user* const __user* envp) {
	long ret = -1;
	struct filename* execve_filename = NULL;

	if (!IS_ERR(filename)) {
		execve_filename = getname_ptr(filename);
	}

	ret = sys_execve_ptr(filename, argv, envp);
	if (ret != 0L) {
		goto execve_filename_fail;
	}

	if (execve_filename == NULL) {
		goto execve_filename_fail;
	}

	mutex_lock(&global_lock);
	if (global_state == WATCHING) {
		stopped_pids_list_node_t* stopped_pids_list_node = NULL;
		watch_process_list_node_t* it_ptr = NULL;
		list_for_each_entry(it_ptr, &watched_processes_list, list) {
			if (strcmp(it_ptr->process_name, execve_filename->name) == 0 &&
					currently_pending_stopped_notifications < DWDRIVER_MAX_PENDING_STOPPED_NOTIFICATIONS) {
				struct siginfo info_stop;
				struct siginfo info_notification;
				memset(&info_stop, 0, sizeof(struct siginfo));
				info_stop.si_signo = SIGSTOP;
				info_stop.si_code = SI_KERNEL;
				memset(&info_notification, 0, sizeof(struct siginfo));
				info_notification.si_signo = SIGUSR1;
				info_notification.si_code = SI_KERNEL;
				{
					struct task_struct* authoritative_task_ptr = NULL;
					rcu_read_lock();
					authoritative_task_ptr = pid_task(find_vpid(authoritative_task_pid), PIDTYPE_PID);
					if (authoritative_task_ptr != NULL) {
						send_sig_info(SIGSTOP, &info_stop, current);
						group_send_sig_info_ptr(SIGUSR1, &info_notification, authoritative_task_ptr);
					}
					rcu_read_unlock();
					if (authoritative_task_ptr != NULL) {
						stopped_pids_list_node = (stopped_pids_list_node_t*)kmalloc(sizeof(stopped_pids_list_node_t), GFP_KERNEL);
						if (stopped_pids_list_node == NULL) {
							goto add_to_list_fail;
						}
						stopped_pids_list_node->pid = current->pid;
						INIT_LIST_HEAD(&stopped_pids_list_node->list);
						list_add_tail(&stopped_pids_list_node->list, &stopped_pids_list);
						currently_pending_stopped_notifications++;
					} else {
						unwatch();
					}
				}
				break;
			}
		}
	}

add_to_list_fail:
	mutex_unlock(&global_lock);

execve_filename_fail:
	if (execve_filename != NULL) {
		putname_ptr(execve_filename);
		execve_filename = NULL;
	}
	return ret;
}

static long unlocked_ioctl(struct file* f, unsigned int cmd, unsigned long arg) {
	long ret_val = DWDRIVER_ERROR;
	pid_t authoritative_task_tgid = -1;

	mutex_lock(&global_lock);

	if (has_capability(current, CAP_SYS_MODULE) == false) {
		goto cleanup;
	}

	rcu_read_lock();
	{
		struct task_struct* authoritative_task_ptr = pid_task(find_vpid(authoritative_task_pid), PIDTYPE_PID);
		if (authoritative_task_ptr != NULL) {
			authoritative_task_tgid = authoritative_task_ptr->tgid;
		}
	}
	rcu_read_unlock();

	if (authoritative_task_tgid == -1) {
		// Module is orphan
		if (cmd == DWDRIVER_IOCTL_ENABLE_WATCHDOG && arg == DWDRIVER_WATCH) {
			// Assign new owner
			unwatch();
			authoritative_task_pid = current->pid;
			authoritative_task_tgid = current->tgid;
		}
	}

	if (current->tgid != authoritative_task_tgid) {
		goto cleanup;
	}

	switch(cmd) {
	case DWDRIVER_IOCTL_ENABLE_WATCHDOG:
        if (arg == DWDRIVER_UNWATCH) {
        	if (global_state == WATCHING) {
        		unwatch();
        	}
        } else if (arg == DWDRIVER_WATCH) {
        	if (global_state == UNWATCHING) {
				ENABLE_WRITE_MEMORY;
				*sys_execve_ptr_in_sys_call_table = sys_execve_stub_ptregs_64_hook;
				DISABLE_WRITE_MEMORY;
				global_state = WATCHING;
        	}
        } else {
        	goto cleanup;
        }
		break;
	case DWDRIVER_IOCTL_WATCH_PROCESS:
		if (global_state != WATCHING) {
			goto cleanup;
		}
		{
			watch_process_list_node_t* watch_process_list_node = NULL;
			dwdriver_watch_process_t watch_process;
			char* watch_process_name = NULL;
			if (copy_from_user(&watch_process, (dwdriver_watch_process_t*)arg, sizeof(dwdriver_watch_process_t)) != 0) {
				goto cleanup;
			}

			if (watch_process.process_name_length > PATH_MAX) {
				goto cleanup;
			}

			watch_process_name = (char*)kmalloc(watch_process.process_name_length + 1, GFP_KERNEL);
			if (watch_process_name == NULL) {
				goto cleanup;
			}

			if (copy_from_user(watch_process_name, watch_process.process_name, watch_process.process_name_length) != 0) {
				kfree(watch_process_name);
				goto cleanup;
			}
			(watch_process_name)[watch_process.process_name_length] = 0;

			if (watch_process.state == DWDRIVER_WATCH) {
				if (currently_watched_processes == DWDRIVER_MAX_WATCHED_PROCESSES) {
					kfree(watch_process_name);
					goto cleanup;
				}

				watch_process_list_node = (watch_process_list_node_t*)kmalloc(sizeof(watch_process_list_node_t), GFP_KERNEL);
				if (watch_process_list_node == NULL) {
					kfree(watch_process_name);
					goto cleanup;
				}
				watch_process_list_node->process_name = watch_process_name;
				INIT_LIST_HEAD(&watch_process_list_node->list);
				list_add_tail(&watch_process_list_node->list, &watched_processes_list);
				currently_watched_processes++;
			} else if (watch_process.state == DWDRIVER_UNWATCH) {
				{
					watch_process_list_node_t* it_ptr, *next_ptr;
					list_for_each_entry_safe(it_ptr, next_ptr, &watched_processes_list, list) {
						if (strcmp(it_ptr->process_name, watch_process_name) == 0) {
							list_del(&it_ptr->list);
							kfree(it_ptr->process_name);
							kfree(it_ptr);
							currently_watched_processes--;
							break;
						}
					}
				}
				kfree(watch_process_name);
			} else {
				kfree(watch_process_name);
				goto cleanup;
			}
		}
		break;
	case DWDRIVER_IOCTL_GET_STOPPED_PIDS:
		{
			dwdriver_stopped_pids_t stopped_pids;
			unsigned int max_stopped_pids_length = 0U;
			unsigned int max_stopped_pids_count = 0U;
			unsigned int copied_bytes = 0U;
			if (copy_from_user(&stopped_pids, (dwdriver_stopped_pids_t*)arg, sizeof(dwdriver_stopped_pids_t)) != 0) {
				goto cleanup;
			}
			if (copy_from_user(&max_stopped_pids_length, stopped_pids.pids_buffer_length, sizeof(unsigned int)) != 0) {
				goto cleanup;
			}
			max_stopped_pids_count = max_stopped_pids_length / sizeof(pid_t);
			{
				stopped_pids_list_node_t* it_ptr, *next_ptr;
				list_for_each_entry_safe(it_ptr, next_ptr, &stopped_pids_list, list) {
					if (max_stopped_pids_count == 0) {
						break;
					}
					if (copy_to_user(((char*)stopped_pids.pids_buffer + copied_bytes), &(it_ptr->pid), sizeof(pid_t)) != 0) {
						goto cleanup;
					}
					copied_bytes += sizeof(pid_t);
					max_stopped_pids_count--;
					list_del(&it_ptr->list);
					kfree(it_ptr);
					currently_pending_stopped_notifications--;
				}
			}
			if (copy_to_user(stopped_pids.pids_buffer_length, &copied_bytes, sizeof(unsigned int)) != 0) {
				goto cleanup;
			}
		}
		break;
	}
	ret_val = DWDRIVER_SUCCESS;
    goto cleanup;

cleanup:
	mutex_unlock(&global_lock);
	return ret_val;
}

static void unwatch(void) {

	global_state = UNWATCHING;

	if (sys_execve_stub_ptregs_64_ptr != NULL) {
		ENABLE_WRITE_MEMORY;
		*sys_execve_ptr_in_sys_call_table = sys_execve_stub_ptregs_64_ptr;
		DISABLE_WRITE_MEMORY;
	}

	{
		stopped_pids_list_node_t* it_ptr, *next_ptr;
		list_for_each_entry_safe(it_ptr, next_ptr, &stopped_pids_list, list) {
			list_del(&it_ptr->list);
			kfree(it_ptr);
			currently_pending_stopped_notifications--;
		}
	}

	{
		watch_process_list_node_t* it_ptr, *next_ptr;
		list_for_each_entry_safe(it_ptr, next_ptr, &watched_processes_list, list) {
			list_del(&it_ptr->list);
			kfree(it_ptr->process_name);
			kfree(it_ptr);
			currently_watched_processes--;
		}
	}
}

static void debugwatchdog_cleanup(void) {
    if (device_created == 1U) {
        device_destroy(debugwatchdog_class, debugwatchdog_major);
        cdev_del(&debugwatchdog_cdev);
        device_created = 0U;
    }
    if (debugwatchdog_class) {
        class_destroy(debugwatchdog_class);
        debugwatchdog_class = NULL;
    }
    if (debugwatchdog_major != -1) {
        unregister_chrdev_region(debugwatchdog_major, 1);
        debugwatchdog_major = -1;
    }
}

static void __exit debugwatchdog_cleanup_module(void) {
	mutex_lock(&global_lock);
	debugwatchdog_cleanup();
	unwatch();
	mutex_unlock(&global_lock);

	// Wait to let threads executing sys_execve_hook finish executing this
	// code. These threads started executing before the sys_call_table was patched
	// with the original sys_execve value. When the module get unloaded,
	// sys_execve_hook memory will be unmapped, and we don't want any thread to
	// execute unmapped memory.
	msleep(1U);
}

static int __init debugwatchdog_init_module(void) {

    if (alloc_chrdev_region(&debugwatchdog_major, 0, 1, DWDRIVER_NAME "_proc") != 0) {
    	goto error;
    }

    if ((debugwatchdog_class = class_create(THIS_MODULE, DWDRIVER_NAME "_sys")) == NULL) {
    	goto error;
	}

    if (device_create(debugwatchdog_class, NULL, debugwatchdog_major, NULL, DWDRIVER_NAME "_dev") == NULL) {
    	goto error;
	}

    device_created = 1U;

    cdev_init(&debugwatchdog_cdev, &fops);

    if (cdev_add(&debugwatchdog_cdev, debugwatchdog_major, 1) == -1) {
    	goto error;
    }

    // Resolve symbols
    sys_execve_ptr_in_sys_call_table = (void**)kallsyms_lookup_name("sys_call_table") + __NR_execve;
    stub_ptregs_64_ptr = (void*)kallsyms_lookup_name("stub_ptregs_64");
    sys_execve_ptr = (long(*)(const char __user *, const char __user *const __user *, const char __user *const __user *))kallsyms_lookup_name("SyS_execve");
    getname_ptr = (struct filename *(*)(const char __user *))kallsyms_lookup_name("getname");
    putname_ptr = (void(*)(struct filename*))kallsyms_lookup_name("putname");
    sys_execve_hook_ptr = (void*)sys_execve_hook;
    sys_execve_stub_ptregs_64_ptr = (void*)*sys_execve_ptr_in_sys_call_table;
    group_send_sig_info_ptr = (int (*)(int, struct siginfo*, struct task_struct*))kallsyms_lookup_name("group_send_sig_info");

    if (sys_execve_ptr_in_sys_call_table == NULL || stub_ptregs_64_ptr == NULL || sys_execve_ptr == NULL ||
    		getname_ptr == NULL || sys_execve_hook_ptr == NULL || sys_execve_stub_ptregs_64_ptr == NULL ||
			group_send_sig_info_ptr == NULL || putname_ptr == NULL) {
    	goto error;
    }

    goto success;

error:
	debugwatchdog_cleanup();
	return DWDRIVER_ERROR;

success:
	authoritative_task_pid = current->pid;
	return DWDRIVER_SUCCESS;
}

module_init(debugwatchdog_init_module);
module_exit(debugwatchdog_cleanup_module);
MODULE_LICENSE("GPL");
