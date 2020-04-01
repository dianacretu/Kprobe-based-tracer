// SPDX-License-Identifier: GPL-2.0+
/*
 * SO2 kprobe based tracer header file
 *
 * this is shared with user space
 */

#ifndef TRACER_H__
#define TRACER_H__ 1

#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

#define TRACER_DEV_MINOR 42
#define TRACER_DEV_NAME "tracer"

#define TRACER_ADD_PROCESS	_IOW(_IOC_WRITE, 42, pid_t)
#define TRACER_REMOVE_PROCESS	_IOW(_IOC_WRITE, 43, pid_t)

#define MAXACTIVE	40

#define KRETPROBES	7

struct proc_dir_entry *proc_list_read;

struct data {
	int size;
};

struct memory_info {
	int size;
	int address;
	struct list_head list;
};

struct process_info {
	pid_t pid;
	int kmalloc_calls;
	int kfree_calls;
	int kmalloc_mem;
	int kfree_mem;
	int sched;
	int up;
	int down;
	int lock;
	int unlock;
	struct list_head memory;
	struct list_head list;
};

static struct list_head head;

#endif /* TRACER_H_ */
