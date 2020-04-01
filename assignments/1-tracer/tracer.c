// SPDX-License-Identifier: GPL-2.0+
/*
 * tracer.c - Linux kernel kprobe
 *
 * Author: Diana Cretu <dianacretu2806@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "tracer.h"

DEFINE_SPINLOCK(lock);

/* Returns the struct with the PID given
 * as an argument
 */
static struct process_info *process_info_find_pid(int pid)
{
	struct list_head *p;
	struct process_info *pi;

	list_for_each(p, &head) {
		pi = list_entry(p, struct process_info, list);
		if (pi->pid == pid)
			return pi;
	}

	return NULL;
}

/* Post handler for __kmalloc function */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct data *data;
	struct process_info *pi;
	struct memory_info *mi;
	int address;

	/* __kmalloc returns the address where the memory was allocated */
	address = regs_return_value(regs);
	data = (struct data *)ri->data;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	/* Increment the number of __kmalloc calls */
	pi->kmalloc_calls++;

	mi = kmalloc(sizeof(*mi), GFP_ATOMIC);
	if (!mi) {
		spin_unlock(&lock);
		return -ENOMEM;
	}

	/* Add the pair (address, size of memory allocated) in the list */
	mi->address = address;
	pi->kmalloc_mem += data->size;
	mi->size = data->size;
	list_add(&mi->list, &pi->memory);
	spin_unlock(&lock);

	return 0;
}

/* Entry handler for __kmalloc */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct data *data;

	data = (struct data *)ri->data;
	/* Function __kmalloc receives the size of the memory to be allocated
	 * as argument when it is called
	 */
	data->size = regs->ax;

	return 0;
}

static int kfree_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int address;
	struct process_info *pi;
	struct memory_info *mi;
	struct list_head *p;

	/* Kfree function receives as argument the address which
	 * should be freed
	 */
	address = regs->ax;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	pi->kfree_calls++;
	list_for_each(p, &pi->memory) {
		mi = list_entry(p, struct memory_info, list);

		if (mi->address == address)
			pi->kfree_mem += mi->size;
	}
	spin_unlock(&lock);

	return 0;
}

static int sched_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *pi;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	pi->sched++;
	spin_unlock(&lock);

	return 0;
}

static int up_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *pi;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	pi->up++;
	spin_unlock(&lock);

	return 0;
}

static int down_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *pi;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	pi->down++;
	spin_unlock(&lock);

	return 0;
}

static int lock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *pi;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	pi->lock++;
	spin_unlock(&lock);

	return 0;
}

static int unlock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info *pi;

	spin_lock(&lock);
	pi = process_info_find_pid(ri->task->pid);
	if (!pi) {
		spin_unlock(&lock);
		return -EINVAL;
	}

	pi->unlock++;
	spin_unlock(&lock);

	return 0;
}

struct kretprobe **kps = (struct kretprobe *[]){
	&(struct kretprobe) {
		.kp.symbol_name = "__kmalloc",
		.handler	= ret_handler,
		.entry_handler	= entry_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
	&(struct kretprobe) {
		.kp.symbol_name = "kfree",
		.entry_handler	= kfree_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
	&(struct kretprobe) {
		.kp.symbol_name = "schedule",
		.entry_handler	= sched_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
	&(struct kretprobe) {
		.kp.symbol_name = "up",
		.entry_handler	= up_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
	&(struct kretprobe) {
		.kp.symbol_name = "down_interruptible",
		.entry_handler	= down_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
	&(struct kretprobe) {
		.kp.symbol_name = "mutex_lock_nested",
		.entry_handler	= lock_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
	&(struct kretprobe) {
		.kp.symbol_name = "mutex_unlock",
		.entry_handler	= unlock_handler,
		.data_size	= sizeof(struct data),
		.maxactive	= MAXACTIVE,
	},
};

static void exit_handler (struct kprobe *k,
						  struct pt_regs *regs,
						  unsigned long flags)
{
	struct list_head *p, *q;
	struct process_info *pi;
	struct memory_info *mi;

	spin_lock(&lock);
	list_for_each_safe(p, q, &head) {
		pi = list_entry(p, struct process_info, list);
		if (pi->pid == current->pid) {
			struct list_head *m, *n;

			list_for_each_safe(m, n, &pi->memory) {
				mi = list_entry(m, struct memory_info, list);
				list_del(m);
				kfree(mi);
			}
			list_del(p);
			kfree(pi);
			break;
		}
	}
	spin_unlock(&lock);
}

static struct kprobe kp = {
	.symbol_name = "do_exit",
	.post_handler = exit_handler,
};

/* Create a new struct to be added in the list of processes */
static struct process_info *process_info_alloc(int pid)
{
	struct process_info *pi;

	pi = kmalloc(sizeof(*pi), GFP_ATOMIC);
	if (!pi)
		return NULL;

	pi->pid = pid;
	pi->kmalloc_calls = 0;
	pi->kfree_calls = 0;
	pi->kmalloc_mem = 0;
	pi->kfree_mem = 0;
	pi->sched = 0;
	pi->up = 0;
	pi->down = 0;
	pi->lock = 0;
	pi->unlock = 0;
	INIT_LIST_HEAD(&pi->memory);

	return pi;
}

int tracer_open(struct inode *inode, struct file *filp)
{
	return 0;
}

int tracer_release(struct inode *inode, struct file *filp)
{
	return 0;
}

long tracer_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct process_info *pi;
	struct list_head *p, *q, *aux_list = NULL;
	struct process_info *aux;
	struct list_head *m, *n;
	struct memory_info *mi;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pi = process_info_alloc(arg);
		spin_lock(&lock);
		list_add(&pi->list, &head);
		spin_unlock(&lock);
		break;
	case TRACER_REMOVE_PROCESS:
		spin_lock(&lock);
		list_for_each_safe(p, q, &head) {
			pi = list_entry(p, struct process_info, list);
			if (pi->pid == arg) {
				aux = pi;
				aux_list = p;
				break;
			}
		}
		spin_unlock(&lock);

		if (!aux_list || !aux)
			break;

		list_for_each_safe(m, n, &aux->memory) {
			mi = list_entry(m, struct memory_info,
							list);
			list_del(m);
			kfree(mi);
		}
		list_del(aux_list);
		kfree(aux);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static struct file_operations tracer_ops = {
	.owner = THIS_MODULE,
	.open = tracer_open,
	.release = tracer_release,
	.unlocked_ioctl = tracer_ioctl,
};

static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.fops = &tracer_ops,
	.name = TRACER_DEV_NAME,
};

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct process_info *pi;

	seq_puts(m, "PID   kmalloc  kfree  kmalloc_mem  kfree_mem sched  up   down  lock  unlock\n");

	list_for_each(p, &head) {
		pi = list_entry(p, struct process_info, list);
		seq_printf(m, "%d ", pi->pid);
		seq_printf(m, "%d ", pi->kmalloc_calls);
		seq_printf(m, "%d ", pi->kfree_calls);
		seq_printf(m, "%d ", pi->kmalloc_mem);
		seq_printf(m, "%d ", pi->kfree_mem);
		seq_printf(m, "%d ", pi->sched);
		seq_printf(m, "%d ", pi->up);
		seq_printf(m, "%d ", pi->down);
		seq_printf(m, "%d ", pi->lock);
		seq_printf(m, "%d ", pi->unlock);
		seq_puts(m, "\n");
	}
	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static const struct file_operations r_fops = {
	.owner		= THIS_MODULE,
	.open		= list_read_open,
	.read		= seq_read,
	.release	= single_release,
};

static int tracer_init(void)
{
	int ret;

	proc_list_read = proc_create(TRACER_DEV_NAME, 0000, NULL,
				&r_fops);
	if (!proc_list_read)
		return -ENOMEM;

	ret = misc_register(&tracer_dev);

	if (ret < 0)
		goto exit;

	INIT_LIST_HEAD(&head);

	ret = register_kretprobes(kps, KRETPROBES);

	if (ret < 0)
		goto error_kretprobes;

	ret = register_kprobe(&kp);

	if (ret < 0)
		goto error_kprobe;

	return 0;

error_kprobe:
	unregister_kprobe(&kp);
error_kretprobes:
	unregister_kretprobes(kps, KRETPROBES);
exit:
	misc_deregister(&tracer_dev);
	proc_remove(proc_list_read);
	return ret;
}

static void tracer_exit(void)
{
	unregister_kprobe(&kp);
	unregister_kretprobes(kps, KRETPROBES);
	proc_remove(proc_list_read);
	misc_deregister(&tracer_dev);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Linux kernel kprobe");
MODULE_AUTHOR("Diana Cretu <dianacretu2806@gmail.com>");
MODULE_LICENSE("GPL v2");
