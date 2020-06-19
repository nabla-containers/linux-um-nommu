/*
 * Copyright (C) 2003 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Copyright 2003 PathScale, Inc.
 *
 * Licensed under the GPL
 */

#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <asm/prctl.h> /* XXX This should get the constants from libc */
#include <os.h>
#include <asm/thread_info.h>

long long os_nsecs(void);

/*
 * The guest libc can change FS, which confuses the host libc.
 * In fact, changing FS directly is not supported (check
 * man arch_prctl). So, whenever we make a host syscall,
 * we should be changing FS to the original FS (not the
 * one set by the guest libc). This original FS is stored
 * in host_fs.
 */
long long host_fs = -1;

long arch_prctl(struct task_struct *task, int option,
		unsigned long __user *arg2)
{
	unsigned long *ptr = arg2, tmp;
	long ret;
	int pid = task->mm->context.id.u.pid;

	struct uml_pt_regs *regs = &current->thread.regs.regs;

	/*
	 * With ARCH_SET_FS (and ARCH_SET_GS is treated similarly to
	 * be safe), we need to call arch_prctl on the host because
	 * setting %fs may result in something else happening (like a
	 * GDT or thread.fs being set instead).  So, we let the host
	 * fiddle the registers and thread struct and restore the
	 * registers afterwards.
	 *
	 * So, the saved registers are stored to the process (this
	 * needed because a stub may have been the last thing to run),
	 * arch_prctl is run on the host, then the registers are read
	 * back.
	 */


// rkj: XXX: this is incomplete. we need to save and restore
// the FS/GS registers on every context switch. Might be
// enough to implement restore/save registers.


	switch (option) {
	case ARCH_SET_FS:
#ifdef CONFIG_MMU
		ret = restore_registers(pid, &current->thread.regs.regs);
		if (ret)
			return ret;
#else
		if (host_fs == -1) {
			os_arch_prctl(0, ARCH_GET_FS, (void *)&host_fs);
		}
#endif
		break;
	case ARCH_SET_GS:
#ifdef CONFIG_MMU
		ret = restore_registers(pid, &current->thread.regs.regs);
		if (ret)
			return ret;
#endif
		break;
	case ARCH_GET_FS:
		ptr = &tmp;
		break;
	case ARCH_GET_GS:
		/*
		 * With these two, we read to a local pointer and
		 * put_user it to the userspace pointer that we were
		 * given.  If addr isn't valid (because it hasn't been
		 * faulted in or is just bogus), we want put_user to
		 * fault it in (or return -EFAULT) instead of having
		 * the host return -EFAULT.
		 */
		ptr = &tmp;
	}

	ret = os_arch_prctl(pid, option, ptr);
	if (ret)
		return ret;

	switch (option) {
	case ARCH_SET_FS:
		current->thread.arch.fs = (unsigned long) ptr;
#ifdef CONFIG_MMU
		ret = save_registers(pid, &current->thread.regs.regs);
#else
		regs->gp[HOST_FS] = ptr;
#endif
		break;
	case ARCH_SET_GS:
#ifdef CONFIG_MMU
		ret = save_registers(pid, &current->thread.regs.regs);
#else
		regs->gp[HOST_GS] = ptr;
#endif
		break;
	case ARCH_GET_FS:
		ret = put_user(tmp, arg2);
		break;
	case ARCH_GET_GS:
		ret = put_user(tmp, arg2);
		break;
	}

	return ret;
}

SYSCALL_DEFINE2(arch_prctl, int, option, unsigned long, arg2)
{
	return arch_prctl(current, option, (unsigned long __user *) arg2);
}

void arch_switch_to(struct task_struct *to)
{
	current_top_of_stack = task_top_of_stack(to);
	current_ptregs = task_pt_regs(to);

	if ((to->thread.arch.fs == 0) || (to->mm == NULL))
		return;

	// rkj: this changes the FS on every context switch
	arch_prctl(to, ARCH_SET_FS, (void __user *) to->thread.arch.fs);
}
