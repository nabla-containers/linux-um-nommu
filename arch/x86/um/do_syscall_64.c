/*
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <kern_util.h>
#include <sysdep/ptrace.h>
#include <sysdep/ptrace_user.h>
#include <sysdep/syscalls.h>
#include <shared/timer-internal.h>
#include <asm/unistd.h>
#include <os.h>

//#define RKJ_DEBUG_MSGS

#ifndef CONFIG_MMU

__visible void do_syscall_64(struct pt_regs *regs)
{
	int syscall;

	syscall = PT_SYSCALL_NR(regs->regs.gp);

#ifdef RKJ_DEBUG_MSGS
	printk(KERN_DEBUG "syscall(%ld) (current=%lx) (fn=%lx)\n",
		syscall, current, (unsigned long)sys_call_table[syscall]);
#endif
	if (likely(syscall < NR_syscalls)) {
		PT_REGS_SET_SYSCALL_RETURN(regs,
				EXECUTE_SYSCALL(syscall, regs));
	}
#ifdef RKJ_DEBUG_MSGS
	printk(KERN_DEBUG "syscall(%ld) --> %lx\n", syscall,
		regs->regs.gp[HOST_AX]);
#endif

	/* execve succeeded */
	if (syscall == 59 && regs->regs.gp[HOST_AX] == 0) {
		userspace(&current->thread.regs.regs,
			current_thread_info()->aux_fp_regs);
	}
}
#endif
