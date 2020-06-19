/*
 * Copyright (C) 2007 Jeff Dike (jdike@{addtoit.com,linux.intel.com})
 * Licensed under the GPL
 */

#include <sys/ptrace.h>
#include <asm/ptrace.h>

#include <asm/prctl.h>
#include <sys/prctl.h>


#ifdef CONFIG_MMU
int os_arch_prctl(int pid, int option, unsigned long *arg2)
{
	return ptrace(PTRACE_ARCH_PRCTL, pid, (unsigned long) arg2, option);
}
#else

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

int os_arch_prctl(int pid, int option, unsigned long *arg2)
{
	return syscall(158, option, arg2);
}
#endif
