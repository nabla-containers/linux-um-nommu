// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2011 Richard Weinberger <richrd@nod.at>
 *
 * This vDSO turns all calls into a syscall so that UML can trap them.
 */


/* Disable profiling for userspace code */
#define DISABLE_BRANCH_PROFILING

#include <linux/time.h>
#include <linux/getcpu.h>
#include <asm/unistd.h>

/*
 * This is based on 0x60000000 (from arch/x86/Makefile.um) + 0x1000
 * (from arch/um/kernel/uml.lds)
 *
 * THIS REQUIRES A STATIC BUILD, AS __um_data_start IS ONLY
 * DEFINED IN THE STATIC UML LDS.
 * */
#define __um_data_start 0x0000000060001000

static unsigned long sys_call_table_ptr = __um_data_start;

void vdso_printmsg(char *msg, int len){
        register int    syscall_no  asm("rax") = 1;
        register int    arg1        asm("rdi") = 1;
        register char*  arg2        asm("rsi") = msg;
        register int    arg3        asm("rdx") = len;
        asm("syscall");
}

int __vdso_clock_gettime(clockid_t clock, struct timespec *ts)
{
	long ret;

	vdso_printmsg("clock_gettime\r\n", 15);
	asm("syscall" : "=a" (ret) :
		"0" (__NR_clock_gettime), "D" (clock), "S" (ts) : "memory");

	return ret;
}
//int clock_gettime(clockid_t, struct timespec *)
//	__attribute__((weak, alias("__vdso_clock_gettime")));

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);

int *sys_call_table;
//unsigned long *sys_call_table;
//sys_call_ptr_t *sys_call_table;

#define EXECUTE_SYSCALL(syscall, regs) \
        (((long (*)(long, long, long, long, long, long)) \
          (*sys_call_table[syscall]))(UPT_SYSCALL_ARG1(&regs->regs), \
                                      UPT_SYSCALL_ARG2(&regs->regs), \
                                      UPT_SYSCALL_ARG3(&regs->regs), \
                                      UPT_SYSCALL_ARG4(&regs->regs), \
                                      UPT_SYSCALL_ARG5(&regs->regs), \
                                      UPT_SYSCALL_ARG6(&regs->regs)))

/*
void write()
{
	syscall = (syscall_fn)
		(sys_call_table[regs->syscall_nr]);
        regs->r00 = syscall(regs->r00, regs->r01,
		regs->r02, regs->r03,
		regs->r04, regs->r05);
}
*/

extern char vvar_page[];


size_t
strlen(const char *str)
{
        const char *s;

        for (s = str; *s; ++s)
                ;
        return (s - str);
}


int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret;
	char msg[] = "gettimeofday";

	//vdso_printmsg(msg, 14);

	//sys_call_table = 0x602d1680;
	//
	asm("syscall" : "=a" (ret) :
		"0" (__NR_gettimeofday), "D" (tv), "S" (tz) : "memory");
	
	int (*sys_write)(int, const void *, size_t);
	sys_write = ((long *)(*(unsigned long *)sys_call_table_ptr))[1];
	//sys_write = ((long *)0x60365680)[1];
	//ssize_t (*sys_write)(int, const void, size_t) = ((long *)0x602d1680)[1];

	//(*sys_write)(2, "hola", 4);
	(*sys_write)(1, msg, strlen(msg));

	//long long (*sys_clock_gettime)(void);
	//sys_clock_gettime = 0x6002cb48;
	//sys_clock_gettime();

	//return ((long *)0x602d1680)[1];
	//return sys_call_table[0];
	return ret;
}

int gettimeofday(struct timeval *, struct timezone *)
	__attribute__((weak, alias("__vdso_gettimeofday")));


ssize_t __vdso_write(int fd, const void *buf, size_t count)
{
	int (*sys_write)(int, const void *, size_t);
	sys_write = ((long *)(*(unsigned long *)sys_call_table_ptr))[1];
	return (*sys_write)(fd, buf, count);
	while(1);
	return 0;
}

ssize_t write(int fd, const void *buf, size_t count)
	__attribute__((weak, alias("__vdso_write")));

void __kernel_vsyscall(void)
{
	while(1);
}

time_t __vdso_time(time_t *t)
{
	long secs;

	asm volatile("syscall"
		: "=a" (secs)
		: "0" (__NR_time), "D" (t) : "cc", "r11", "cx", "memory");
	
	return secs;
}
int time(time_t *t) __attribute__((weak, alias("__vdso_time")));

long
__vdso_getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *unused)
{
	/*
	 * UML does not support SMP, we can cheat here. :)
	 */

	if (cpu)
		*cpu = 0;
	if (node)
		*node = 0;

	return 0;
}

long getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache)
	__attribute__((weak, alias("__vdso_getcpu")));
