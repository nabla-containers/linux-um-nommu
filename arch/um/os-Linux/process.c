/*
 * Copyright (C) 2015 Thomas Meyer (thomas@m3y3r.de)
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <init.h>
#include <longjmp.h>
#include <os.h>
#include <err.h>
#include <seccomp.h>

#define ARBITRARY_ADDR -1
#define FAILURE_PID    -1

#define STAT_PATH_LEN sizeof("/proc/#######/stat\0")
#define COMM_SCANF "%*[^)])"

#ifdef CONFIG_MMU
unsigned long os_process_pc(int pid)
{
	char proc_stat[STAT_PATH_LEN], buf[256];
	unsigned long pc = ARBITRARY_ADDR;
	int fd, err;

	sprintf(proc_stat, "/proc/%d/stat", pid);
	fd = open(proc_stat, O_RDONLY, 0);
	if (fd < 0) {
		printk(UM_KERN_ERR "os_process_pc - couldn't open '%s', "
		       "errno = %d\n", proc_stat, errno);
		goto out;
	}
	CATCH_EINTR(err = read(fd, buf, sizeof(buf)));
	if (err < 0) {
		printk(UM_KERN_ERR "os_process_pc - couldn't read '%s', "
		       "err = %d\n", proc_stat, errno);
		goto out_close;
	}
	os_close_file(fd);
	pc = ARBITRARY_ADDR;
	if (sscanf(buf, "%*d " COMM_SCANF " %*c %*d %*d %*d %*d %*d %*d %*d "
		   "%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d "
		   "%*d %*d %*d %*d %*d %lu", &pc) != 1)
		printk(UM_KERN_ERR "os_process_pc - couldn't find pc in '%s'\n",
		       buf);
 out_close:
	close(fd);
 out:
	return pc;
}

int os_process_parent(int pid)
{
	char stat[STAT_PATH_LEN];
	char data[256];
	int parent = FAILURE_PID, n, fd;

	if (pid == -1)
		return parent;

	snprintf(stat, sizeof(stat), "/proc/%d/stat", pid);
	fd = open(stat, O_RDONLY, 0);
	if (fd < 0) {
		printk(UM_KERN_ERR "Couldn't open '%s', errno = %d\n", stat,
		       errno);
		return parent;
	}

	CATCH_EINTR(n = read(fd, data, sizeof(data)));
	close(fd);

	if (n < 0) {
		printk(UM_KERN_ERR "Couldn't read '%s', errno = %d\n", stat,
		       errno);
		return parent;
	}

	parent = FAILURE_PID;
	n = sscanf(data, "%*d " COMM_SCANF " %*c %d", &parent);
	if (n != 1)
		printk(UM_KERN_ERR "Failed to scan '%s'\n", data);

	return parent;
}
#endif

void os_alarm_process(int pid)
{
	kill(pid, SIGALRM);
}

void os_stop_process(int pid)
{
	kill(pid, SIGSTOP);
}

void os_kill_process(int pid, int reap_child)
{
	kill(pid, SIGKILL);
	if (reap_child)
		CATCH_EINTR(waitpid(pid, NULL, __WALL));
}

#ifdef CONFIG_MMU

/* Kill off a ptraced child by all means available.  kill it normally first,
 * then PTRACE_KILL it, then PTRACE_CONT it in case it's in a run state from
 * which it can't exit directly.
 */

void os_kill_ptraced_process(int pid, int reap_child)
{
	kill(pid, SIGKILL);
	ptrace(PTRACE_KILL, pid);
	ptrace(PTRACE_CONT, pid);
	if (reap_child)
		CATCH_EINTR(waitpid(pid, NULL, __WALL));
}

#endif

/* Don't use the glibc version, which caches the result in TLS. It misses some
 * syscalls, and also breaks with clone(), which does not unshare the TLS.
 */

int os_getpid(void)
{
	return syscall(__NR_getpid);
}

int os_getpgrp(void)
{
	return getpgrp();
}

int os_map_memory(void *virt, int fd, unsigned long long off, unsigned long len,
		  int r, int w, int x)
{
	void *loc;
	int prot;

	prot = (r ? PROT_READ : 0) | (w ? PROT_WRITE : 0) |
		(x ? PROT_EXEC : 0);

#ifdef CONFIG_MMU
	loc = mmap64((void *) virt, len, prot, MAP_SHARED | MAP_FIXED,
		     fd, off);
#else
	loc = mmap64((void *) virt, len, prot, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
		     fd, off);
#endif
	if (loc == MAP_FAILED)
		return -errno;
	return 0;
}

int os_protect_memory(void *addr, unsigned long len, int r, int w, int x)
{
	int prot = ((r ? PROT_READ : 0) | (w ? PROT_WRITE : 0) |
		    (x ? PROT_EXEC : 0));

	if (mprotect(addr, len, prot) < 0)
		return -errno;

	return 0;
}

int os_unmap_memory(void *addr, int len)
{
	int err;

	err = munmap(addr, len);
	if (err < 0)
		return -errno;
	return 0;
}

#ifndef MADV_REMOVE
#define MADV_REMOVE KERNEL_MADV_REMOVE
#endif

int os_drop_memory(void *addr, int length)
{
	int err;

	err = madvise(addr, length, MADV_REMOVE);
	if (err < 0)
		err = -errno;
	return err;
}

int __init can_drop_memory(void)
{
	void *addr;
	int fd, ok = 0;

	printk(UM_KERN_INFO "Checking host MADV_REMOVE support...");
	fd = create_mem_file(UM_KERN_PAGE_SIZE);
	if (fd < 0) {
		printk(UM_KERN_ERR "Creating test memory file failed, "
		       "err = %d\n", -fd);
		goto out;
	}

	addr = mmap64(NULL, UM_KERN_PAGE_SIZE, PROT_READ | PROT_WRITE,
		      MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		printk(UM_KERN_ERR "Mapping test memory file failed, "
		       "err = %d\n", -errno);
		goto out_close;
	}

	if (madvise(addr, UM_KERN_PAGE_SIZE, MADV_REMOVE) != 0) {
		printk(UM_KERN_ERR "MADV_REMOVE failed, err = %d\n", -errno);
		goto out_unmap;
	}

	printk(UM_KERN_CONT "OK\n");
	ok = 1;

out_unmap:
	munmap(addr, UM_KERN_PAGE_SIZE);
out_close:
	close(fd);
out:
	return ok;
}

static int os_page_mincore(void *addr)
{
	char vec[2];
	int ret;

	ret = mincore(addr, UM_KERN_PAGE_SIZE, vec);
	if (ret < 0) {
		if (errno == ENOMEM || errno == EINVAL)
			return 0;
		else
			return -errno;
	}

	return vec[0] & 1;
}

int os_mincore(void *addr, unsigned long len)
{
	char *vec;
	int ret, i;

	if (len <= UM_KERN_PAGE_SIZE)
		return os_page_mincore(addr);

	vec = calloc(1, (len + UM_KERN_PAGE_SIZE - 1) / UM_KERN_PAGE_SIZE);
	if (!vec)
		return -ENOMEM;

	ret = mincore(addr, UM_KERN_PAGE_SIZE, vec);
	if (ret < 0) {
		if (errno == ENOMEM || errno == EINVAL)
			ret = 0;
		else
			ret = -errno;

		goto out;
	}

	for (i = 0; i < ((len + UM_KERN_PAGE_SIZE - 1) / UM_KERN_PAGE_SIZE); i++) {
		if (!(vec[i] & 1)) {
			ret = 0;
			goto out;
		}
	}

	ret = 1;
out:
	free(vec);
	return ret;
}

void init_new_thread_signals(void)
{
	set_handler(SIGSEGV);
	set_handler(SIGTRAP);
	set_handler(SIGFPE);
	set_handler(SIGILL);
	set_handler(SIGBUS);
	signal(SIGHUP, SIG_IGN);
	set_handler(SIGIO);
	signal(SIGWINCH, SIG_IGN);
}

static const int allowed_list[] = {
	/*
	 * These (above "at exit") are enough to run "anything".  Not allowing
	 * the ones "at exit" will crash the process at exit only.
	 */
	SCMP_SYS(clock_gettime),
	SCMP_SYS(write),
	SCMP_SYS(read),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(poll),
	SCMP_SYS(timer_settime),
	SCMP_SYS(epoll_wait),
	SCMP_SYS(arch_prctl),
	SCMP_SYS(clock_nanosleep),
	/*
	 * Used by tuntap at init:
	 *
	 * Need all of thse when using a tap device because the tuntap device
	 * is opened when setting the interface in the guest (after the guest
	 * kernel has booted!).
	 */
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(fcntl),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(ioctl),
	SCMP_SYS(open),
	SCMP_SYS(brk),
	SCMP_SYS(getpid),

	/* at exit */
	SCMP_SYS(ioctl),
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(wait4),
	SCMP_SYS(kill),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(exit_group),
	SCMP_SYS(close),
#ifdef CONFIG_UMID_DIR
	SCMP_SYS(munmap),
	SCMP_SYS(getdents),
	SCMP_SYS(open),
	SCMP_SYS(rmdir),
	SCMP_SYS(mmap),
	SCMP_SYS(mprotect),
	SCMP_SYS(fstat),
	SCMP_SYS(unlink),
#endif
};

#define ELEMENTS(x) (sizeof (x) / sizeof (*(x)))

void os_setup_seccomp(void)
{
	int i, rc = -1;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		err(1, "seccomp_init");

	for (i = 0; i < ELEMENTS(allowed_list); i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed_list[i], 0);
		if (rc < 0)
			err(1, "seccomp_rule_add");
	}

	rc = seccomp_load(ctx);
	if (rc < 0)
		err(1, "seccomp_load");

	seccomp_release(ctx);
}
