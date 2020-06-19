/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linker script for 64-bit vDSO.
 * We #include the file to define the layout details.
 * Here we only choose the prelinked virtual address.
 *
 * This file defines the version script giving the user-exported symbols in
 * the DSO.  We can define local symbols here called VDSO* to make their
 * values visible using the asm-x86/vdso.h macros from the kernel proper.
 */

#define VDSO_PRELINK 0xffffffffff700000
#include "vdso-layout.lds.S"

ENTRY(__kernel_vsyscall);

/*
 * This controls what userland symbols we export from the vDSO.
 */
VERSION {
	LINUX_2.6 {
	global:
		write;
		__vdso_write;
		clock_gettime;
		__vdso_clock_gettime;
		gettimeofday;
		__vdso_gettimeofday;
		getcpu;
		__vdso_getcpu;
		time;
		__vdso_time;
	local: *;
	};

	LINUX_2.5 {
	global:
		__kernel_vsyscall;
		__kernel_sigreturn;
		__kernel_rt_sigreturn;
	local: *;
	};
}

VDSO64_PRELINK = VDSO_PRELINK;
