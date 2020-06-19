#include <asm/errno.h>

#include <linux/linkage.h>
#include <asm/percpu.h>
#include <asm/desc.h>

#include "../entry/calling.h"

#ifdef CONFIG_SMP
#error need to stash these variables somewhere else
#endif

#define UM_GLOBAL_VAR(x) .data; .align 8; .globl x; x:; .long 0

UM_GLOBAL_VAR(current_top_of_stack)
UM_GLOBAL_VAR(current_ptregs)

.code64
.section .entry.text, "ax"

.align 8
#define ENTRY(x) .text; .globl x; .type x,%function; x:
#define END(x)   .size x, . - x

/*
 * %rcx has the return address (we set it like that in musl).
 *
 * Registers on entry:
 * rax  system call number
 * rcx  return address
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3
 * r8   arg4
 * r9   arg5
 *
 * (note: we are allowed to mess with r11: r11 is callee-clobbered
 * register in C ABI)
 */
ENTRY(__kernel_vsyscall)

	movq	%rsp, %r11

	/* Point rsp to the top of the ptregs array, so we can
           just fill it with a bunch of push'es. */
	movq	current_ptregs, %rsp

	/* 8 bytes * 20 registers (plus 8 for the push) */
	addq	$168, %rsp

	/* Construct struct pt_regs on stack */
	pushq	$0		/* pt_regs->ss (index 20) */
	pushq   %r11		/* pt_regs->sp */
	pushfq			/* pt_regs->flags */
	pushq	$0		/* pt_regs->cs */
	pushq	%rcx		/* pt_regs->ip */
	pushq	%rax		/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	mov %rsp, %rdi

	/*
	 * Switch to current top of stack, so "current->" points
	 * to the right task.
	 */
	movq	current_top_of_stack, %rsp

	call	do_syscall_64

	movq	current_ptregs, %rsp

	POP_REGS
	
	addq	$8, %rsp	/* skip orig_ax */
	addq	$8, %rsp	/* skip ip */
	addq	$8, %rsp	/* skip cs */
	addq	$8, %rsp	/* skip flags */
	popq	%rsp

	ret

END(__kernel_vsyscall)

// void userspace(struct uml_pt_regs *regs, unsigned long *aux_fp_regs)
ENTRY(userspace)

	movq	current_ptregs, %rsp

	POP_REGS skip_r11rcx=1

	addq	$8, %rsp	/* skip orig_ax */
	popq	%r11	/* pt_regs->ip */
	addq	$8, %rsp	/* skip cs */
	addq	$8, %rsp	/* skip flags */
	popq	%rsp

	jmp	*%r11

END(userspace)
