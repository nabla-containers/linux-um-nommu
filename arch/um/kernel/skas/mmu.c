/*
 * Copyright (C) 2015 Thomas Meyer (thomas@m3y3r.de)
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>
#include <as-layout.h>
#include <os.h>
#include <skas.h>

int init_new_context(struct task_struct *task, struct mm_struct *mm)
{
#ifdef CONFIG_MMU
	force_sigsegv(SIGSEGV);
#endif
	return 0;
}

void arch_exit_mmap(struct mm_struct *mm)
{
#ifdef CONFIG_MMU
	force_sigsegv(SIGSEGV);
#endif
}

void destroy_context(struct mm_struct *mm)
{
#ifdef CONFIG_MMU
	force_sigsegv(SIGSEGV);
#endif
}

void uml_setup_stubs(struct mm_struct *mm)
{
#ifdef CONFIG_MMU
	force_sigsegv(SIGSEGV);
#endif
}
