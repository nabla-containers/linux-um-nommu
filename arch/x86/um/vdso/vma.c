// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2011 Richard Weinberger <richrd@nod.at>
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <asm/elf.h>
#include <linux/init.h>
#include <linux/mman.h>

static unsigned int __read_mostly vdso_enabled = 1;
unsigned long um_vdso_addr;

extern unsigned long task_size;
extern char vdso_start[], vdso_end[];

static struct page **vdsop;
static struct page *um_vdso;

static int __init init_vdso(void)
{
	BUG_ON(vdso_end - vdso_start > PAGE_SIZE);

#ifdef CONFIG_MMU
	um_vdso_addr = task_size - PAGE_SIZE;
#endif

	vdsop = kmalloc(sizeof(struct page *), GFP_KERNEL);
	if (!vdsop)
		goto oom;

	um_vdso = alloc_page(GFP_KERNEL);
	if (!um_vdso) {
		kfree(vdsop);

		goto oom;
	}

	unsigned long pg_um_vdso = page_address(um_vdso);

	printk(KERN_ERR "vdso_start=%lx um_vdso_addr=%lx pg_um_vdso=%lx\n\r",
		vdso_start, um_vdso_addr, pg_um_vdso);
	copy_page(pg_um_vdso, vdso_start);
	*vdsop = um_vdso;

#ifndef CONFIG_MMU
	// rkj: this is fine with NOMMU as everything is accessible
	um_vdso_addr = pg_um_vdso;
	printk(KERN_ERR "map vdso um_vdso_addr=%lx\r\n", um_vdso_addr);
#endif

	return 0;

oom:
	printk(KERN_ERR "Cannot allocate vdso\n");
	vdso_enabled = 0;

	return -ENOMEM;
}
subsys_initcall(init_vdso);

#ifdef CONFIG_MMU
int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	int err;
	struct mm_struct *mm = current->mm;

	if (!vdso_enabled)
		return 0;

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

	err = install_special_mapping(mm, um_vdso_addr, PAGE_SIZE,
		VM_READ|VM_EXEC|
		VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
		vdsop);

	up_write(&mm->mmap_sem);

	return err;
}
#endif
