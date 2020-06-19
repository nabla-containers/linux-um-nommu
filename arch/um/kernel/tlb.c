/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched/signal.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <as-layout.h>
#include <mem_user.h>
#include <os.h>
#include <skas.h>
#include <kern_util.h>

struct host_vm_change {
	struct host_vm_op {
		enum { NONE, MMAP, MUNMAP, MPROTECT } type;
		union {
			struct {
				unsigned long addr;
				unsigned long len;
				unsigned int prot;
				int fd;
				__u64 offset;
			} mmap;
			struct {
				unsigned long addr;
				unsigned long len;
			} munmap;
			struct {
				unsigned long addr;
				unsigned long len;
				unsigned int prot;
			} mprotect;
		} u;
	} ops[1];
	int userspace;
	int index;
	struct mm_struct *mm;
	void *data;
	int force;
};

#define INIT_HVC(mm, force, userspace) \
	((struct host_vm_change) \
	 { .ops		= { { .type = NONE } },	\
	   .mm		= mm, \
       	   .data	= NULL, \
	   .userspace	= userspace, \
	   .index	= 0, \
	   .force	= force })

static void report_enomem(void)
{
	printk(KERN_ERR "UML ran out of memory on the host side! "
			"This can happen due to a memory limitation or "
			"vm.max_map_count has been reached.\n");
}


void fix_range_common(struct mm_struct *mm, unsigned long start_addr,
		      unsigned long end_addr, int force)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}


void flush_tlb_page(struct vm_area_struct *vma, unsigned long address)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

pgd_t *pgd_offset_proc(struct mm_struct *mm, unsigned long address)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

pud_t *pud_offset_proc(pgd_t *pgd, unsigned long address)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

pmd_t *pmd_offset_proc(pud_t *pud, unsigned long address)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

pte_t *pte_offset_proc(pmd_t *pmd, unsigned long address)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

pte_t *addr_pte(struct task_struct *task, unsigned long addr)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void flush_tlb_all(void)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void flush_tlb_kernel_vm(void)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void __flush_tlb_one(unsigned long addr)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}
EXPORT_SYMBOL(flush_tlb_range);

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
			unsigned long end)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void flush_tlb_mm(struct mm_struct *mm)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}

void force_flush_all(void)
{
#ifdef CONFIG_MMU
	force_sig(SIGKILL);
#endif
}
