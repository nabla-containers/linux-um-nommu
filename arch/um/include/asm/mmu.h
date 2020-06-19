/* 
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#ifndef __ARCH_UM_MMU_H
#define __ARCH_UM_MMU_H

#include <mm_id.h>
#include <asm/mm_context.h>

typedef struct mm_context {
	struct mm_id id;
	struct uml_arch_mm_context arch;
	struct page *stub_pages[2];

        unsigned long   end_brk;
#ifdef CONFIG_BINFMT_ELF_FDPIC
        unsigned long   exec_fdpic_loadmap;
        unsigned long   interp_fdpic_loadmap;
#endif

	void __user *vdso;			/* vdso base address */
	const struct vdso_image *vdso_image;	/* vdso image in use */

} mm_context_t;

extern void __switch_mm(struct mm_id * mm_idp);

/* Avoid tangled inclusion with asm/ldt.h */
extern long init_new_ldt(struct mm_context *to_mm, struct mm_context *from_mm);
extern void free_ldt(struct mm_context *mm);

#endif
