/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UM_PROCESSOR_H
#define __UM_PROCESSOR_H

/* include faultinfo structure */
#include <sysdep/faultinfo.h>

#ifdef CONFIG_X86_32
# include "processor_32.h"
#else
# include "processor_64.h"
#endif

#define KSTK_EIP(tsk) KSTK_REG(tsk, HOST_IP)
#define KSTK_ESP(tsk) KSTK_REG(tsk, HOST_SP)
#define KSTK_EBP(tsk) KSTK_REG(tsk, HOST_BP)

#define ARCH_IS_STACKGROW(address) \
       (address + 65536 + 32 * sizeof(unsigned long) >= UPT_SP(&current->thread.regs.regs))

#include <asm/user.h>

/* REP NOP (PAUSE) is a good thing to insert into busy-wait loops. */
static inline void rep_nop(void)
{
	__asm__ __volatile__("rep;nop": : :"memory");
}

#define cpu_relax()		rep_nop()

#define task_top_of_stack(task) \
({									\
	unsigned long __ptr = (unsigned long)task->stack;	\
	__ptr += THREAD_SIZE;			\
	__ptr;					\
})

#define task_pt_regs(t) (&(t)->thread.regs)

#ifndef CONFIG_MMU
extern long current_top_of_stack;
extern long current_ptregs;
#endif

#include <asm/processor-generic.h>

#endif
