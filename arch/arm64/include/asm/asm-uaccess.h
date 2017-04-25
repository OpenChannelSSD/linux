#ifndef __ASM_ASM_UACCESS_H
#define __ASM_ASM_UACCESS_H

#include <asm/alternative.h>
#include <asm/kernel-pgtable.h>
#include <asm/sysreg.h>
#include <asm/assembler.h>

/*
 * User access enabling/disabling macros.
 */
#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	.macro	__uaccess_ttbr0_disable, tmp1
	mrs	\tmp1, ttbr1_el1		// swapper_pg_dir
	add	\tmp1, \tmp1, #SWAPPER_DIR_SIZE	// reserved_ttbr0 at the end of swapper_pg_dir
	msr	ttbr0_el1, \tmp1		// set reserved TTBR0_EL1
	isb
	.endm

	.macro	__uaccess_ttbr0_enable, tmp1
	get_thread_info \tmp1
	ldr	\tmp1, [\tmp1, #TSK_TI_TTBR0]	// load saved TTBR0_EL1
	msr	ttbr0_el1, \tmp1		// set the non-PAN TTBR0_EL1
	isb
	.endm

	.macro	uaccess_ttbr0_disable, tmp1
alternative_if_not ARM64_HAS_PAN
	__uaccess_ttbr0_disable \tmp1
alternative_else_nop_endif
	.endm

	.macro	uaccess_ttbr0_enable, tmp1, tmp2
alternative_if_not ARM64_HAS_PAN
	save_and_disable_irq \tmp2		// avoid preemption
	__uaccess_ttbr0_enable \tmp1
	restore_irq \tmp2
alternative_else_nop_endif
	.endm
#else
	.macro	uaccess_ttbr0_disable, tmp1
	.endm

	.macro	uaccess_ttbr0_enable, tmp1, tmp2
	.endm
#endif

/*
 * These macros are no-ops when UAO is present.
 */
	.macro	uaccess_disable_not_uao, tmp1
	uaccess_ttbr0_disable \tmp1
alternative_if ARM64_ALT_PAN_NOT_UAO
	SET_PSTATE_PAN(1)
alternative_else_nop_endif
	.endm

	.macro	uaccess_enable_not_uao, tmp1, tmp2
	uaccess_ttbr0_enable \tmp1, \tmp2
alternative_if ARM64_ALT_PAN_NOT_UAO
	SET_PSTATE_PAN(0)
alternative_else_nop_endif
	.endm

#endif
