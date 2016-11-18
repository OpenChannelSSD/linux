/*
 *
 * Automatically generated file; DO NOT EDIT.
 * Linux/x86 3.10.102 Kernel Configuration
 *
 */
/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 *
 */
/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
/*
 * Linker script for x32 vDSO.
 * We #include the file to define the layout details.
 * Here we only choose the prelinked virtual address.
 *
 * This file defines the version script giving the user-exported symbols in
 * the DSO.  We can define local symbols here called VDSO* to make their
 * values visible using the asm-x86/vdso.h macros from the kernel proper.
 */
/*
 * Linker script for vDSO.  This is an ELF shared object prelinked to
 * its virtual address, and with only one read-only segment.
 * This script controls its layout.
 */
SECTIONS
{
 . = 0 + SIZEOF_HEADERS;
 .hash : { *(.hash) } :text
 .gnu.hash : { *(.gnu.hash) }
 .dynsym : { *(.dynsym) }
 .dynstr : { *(.dynstr) }
 .gnu.version : { *(.gnu.version) }
 .gnu.version_d : { *(.gnu.version_d) }
 .gnu.version_r : { *(.gnu.version_r) }
 .note : { *(.note.*) } :text :note
 .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
 .eh_frame : { KEEP (*(.eh_frame)) } :text
 .dynamic : { *(.dynamic) } :text :dynamic
 .rodata : { *(.rodata*) } :text
 .data : {
       *(.data*)
       *(.sdata*)
       *(.got.plt) *(.got)
       *(.gnu.linkonce.d.*)
       *(.bss*)
       *(.dynbss*)
       *(.gnu.linkonce.b.*)
 }
 .altinstructions : { *(.altinstructions) }
 .altinstr_replacement : { *(.altinstr_replacement) }
 /*
	 * Align the actual code well away from the non-instruction data.
	 * This is the best thing for the I-cache.
	 */
 . = ALIGN(0x100);
 .text : { *(.text*) } :text =0x90909090
}
/*
 * Very old versions of ld do not recognize this name token; use the constant.
 */
/*
 * We must supply the ELF program headers explicitly to get just one
 * PT_LOAD segment, and set the flags explicitly to make segments read-only.
 */
PHDRS
{
 text PT_LOAD FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
 dynamic PT_DYNAMIC FLAGS(4); /* PF_R */
 note PT_NOTE FLAGS(4); /* PF_R */
 eh_frame_hdr 0x6474e550;
}
/*
 * This controls what userland symbols we export from the vDSO.
 */
VERSION {
 LINUX_2.6 {
 global:
  __vdso_clock_gettime;
  __vdso_gettimeofday;
  __vdso_getcpu;
  __vdso_time;
 local: *;
 };
}
VDSOX32_PRELINK = 0;
