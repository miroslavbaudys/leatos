/*
 * rrouter kernel linker script — QEMU aarch64 `virt` machine.
 *
 * RAM starts at 0x4000_0000. For bare-metal ELF images QEMU places the
 * device tree blob at the very start of RAM and reserves up to 1 MiB for it,
 * so the kernel is linked 2 MiB in to stay clear of it.
 *
 *   0x4000_0000  DTB (placed by QEMU)
 *   0x4020_0000  .text (RX) | .rodata (R) | .data .bss .page_tables (RW)
 *                [guard] exception stack  [guard] kernel stack
 *   __kernel_end -> heap starts here (rest of RAM, size from the DTB)
 *
 * Every section boundary is page-aligned so the MMU can apply W^X
 * permissions per section (kernel/src/mmu.rs). Guard pages are left
 * unmapped so stack overflows fault instead of corrupting memory.
 */
ENTRY(_start)

KERNEL_BASE    = 0x40200000;
STACK_SIZE     = 0x40000; /* 256 KiB kernel (thread) stack, SP_EL0 */
EXC_STACK_SIZE = 0x4000;  /* 16 KiB exception stack, SP_EL1     */
PAGE           = 4096;

SECTIONS
{
    . = KERNEL_BASE;
    __kernel_start = .;

    __text_start = .;
    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    . = ALIGN(PAGE);
    __text_end = .;

    __rodata_start = .;
    .rodata : { *(.rodata .rodata.*) }
    . = ALIGN(PAGE);
    __rodata_end = .;

    __data_start = .;
    .data : { *(.data .data.*) }

    . = ALIGN(16);
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    /* Boot level-1 translation table (coarse 1 GiB identity map, boot.S). */
    . = ALIGN(PAGE);
    .page_tables (NOLOAD) : {
        __l1_table = .;
        . += PAGE;
    }
    . = ALIGN(PAGE);
    __data_end = .;

    .stacks (NOLOAD) : {
        __exc_stack_guard = .;
        . += PAGE;
        __exc_stack_bottom = .;
        . += EXC_STACK_SIZE;
        __exc_stack_top = .;

        __stack_guard = .;
        . += PAGE;
        __stack_bottom = .;
        . += STACK_SIZE;
        __stack_top = .;
    }

    . = ALIGN(PAGE);
    __kernel_end = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
