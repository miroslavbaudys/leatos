/*
 * rrouter kernel linker script — QEMU aarch64 `virt` machine.
 *
 * RAM starts at 0x4000_0000. For bare-metal ELF images QEMU places the
 * device tree blob at the very start of RAM and reserves up to 1 MiB for it,
 * so the kernel is linked 2 MiB in to stay clear of it.
 *
 *   0x4000_0000  DTB (placed by QEMU)
 *   0x4020_0000  .text.boot (_start) ... .text .rodata .data .bss
 *                page tables, boot stack
 *   __kernel_end -> heap starts here (rest of RAM, size from the DTB)
 */
ENTRY(_start)

KERNEL_BASE = 0x40200000;
STACK_SIZE  = 0x10000; /* 64 KiB boot stack */

SECTIONS
{
    . = KERNEL_BASE;
    __kernel_start = .;

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) }

    . = ALIGN(4096);
    .data : { *(.data .data.*) }

    . = ALIGN(16);
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    /* Level-1 translation table: 512 x 1 GiB blocks, filled in by boot.S. */
    . = ALIGN(4096);
    .page_tables (NOLOAD) : {
        __l1_table = .;
        . += 4096;
    }

    . = ALIGN(16);
    .stack (NOLOAD) : {
        __stack_bottom = .;
        . += STACK_SIZE;
        __stack_top = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
