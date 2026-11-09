/*
 * rrouter kernel linker script — x86_64 (QEMU q35 via PVH; later the apu4).
 *
 * Loaded at 1 MiB (physical = virtual, identity map). Low memory below
 * 1 MiB holds firmware data (BIOS, ACPI pointers, the PVH start info) and is
 * left unmapped by mm::mmu, so null-pointer accesses fault.
 *
 *   0x0010_0000  .text (RX) | .note.Xen + .rodata (R) | .data .bss .page_tables (RW)
 *                [guard] exception stack (IST1)  [guard] kernel stack
 *   __kernel_end -> heap (rest of the RAM region, from the PVH memory map)
 *
 * Same symbol names as linker.ld (aarch64); see kernel/src/mm/sym.rs.
 */
ENTRY(_start32)

KERNEL_BASE    = 0x100000;
STACK_SIZE     = 0x40000; /* 256 KiB kernel stack */
EXC_STACK_SIZE = 0x4000;  /* 16 KiB exception stack (TSS IST1) */
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
    /* PVH entry note: must stay an allocated SHT_NOTE (own PT_NOTE segment). */
    .note.Xen : { KEEP(*(.note.Xen)) }
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

    /* Boot page tables (boot.S): PML4, PDPT, 4 x PD = identity map of 0..4 GiB. */
    . = ALIGN(PAGE);
    .page_tables (NOLOAD) : {
        __boot_pml4 = .;
        . += PAGE;
        __boot_pdpt = .;
        . += PAGE;
        __boot_pd = .;
        . += 4 * PAGE;
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
