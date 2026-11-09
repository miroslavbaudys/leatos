/*
 * rrouter x86_64 entry (PVH boot protocol).
 *
 * QEMU `-kernel` (and Xen, and PVH-capable bootloaders) find the 32-bit
 * entry point in the XEN_ELFNOTE_PHYS32_ENTRY note below and jump to it in
 * 32-bit protected mode, paging off, with %ebx = physical address of the
 * hvm_start_info structure (memory map, command line, ACPI RSDP).
 *
 * This stub:
 *   1. zeroes .bss and the boot page tables,
 *   2. identity-maps the low 4 GiB with 2 MiB pages (RAM, ACPI tables,
 *      PCIe ECAM, LAPIC/IOAPIC; replaced by mm::mmu with W^X 4 KiB pages),
 *   3. enables PAE, long mode, NX (EFER.NXE) and CR0.WP (supervisor writes
 *      honour read-only pages: the W^X guarantee),
 *   4. loads a 64-bit GDT, jumps to 64-bit code, sets up the kernel stack
 *      and calls kernel_main(start_info) in Rust.
 */

    .pushsection .note.Xen, "a", @note
    .balign 4
    .long 4                 /* name size ("Xen\0") */
    .long 4                 /* descriptor size */
    .long 18                /* XEN_ELFNOTE_PHYS32_ENTRY */
    .asciz "Xen"
    .balign 4
    .long _start32
    .balign 4
    .popsection

    .section .text.boot, "ax"
    .code32
    .global _start32
_start32:
    cli
    cld
    mov     %ebx, %ebp                  /* keep the start-info pointer */

    /* zero .bss */
    mov     $__bss_start, %edi
    mov     $__bss_end, %ecx
    sub     %edi, %ecx
    shr     $2, %ecx
    xor     %eax, %eax
    rep stosl

    /* zero the boot page tables (PML4, PDPT, 4 x PD = 6 pages) */
    mov     $__boot_pml4, %edi
    mov     $(6 * 1024), %ecx
    rep stosl

    /* PML4[0] -> PDPT */
    mov     $__boot_pdpt, %eax
    or      $0x3, %eax                  /* present | writable */
    mov     %eax, __boot_pml4

    /* PDPT[0..4] -> PD0..PD3 */
    mov     $__boot_pd, %eax
    or      $0x3, %eax
    mov     $__boot_pdpt, %edi
    mov     $4, %ecx
1:  mov     %eax, (%edi)
    add     $4096, %eax
    add     $8, %edi
    loop    1b

    /* PD0..PD3: 2048 x 2 MiB pages = 0..4 GiB, present | writable | PS */
    mov     $__boot_pd, %edi
    mov     $0x83, %eax
    mov     $2048, %ecx
2:  mov     %eax, (%edi)
    add     $0x200000, %eax
    add     $8, %edi
    loop    2b

    /* CR4.PAE */
    mov     %cr4, %eax
    or      $(1 << 5), %eax
    mov     %eax, %cr4
    mov     $__boot_pml4, %eax
    mov     %eax, %cr3

    /* EFER.LME | EFER.NXE */
    mov     $0xc0000080, %ecx
    rdmsr
    or      $((1 << 8) | (1 << 11)), %eax
    wrmsr

    /* CR0.PG | CR0.WP | CR0.PE: long mode active */
    mov     %cr0, %eax
    or      $0x80010001, %eax
    mov     %eax, %cr0

    lgdt    gdt_ptr
    ljmp    $0x08, $_start64

    .code64
_start64:
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    xor     %eax, %eax
    mov     %ax, %fs
    mov     %ax, %gs
    mov     $__stack_top, %rsp
    mov     %ebp, %edi                  /* arg 0: start-info (zero-extended) */
    xor     %ebp, %ebp
    call    kernel_main
3:  cli
    hlt
    jmp     3b

/*
 * GDT: null, 64-bit code (0x08), data (0x10), and a 16-byte TSS descriptor
 * (0x18) that exceptions.rs fills in before `ltr`. Writable (.data): the
 * CPU sets accessed/busy bits in descriptors.
 */
    .section .data
    .balign 16
    .global gdt
gdt:
    .quad 0
    .quad 0x00af9a000000ffff            /* code: present, ring 0, long mode */
    .quad 0x00cf92000000ffff            /* data: present, ring 0, writable */
    .global gdt_tss
gdt_tss:
    .quad 0
    .quad 0
gdt_end:

    .balign 8
gdt_ptr:
    .word gdt_end - gdt - 1
    .quad gdt
