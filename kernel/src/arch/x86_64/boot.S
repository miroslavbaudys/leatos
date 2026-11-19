/*
 * leatos x86_64 entry: PVH (QEMU `-kernel`) or Multiboot2 (Limine on the
 * apu4, booted by SeaBIOS from USB/SD).
 *
 * PVH loaders find the 32-bit entry point in the XEN_ELFNOTE_PHYS32_ENTRY
 * note below; Multiboot2 loaders find the header in .multiboot2 (first
 * 32 KiB of the file) and use the ELF entry, the same _start32. Both enter
 * in 32-bit protected mode, paging off, with %ebx = physical address of
 * the boot information (PVH hvm_start_info / Multiboot2 info); Multiboot2
 * also sets %eax = 0x36d76289, which kernel_main gets as its second argument.
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

    /* Multiboot2 header: magic, architecture 0 (i386), length, checksum,
     * then only the end tag (the ELF headers say where to load). */
    .section .multiboot2, "a"
    .balign 8
mb2_header:
    .long   0xe85250d6
    .long   0
    .long   mb2_header_end - mb2_header
    .long   0x100000000 - (0xe85250d6 + (mb2_header_end - mb2_header))
    .word   0, 0
    .long   8
mb2_header_end:

    .section .text.boot, "ax"
    .code32
    .global _start32
_start32:
    cli
    cld
    mov     %ebx, %ebp                  /* keep the boot-info pointer */
    mov     %eax, %esi                  /* and the Multiboot2 magic */

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
    mov     %ebp, %edi                  /* arg 0: boot info (zero-extended) */
    mov     %esi, %esi                  /* arg 1: magic (clear the upper half) */
    xor     %ebp, %ebp
    call    kernel_main
3:  cli
    hlt
    jmp     3b

/*
 * Secondary cores (smp.rs): the real-mode trampoline below is copied to
 * AP_TRAMPOLINE (< 1 MiB) and started by INIT-SIPI-SIPI. It enters long
 * mode on the boot page tables (identity 0..4 GiB, executable), then jumps
 * here: switch to the kernel's final tables, take this core's stack and
 * call ap_rust(core). ap_boot = [cr3, stack top, core], written by the boot
 * core before each start.
 */
    .section .text
    .code64
    .global ap_start64
ap_start64:
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    xor     %eax, %eax
    mov     %ax, %fs
    mov     %ax, %gs
    mov     ap_boot(%rip), %rax
    mov     %rax, %cr3
    mov     ap_boot+8(%rip), %rsp
    mov     ap_boot+16(%rip), %rdi
    xor     %ebp, %ebp
    call    ap_rust
4:  cli
    hlt
    jmp     4b

    .set    AP_TRAMPOLINE, 0x8000
    .section .rodata.ap_trampoline, "a"
    .global ap_trampoline_start, ap_trampoline_end
    .code16
ap_trampoline_start:
    cli
    cld
    xor     %ax, %ax
    mov     %ax, %ds
    lgdtl   AP_TRAMPOLINE + (ap_gdt_ptr - ap_trampoline_start)
    mov     %cr0, %eax
    or      $1, %eax                    /* PE */
    mov     %eax, %cr0
    ljmpl   $0x08, $(AP_TRAMPOLINE + (ap_pm32 - ap_trampoline_start))
    .code32
ap_pm32:
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    mov     %cr4, %eax
    or      $(1 << 5), %eax             /* PAE */
    mov     %eax, %cr4
    mov     $__boot_pml4, %eax
    mov     %eax, %cr3
    mov     $0xc0000080, %ecx           /* EFER.LME | EFER.NXE */
    rdmsr
    or      $((1 << 8) | (1 << 11)), %eax
    wrmsr
    mov     %cr0, %eax
    or      $0x80010001, %eax           /* PG | WP | PE */
    mov     %eax, %cr0
    lgdt    gdt_ptr
    ljmp    $0x08, $ap_start64
    .balign 8
ap_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff            /* 32-bit code */
    .quad 0x00cf92000000ffff            /* data */
ap_gdt_ptr:
    .word 23
    .long AP_TRAMPOLINE + (ap_gdt - ap_trampoline_start)
ap_trampoline_end:
    .code64

/*
 * GDT: null, 64-bit code (0x08), data (0x10), and one 16-byte TSS
 * descriptor per core (0x18, 0x28, 0x38, 0x48) that exceptions.rs fills in
 * before `ltr`. Writable (.data): the CPU sets accessed/busy bits in
 * descriptors.
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
    .quad 0, 0
    .quad 0, 0
    .quad 0, 0
    .quad 0, 0
gdt_end:

    .balign 8
gdt_ptr:
    .word gdt_end - gdt - 1
    .quad gdt
