/*
 * In-RAM upgrade trampoline (kexec.rs). Position-independent bytes in
 * .rodata: kexec.rs copies them into the staging area and jumps there,
 * because the copy below overwrites the running kernel.
 *
 * Entry: 64-bit mode, IRQs off, CR3 = identity map of 0..4 GiB without NX,
 *   rdi = source (flat image in staging), rsi = destination (load address),
 *   rdx = length, rcx = entry point, r8 = Multiboot2 boot information.
 * Exit: like a Multiboot2 loader: 32-bit protected mode, paging off,
 *   eax = 0x36d76289, ebx = boot information, jump to the entry.
 */
    .section .rodata
    .balign 16
    .global kexec_blob_start, kexec_blob_end
kexec_blob_start:
    .code64
    lea     kexec_stack_top(%rip), %rsp /* our own stack: the old one is overwritten */
    mov     %ecx, %ebp                  /* entry (below 4 GiB) */
    mov     %r8d, %ebx                  /* boot information (below 4 GiB) */
    mov     %rdx, %rcx
    xchg    %rdi, %rsi                  /* movsb copies (%rsi) -> (%rdi) */
    cld                                 /* source is above the destination: forward is safe */
    rep movsb

    lea     kexec_gdt(%rip), %rax
    mov     %rax, kexec_gdtr+2(%rip)
    lgdt    kexec_gdtr(%rip)
    lea     1f(%rip), %rax
    pushq   $0x08                       /* 32-bit code segment: compatibility mode */
    pushq   %rax
    lretq

    .code32
1:  mov     $0x10, %eax
    mov     %eax, %ds
    mov     %eax, %es
    mov     %eax, %fs
    mov     %eax, %gs
    mov     %eax, %ss
    mov     %cr0, %eax
    and     $0x7fffffff, %eax           /* paging off: leaves long mode */
    mov     %eax, %cr0
    mov     $0xc0000080, %ecx
    rdmsr
    and     $0xfffffeff, %eax           /* EFER.LME off */
    wrmsr
    mov     $0x36d76289, %eax
    jmp     *%ebp

    .code64
    .balign 8
kexec_gdt:
    .quad   0
    .quad   0x00cf9a000000ffff          /* 0x08: 32-bit code, flat */
    .quad   0x00cf92000000ffff          /* 0x10: data, flat */
kexec_gdtr:
    .word   23
    .quad   0                           /* base: patched at run time */
    .balign 16
    .skip   256
kexec_stack_top:
kexec_blob_end:
