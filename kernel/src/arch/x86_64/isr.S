/*
 * Interrupt and exception entry stubs. Each stub pushes a dummy error code
 * (where the CPU pushes none) and its vector, then isr_common saves all
 * general-purpose registers and calls x86_trap(&mut Frame) in
 * exceptions.rs. The kernel uses no SSE (soft-float target), so no FPU
 * state needs saving.
 *
 * Vectors: 0-31 CPU exceptions, 32 local APIC timer, 33 wake/stop IPI, 48-63 device MSI-X,
 * 224-239 the remapped (masked) 8259 PICs, 255 spurious. `isr_vectors` lists (vector, stub address) pairs for the IDT.
 */
    .section .text

    .macro ISR_NOERR n
isr_\n:
    pushq   $0
    pushq   $\n
    jmp     isr_common
    .endm

    .macro ISR_ERR n
isr_\n:
    pushq   $\n
    jmp     isr_common
    .endm

    .irp n, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31
    ISR_NOERR \n
    .endr
    .irp n, 8,10,11,12,13,14,17,21,29,30
    ISR_ERR \n
    .endr
    .irp n, 32,33,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,255
    ISR_NOERR \n
    .endr

isr_common:
    cld
    push    %rax
    push    %rcx
    push    %rdx
    push    %rbx
    push    %rbp
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    push    %r11
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    mov     %rsp, %rdi      /* &mut Frame; 16-byte aligned (CPU aligns, 22 x 8 pushed) */
    call    x86_trap
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rbp
    pop     %rbx
    pop     %rdx
    pop     %rcx
    pop     %rax
    add     $16, %rsp       /* vector + error code */
    iretq

    .section .rodata
    .balign 8
    .global isr_vectors
isr_vectors:
    .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,255
    .quad   \n
    .quad   isr_\n
    .endr
