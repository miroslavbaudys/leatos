// rrouter early boot — aarch64, QEMU `virt`.
//
// Entered by QEMU at _start (ELF entry) on every powered-on core, with the
// MMU off. Under HVF the core starts at EL1; under TCG with
// `virtualization=on` it may start at EL2, so we drop to EL1 if needed.
//
// Steps: park secondaries -> (EL2 -> EL1) -> enable FP/SIMD -> sane SCTLR ->
//        stacks -> zero .bss -> identity-map page tables -> MMU + caches on ->
//        exception vectors -> kernel_main(dtb)
//
// NOTE: this file goes through `global_asm!`, so it must not contain braces.

.section .text.boot, "ax"
.global _start
_start:
    // Only core 0 boots. (QEMU keeps secondaries off until PSCI CPU_ON.)
    mrs     x1, mpidr_el1
    and     x1, x1, #0xff
    cbnz    x1, park

    mov     x19, x0                 // x0 may hold the DTB address; keep it

    // ---- Drop from EL2 to EL1 if necessary --------------------------------
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    cmp     x1, #2
    b.ne    at_el1
    mov     x1, #3
    msr     cnthctl_el2, x1         // EL1 may use the physical timer/counter
    msr     cntvoff_el2, xzr
    mov     x1, #(1 << 31)          // HCR_EL2.RW: EL1 is AArch64
    msr     hcr_el2, x1
    mov     x1, #0x3c5              // SPSR: EL1h, DAIF masked
    msr     spsr_el2, x1
    adr     x1, at_el1
    msr     elr_el2, x1
    eret

at_el1:
    // ---- FP/SIMD on (rustc emits NEON for memcpy etc.) ----------------------
    mov     x1, #(3 << 20)          // CPACR_EL1.FPEN = 0b11
    msr     cpacr_el1, x1
    // ---- Known SCTLR_EL1: RES1 bits only, MMU/caches/alignment-check off ---
    ldr     x1, =0x30d00800
    msr     sctlr_el1, x1
    isb

    // ---- Stacks --------------------------------------------------------------
    // SP_EL1 = exception stack, SP_EL0 = kernel (thread) stack. The kernel
    // runs with SPSel=0 ("EL1t"), so every exception switches to SP_EL1 and
    // a kernel stack overflow (guard page hit) can still be reported.
    ldr     x1, =__exc_stack_top
    mov     sp, x1                  // SPSel=1 here: writes SP_EL1
    msr     spsel, #0
    ldr     x1, =__stack_top
    mov     sp, x1                  // SPSel=0 now: writes SP_EL0

    // ---- Zero .bss (16-byte aligned by the linker script) --------------------
    ldr     x1, =__bss_start
    ldr     x2, =__bss_end
zero_bss:
    cmp     x1, x2
    b.hs    bss_done
    stp     xzr, xzr, [x1], #16
    b       zero_bss
bss_done:

    // ---- Identity map, level-1 table, 4 KiB granule, 512 x 1 GiB blocks -----
    // Entries 1..3 (0x4000_0000 - 0xFFFF_FFFF) = Normal WB cacheable (RAM).
    // Everything else = Device-nGnRnE, execute-never (MMIO, PCIe ECAM, ...).
    ldr     x1, =__l1_table
    ldr     x4, =0x0060000000000401 // device: UXN|PXN|AF|attr0|block
    ldr     x5, =0x0000000000000705 // normal: AF|inner-shareable|attr1|block
    mov     x2, #0
fill_l1:
    lsl     x3, x2, #30             // output address = index * 1 GiB
    cmp     x2, #1
    b.lo    l1_device
    cmp     x2, #4
    b.hs    l1_device
    orr     x6, x3, x5
    b       l1_store
l1_device:
    orr     x6, x3, x4
l1_store:
    str     x6, [x1, x2, lsl #3]
    add     x2, x2, #1
    cmp     x2, #512
    b.lo    fill_l1

    // MAIR: attr0 = Device-nGnRnE (0x00), attr1 = Normal WB RW-alloc (0xff)
    mov     x2, #0xff00
    msr     mair_el1, x2
    // TCR: T0SZ=25 (39-bit VA, start at L1), WB-cacheable inner-shareable
    //      walks, TG0=4K, EPD1 (no TTBR1 walks), IPS=40-bit PA
    ldr     x2, =0x200803519
    msr     tcr_el1, x2
    msr     ttbr0_el1, x1
    dsb     ish
    isb
    tlbi    vmalle1
    dsb     ish
    isb
    mrs     x2, sctlr_el1
    orr     x2, x2, #(1 << 0)       // M: MMU on
    orr     x2, x2, #(1 << 2)       // C: data cache on
    orr     x2, x2, #(1 << 12)      // I: instruction cache on
    msr     sctlr_el1, x2
    isb

    // ---- Exception vectors ---------------------------------------------------
    ldr     x1, =exception_vectors
    msr     vbar_el1, x1
    isb

    mov     x0, x19
    bl      kernel_main             // never returns

park:
    wfe
    b       park

// ---- Exception vector table -------------------------------------------------
// 16 entries x 0x80 bytes. Order: [cur EL SP0 | cur EL SPx | lower EL A64 |
// lower EL A32] x [sync, irq, fiq, serror]. The kernel runs on SP0 (EL1t),
// so entry 1 is the normal IRQ path. Everything else is fatal for now.
.macro FATAL i
    .balign 0x80
    mov     x0, #\i
    mrs     x1, esr_el1
    mrs     x2, elr_el1
    mrs     x3, far_el1
    b       rust_exception
.endm

.section .text, "ax"
.balign 0x800
.global exception_vectors
exception_vectors:
    FATAL   0
    .balign 0x80
    b       irq_entry              // 1: IRQ, current EL, SP0 = normal kernel IRQ
    FATAL   2
    FATAL   3
    FATAL   4
    FATAL   5
    FATAL   6
    FATAL   7
    FATAL   8
    FATAL   9
    FATAL   10
    FATAL   11
    FATAL   12
    FATAL   13
    FATAL   14
    FATAL   15

// ---- IRQ entry ----------------------------------------------------------------
// Runs on SP_EL1. Saves every caller-saved register (GPRs, all SIMD q
// registers because rustc may use NEON anywhere, FPCR/FPSR, ELR/SPSR), calls
// rust_irq, and restores. Frame (720 B): x0-x18, x29, x30, ELR @0..176,
// SPSR @176, FPCR @184, FPSR @192, q0-q31 @208..720.
irq_entry:
    sub     sp, sp, #720
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x29, [sp, #144]
    mrs     x0, elr_el1
    stp     x30, x0, [sp, #160]
    mrs     x0, spsr_el1
    str     x0, [sp, #176]
    stp     q0, q1, [sp, #208]
    stp     q2, q3, [sp, #240]
    stp     q4, q5, [sp, #272]
    stp     q6, q7, [sp, #304]
    stp     q8, q9, [sp, #336]
    stp     q10, q11, [sp, #368]
    stp     q12, q13, [sp, #400]
    stp     q14, q15, [sp, #432]
    stp     q16, q17, [sp, #464]
    stp     q18, q19, [sp, #496]
    stp     q20, q21, [sp, #528]
    stp     q22, q23, [sp, #560]
    stp     q24, q25, [sp, #592]
    stp     q26, q27, [sp, #624]
    stp     q28, q29, [sp, #656]
    stp     q30, q31, [sp, #688]
    mrs     x0, fpcr
    str     x0, [sp, #184]
    mrs     x0, fpsr
    str     x0, [sp, #192]

    bl      rust_irq

    ldr     x0, [sp, #184]
    msr     fpcr, x0
    ldr     x0, [sp, #192]
    msr     fpsr, x0
    ldp     q0, q1, [sp, #208]
    ldp     q2, q3, [sp, #240]
    ldp     q4, q5, [sp, #272]
    ldp     q6, q7, [sp, #304]
    ldp     q8, q9, [sp, #336]
    ldp     q10, q11, [sp, #368]
    ldp     q12, q13, [sp, #400]
    ldp     q14, q15, [sp, #432]
    ldp     q16, q17, [sp, #464]
    ldp     q18, q19, [sp, #496]
    ldp     q20, q21, [sp, #528]
    ldp     q22, q23, [sp, #560]
    ldp     q24, q25, [sp, #592]
    ldp     q26, q27, [sp, #624]
    ldp     q28, q29, [sp, #656]
    ldp     q30, q31, [sp, #688]
    ldr     x0, [sp, #176]
    msr     spsr_el1, x0
    ldp     x30, x0, [sp, #160]
    msr     elr_el1, x0
    ldp     x18, x29, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #720
    eret
