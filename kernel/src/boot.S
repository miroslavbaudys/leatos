// rrouter early boot — aarch64, QEMU `virt`.
//
// Entered by QEMU at _start (ELF entry) on every powered-on core, with the
// MMU off. Under HVF the core starts at EL1; under TCG with
// `virtualization=on` it may start at EL2, so we drop to EL1 if needed.
//
// Steps: park secondaries -> (EL2 -> EL1) -> enable FP/SIMD -> sane SCTLR ->
//        stack -> zero .bss -> identity-map page tables -> MMU + caches on ->
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

    // ---- Stack ---------------------------------------------------------------
    ldr     x1, =__stack_top
    mov     sp, x1

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
// 16 entries x 0x80 bytes. For now every exception is fatal: pass the vector
// index and the syndrome registers to Rust, which reports and halts.
// Order: [cur EL SP0 | cur EL SPx | lower EL A64 | lower EL A32] x
//        [sync, irq, fiq, serror]
.section .text, "ax"
.balign 0x800
.global exception_vectors
exception_vectors:
.irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
.balign 0x80
    mov     x0, #\i
    mrs     x1, esr_el1
    mrs     x2, elr_el1
    mrs     x3, far_el1
    b       rust_exception
.endr
