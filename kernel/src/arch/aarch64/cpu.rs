//! CPU state: exception level, interrupt masking, idle, halt.

use aarch64_cpu::registers::{CurrentEL, Read};
use core::arch::asm;

/// Current exception level (0–3).
pub fn privilege_level() -> u8 {
    CurrentEL.read(CurrentEL::EL) as u8
}

/// This core's index (`smp`), kept in `TPIDR_EL1` (set by `boot.S`: 0 on
/// the boot core, the index passed to `CPU_ON` on the others).
#[inline]
pub fn core_id() -> usize {
    let v: u64;
    // SAFETY: reads a system register; no side effects.
    unsafe { asm!("mrs {}, tpidr_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v as usize
}

/// This core's hardware ID: MPIDR affinity in the device tree's `reg`
/// layout (Aff2.Aff1.Aff0 in bits 0..24, Aff3 in bits 32..40).
pub fn hw_core_id() -> u64 {
    let m: u64;
    // SAFETY: reads a system register; no side effects.
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) m, options(nomem, nostack, preserves_flags)) };
    m & 0xff_00ff_ffff
}

/// No CPU signature or microcode to report: firmware updates the cores
/// on Arm (the x86_64 one is printed by `smp::start`).
pub fn cpu_signature() -> Option<&'static str> {
    None
}

pub fn microcode_revision() -> Option<u32> {
    None
}

/// Unmask IRQs on this core.
#[inline]
pub fn irq_enable() {
    // SAFETY: only changes PSTATE.I.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
}

/// Mask IRQs on this core.
#[inline]
pub fn irq_disable() {
    // SAFETY: only changes PSTATE.I.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
}

/// Are IRQs currently unmasked?
#[inline]
pub fn irqs_enabled() -> bool {
    let daif: u64;
    // SAFETY: reading DAIF has no side effects.
    unsafe { asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack)) };
    daif & (1 << 7) == 0
}

/// Order memory accesses against a DMA-capable device (descriptor writes
/// before the doorbell MMIO write; status read before the data it guards).
/// `dmb osh`: the outer-shareable domain includes the devices.
#[inline]
pub fn dma_barrier() {
    // SAFETY: a memory barrier; no other effect.
    unsafe { asm!("dmb osh", options(nostack, preserves_flags)) };
}

/// Sleep until an interrupt is pending (works even while IRQs are masked).
#[cfg_attr(feature = "idle-poll", allow(dead_code))]
pub fn wait_for_interrupt() {
    aarch64_cpu::asm::wfi();
}

/// Stop this core forever, never powering off: a core stopped by another
/// (`smp::stop_others`) while that one still reports and resets.
pub fn park() -> ! {
    irq_disable();
    loop {
        aarch64_cpu::asm::wfe();
    }
}

/// Stop forever. With the `smoke-test` feature, power off instead so an
/// automated QEMU run terminates.
pub fn halt() -> ! {
    #[cfg(feature = "smoke-test")]
    super::power::off();
    #[allow(unreachable_code)]
    loop {
        aarch64_cpu::asm::wfe();
    }
}
