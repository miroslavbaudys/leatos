//! CPU state: exception level, interrupt masking, idle, halt.

use aarch64_cpu::registers::{CurrentEL, Readable};
use core::arch::asm;

/// Current exception level (0–3).
pub fn privilege_level() -> u8 {
    CurrentEL.read(CurrentEL::EL) as u8
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
