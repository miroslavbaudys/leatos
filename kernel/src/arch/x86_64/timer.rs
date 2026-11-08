//! TSC-deadline timer (TODO: TSC calibration via CPUID 0x15 or HPET,
//! `IA32_TSC_DEADLINE` MSR, LAPIC timer vector).

use core::arch::x86_64::_rdtsc;

pub fn frequency() -> u64 {
    todo!("x86_64: TSC frequency calibration")
}

#[inline]
pub fn ticks() -> u64 {
    // SAFETY: RDTSC has no side effects (`_rdtsc` is an unsafe intrinsic only by convention).
    unsafe { _rdtsc() }
}

pub fn set_deadline(_deadline: u64) {
    todo!("x86_64: write IA32_TSC_DEADLINE")
}

pub fn stop() {
    todo!("x86_64: clear IA32_TSC_DEADLINE")
}

pub fn mask_from_irq() {
    // TSC-deadline is one-shot: nothing to mask.
}
