//! Clock = TSC; deadlines = local APIC timer in one-shot mode.
//!
//! The TSC frequency is calibrated once against the 8254 PIT (channel 2,
//! 10 ms), the local APIC timer frequency against the TSC. TSC-deadline
//! mode is not used: the apu4's AMD GX-412TC doesn't have it, and one-shot
//! counts work everywhere. A deadline further away than the 32-bit counter
//! reaches fires early; `crate::timer` then simply re-arms.

use super::irqchip::{TIMER_CURRENT, TIMER_INITIAL, with_lapic};
use super::port::{inb, outb};
use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

static TSC_HZ: Once<u64> = Once::new();
static LAPIC_HZ: AtomicU64 = AtomicU64::new(0);

const PIT_HZ: u64 = 1_193_182;
const PIT_COUNT: u64 = PIT_HZ / 100; // 10 ms

/// Busy-wait 10 ms on PIT channel 2; returns elapsed TSC ticks.
fn pit_10ms_in_tsc() -> u64 {
    // Gate channel 2 on, speaker off; mode 0 (interrupt on terminal count).
    outb(0x61, (inb(0x61) & !0x02) | 0x01);
    outb(0x43, 0xb0);
    outb(0x42, PIT_COUNT as u8);
    outb(0x42, (PIT_COUNT >> 8) as u8);
    let t0 = ticks();
    while inb(0x61) & 0x20 == 0 {
        core::hint::spin_loop();
    }
    ticks() - t0
}

/// TSC frequency in Hz (calibrated on first use).
pub fn frequency() -> u64 {
    *TSC_HZ.call_once(|| {
        // Best of three, to dodge a host preemption during one window.
        let t = (0..3).map(|_| pit_10ms_in_tsc()).min().unwrap_or(1);
        t * PIT_HZ / PIT_COUNT
    })
}

#[inline]
pub fn ticks() -> u64 {
    // SAFETY: RDTSC has no side effects (an unsafe intrinsic only by convention).
    unsafe { _rdtsc() }
}

/// Measure the local APIC timer against the TSC (APIC initialised, IRQs off).
pub(super) fn calibrate_lapic() {
    let window = frequency() / 100; // 10 ms
    let start = with_lapic(|r| {
        r.write32(TIMER_INITIAL, u32::MAX);
        ticks()
    });
    while ticks() - start < window {
        core::hint::spin_loop();
    }
    let left = with_lapic(|r| {
        let left = r.read32(TIMER_CURRENT);
        r.write32(TIMER_INITIAL, 0);
        left
    });
    LAPIC_HZ.store((u32::MAX - left) as u64 * 100, Ordering::Relaxed);
}

pub(super) fn lapic_hz() -> u64 {
    LAPIC_HZ.load(Ordering::Relaxed)
}

/// Arm a one-shot interrupt at TSC value `deadline` (past = immediately).
pub fn set_deadline(deadline: u64) {
    let delta = deadline.saturating_sub(ticks()) as u128;
    let counts = delta * lapic_hz() as u128 / frequency() as u128;
    let counts = counts.clamp(1, u32::MAX as u128) as u32;
    with_lapic(|r| r.write32(TIMER_INITIAL, counts));
}

pub fn stop() {
    with_lapic(|r| r.write32(TIMER_INITIAL, 0));
}

pub fn mask_from_irq() {
    // One-shot: the timer is already idle after firing.
}
