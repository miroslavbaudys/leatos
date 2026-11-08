//! ARM generic *virtual* timer hardware (the tickless logic is in `crate::timer`).

use aarch64_cpu::asm::barrier;
use aarch64_cpu::registers::{
    CNTFRQ_EL0, CNTV_CTL_EL0, CNTV_CVAL_EL0, CNTVCT_EL0, Readable, Writeable,
};

/// Counter frequency in Hz.
pub fn frequency() -> u64 {
    CNTFRQ_EL0.get().max(1)
}

/// Current counter value.
#[inline]
pub fn ticks() -> u64 {
    barrier::isb(barrier::SY);
    CNTVCT_EL0.get()
}

/// Fire the timer interrupt at counter value `deadline` (immediately if past).
pub fn set_deadline(deadline: u64) {
    CNTV_CVAL_EL0.set(deadline);
    CNTV_CTL_EL0.write(CNTV_CTL_EL0::ENABLE::SET + CNTV_CTL_EL0::IMASK::CLEAR);
    barrier::isb(barrier::SY);
}

/// No deadline pending: switch the timer off.
pub fn stop() {
    CNTV_CTL_EL0.set(0);
    barrier::isb(barrier::SY);
}

/// IRQ context: silence the level-sensitive timer output until re-armed.
pub fn mask_from_irq() {
    CNTV_CTL_EL0.write(CNTV_CTL_EL0::ENABLE::SET + CNTV_CTL_EL0::IMASK::SET);
    barrier::isb(barrier::SY);
}
