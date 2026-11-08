//! CPU interrupt masking and the IRQ dispatch table.
//!
//! Rules for handlers (see CLAUDE.md): acknowledge the device and set a flag
//! or atomic only. No allocation, no `println!`, no locks that thread
//! context also takes. The real work happens in the executor.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Highest INTID we dispatch (SGIs, PPIs and SPIs up to 1019).
pub const MAX_INTID: usize = 1020;

/// Handler function pointers stored as `usize` (0 = none).
static HANDLERS: [AtomicUsize; MAX_INTID] = [const { AtomicUsize::new(0) }; MAX_INTID];
static IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

pub type Handler = fn(intid: u32);

/// Register `handler` for `intid`. Does not enable the interrupt in the GIC.
pub fn register(intid: u32, handler: Handler) {
    HANDLERS[intid as usize].store(handler as usize, Ordering::Release);
}

/// Unmask IRQs on this core.
#[inline]
pub fn enable() {
    // SAFETY: only changes the PSTATE.I mask.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
}

/// Mask IRQs on this core.
#[inline]
pub fn disable() {
    // SAFETY: only changes the PSTATE.I mask.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
}

/// Total IRQs handled (for diagnostics).
pub fn count() -> u64 {
    IRQ_COUNT.load(Ordering::Relaxed)
}

pub fn spurious() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

/// Called from `irq_entry` in boot.S on SP_EL1 with IRQs masked.
#[unsafe(no_mangle)]
extern "C" fn rust_irq() {
    // Drain all pending interrupts before returning.
    let mut handled_any = false;
    loop {
        let iar = crate::gic::ack();
        let intid = iar & 0x00ff_ffff;
        if intid >= 1020 {
            // 1020..=1023 are special/spurious: nothing (more) pending.
            if !handled_any {
                SPURIOUS.fetch_add(1, Ordering::Relaxed);
            }
            break;
        }
        handled_any = true;
        IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
        let h = HANDLERS[intid as usize].load(Ordering::Acquire);
        if h != 0 {
            // SAFETY: only `register` stores into HANDLERS, always a valid `Handler`.
            let handler: Handler = unsafe { core::mem::transmute::<usize, Handler>(h) };
            handler(intid);
        } else {
            // Unexpected interrupt: disable it so it cannot storm.
            crate::gic::disable(intid);
        }
        crate::gic::eoi(iar);
    }
}
