//! CPU state: interrupt flag, idle, halt.

use core::arch::asm;

/// Always ring 0 for this kernel.
pub fn privilege_level() -> u8 {
    0
}

#[inline]
pub fn irq_enable() {
    // SAFETY: only sets RFLAGS.IF.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

#[inline]
pub fn irq_disable() {
    // SAFETY: only clears RFLAGS.IF.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

#[inline]
pub fn irqs_enabled() -> bool {
    let flags: u64;
    // SAFETY: reads RFLAGS via the stack; no other side effects.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    flags & (1 << 9) != 0
}

/// Note: unlike aarch64 `wfi`, `hlt` with IF=0 does not wake on interrupts;
/// the executor's idle path must use `sti; hlt` here (port TODO).
#[cfg_attr(feature = "idle-poll", allow(dead_code))]
pub fn wait_for_interrupt() {
    // SAFETY: `sti; hlt` atomically enables interrupts and halts until one arrives.
    unsafe { asm!("sti", "hlt", options(nomem, nostack)) };
}

pub fn halt() -> ! {
    loop {
        // SAFETY: stops the CPU until the next interrupt; interrupts stay masked.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
