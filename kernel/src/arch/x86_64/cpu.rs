//! CPU state: interrupt flag, idle, halt, CPUID, MSRs, control registers.

use core::arch::asm;
use core::arch::x86_64::{__cpuid, CpuidResult};

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

/// Order memory accesses against a DMA-capable device. x86 is TSO and
/// orders write-back stores before uncached MMIO stores (and loads with
/// loads), so only the compiler must not reorder.
#[inline]
pub fn dma_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Called with interrupts disabled (the executor's idle path). `sti; hlt`
/// is atomic: the interrupt shadow of `sti` covers `hlt`, so an IRQ that
/// arrives in between still wakes the CPU. Interrupts stay enabled after.
#[cfg_attr(feature = "idle-poll", allow(dead_code))]
pub fn wait_for_interrupt() {
    // SAFETY: `sti; hlt` enables interrupts and halts until one arrives.
    unsafe { asm!("sti", "hlt", options(nomem, nostack)) };
}

pub fn halt() -> ! {
    loop {
        // SAFETY: stops the CPU; interrupts stay masked.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

pub fn cpuid(leaf: u32) -> CpuidResult {
    // `__cpuid` is safe on every x86_64 CPU (CPUID always exists in long mode).
    __cpuid(leaf)
}

/// CPUID.1:ECX[31]: running under a hypervisor.
pub fn hypervisor() -> bool {
    cpuid(1).ecx & (1 << 31) != 0
}

pub fn cr2() -> u64 {
    let v: u64;
    // SAFETY: reading CR2 (last page-fault address) has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}
