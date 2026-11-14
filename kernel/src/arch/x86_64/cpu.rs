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

/// This core's index (`smp`): the first word of the per-core block that
/// GS points at (`exceptions::per_core` sets it up first thing).
#[inline]
pub fn core_id() -> usize {
    let v: u64;
    // SAFETY: reads 8 bytes at GS base, the core's own `PERCPU` slot.
    unsafe { asm!("mov {}, gs:[0]", out(reg) v, options(nostack, preserves_flags, readonly)) };
    v as usize
}

/// Point GS at this core's per-core block (IA32_GS_BASE).
pub fn set_gs_base(addr: u64) {
    // SAFETY: writes IA32_GS_BASE; only GS-relative loads use it.
    unsafe {
        asm!("wrmsr", in("ecx") 0xc000_0101u32, in("eax") addr as u32, in("edx") (addr >> 32) as u32, options(nostack, preserves_flags))
    };
}

/// This core's initial local APIC ID (CPUID.1:EBX[31:24]).
pub fn apic_id() -> u64 {
    (cpuid(1).ebx >> 24) as u64
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

/// Stop this core forever (as [`halt`]; the aarch64 one differs).
pub fn park() -> ! {
    halt()
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
