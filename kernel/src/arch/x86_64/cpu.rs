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

/// The CPU's vendor and signature (CPUID.0 and CPUID.1:EAX), printed
/// next to the microcode revisions (`smp::start`).
#[derive(Clone, Copy)]
pub struct CpuSignature {
    vendor: Vendor,
    eax: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum Vendor {
    Amd,
    Hygon,
    Intel,
    Other,
}

impl CpuSignature {
    /// Family and model with the extended fields folded in, as Linux's
    /// `x86_family` / `x86_model` (and the microcode file names) use them.
    fn family(self) -> u32 {
        let base = (self.eax >> 8) & 0xf;
        if base == 0xf { base + ((self.eax >> 20) & 0xff) } else { base }
    }

    fn model(self) -> u32 {
        let base = (self.eax >> 4) & 0xf;
        let family = (self.eax >> 8) & 0xf;
        if family == 0x6 || family == 0xf {
            base | ((self.eax >> 12) & 0xf0)
        } else {
            base
        }
    }
}

impl core::fmt::Display for CpuSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let vendor = match self.vendor {
            Vendor::Amd => "AMD",
            Vendor::Hygon => "Hygon",
            Vendor::Intel => "Intel",
            Vendor::Other => "x86",
        };
        write!(
            f,
            "{vendor} family {:#x} model {:#x} stepping {} (cpuid {:08x})",
            self.family(),
            self.model(),
            self.eax & 0xf,
            self.eax
        )
    }
}

pub fn cpu_signature() -> Option<CpuSignature> {
    let v = cpuid(0);
    let vendor = match (v.ebx, v.edx, v.ecx) {
        (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Vendor::Amd, // AuthenticAMD
        (0x6f67_7948, 0x6e65_476e, 0x656e_6975) => Vendor::Hygon, // HygonGenuine
        (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Vendor::Intel, // GenuineIntel
        _ => Vendor::Other,
    };
    Some(CpuSignature { vendor, eax: cpuid(1).eax })
}

/// This core's microcode revision (MSR 0x8B), as Linux reads it at boot:
/// AMD family 10h and later keep the patch level there (PATCH_LEVEL);
/// Intel needs a 0 written and a CPUID before the revision appears in the
/// high half (IA32_BIOS_SIGN_ID). `None` on CPUs without the MSR. Under a
/// hypervisor this is whatever it reports, not the host CPU's level.
pub fn microcode_revision() -> Option<u32> {
    let sig = cpu_signature()?;
    match sig.vendor {
        Vendor::Amd | Vendor::Hygon if sig.family() >= 0x10 => Some(rdmsr(0x8b) as u32),
        Vendor::Intel => {
            // SAFETY: IA32_BIOS_SIGN_ID exists on every x86_64 Intel CPU;
            // writing 0 only clears the revision field CPUID then refills.
            unsafe {
                asm!("wrmsr", in("ecx") 0x8bu32, in("eax") 0u32, in("edx") 0u32, options(nostack, preserves_flags))
            };
            let _ = cpuid(1);
            Some((rdmsr(0x8b) >> 32) as u32)
        }
        _ => None,
    }
}

/// Read MSR 0x8B (the only caller checks the vendor and family first).
fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: callers pass only an MSR this CPU implements; reading it
    // has no side effects.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (u64::from(hi) << 32) | u64::from(lo)
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
