//! Secondary cores on aarch64: PSCI `CPU_ON` into `_secondary_start`
//! (`boot.S`), which switches to the kernel's page tables and stacks and
//! calls [`secondary_rust`].

use crate::smp::MAX_CORES;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const CPU_ON: u64 = 0xc400_0003; // PSCI 0.2+, SMC64/HVC64 calling convention

/// Root translation table for secondaries (read by `boot.S` with the MMU off).
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // referenced by name from boot.S
static secondary_ttbr: AtomicU64 = AtomicU64::new(0);

/// Per core: [exception stack top, kernel stack top] (read by `boot.S`).
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)] // referenced by name from boot.S
static secondary_stacks: [[AtomicU64; 2]; MAX_CORES] =
    [const { [AtomicU64::new(0), AtomicU64::new(0)] }; MAX_CORES];

/// MPIDR affinity of each core (for IPIs).
static MPIDR: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];

unsafe extern "C" {
    fn _secondary_start();
}

/// Record the boot core's affinity (called from `irqchip::init`).
pub(super) fn set_boot_mpidr(id: u64) {
    MPIDR[0].store(id, Ordering::Relaxed);
}

pub(super) fn mpidr(core: usize) -> u64 {
    MPIDR[core].load(Ordering::Relaxed)
}

/// Start `core` (hardware ID `hw_id`) on the given stacks.
pub fn start(
    core: usize,
    hw_id: u64,
    exc_top: usize,
    stack_top: usize,
) -> Result<(), &'static str> {
    MPIDR[core].store(hw_id, Ordering::Relaxed);
    secondary_stacks[core][0].store(exc_top as u64, Ordering::Relaxed);
    secondary_stacks[core][1].store(stack_top as u64, Ordering::Relaxed);
    secondary_ttbr.store(crate::mm::mmu::root(), Ordering::Relaxed);
    let ttbr = &secondary_ttbr as *const AtomicU64 as u64;
    // SAFETY: cleans one cache line to the point of coherency (no data
    // change), so the new core sees `secondary_ttbr` with its MMU off.
    unsafe { asm!("dc cvac, {}", "dsb sy", in(reg) ttbr, options(nostack, preserves_flags)) };
    let entry = _secondary_start as *const () as usize as u64;
    let ret: i64;
    if super::power::uses_smc() {
        // SAFETY: PSCI CPU_ON: starts another core at `entry` (kernel text,
        // identity-mapped) with x0 = core; no effect on this core.
        unsafe {
            asm!("smc #0", inlateout("x0") CPU_ON as i64 => ret, in("x1") hw_id, in("x2") entry, in("x3") core as u64, options(nostack))
        };
    } else {
        // SAFETY: as above, through the hypervisor conduit.
        unsafe {
            asm!("hvc #0", inlateout("x0") CPU_ON as i64 => ret, in("x1") hw_id, in("x2") entry, in("x3") core as u64, options(nostack))
        };
    }
    match ret {
        0 => Ok(()),
        -2 => Err("PSCI CPU_ON: invalid parameters"),
        -4 => Err("PSCI CPU_ON: already on"),
        -1 => Err("PSCI CPU_ON: not supported"),
        _ => Err("PSCI CPU_ON failed"),
    }
}

/// Nothing to do on aarch64 (no in-RAM kernel replacement).
#[allow(dead_code)]
pub fn park_others() {}

/// Called by `boot.S` on a secondary core.
#[unsafe(no_mangle)]
extern "C" fn secondary_rust(core: usize) -> ! {
    crate::smp::secondary_main(core)
}
