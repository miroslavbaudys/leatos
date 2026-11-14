//! aarch64 backend (QEMU `virt`: GICv3, generic timer, PL011, PSCI, DTB).

pub mod console;
pub mod cpu;
mod exceptions;
pub mod irqchip;
pub mod kexec;
pub mod mmu;
pub mod power;
pub mod smp;
pub mod timer;

use crate::platform::BootInfo;

core::arch::global_asm!(include_str!("boot.S"));

/// Entry point called from `boot.S` with the MMU on and a valid stack.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(x0: usize) -> ! {
    crate::kmain(x0)
}

/// Discover the machine from the device tree. `boot_arg` is `x0` at entry.
pub fn discover(boot_arg: usize) -> Result<BootInfo, &'static str> {
    // SAFETY: called once at boot; QEMU keeps the DTB at the start of RAM,
    // which stays mapped (read-only) for the kernel's lifetime.
    unsafe { crate::platform::dtb::discover(boot_arg, crate::mm::sym::kernel_start()) }
}
