//! rrouter — bare-metal aarch64 unikernel for SOHO routing.
//!
//! Single address space, everything runs at EL1 (on SP_EL0; exceptions use
//! SP_EL1). Boot flow:
//! `boot.S` (_start) → [`kernel_main`] → DTB discovery → heap → MMU (W^X) →
//! GIC + timer IRQ → PCIe enumeration → executor.
//!
//! See `docs/architecture.md` and `docs/boot-and-memory.md`.

#![no_std]
#![no_main]

extern crate alloc;

mod arch;
mod console;
mod dtb;
mod exceptions;
mod executor;
mod gic;
mod heap;
mod irq;
mod mmu;
mod pci;
mod psci;
mod selftest;
mod timer;

core::arch::global_asm!(include_str!("boot.S"));

/// Rust entry point, called from `boot.S` with the MMU on and a valid stack.
///
/// `x0_dtb` is whatever QEMU left in `x0` (the DTB address for Linux-style
/// boots, usually 0 for bare-metal ELF boots).
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(x0_dtb: usize) -> ! {
    timer::init_clock();
    println!();
    println!("rrouter {} — aarch64 bare-metal", env!("CARGO_PKG_VERSION"));
    println!("  exception level : EL{}", arch::current_el());

    // SAFETY: called once, early, before anything else reads the DTB.
    let info = match unsafe { dtb::BootInfo::discover(x0_dtb) } {
        Ok(info) => info,
        Err(e) => panic!("device tree not found: {e}"),
    };
    if let Some(base) = info.uart_base {
        console::set_base(base);
    }
    info.print();

    heap::init(&info);
    mmu::init(&info);

    let gic = info.gic.expect("no GICv3 in device tree");
    gic::init(&gic);
    timer::init_irq(info.vtimer_intid);
    irq::enable();
    println!("  timer           : {} Hz, tickless", timer::frequency());

    if let Some(pcie) = info.pcie {
        let devices = pci::enumerate(&pcie);
        pci::print(&devices);
    }

    selftest::fault_tests();
    selftest::spawn(info.psci);

    executor::run()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // SAFETY: we are about to halt; taking the console from a holder that
    // may have been interrupted is acceptable here.
    unsafe { console::force_unlock() };
    println!("\n!!! KERNEL PANIC: {info}");
    arch::halt()
}
