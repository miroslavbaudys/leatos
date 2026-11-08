//! rrouter — bare-metal unikernel for SOHO routing (aarch64 today, x86_64 later).
//!
//! Single address space; everything runs in kernel mode. Boot order is
//! arch-neutral (this file); the arch backend supplies entry, CPU, irqchip,
//! timer and MMU hardware (`arch/`). See docs/architecture.md and
//! docs/safety-and-portability.md.
//!
//! `unsafe` is denied crate-wide. Only modules declared with
//! `#[allow(unsafe_code)]` may use it: `grep -rn "allow(unsafe_code)"`
//! lists the whole audit surface.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
// The x86_64 backend is a compile-only skeleton (no IRQ entry yet).
#![cfg_attr(target_arch = "x86_64", allow(dead_code))]

extern crate alloc;

mod arch;
mod console;
mod drivers;
mod executor;
mod irq;
mod mm;
#[allow(unsafe_code)] // the one constructor that turns an address into a device region
mod mmio;
mod net;
#[allow(unsafe_code)] // ECAM handle creation (2 operations)
mod pci;
mod platform;
#[allow(unsafe_code)] // feature-gated deliberate faults
mod selftest;
mod timer;

use executor::Priority;

/// Arch-neutral kernel main, called by the arch entry point with the MMU on
/// and a valid stack. `boot_arg` is the firmware hand-off (DTB address in x0).
pub fn kmain(boot_arg: usize) -> ! {
    timer::init_clock();
    println!();
    println!("rrouter {} — bare metal", env!("CARGO_PKG_VERSION"));
    println!("  privilege level : {}", arch::cpu::privilege_level());

    let info = arch::discover(boot_arg).unwrap_or_else(|e| panic!("platform discovery: {e}"));
    arch::console::init(info.console_base);
    arch::power::init(info.power);
    info.print();

    mm::heap::init(&info);
    mm::mmu::init(&info);
    arch::irqchip::init(&info);
    timer::init_irq(info.timer_intid);
    irq::enable();
    println!("  timer           : {} Hz, tickless", timer::frequency());

    net::packet::init_pool(net_pool_size());
    let mut pci = info.pcie.map(|p| pci::init(&p));
    if let Some(pci) = &pci {
        pci::print(pci);
    }
    let ifs = pci.as_mut().map(net::stack::bring_up).unwrap_or_default();
    let has_net = !ifs.is_empty();

    selftest::fault_tests();
    selftest::spawn(has_net);
    executor::spawn(Priority::Datapath, "net", net::stack::run(ifs));
    executor::run()
}

/// Packet buffers to preallocate: 2 NICs × (RX ring + TX ring) plus room
/// for queues. 1024 × 2 KiB = 2 MiB.
fn net_pool_size() -> usize {
    1024
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    fatal_println!("\n!!! KERNEL PANIC: {info}");
    arch::cpu::halt()
}
