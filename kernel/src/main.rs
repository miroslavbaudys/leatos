//! rrouter — bare-metal aarch64 unikernel for SOHO routing.
//!
//! Single address space, everything runs at EL1. Boot flow:
//! `boot.S` (_start) → [`kernel_main`] → discover hardware from the DTB →
//! heap → (later) drivers, executor, network stack, services.
//!
//! See `docs/architecture.md` and `docs/boot-and-memory.md`.

#![no_std]
#![no_main]

extern crate alloc;

mod arch;
mod console;
mod dtb;
mod exceptions;
mod heap;
mod psci;
mod timer;

use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt::Write as _;

core::arch::global_asm!(include_str!("boot.S"));

/// Rust entry point, called from `boot.S` with the MMU on and a valid stack.
///
/// `x0_dtb` is whatever QEMU left in `x0` (the DTB address for Linux-style
/// boots, usually 0 for bare-metal ELF boots).
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(x0_dtb: usize) -> ! {
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

    timer::init();
    println!("  timer           : {} Hz", timer::frequency());

    heap::init(&info);
    heap_self_test();

    println!("  uptime          : {} us", timer::uptime_us());
    println!("rrouter: boot ok");

    #[cfg(feature = "smoke-test")]
    psci::system_off(info.psci);

    #[cfg(not(feature = "smoke-test"))]
    {
        let _ = info.psci;
        println!("idle (Ctrl-A X to quit QEMU)");
        loop {
            arch::wait_for_interrupt();
        }
    }
}

/// Exercise the allocator so a broken heap fails loudly at boot.
fn heap_self_test() {
    let v: Vec<u64> = (0..1024).collect();
    assert_eq!(v.iter().sum::<u64>(), 1023 * 1024 / 2);
    let b = Box::new([0xa5u8; 4096]);
    assert!(b.iter().all(|&x| x == 0xa5));
    let mut s = String::new();
    let n = 42;
    let _ = write!(s, "heap-{n}");
    assert_eq!(s, "heap-42");
    println!("  heap self-test  : ok");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // SAFETY: we are about to halt; taking the console from a holder that
    // may have been interrupted is acceptable here.
    unsafe { console::force_unlock() };
    println!("\n!!! KERNEL PANIC: {info}");
    arch::halt()
}
