//! x86 port I/O (the only way to reach the 16550 UART, PIT, PIC and ACPI
//! PM registers). Each function is one `in`/`out` instruction.

use core::arch::asm;

pub fn outb(port: u16, v: u8) {
    // SAFETY: a single port write; callers own the device behind `port`.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags))
    };
}

pub fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: a single port read; callers own the device behind `port`.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags))
    };
    v
}

pub fn outw(port: u16, v: u16) {
    // SAFETY: a single port write; callers own the device behind `port`.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags))
    };
}
