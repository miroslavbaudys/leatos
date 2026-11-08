//! 16550 UART on COM1 (I/O port 0x3f8).

use core::arch::asm;
use spin::Mutex;

const COM1: u16 = 0x3f8;
const LSR: u16 = 5;
const LSR_THRE: u8 = 1 << 5;

static LOCK: Mutex<()> = Mutex::new(());

fn outb(port: u16, v: u8) {
    // SAFETY: COM1 data port write; the UART is owned by this module.
    unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack)) };
}

fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: COM1 status port read; no side effects beyond the device.
    unsafe { asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack)) };
    v
}

/// Port I/O console: `base` (MMIO) is not used on x86.
pub fn init(_base: Option<usize>) {}

fn put(b: u8) {
    while inb(COM1 + LSR) & LSR_THRE == 0 {
        core::hint::spin_loop();
    }
    outb(COM1, b);
}

fn write_raw(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            put(b'\r');
        }
        put(b);
    }
}

pub fn write_str(s: &str) {
    let _g = LOCK.lock();
    write_raw(s);
}

pub fn emergency_write_str(s: &str) {
    // SAFETY: fatal paths only, which never return to normal operation.
    unsafe { LOCK.force_unlock() };
    write_str(s);
}
