//! 16550 UART on COM1 (I/O port 0x3f8), 115200 8N1.

use super::port::{inb, outb};
use spin::Mutex;

const COM1: u16 = 0x3f8;
const IER: u16 = 1;
const FCR: u16 = 2;
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const LSR_THRE: u8 = 1 << 5;

static LOCK: Mutex<()> = Mutex::new(());

/// Program 115200 8N1 with FIFOs (firmware usually did already). `base`
/// (MMIO) is not used on x86.
pub fn init(_base: Option<usize>) {
    let _g = LOCK.lock();
    outb(COM1 + IER, 0); // no UART interrupts (polled output)
    outb(COM1 + LCR, 0x80); // DLAB: divisor follows
    outb(COM1, 1); // divisor 1 = 115200 baud
    outb(COM1 + IER, 0);
    outb(COM1 + LCR, 0x03); // 8N1
    outb(COM1 + FCR, 0xc7); // enable + clear FIFOs, 14-byte threshold
    outb(COM1 + MCR, 0x03); // DTR + RTS
}

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
