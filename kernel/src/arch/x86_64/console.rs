//! 16550 UART on COM1 (I/O port 0x3f8), 115200 8N1.

use super::port::{inb, outb};
use spin::Mutex;

const COM1: u16 = 0x3f8;
const IER: u16 = 1;
const FCR: u16 = 2;
const LCR: u16 = 3;
const MCR: u16 = 4;
const LSR: u16 = 5;
const LSR_DR: u8 = 1 << 0;
const LSR_THRE: u8 = 1 << 5;
const LSR_TEMT: u8 = 1 << 6;

static LOCK: Mutex<()> = Mutex::new(());

/// Program 115200 8N1 with FIFOs (firmware usually did already). `base`
/// (MMIO) is not used on x86.
pub fn init(_base: Option<usize>) {
    let _g = LOCK.lock();
    // Let the transmitter drain first: reprogramming the divisor while a
    // byte is still shifting out garbles it (seen on the apu4).
    for _ in 0..100_000 {
        if inb(COM1 + LSR) & LSR_TEMT != 0 {
            break;
        }
        core::hint::spin_loop();
    }
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

/// One received byte, if any (polled: the serial CLI; COM1's interrupt
/// would need IOAPIC routing). Thread context.
pub fn read_byte() -> Option<u8> {
    let _g = LOCK.lock();
    (inb(COM1 + LSR) & LSR_DR != 0).then(|| inb(COM1))
}

pub fn emergency_write_str(s: &str) {
    // SAFETY: fatal paths only, which never return to normal operation.
    unsafe { LOCK.force_unlock() };
    write_str(s);
}
