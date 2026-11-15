//! 16550 UART on COM1 (I/O port 0x3f8), 115200 8N1. Output is polled;
//! input comes through the RX interrupt (ISA IRQ 4 via the IOAPIC), which
//! drains the 16-byte FIFO into `crate::console`'s ring.

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
    outb(COM1 + IER, 0); // no UART interrupts until rx_irq_enable
    outb(COM1 + LCR, 0x80); // DLAB: divisor follows
    outb(COM1, 1); // divisor 1 = 115200 baud
    outb(COM1 + IER, 0);
    outb(COM1 + LCR, 0x03); // 8N1
    outb(COM1 + FCR, 0x47); // enable + clear FIFOs, RX interrupt at 4 bytes
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

/// Taken by whoever drains the receive FIFO (the RX interrupt, or thread
/// context with IRQs masked): only `try_lock`, never waited for.
static RX: Mutex<()> = Mutex::new(());
const LSR_OE: u8 = 1 << 1;
const IER_RDA: u8 = 1 << 0;
const MCR_OUT2: u8 = 1 << 3;

fn drain(push: fn(u8)) -> usize {
    let Some(_g) = RX.try_lock() else { return 0 };
    let mut n = 0;
    // Bounded: a stuck LSR cannot keep us here.
    for _ in 0..64 {
        let lsr = inb(COM1 + LSR);
        if lsr & LSR_OE != 0 {
            crate::console::rx_overrun();
        }
        if lsr & LSR_DR == 0 {
            break;
        }
        push(inb(COM1));
        n += 1;
    }
    n
}

/// RX interrupt: empty the FIFO (reading it is the acknowledgement).
pub fn rx_drain_irq(push: fn(u8)) {
    drain(push);
}

/// Thread context: empty the FIFO with IRQs masked (the RX interrupt on
/// this core must not find the lock held).
pub fn rx_drain_thread(push: fn(u8)) -> usize {
    let was = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    let n = drain(push);
    if was {
        super::cpu::irq_enable();
    }
    n
}

/// Route COM1's interrupt (ISA IRQ 4) through the IOAPIC, masked.
pub fn rx_irq_setup(info: &crate::platform::BootInfo) -> Option<(u32, crate::irq::Trigger)> {
    super::irqchip::route_com1(info)
}

/// Let the UART raise its RX interrupt (data available / timeout).
pub fn rx_irq_enable() {
    let _g = LOCK.lock();
    outb(COM1 + MCR, 0x03 | MCR_OUT2); // OUT2 gates the IRQ line on PCs
    outb(COM1 + IER, IER_RDA);
}

/// No more UART interrupts (before entering another kernel).
pub(super) fn rx_irq_off() {
    outb(COM1 + IER, 0);
    outb(COM1 + MCR, 0x03);
}

pub fn emergency_write_str(s: &str) {
    // SAFETY: fatal paths only, which never return to normal operation.
    unsafe { LOCK.force_unlock() };
    write_str(s);
}
