//! PL011 UART console backend. QEMU's PL011 needs no initialisation: poll
//! the TX-FIFO-full flag and write bytes. Receive: the RX and RX-timeout
//! interrupts drain the FIFO into `crate::console`'s ring.

use crate::mmio::Region;
use spin::Mutex;

/// QEMU `virt` PL011 (`/pl011@9000000`), used until `init` runs.
const DEFAULT_BASE: usize = 0x0900_0000;
const SIZE: usize = 0x1000;
const UARTDR: usize = 0x00;
const UARTFR: usize = 0x18;
const FR_TXFF: u32 = 1 << 5;
const FR_RXFE: u32 = 1 << 4;

static UART: Mutex<Option<Region>> = Mutex::new(None);

fn new_region(base: usize) -> Region {
    // SAFETY: the PL011 block is device memory mapped by the boot map and
    // mm::mmu; this module is its only user: transmit and control through
    // the UART lock, receive (UARTDR reads, UARTICR) through the RX lock.
    unsafe { Region::new(base, SIZE) }
}

/// Switch to the address from the firmware tables.
pub fn init(base: Option<usize>) {
    let base = base.unwrap_or(DEFAULT_BASE);
    *UART.lock() = Some(new_region(base));
    // Before IRQs are enabled: no need to mask them for the RX lock.
    *RX.lock() = Some(new_region(base));
}

fn put(uart: &mut Region, b: u8) {
    while uart.read32(UARTFR) & FR_TXFF != 0 {
        core::hint::spin_loop();
    }
    uart.write32(UARTDR, b as u32);
}

fn write_with(uart: &mut Region, s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            put(uart, b'\r');
        }
        put(uart, b);
    }
}

/// Write a string (thread context only, never from IRQ handlers).
pub fn write_str(s: &str) {
    let mut guard = UART.lock();
    let uart = guard.get_or_insert_with(|| new_region(DEFAULT_BASE));
    write_with(uart, s);
}

/// The receive side: a second view of the same PL011 (data and interrupt
/// registers only), taken by whoever drains the FIFO (the RX interrupt, or
/// thread context with IRQs masked): only `try_lock`, never waited for.
static RX: Mutex<Option<Region>> = Mutex::new(None);
const UARTIMSC: usize = 0x38;
const UARTICR: usize = 0x44;
const INT_RX: u32 = 1 << 4;
const INT_RT: u32 = 1 << 6;
const DR_OE: u32 = 1 << 11;

fn drain(push: fn(u8)) -> usize {
    let Some(mut guard) = RX.try_lock() else { return 0 };
    let Some(uart) = guard.as_mut() else { return 0 };
    let mut n = 0;
    for _ in 0..64 {
        if uart.read32(UARTFR) & FR_RXFE != 0 {
            break;
        }
        // Bits 8-11 are error flags: a byte with an error is still kept.
        let d = uart.read32(UARTDR);
        if d & DR_OE != 0 {
            crate::console::rx_overrun();
        }
        push(d as u8);
        n += 1;
    }
    // Reading empties the FIFO; the receive timeout needs clearing too.
    uart.write32(UARTICR, INT_RX | INT_RT);
    n
}

/// RX interrupt: empty the FIFO (that is the acknowledgement).
pub fn rx_drain_irq(push: fn(u8)) {
    drain(push);
}

/// Thread context: empty the FIFO with IRQs masked (a level interrupt on
/// this core must not find the lock held: it would fire forever).
pub fn rx_drain_thread(push: fn(u8)) -> usize {
    let was = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    let n = drain(push);
    if was {
        super::cpu::irq_enable();
    }
    n
}

/// The PL011's interrupt from the DTB (level, routed to this core by
/// `irqchip::enable`).
pub fn rx_irq_setup(info: &crate::platform::BootInfo) -> Option<(u32, crate::irq::Trigger)> {
    Some((info.console_irq?, crate::irq::Trigger::Level))
}

/// Let the PL011 raise its receive and receive-timeout interrupts.
pub fn rx_irq_enable() {
    let mut guard = UART.lock();
    let uart = guard.get_or_insert_with(|| new_region(DEFAULT_BASE));
    uart.write32(UARTIMSC, INT_RX | INT_RT);
}

/// Fatal paths only (panic, unhandled exception): never returns to normal
/// operation, so taking the console from an interrupted holder is acceptable.
pub fn emergency_write_str(s: &str) {
    // SAFETY: called only on paths that halt afterwards (see above).
    unsafe { UART.force_unlock() };
    write_str(s);
}
