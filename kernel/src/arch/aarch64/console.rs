//! PL011 UART console backend. QEMU's PL011 needs no initialisation: poll
//! the TX-FIFO-full flag and write bytes.

use crate::mmio::Region;
use spin::Mutex;

/// QEMU `virt` PL011 (`/pl011@9000000`), used until `init` runs.
const DEFAULT_BASE: usize = 0x0900_0000;
const SIZE: usize = 0x1000;
const UARTDR: usize = 0x00;
const UARTFR: usize = 0x18;
const FR_TXFF: u32 = 1 << 5;

static UART: Mutex<Option<Region>> = Mutex::new(None);

fn new_region(base: usize) -> Region {
    // SAFETY: the PL011 block is device memory mapped by the boot map and
    // mm::mmu; this module is its only user (UART lock).
    unsafe { Region::new(base, SIZE) }
}

/// Switch to the address from the firmware tables.
pub fn init(base: Option<usize>) {
    *UART.lock() = Some(new_region(base.unwrap_or(DEFAULT_BASE)));
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

/// Fatal paths only (panic, unhandled exception): never returns to normal
/// operation, so taking the console from an interrupted holder is acceptable.
pub fn emergency_write_str(s: &str) {
    // SAFETY: called only on paths that halt afterwards (see above).
    unsafe { UART.force_unlock() };
    write_str(s);
}
