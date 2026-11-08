//! PL011 UART console and `print!` / `println!` macros.
//!
//! QEMU's PL011 needs no initialisation, so we only poll the TX-FIFO-full
//! flag and write bytes. The base address defaults to the QEMU `virt` value
//! and is replaced by the one found in the DTB.

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

/// QEMU `virt` PL011 (`/pl011@9000000`).
const DEFAULT_BASE: usize = 0x0900_0000;
const UARTDR: usize = 0x00;
const UARTFR: usize = 0x18;
const FR_TXFF: u32 = 1 << 5;

static BASE: AtomicUsize = AtomicUsize::new(DEFAULT_BASE);
static LOCK: Mutex<()> = Mutex::new(());

pub fn set_base(base: usize) {
    BASE.store(base, Ordering::Relaxed);
}

fn put_byte(b: u8) {
    let base = BASE.load(Ordering::Relaxed);
    // SAFETY: `base` is the PL011 MMIO block, identity-mapped as device memory.
    unsafe {
        while core::ptr::read_volatile((base + UARTFR) as *const u32) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        core::ptr::write_volatile((base + UARTDR) as *mut u32, b as u32);
    }
}

struct Uart;

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                put_byte(b'\r');
            }
            put_byte(b);
        }
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    let _guard = LOCK.lock();
    let _ = fmt::Write::write_fmt(&mut Uart, args);
}

/// Release the console lock regardless of who holds it.
///
/// # Safety
/// Only for fatal paths (panic, unhandled exception) that never return.
pub unsafe fn force_unlock() {
    // SAFETY: forwarded to the caller's contract.
    unsafe { LOCK.force_unlock() };
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}
