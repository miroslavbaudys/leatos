//! `print!` / `println!` (thread context) and `fatal_println!` (panic and
//! fatal-exception paths) on top of the arch console backend.

use core::fmt;

struct Console {
    fatal: bool,
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.fatal {
            crate::arch::console::emergency_write_str(s);
        } else {
            crate::arch::console::write_str(s);
        }
        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments, fatal: bool) {
    let _ = fmt::Write::write_fmt(&mut Console { fatal }, args);
}

/// Print to the console. Thread context only (never in IRQ handlers).
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*), false) };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}

/// Print on a fatal path: takes the console even if it is held.
#[macro_export]
macro_rules! fatal_println {
    ($($arg:tt)*) => {
        $crate::console::_print(format_args!("{}\n", format_args!($($arg)*)), true)
    };
}
