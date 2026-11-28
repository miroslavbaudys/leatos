//! `print!` / `println!` (thread context) and `fatal_println!` (panic and
//! fatal-exception paths) on top of the arch console backend, plus the
//! serial CLI's side of the console:
//!
//! - **Input line**: the CLI tells the console what it has on the current
//!   line (prompt + typed text, [`prompt`] / [`echo`]). Other output (log
//!   lines from any core) first erases that line (`\r` + `ESC [K`), then
//!   redraws it once the output ends with a newline, so log messages never
//!   land in the middle of what is being typed.
//! - **Receive ring**: the UART's RX interrupt drains the hardware FIFO
//!   (16 bytes on a 16550, 1.4 ms at 115200 baud) into a lock-free ring
//!   ([`rx_push`]); the CLI reads it with [`read_byte`]. Without an
//!   interrupt, [`poll_rx`] drains the FIFO from thread context. The
//!   screen's keyboard (`arch::kbd`, [`init_kbd`]) types into the same
//!   ring, with its own interrupt and the same event.

use alloc::collections::VecDeque;
use alloc::string::String;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

struct Console {
    fatal: bool,
    last: u8,
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.fatal {
            crate::arch::console::emergency_write_str(s);
            crate::drivers::screen::emergency_write(s);
        } else {
            crate::arch::console::write_str(s);
            crate::drivers::screen::write(s);
        }
        if let Some(&b) = s.as_bytes().last() {
            self.last = b;
        }
        Ok(())
    }
}

/// The CLI's line at the cursor.
struct InputLine {
    /// What the CLI has on the current line (prompt + typed text); `None`
    /// while the cursor is at the start of a line the CLI does not own.
    text: Option<String>,
    /// `text` is on the screen right now (false after other output left
    /// the cursor in the middle of its own line).
    shown: bool,
}

/// Serialises normal output (all cores) and guards the input line. Never
/// taken in IRQ context; the fatal path bypasses it.
static OUT: Mutex<InputLine> = Mutex::new(InputLine {
    text: None,
    shown: false,
});

const ERASE_LINE: &str = "\r\x1b[K";

fn raw(s: &str) {
    crate::arch::console::write_str(s);
    crate::drivers::screen::write(s);
}

// ---- RAM log ------------------------------------------------------------

/// Bytes of log text kept (oldest whole lines go first).
const LOG_SIZE: usize = 64 * 1024;

struct RamLog {
    buf: VecDeque<u8>,
    /// The next byte starts a line (gets a timestamp).
    line_start: bool,
    dropped_lines: u64,
}

/// Once set ([`log_to_ram`]), log output goes here instead of the UART.
static LOG: Mutex<Option<RamLog>> = Mutex::new(None);
static TO_RAM: AtomicBool = AtomicBool::new(false);
/// Cores currently printing CLI output ([`cli_output`]): that goes to the
/// UART even while log output goes to RAM. Cooperative tasks: nothing else
/// runs on the core in the meantime.
static CLI_CORE: [AtomicBool; crate::smp::MAX_CORES] =
    [const { AtomicBool::new(false) }; crate::smp::MAX_CORES];

struct LogWriter<'a>(&'a mut RamLog);

impl fmt::Write for LogWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let log = &mut *self.0;
        for &b in s.as_bytes() {
            if log.line_start {
                log.line_start = false;
                let t = crate::timer::uptime();
                let stamp = alloc::format!("[{:6}.{:03}] ", t.as_secs(), t.subsec_millis());
                log.buf.extend(stamp.as_bytes());
            }
            if b != b'\r' {
                log.buf.push_back(b);
            }
            log.line_start = b == b'\n';
        }
        while log.buf.len() > LOG_SIZE {
            // Drop the oldest line.
            while let Some(b) = log.buf.pop_front() {
                if b == b'\n' {
                    break;
                }
            }
            log.dropped_lines += 1;
        }
        Ok(())
    }
}

/// End of boot: log output goes to the RAM log from now on (the serial
/// console stays free for the CLI). CLI output, panics and fatal reports
/// still go to the UART.
pub fn log_to_ram() {
    *LOG.lock() = Some(RamLog {
        buf: VecDeque::with_capacity(LOG_SIZE),
        line_start: true,
        dropped_lines: 0,
    });
    TO_RAM.store(true, Ordering::Release);
}

/// Is log output going to RAM?
pub fn logging_to_ram() -> bool {
    TO_RAM.load(Ordering::Acquire)
}

/// Run `f` with this core's output going to the UART (the CLI's command
/// output).
pub fn cli_output<R>(f: impl FnOnce() -> R) -> R {
    let core = crate::smp::current();
    let was = CLI_CORE[core].swap(true, Ordering::Relaxed);
    let r = f();
    CLI_CORE[core].store(was, Ordering::Relaxed);
    r
}

/// The RAM log's last lines that fit in `max_bytes` (at most `lines` of
/// them, all if `None`), and the count of lines dropped so far.
pub fn log_tail(lines: Option<usize>, max_bytes: usize) -> (String, u64) {
    let guard = LOG.lock();
    let Some(log) = guard.as_ref() else {
        return (String::new(), 0);
    };
    (tail_of(&log.buf, lines, max_bytes), log.dropped_lines)
}

fn tail_of(buf: &VecDeque<u8>, lines: Option<usize>, max_bytes: usize) -> String {
    let mut start = buf.len();
    let mut n = 0;
    // Walk back over whole lines (a trailing partial line counts as one).
    let mut i = buf.len();
    while i > 0 {
        let mut j = i - 1;
        while j > 0 && buf[j - 1] != b'\n' {
            j -= 1;
        }
        if buf.len() - j > max_bytes || lines.is_some_and(|l| n >= l) {
            break;
        }
        start = j;
        n += 1;
        i = j;
    }
    let bytes: alloc::vec::Vec<u8> = buf.range(start..).copied().collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Empty the RAM log.
pub fn log_clear() {
    if let Some(log) = LOG.lock().as_mut() {
        log.buf.clear();
        log.line_start = true;
    }
}

/// Fatal paths: the RAM log's last lines on the console (what led up to
/// the crash). Takes no lock it could wait for.
pub fn fatal_dump_log() {
    if !logging_to_ram() {
        return;
    }
    let Some(guard) = LOG.try_lock() else {
        crate::arch::console::emergency_write_str("!!! (RAM log busy)\n");
        return;
    };
    let Some(log) = guard.as_ref() else { return };
    crate::arch::console::emergency_write_str("!!! last log lines:\n");
    let (a, b) = log.buf.as_slices();
    let total = a.len() + b.len();
    // About the last 2 KiB, from a line start.
    let mut skip = total.saturating_sub(2048);
    while skip > 0 && skip < total && log.buf[skip - 1] != b'\n' {
        skip += 1;
    }
    for part in [a, b] {
        let s = skip.min(part.len());
        skip -= s;
        for chunk in part[s..].utf8_chunks() {
            crate::arch::console::emergency_write_str(chunk.valid());
        }
    }
    if !log.line_start {
        crate::arch::console::emergency_write_str("\n");
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments, fatal: bool) {
    if fatal {
        let _ = fmt::Write::write_fmt(&mut Console { fatal, last: 0 }, args);
        return;
    }
    if TO_RAM.load(Ordering::Acquire) && !CLI_CORE[crate::smp::current()].load(Ordering::Relaxed)
    {
        if let Some(log) = LOG.lock().as_mut() {
            let _ = fmt::Write::write_fmt(&mut LogWriter(log), args);
        }
        return;
    }
    let mut line = OUT.lock();
    if line.shown {
        raw(ERASE_LINE);
        line.shown = false;
    }
    let mut c = Console { fatal, last: 0 };
    let _ = fmt::Write::write_fmt(&mut c, args);
    if c.last == b'\n'
        && let Some(t) = &line.text
    {
        raw(t);
        line.shown = true;
    }
}

/// The CLI starts a new line with `text` (its prompt), at the start of a line.
pub fn prompt(text: &str) {
    let mut line = OUT.lock();
    raw(text);
    line.text = Some(String::from(text));
    line.shown = true;
}

/// The CLI echoes `bytes`; afterwards its line reads `now`. Echo ending in
/// a newline (Enter, Ctrl-C) ends the CLI's line.
pub fn echo(bytes: &str, now: &str) {
    let mut line = OUT.lock();
    if line.text.is_some() && !line.shown {
        // Other output left the cursor mid-line: start afresh.
        raw("\n");
        raw(now);
    } else {
        raw(bytes);
    }
    if bytes.ends_with('\n') {
        line.text = None;
        line.shown = false;
    } else {
        line.text = Some(String::from(now));
        line.shown = true;
    }
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

// ---- receive ring -------------------------------------------------------

const RX_SIZE: usize = 4096;
/// Single producer: whoever holds the arch backend's RX lock (the RX
/// interrupt, or [`poll_rx`]). Single consumer: the CLI ([`read_byte`]).
static RX_BUF: [AtomicU8; RX_SIZE] = [const { AtomicU8::new(0) }; RX_SIZE];
/// Bytes written / read so far (wrapping; index = value % RX_SIZE).
static RX_HEAD: AtomicUsize = AtomicUsize::new(0);
static RX_TAIL: AtomicUsize = AtomicUsize::new(0);
static RX_DROPPED: AtomicU64 = AtomicU64::new(0);
static RX_IRQ: AtomicBool = AtomicBool::new(false);
static RX_EVENT: spin::Once<&'static crate::irq::IrqEvent> = spin::Once::new();

/// Store a received byte (IRQ-safe: atomics only). A full ring drops it.
pub fn rx_push(b: u8) {
    let head = RX_HEAD.load(Ordering::Relaxed);
    if head.wrapping_sub(RX_TAIL.load(Ordering::Acquire)) >= RX_SIZE {
        RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RX_BUF[head % RX_SIZE].store(b, Ordering::Relaxed);
    RX_HEAD.store(head.wrapping_add(1), Ordering::Release);
}

/// The next received byte, if any (the CLI, thread context).
pub fn read_byte() -> Option<u8> {
    let tail = RX_TAIL.load(Ordering::Relaxed);
    if tail == RX_HEAD.load(Ordering::Acquire) {
        return None;
    }
    let b = RX_BUF[tail % RX_SIZE].load(Ordering::Relaxed);
    RX_TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(b)
}

/// Received bytes not read yet.
pub fn rx_pending() -> bool {
    RX_TAIL.load(Ordering::Relaxed) != RX_HEAD.load(Ordering::Acquire)
}

/// Bytes lost to a full ring (or a hardware FIFO overrun seen by the backend).
pub fn rx_dropped() -> u64 {
    RX_DROPPED.load(Ordering::Relaxed)
}

/// The backend saw a FIFO overrun (IRQ-safe).
pub fn rx_overrun() {
    RX_DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Drain the hardware FIFO from thread context: the fallback without an
/// RX interrupt (and a safety net with one). Returns the bytes taken.
pub fn poll_rx() -> usize {
    crate::arch::console::rx_drain_thread(rx_push) + crate::arch::kbd::drain_thread(rx_push)
}

/// Is the RX interrupt in use?
pub fn rx_irq() -> bool {
    RX_IRQ.load(Ordering::Relaxed)
}

/// Signalled when bytes arrive through the RX interrupt (the CLI's task
/// waits on it).
pub fn rx_event() -> Option<&'static crate::irq::IrqEvent> {
    RX_EVENT.get().copied()
}

fn rx_irq_action(_intid: u32) {
    crate::arch::console::rx_drain_irq(rx_push);
}

fn kbd_irq_action(_intid: u32) {
    crate::arch::kbd::drain_irq(rx_push);
}

/// The screen's keyboard (after [`init_rx`]): typed bytes go into the
/// receive ring, its interrupt signals the same event. Boot argument
/// `kbd=0` leaves the controller alone.
pub fn init_kbd(info: &crate::platform::BootInfo) {
    if crate::config::kbd_off() {
        crate::println!("  keyboard        : off (kbd=0)");
        return;
    }
    if !crate::arch::kbd::init() {
        return; // no controller (aarch64, the apu4): nothing to say
    }
    let Some((intid, trigger)) = crate::arch::kbd::irq_setup(info) else {
        crate::println!("  keyboard        : PS/2, polled (no interrupt)");
        return;
    };
    let ev = *RX_EVENT.call_once(crate::irq::new_event);
    crate::irq::register(intid, kbd_irq_action, ev);
    crate::arch::irqchip::enable(intid, trigger);
    crate::arch::kbd::irq_enable();
    crate::println!("  keyboard        : PS/2, interrupt {intid} (US layout, into the CLI)");
}

/// Route the UART's receive interrupt (after `irqchip::init`), if the
/// platform describes one.
pub fn init_rx(info: &crate::platform::BootInfo) {
    let Some((intid, trigger)) = crate::arch::console::rx_irq_setup(info) else {
        crate::println!("  console rx      : polled (no interrupt)");
        return;
    };
    let ev = crate::irq::new_event();
    RX_EVENT.call_once(|| ev);
    crate::irq::register(intid, rx_irq_action, ev);
    crate::arch::irqchip::enable(intid, trigger);
    crate::arch::console::rx_irq_enable();
    RX_IRQ.store(true, Ordering::Relaxed);
    crate::println!("  console rx      : interrupt {intid}, {RX_SIZE}-byte ring");
}
