//! PS/2 keyboard on the i8042 controller (ports 0x60 / 0x64, ISA IRQ 1):
//! the screen's keyboard (a Proxmox VM's noVNC console, the QEMU window).
//! Scan codes (set 1: the controller's translation stays on, as the BIOS
//! left it) go through `ps2_kbd::Keyboard` into `crate::console`'s receive
//! ring, so the CLI reads them like serial input.
//!
//! Like the UART's receive side: the interrupt drains the controller
//! (reading the data port is the acknowledgement), thread context drains
//! with IRQs masked (the CLI's poll), both under a lock only ever
//! `try_lock`ed. Mouse bytes (auxiliary port) are read and dropped; the
//! mouse port stays disabled.
//!
//! [`init`] finds no controller where port 0x64 reads 0xff (nothing
//! decodes it: the apu4) or where it does not answer a command; then
//! nothing else is ever written.

use super::port::{inb, outb};
use ps2_kbd::Keyboard;
use spin::Mutex;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;
const ST_OUTPUT_FULL: u8 = 1 << 0;
const ST_INPUT_FULL: u8 = 1 << 1;
const ST_AUX: u8 = 1 << 5;

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_AUX: u8 = 0xa7;
const CMD_DISABLE_KBD: u8 = 0xad;
const CMD_ENABLE_KBD: u8 = 0xae;

const CFG_KBD_IRQ: u8 = 1 << 0;
const CFG_AUX_IRQ: u8 = 1 << 1;
const CFG_KBD_CLOCK_OFF: u8 = 1 << 4;
const CFG_TRANSLATE: u8 = 1 << 6;

/// Polls of the status register before a command counts as unanswered.
const SPINS: usize = 100_000;

/// The decoder; taken only with `try_lock` (interrupt or thread context
/// with IRQs masked).
static KBD: Mutex<Keyboard> = Mutex::new(Keyboard::new());
static PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn wait_input_empty() -> bool {
    (0..SPINS).any(|_| inb(STATUS) & ST_INPUT_FULL == 0)
}

fn command(c: u8) -> bool {
    wait_input_empty() && {
        outb(COMMAND, c);
        true
    }
}

fn read_reply() -> Option<u8> {
    (0..SPINS).find(|_| inb(STATUS) & ST_OUTPUT_FULL != 0).map(|_| inb(DATA))
}

fn read_config() -> Option<u8> {
    command(CMD_READ_CONFIG).then(read_reply).flatten()
}

fn write_config(cfg: u8) -> bool {
    command(CMD_WRITE_CONFIG) && wait_input_empty() && {
        outb(DATA, cfg);
        true
    }
}

fn flush() {
    for _ in 0..64 {
        if inb(STATUS) & ST_OUTPUT_FULL == 0 {
            break;
        }
        inb(DATA);
    }
}

/// Find and set up the controller: keyboard port on, its interrupt still
/// off ([`irq_enable`]), mouse port off, translation on. `false`: none.
pub fn init() -> bool {
    if inb(STATUS) == 0xff {
        return false;
    }
    if !command(CMD_DISABLE_KBD) || !command(CMD_DISABLE_AUX) {
        return false;
    }
    flush();
    let Some(cfg) = read_config() else {
        return false;
    };
    let cfg = (cfg | CFG_TRANSLATE) & !(CFG_KBD_IRQ | CFG_AUX_IRQ | CFG_KBD_CLOCK_OFF);
    if !write_config(cfg) || !command(CMD_ENABLE_KBD) {
        return false;
    }
    flush();
    PRESENT.store(true, core::sync::atomic::Ordering::Relaxed);
    true
}

/// Route IRQ 1 through the IOAPIC, masked.
pub fn irq_setup(info: &crate::platform::BootInfo) -> Option<(u32, crate::irq::Trigger)> {
    super::irqchip::route_kbd(info)
}

/// Let the controller raise IRQ 1 for keyboard bytes.
pub fn irq_enable() {
    let was = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    // The decoder lock keeps drains away while the config is rewritten.
    if let Some(_g) = KBD.try_lock()
        && let Some(cfg) = read_config()
    {
        write_config(cfg | CFG_KBD_IRQ);
    }
    if was {
        super::cpu::irq_enable();
    }
}

/// No more keyboard interrupts (before entering another kernel).
pub(super) fn irq_off() {
    if PRESENT.load(core::sync::atomic::Ordering::Relaxed)
        && let Some(cfg) = read_config()
    {
        write_config(cfg & !CFG_KBD_IRQ);
    }
}

fn drain(push: fn(u8)) -> usize {
    if !PRESENT.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let Some(mut kbd) = KBD.try_lock() else { return 0 };
    let mut n = 0;
    // Bounded: a stuck status register cannot keep us here.
    for _ in 0..32 {
        let st = inb(STATUS);
        if st & ST_OUTPUT_FULL == 0 {
            break;
        }
        let b = inb(DATA);
        if st & ST_AUX == 0 {
            kbd.feed(b, |x| {
                push(x);
                n += 1;
            });
        }
    }
    n
}

/// IRQ 1: decode what the controller holds.
pub fn drain_irq(push: fn(u8)) {
    drain(push);
}

/// Thread context: the same with IRQs masked (the CLI's poll). Returns the
/// bytes typed.
pub fn drain_thread(push: fn(u8)) -> usize {
    let was = super::cpu::irqs_enabled();
    super::cpu::irq_disable();
    let n = drain(push);
    if was {
        super::cpu::irq_enable();
    }
    n
}
