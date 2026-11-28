//! PS/2 keyboard scan codes to the bytes a serial terminal would send, so
//! the console's CLI reads the screen's keyboard (a Proxmox VM's noVNC
//! console, the QEMU window) like the serial port: `kernel/src/arch/
//! x86_64/kbd.rs` reads the i8042 and feeds [`Keyboard::feed`].
//!
//! Scan code set 1: what the i8042 delivers with translation on (the
//! BIOS's setting, kept by the driver). US layout. Shift, Caps Lock and
//! Ctrl (Ctrl + letter = the control byte: Ctrl-C, Ctrl-U); Enter = `\r`,
//! Backspace = DEL (0x7f), Tab, Esc; arrows, Home, End, Delete as VT100
//! escape sequences; the keypad as with Num Lock on. Alt, the Windows keys,
//! function keys, Pause and Print Screen send nothing.
//!
//! Sans-IO: bytes in, bytes out through a callback; no allocation, no
//! unsafe. The state is a few flags, so a `Keyboard` can live in a static.

#![no_std]
#![forbid(unsafe_code)]

/// Prefix of the extended (grey) keys.
const EXT: u8 = 0xe0;
/// Prefix of Pause: five more bytes follow (`E1 1D 45 E1 9D C5`).
const PAUSE: u8 = 0xe1;
const BREAK: u8 = 0x80;

const LSHIFT: u8 = 0x2a;
const RSHIFT: u8 = 0x36;
const CTRL: u8 = 0x1d;
const CAPS: u8 = 0x3a;

/// Set 1 make codes 0x00..0x3a, US layout: (plain, shifted); 0 = nothing.
const KEYS: [(u8, u8); 0x3a] = {
    let mut t = [(0u8, 0u8); 0x3a];
    t[0x01] = (0x1b, 0x1b);
    let row1 = b"1234567890-=";
    let row1s = b"!@#$%^&*()_+";
    let mut i = 0;
    while i < row1.len() {
        t[0x02 + i] = (row1[i], row1s[i]);
        i += 1;
    }
    t[0x0e] = (0x7f, 0x7f);
    t[0x0f] = (b'\t', b'\t');
    let row2 = b"qwertyuiop[]";
    let row2s = b"QWERTYUIOP{}";
    i = 0;
    while i < row2.len() {
        t[0x10 + i] = (row2[i], row2s[i]);
        i += 1;
    }
    t[0x1c] = (b'\r', b'\r');
    let row3 = b"asdfghjkl;'`";
    let row3s = b"ASDFGHJKL:\"~";
    i = 0;
    while i < row3.len() {
        t[0x1e + i] = (row3[i], row3s[i]);
        i += 1;
    }
    t[0x2b] = (b'\\', b'|');
    let row4 = b"zxcvbnm,./";
    let row4s = b"ZXCVBNM<>?";
    i = 0;
    while i < row4.len() {
        t[0x2c + i] = (row4[i], row4s[i]);
        i += 1;
    }
    t[0x37] = (b'*', b'*'); // keypad
    t[0x39] = (b' ', b' ');
    t
};

/// Keypad 0x47..=0x53 with Num Lock on.
const KEYPAD: &[u8; 13] = b"789-456+1230.";

#[derive(Clone, Copy, Debug, Default)]
pub struct Keyboard {
    lshift: bool,
    rshift: bool,
    lctrl: bool,
    rctrl: bool,
    caps: bool,
    /// The previous byte was [`EXT`].
    ext: bool,
    /// Bytes of a Pause sequence still to skip.
    skip: u8,
}

impl Keyboard {
    pub const fn new() -> Self {
        Self {
            lshift: false,
            rshift: false,
            lctrl: false,
            rctrl: false,
            caps: false,
            ext: false,
            skip: 0,
        }
    }

    /// Caps Lock is on (for the keyboard's LED, if a driver sets it).
    pub fn caps_lock(&self) -> bool {
        self.caps
    }

    /// One byte from the keyboard; `emit` gets the bytes it types.
    pub fn feed(&mut self, code: u8, mut emit: impl FnMut(u8)) {
        if self.skip > 0 {
            self.skip -= 1;
            return;
        }
        match code {
            EXT => {
                self.ext = true;
                return;
            }
            PAUSE => {
                self.skip = 5;
                self.ext = false;
                return;
            }
            // Controller and keyboard replies (ACK, resend, errors), not keys.
            0x00 | 0xfa | 0xfe | 0xff => {
                self.ext = false;
                return;
            }
            _ => {}
        }
        let ext = core::mem::replace(&mut self.ext, false);
        let make = code & BREAK == 0;
        let key = code & !BREAK;
        if ext {
            self.extended(key, make, &mut emit);
            return;
        }
        match key {
            LSHIFT => self.lshift = make,
            RSHIFT => self.rshift = make,
            CTRL => self.lctrl = make,
            CAPS if make => self.caps = !self.caps,
            0x47..=0x53 if make => emit(KEYPAD[usize::from(key - 0x47)]),
            _ if make && usize::from(key) < KEYS.len() => self.typed(key, &mut emit),
            _ => {}
        }
    }

    fn typed(&self, key: u8, emit: &mut impl FnMut(u8)) {
        let (plain, shifted) = KEYS[usize::from(key)];
        if plain == 0 {
            return;
        }
        let shift = self.lshift || self.rshift;
        let letter = plain.is_ascii_lowercase();
        let upper = if letter { shift != self.caps } else { shift };
        let b = if upper { shifted } else { plain };
        if (self.lctrl || self.rctrl) && letter {
            emit(plain & 0x1f);
        } else {
            emit(b);
        }
    }

    fn extended(&mut self, key: u8, make: bool, emit: &mut impl FnMut(u8)) {
        let seq: &[u8] = match key {
            CTRL => {
                self.rctrl = make;
                return;
            }
            _ if !make => return,
            0x1c => b"\r",  // keypad Enter
            0x35 => b"/",   // keypad /
            0x48 => b"\x1b[A",
            0x50 => b"\x1b[B",
            0x4d => b"\x1b[C",
            0x4b => b"\x1b[D",
            0x47 => b"\x1b[H",
            0x4f => b"\x1b[F",
            0x53 => b"\x1b[3~",
            _ => return, // fake shifts (Print Screen), Windows keys, media keys
        };
        for &b in seq {
            emit(b);
        }
    }
}

#[cfg(test)]
mod tests;
