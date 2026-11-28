//! A text screen fed with the serial console's output: the kernel mirrors
//! its console onto the machine's screen (`kernel/src/drivers/screen.rs`;
//! the noVNC console of a Proxmox VM, docs/proxmox.md §8): VGA text mode
//! (80x25) or a linear framebuffer the boot loader set up, drawn with the
//! glyphs of [`glyph`] (182x50 at 1280x800).
//!
//! It understands what the console sends: printable text (UTF-8, shown in
//! code page 437 where a glyph exists, `?` otherwise), `\n` (a new line:
//! the kernel's console turns it into CR LF), `\r`, backspace, tab, and
//! `ESC [ K` (erase to the end of the line, used to redraw the CLI's input
//! line). Other escape sequences are swallowed. Lines wrap at the right
//! edge (deferred, as terminals do: a full line and a newline make one
//! line); the screen scrolls up at the bottom.
//!
//! Sans-IO: [`Screen::write`] updates the cells; the caller copies the
//! range [`Screen::take_dirty`] returns to video memory (or draws it) and
//! puts the cursor at [`Screen::cursor`]. Cells are VGA words: character
//! (code page 437) in the low byte, attribute (light grey on black) in the
//! high byte. The size is set at run time ([`Screen::resize`], up to
//! [`MAX_CELLS`]); storage is fixed.
//!
//! `#![no_std]`, no allocation (a `const` constructor, usable in a static
//! before the kernel has a heap), no unsafe.

#![no_std]
#![forbid(unsafe_code)]

use core::ops::Range;

pub mod glyph;

/// VGA text mode: the size a new [`Screen`] has.
pub const COLS: usize = 80;
pub const ROWS: usize = 25;
/// Storage: enough for 1920x1200 in 7x16 glyphs (274x75).
pub const MAX_CELLS: usize = 280 * 80;
/// Light grey on black.
pub const ATTR: u8 = 0x07;
pub const BLANK: u16 = cell(b' ');

const fn cell(ch: u8) -> u16 {
    (ATTR as u16) << 8 | ch as u16
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Esc {
    None,
    /// After ESC.
    Started,
    /// Inside `ESC [`, with the first parameter so far.
    Csi(u16),
}

#[derive(Clone)]
pub struct Screen {
    cells: [u16; MAX_CELLS],
    cols: usize,
    rows: usize,
    row: usize,
    /// 0..=cols; cols = a wrap is pending (the last column was written).
    col: usize,
    esc: Esc,
    /// UTF-8 decoding: the code point so far and continuation bytes still due.
    cp: u32,
    need: u8,
    dirty: Option<(usize, usize)>,
}

impl Default for Screen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen {
    /// A blank 80x25 screen, cursor at the top left.
    pub const fn new() -> Self {
        Self {
            cells: [BLANK; MAX_CELLS],
            cols: COLS,
            rows: ROWS,
            row: 0,
            col: 0,
            esc: Esc::None,
            cp: 0,
            need: 0,
            dirty: None,
        }
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// The cells, row by row (`cols * rows`).
    pub fn cells(&self) -> &[u16] {
        &self.cells[..self.cols * self.rows]
    }

    /// The character at (`row`, `col`) (tests, fuzzing).
    pub fn char_at(&self, row: usize, col: usize) -> u8 {
        self.cells[row * self.cols + col] as u8
    }

    /// The cell the cursor belongs on.
    pub fn cursor(&self) -> usize {
        self.row * self.cols + self.col.min(self.cols - 1)
    }

    /// Change the size (clamped to 1..=[`MAX_CELLS`] cells, at least 8
    /// columns). The text is kept where it fits, its last rows if fewer
    /// rows fit; every cell counts as changed.
    pub fn resize(&mut self, cols: usize, rows: usize) {
        let cols = cols.clamp(8, MAX_CELLS);
        let rows = rows.clamp(1, MAX_CELLS / cols);
        let old = self.cells;
        let (oc, or) = (self.cols, self.rows);
        // Rows in use: up to the cursor's.
        let used = (self.row + 1).min(or);
        let skip = used.saturating_sub(rows);
        self.cells = [BLANK; MAX_CELLS];
        for r in 0..used - skip {
            let n = oc.min(cols);
            let src = (r + skip) * oc;
            self.cells[r * cols..r * cols + n].copy_from_slice(&old[src..src + n]);
        }
        self.row -= skip;
        self.col = self.col.min(cols);
        (self.cols, self.rows) = (cols, rows);
        self.mark_all_dirty();
    }

    /// The cells changed since the last call (none: `None`).
    pub fn take_dirty(&mut self) -> Option<Range<usize>> {
        self.dirty.take().map(|(s, e)| s..e)
    }

    /// Every cell counts as changed (the first copy to video memory).
    pub fn mark_all_dirty(&mut self) {
        self.dirty = Some((0, self.cols * self.rows));
    }

    fn touch(&mut self, from: usize, to: usize) {
        self.dirty = Some(match self.dirty {
            Some((s, e)) => (s.min(from), e.max(to)),
            None => (from, to),
        });
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.byte(b);
        }
    }

    fn byte(&mut self, b: u8) {
        match self.esc {
            Esc::Started => {
                self.esc = if b == b'[' { Esc::Csi(0) } else { Esc::None };
                return;
            }
            Esc::Csi(arg) => {
                match b {
                    b'0'..=b'9' => {
                        let d = u16::from(b - b'0');
                        self.esc = Esc::Csi(arg.saturating_mul(10).saturating_add(d));
                    }
                    0x20..=0x3f => self.esc = Esc::Csi(u16::MAX), // other parameters
                    0x40..=0x7e => {
                        self.esc = Esc::None;
                        if b == b'K' && arg == 0 {
                            self.erase_to_eol();
                        }
                    }
                    _ => self.esc = Esc::None, // malformed: drop it
                }
                return;
            }
            Esc::None => {}
        }
        if self.need > 0 {
            if b & 0xc0 == 0x80 {
                self.cp = self.cp << 6 | u32::from(b & 0x3f);
                self.need -= 1;
                if self.need == 0 {
                    self.put(cp437(self.cp));
                }
                return;
            }
            self.need = 0;
            self.put(b'?');
        }
        match b {
            b'\n' => self.newline(),
            b'\r' => self.col = 0,
            0x08 => self.col = self.col.min(self.cols).saturating_sub(1),
            b'\t' => {
                let stop = ((self.col / 8) + 1) * 8;
                while self.col < stop.min(self.cols) {
                    self.put(b' ');
                }
            }
            0x1b => self.esc = Esc::Started,
            0x20..=0x7e => self.put(b),
            0xc2..=0xdf => (self.cp, self.need) = (u32::from(b & 0x1f), 1),
            0xe0..=0xef => (self.cp, self.need) = (u32::from(b & 0x0f), 2),
            0xf0..=0xf4 => (self.cp, self.need) = (u32::from(b & 0x07), 3),
            0x80..=0xff => self.put(b'?'),
            _ => {} // other control characters
        }
    }

    fn put(&mut self, ch: u8) {
        if self.col >= self.cols {
            self.newline();
        }
        let i = self.row * self.cols + self.col;
        self.cells[i] = cell(ch);
        self.touch(i, i + 1);
        self.col += 1;
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        let n = self.cols * self.rows;
        self.cells.copy_within(self.cols..n, 0);
        self.cells[n - self.cols..n].fill(BLANK);
        self.mark_all_dirty();
    }

    fn erase_to_eol(&mut self) {
        if self.col >= self.cols {
            return;
        }
        let (s, e) = (self.row * self.cols + self.col, (self.row + 1) * self.cols);
        self.cells[s..e].fill(BLANK);
        self.touch(s, e);
    }
}

/// Code page 437 for the characters the kernel prints; `?` for the rest.
fn cp437(cp: u32) -> u8 {
    match cp {
        0x20..=0x7e => cp as u8,
        0x2013 | 0x2014 | 0x2212 => b'-',
        0x2018 | 0x2019 => b'\'',
        0x201c | 0x201d => b'"',
        0x2026 => b'.',
        0x00d7 => b'x',
        0x2192 => 0x1a,
        0x2190 => 0x1b,
        0x2191 => 0x18,
        0x2193 => 0x19,
        0x00b5 | 0x03bc => 0xe6,
        0x00b0 => 0xf8,
        0x00b1 => 0xf1,
        0x00b7 => 0xfa,
        0x2265 => 0xf2,
        0x2264 => 0xf3,
        0x2248 => 0xf7,
        0x2713 | 0x221a => 0xfb,
        0x2500 => 0xc4,
        0x2502 => 0xb3,
        _ => b'?',
    }
}

#[cfg(test)]
mod tests;
