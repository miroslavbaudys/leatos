//! A small line editor for a serial terminal (VT100: `screen`, `minicom`,
//! QEMU's stdio): echo, backspace, Ctrl-U, Ctrl-C, Up/Down history.
//! Editing happens at the end of the line only (no cursor movement).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

/// Longest line kept; further input is refused with a bell.
pub const MAX_LINE: usize = 1024;
const HISTORY: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Bytes to write back to the terminal.
    Echo(Vec<u8>),
    /// A finished line (Enter), without the line ending.
    Line(String),
    /// Ctrl-C: the line was dropped.
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Esc {
    None,
    /// Got ESC.
    Start,
    /// Got `ESC [` (CSI): parameters until a final byte.
    Csi,
}

pub struct LineEditor {
    line: String,
    esc: Esc,
    /// The previous byte was `\r` (a following `\n` is the same Enter).
    after_cr: bool,
    history: VecDeque<String>,
    /// Position while browsing the history (`None` = the new line).
    browse: Option<usize>,
    /// The line being typed before browsing started.
    draft: String,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

impl LineEditor {
    pub fn new() -> Self {
        LineEditor {
            line: String::new(),
            esc: Esc::None,
            after_cr: false,
            history: VecDeque::new(),
            browse: None,
            draft: String::new(),
        }
    }

    /// The line typed so far (to redraw it after other output).
    pub fn current(&self) -> &str {
        &self.line
    }

    /// Feed received bytes.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Output> {
        let mut out = Vec::new();
        let mut echo = Vec::new();
        for &b in bytes {
            let after_cr = core::mem::replace(&mut self.after_cr, false);
            match self.esc {
                Esc::Start => {
                    self.esc = if b == b'[' || b == b'O' { Esc::Csi } else { Esc::None };
                    continue;
                }
                Esc::Csi => {
                    if (0x40..=0x7e).contains(&b) {
                        self.esc = Esc::None;
                        match b {
                            b'A' => self.history_step(true, &mut echo),
                            b'B' => self.history_step(false, &mut echo),
                            _ => {} // other keys: ignored
                        }
                    }
                    continue;
                }
                Esc::None => {}
            }
            match b {
                0x1b => self.esc = Esc::Start,
                b'\n' if after_cr => {}
                b'\r' | b'\n' => {
                    self.after_cr = b == b'\r';
                    echo.extend_from_slice(b"\r\n");
                    out.push(Output::Echo(core::mem::take(&mut echo)));
                    let line = core::mem::take(&mut self.line);
                    self.browse = None;
                    if !line.trim().is_empty() && self.history.back() != Some(&line) {
                        if self.history.len() == HISTORY {
                            self.history.pop_front();
                        }
                        self.history.push_back(line.clone());
                    }
                    out.push(Output::Line(line));
                }
                0x7f | 0x08 => {
                    if self.line.pop().is_some() {
                        echo.extend_from_slice(b"\x08 \x08");
                    }
                }
                0x15 => self.erase_line(&mut echo), // Ctrl-U
                0x03 => {
                    // Ctrl-C
                    self.line.clear();
                    self.browse = None;
                    echo.extend_from_slice(b"^C\r\n");
                    out.push(Output::Echo(core::mem::take(&mut echo)));
                    out.push(Output::Cancel);
                }
                0x20..=0x7e => {
                    if self.line.len() < MAX_LINE {
                        self.line.push(b as char);
                        echo.push(b);
                    } else {
                        echo.push(0x07); // bell
                    }
                }
                _ => {} // other control bytes and non-ASCII: ignored
            }
        }
        if !echo.is_empty() {
            out.push(Output::Echo(echo));
        }
        out
    }

    fn erase_line(&mut self, echo: &mut Vec<u8>) {
        for _ in 0..self.line.len() {
            echo.extend_from_slice(b"\x08 \x08");
        }
        self.line.clear();
    }

    fn history_step(&mut self, up: bool, echo: &mut Vec<u8>) {
        let n = self.history.len();
        let next = match (self.browse, up) {
            (None, true) if n > 0 => Some(n - 1),
            (Some(i), true) => Some(i.saturating_sub(1)),
            (Some(i), false) if i + 1 < n => Some(i + 1),
            (Some(_), false) => None,
            (None, _) => return,
        };
        if self.browse.is_none() {
            self.draft = self.line.clone();
        }
        self.browse = next;
        self.erase_line(echo);
        self.line = match next {
            Some(i) => self.history[i].clone(),
            None => core::mem::take(&mut self.draft),
        };
        echo.extend_from_slice(self.line.as_bytes());
    }
}
