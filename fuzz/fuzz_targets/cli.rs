//! The serial CLI (`crates/cli`): the line editor fed arbitrary bytes
//! (escape sequences, CR/LF, history keys, Ctrl-C) whole and in
//! fuzzer-chosen pieces, and every finished line through the command
//! parser. Checks: lines and the edited line stay within `MAX_LINE`; the
//! whole and the split feeds give the same lines (no state lost at a
//! chunk boundary).
#![no_main]

use cli::{LineEditor, MAX_LINE, Output};
use libfuzzer_sys::fuzz_target;

fn feed<'a>(pieces: impl Iterator<Item = &'a [u8]>) -> Vec<String> {
    let mut ed = LineEditor::new();
    let mut lines = Vec::new();
    for p in pieces {
        for o in ed.feed(p) {
            if let Output::Line(l) = o {
                assert!(l.len() <= MAX_LINE, "line of {} bytes", l.len());
                let _ = cli::parse(&l);
                lines.push(l);
            }
        }
        assert!(ed.current().len() <= MAX_LINE);
    }
    lines
}

fuzz_target!(|input: (Vec<u8>, Vec<u8>)| {
    let (cuts, data) = input;
    let whole = feed(core::iter::once(&data[..]));
    let mut pieces = Vec::new();
    let mut rest = &data[..];
    for &c in &cuts {
        if rest.is_empty() {
            break;
        }
        let n = (c as usize % 16 + 1).min(rest.len());
        pieces.push(&rest[..n]);
        rest = &rest[n..];
    }
    pieces.push(rest);
    assert_eq!(whole, feed(pieces.into_iter()), "whole and split feeds disagree");
    if let Ok(s) = core::str::from_utf8(&data) {
        for line in s.lines() {
            let _ = cli::parse(line);
        }
    }
});
