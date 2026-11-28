extern crate std;

use super::*;
use std::string::String;

fn row(s: &Screen, r: usize) -> String {
    let t: String = (0..s.cols()).map(|c| s.char_at(r, c) as char).collect();
    String::from(t.trim_end())
}

fn screen(bytes: &[u8]) -> Screen {
    let mut s = Screen::new();
    s.write(bytes);
    s
}

#[test]
fn lines_and_cursor() {
    let s = screen(b"leatos 0.1\n  cpus : 1\n> ");
    assert_eq!(row(&s, 0), "leatos 0.1");
    assert_eq!(row(&s, 1), "  cpus : 1");
    assert_eq!(row(&s, 2), ">");
    assert_eq!(s.cursor(), 2 * COLS + 2);
    assert_eq!(s.cells()[0], 0x0700 | u16::from(b'l'));
}

#[test]
fn crlf_is_one_newline() {
    let s = screen(b"a\r\nb\n");
    assert_eq!(row(&s, 0), "a");
    assert_eq!(row(&s, 1), "b");
    assert_eq!(s.cursor(), 2 * COLS);
}

#[test]
fn wrap_is_deferred() {
    let full = [b'x'; COLS];
    let mut s = screen(&full);
    assert_eq!(s.cursor(), COLS - 1, "cursor stays on the last column");
    s.write(b"\nnext");
    assert_eq!(row(&s, 1), "next", "80 characters + newline = one line");
    let s = screen(&[b'y'; COLS + 3]);
    assert_eq!(row(&s, 1), "yyy");
}

#[test]
fn scrolls_at_the_bottom() {
    let mut s = Screen::new();
    for i in 0..ROWS + 2 {
        s.write(std::format!("line {i}\n").as_bytes());
    }
    assert_eq!(row(&s, 0), "line 3");
    assert_eq!(row(&s, ROWS - 2), std::format!("line {}", ROWS + 1));
    assert_eq!(row(&s, ROWS - 1), "");
    assert_eq!(s.cursor(), (ROWS - 1) * COLS);
    assert_eq!(s.take_dirty(), Some(0..COLS * ROWS));
}

#[test]
fn erase_line_redraws_the_prompt() {
    // console.rs: a log line arriving while the CLI shows "leatos> sta".
    let mut s = screen(b"leatos> sta");
    s.write(b"\r\x1b[Klog message\nleatos> sta");
    assert_eq!(row(&s, 0), "log message");
    assert_eq!(row(&s, 1), "leatos> sta");
    // Erasing after shorter text leaves nothing of the longer one.
    let s = screen(b"abcdef\r\x1b[Kab");
    assert_eq!(row(&s, 0), "ab");
    // ESC [ 2 K or other sequences are swallowed, not printed.
    let s = screen(b"x\x1b[2Ky\x1b[1;32mz\x1bcq");
    assert_eq!(row(&s, 0), "xyzq");
}

#[test]
fn escape_split_across_writes() {
    let mut s = screen(b"abc\r\x1b");
    s.write(b"[");
    s.write(b"K");
    s.write(b"d");
    assert_eq!(row(&s, 0), "d");
}

#[test]
fn backspace_and_tab() {
    // The CLI editor echoes BS SP BS for a deleted character.
    let s = screen(b"stax\x08 \x08tus");
    assert_eq!(row(&s, 0), "status");
    let s = screen(b"a\tb");
    assert_eq!(row(&s, 0), "a       b");
    let s = screen(b"\x08\x08x");
    assert_eq!(row(&s, 0), "x");
}

#[test]
fn utf8_to_cp437() {
    let s = screen("a — b → 5 µs 3°C…".as_bytes());
    let r: std::vec::Vec<u8> = (0..17).map(|c| s.char_at(0, c)).collect();
    assert_eq!(r, b"a - b \x1a 5 \xe6s 3\xf8C.");
    // Unknown characters, stray continuation bytes and cut sequences: '?'.
    let s = screen("€".as_bytes());
    assert_eq!(row(&s, 0), "?");
    let s = screen(b"\x80\xe2\x82z");
    assert_eq!(row(&s, 0), "??z");
}

#[test]
fn dirty_ranges() {
    let mut s = Screen::new();
    assert_eq!(s.take_dirty(), None);
    s.write(b"\nab");
    assert_eq!(s.take_dirty(), Some(COLS..COLS + 2));
    assert_eq!(s.take_dirty(), None);
    s.write(b"\r\x1b[K");
    assert_eq!(s.take_dirty(), Some(COLS..2 * COLS));
    s.write(b"\r\n");
    assert_eq!(s.take_dirty(), None, "cursor moves change no cell");
    s.mark_all_dirty();
    assert_eq!(s.take_dirty(), Some(0..COLS * ROWS));
}

#[test]
fn other_controls_ignored() {
    let s = screen(b"a\x00\x07\x7fb");
    assert_eq!(row(&s, 0), "ab");
}

#[test]
fn resize_keeps_text_and_scrolls_at_the_new_size() {
    let mut s = screen(b"first\nsecond\nthird");
    s.resize(182, 50);
    assert_eq!((s.cols(), s.rows(), s.cells().len()), (182, 50, 182 * 50));
    assert_eq!(row(&s, 0), "first");
    assert_eq!(row(&s, 2), "third");
    assert_eq!(s.cursor(), 2 * 182 + 5);
    assert_eq!(s.take_dirty(), Some(0..182 * 50));
    s.write(&[b'x'; 200]);
    assert_eq!(row(&s, 3).len(), 5 + 200 - 182, "wraps at 182");
    for _ in 0..60 {
        s.write(b"\n");
    }
    assert_eq!(s.cursor(), 49 * 182);
    // Fewer rows: the last ones (up to the cursor's) stay.
    let mut s = screen(b"a\nb\nc\nd");
    s.resize(80, 2);
    assert_eq!((row(&s, 0), row(&s, 1)), ("c".into(), "d".into()));
    assert_eq!(s.cursor(), 80 + 1);
    // Clamped to the storage.
    s.resize(100_000, 100_000);
    assert!(s.cells().len() <= MAX_CELLS);
    s.resize(0, 0);
    assert_eq!((s.cols(), s.rows()), (8, 1));
    s.write(b"0123456789");
    assert_eq!(row(&s, 0), "789", "\"d0123456\" scrolled away");
}
