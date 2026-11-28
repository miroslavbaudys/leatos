extern crate std;

use super::*;
use std::vec::Vec;

/// Make + break for each code.
fn tap(codes: &[u8]) -> Vec<u8> {
    let mut seq = Vec::new();
    for &c in codes {
        seq.push(c);
        seq.push(c | BREAK);
    }
    seq
}

fn typed(k: &mut Keyboard, seq: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in seq {
        k.feed(b, |x| out.push(x));
    }
    out
}

fn run(seq: &[u8]) -> Vec<u8> {
    typed(&mut Keyboard::new(), seq)
}

// Set 1 make codes of a few keys.
const S: u8 = 0x1f;
const T: u8 = 0x14;
const A: u8 = 0x1e;
const U: u8 = 0x16;
const C: u8 = 0x2e;
const ONE: u8 = 0x02;
const ENTER: u8 = 0x1c;
const BACKSPACE: u8 = 0x0e;
const SPACE: u8 = 0x39;
const SLASH: u8 = 0x35;

#[test]
fn letters_digits_enter() {
    let seq = tap(&[S, T, A, T, U, S, SPACE, ONE, ENTER]);
    assert_eq!(run(&seq), b"status 1\r");
    assert_eq!(run(&tap(&[BACKSPACE, 0x0f, 0x01])), b"\x7f\t\x1b");
}

#[test]
fn shift_and_caps_lock() {
    // Shift held over 's' and '1', released before 't'.
    let mut seq = Vec::from([LSHIFT]);
    seq.extend(tap(&[S, ONE, SLASH]));
    seq.push(LSHIFT | BREAK);
    seq.extend(tap(&[T]));
    assert_eq!(run(&seq), b"S!?t");
    // Right shift too.
    let mut seq = Vec::from([RSHIFT]);
    seq.extend(tap(&[A]));
    seq.push(RSHIFT | BREAK);
    assert_eq!(run(&seq), b"A");
    // Caps Lock: letters only; with Shift lower case again.
    let mut k = Keyboard::new();
    assert_eq!(typed(&mut k, &tap(&[CAPS, A, ONE])), b"A1");
    assert!(k.caps_lock());
    let mut seq = Vec::from([LSHIFT]);
    seq.extend(tap(&[A, ONE]));
    seq.push(LSHIFT | BREAK);
    assert_eq!(typed(&mut k, &seq), b"a!");
    assert_eq!(typed(&mut k, &tap(&[CAPS, A])), b"a", "Caps Lock toggles off");
}

#[test]
fn ctrl_letters() {
    let mut seq = Vec::from([CTRL]);
    seq.extend(tap(&[C, U]));
    seq.push(CTRL | BREAK);
    seq.extend(tap(&[C]));
    assert_eq!(run(&seq), b"\x03\x15c");
    // Right Ctrl (E0 1D), with Caps Lock on.
    let mut seq = tap(&[CAPS]);
    seq.extend([EXT, CTRL]);
    seq.extend(tap(&[C]));
    seq.extend([EXT, CTRL | BREAK]);
    seq.extend(tap(&[C]));
    assert_eq!(run(&seq), b"\x03C");
}

#[test]
fn extended_keys() {
    let ext = |k: u8| [EXT, k, EXT, k | BREAK];
    let mut seq = Vec::new();
    for k in [0x48, 0x50, 0x4d, 0x4b, 0x47, 0x4f, 0x53, 0x1c, 0x35] {
        seq.extend(ext(k));
    }
    assert_eq!(run(&seq), b"\x1b[A\x1b[B\x1b[C\x1b[D\x1b[H\x1b[F\x1b[3~\r/");
    // Print Screen's fake shift (E0 2A) must not leave Shift held.
    let mut seq = Vec::from([EXT, LSHIFT, EXT, 0x37, EXT, 0xb7, EXT, LSHIFT | BREAK]);
    seq.extend(tap(&[A]));
    assert_eq!(run(&seq), b"a");
}

#[test]
fn keypad_with_num_lock() {
    let seq = tap(&[0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x37]);
    assert_eq!(run(&seq), b"789-456+1230.*");
}

#[test]
fn pause_replies_and_unknown_codes() {
    let mut seq = Vec::from([0xe1, 0x1d, 0x45, 0xe1, 0x9d, 0xc5]);
    seq.extend([0xfa, 0xfe, 0x00, 0xff]); // ACK, resend, errors
    seq.extend(tap(&[0x3b, 0x58, 0x38, 0x45])); // F1, F12, Alt, Num Lock
    seq.extend(tap(&[A]));
    assert_eq!(run(&seq), b"a");
    // Breaks of keys never pressed type nothing.
    assert_eq!(run(&[A | BREAK, 0xff]), b"");
}

#[test]
fn every_byte_is_safe() {
    let mut k = Keyboard::new();
    let mut n = 0;
    for b in 0..=255u8 {
        k.feed(b, |_| n += 1);
        k.feed(EXT, |_| n += 1);
        k.feed(b, |_| n += 1);
    }
    assert!(n < 256 * 4);
}
