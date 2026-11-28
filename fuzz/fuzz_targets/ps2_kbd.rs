//! The PS/2 keyboard decoder (`crates/ps2-kbd`): any bytes from the
//! controller (a VM's emulated keyboard, or a confused one). Checks: at
//! most four bytes typed per scan code (the longest key is Delete,
//! `ESC [ 3 ~`), only ASCII; after all keys are released (every make code
//! followed by its break, outside a Pause sequence) no modifier is left
//! held: a plain letter types lower case.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ps2_kbd::Keyboard;

fuzz_target!(|data: &[u8]| {
    let mut k = Keyboard::new();
    for &b in data.iter().take(4096) {
        let mut n = 0;
        k.feed(b, |x| {
            assert!(x.is_ascii(), "non-ASCII {x:#x} from {b:#x}");
            n += 1;
        });
        assert!(n <= 4, "{n} bytes from {b:#x}");
    }
    // Release every modifier (left/right Shift, Ctrl, right Ctrl), end any
    // prefix or Pause sequence, then type 'a' (0x1e) twice.
    let caps = k.caps_lock();
    let mut out = Vec::new();
    for b in [0, 0, 0, 0, 0, 0xaa, 0xb6, 0x9d, 0xe0, 0x9d, 0x1e, 0x9e, 0x1e, 0x9e] {
        k.feed(b, |x| out.push(x));
    }
    let a = if caps { b'A' } else { b'a' };
    assert_eq!(out.last(), Some(&a), "modifier stuck: {out:?}");
});
