//! CAKE's ACK filter decision (`qdisc::ack_filter::supersedes`) on
//! arbitrary bytes: never panics, an ACK never supersedes itself (equal
//! ACK numbers are duplicate ACKs, kept), and supersession is never
//! mutual (the newer must acknowledge strictly more).
#![no_main]

use libfuzzer_sys::fuzz_target;
use qdisc::ack_filter::supersedes;

fuzz_target!(|data: (Vec<u8>, Vec<u8>)| {
    let (a, b) = data;
    assert!(!supersedes(&a, &a), "an ACK superseded itself");
    if supersedes(&a, &b) {
        assert!(!supersedes(&b, &a), "mutual supersession");
    }
});
