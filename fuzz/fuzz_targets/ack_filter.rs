//! CAKE's ACK filter decision (`qdisc::ack_filter::supersedes`) on
//! arbitrary bytes, raw or behind a valid IPv4 or IPv6 header (so the TCP
//! option parsing is reached for both families): never panics, an ACK
//! never supersedes itself (equal ACK numbers are duplicate ACKs, kept),
//! and supersession is never mutual (the newer must acknowledge strictly
//! more).
#![no_main]

use libfuzzer_sys::fuzz_target;
use qdisc::ack_filter::{build_ack, supersedes, to_ipv6};

/// `tcp` (a TCP header + options) behind the helper's IPv4 or IPv6 header.
fn wrap(tcp: &[u8], v6: bool) -> Vec<u8> {
    let mut v4 = build_ack(5000, 1, 0x10, None, &[]);
    v4.truncate(20);
    v4.extend_from_slice(tcp);
    let total = v4.len() as u16;
    v4[2..4].copy_from_slice(&total.to_be_bytes());
    if v6 { to_ipv6(&v4) } else { v4 }
}

fuzz_target!(|data: (Vec<u8>, Vec<u8>, u8)| {
    let (a, b, mode) = data;
    let (a, b) = match mode % 3 {
        0 => (a, b),
        m => (wrap(&a, m == 2), wrap(&b, m == 2)),
    };
    assert!(!supersedes(&a, &a), "an ACK superseded itself");
    if supersedes(&a, &b) {
        assert!(!supersedes(&b, &a), "mutual supersession");
    }
});
