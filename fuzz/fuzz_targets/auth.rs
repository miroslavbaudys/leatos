//! `crates/auth` on what reaches it from outside: hash strings (a stored
//! `mgmt.password_hash`, checked on load), session tokens (any client's
//! `Authorization: Bearer`), the login throttle under arbitrary sources and
//! times. PBKDF2 itself only with small iteration counts (the cost is the
//! point). Checks: sessions stay within their cap and only tokens handed
//! out are accepted; a throttled source waits at most MAX_BLOCK_MS; the
//! throttle tracks at most its sources; the hash budget never exceeds its
//! rate.
#![no_main]

use arbitrary::Arbitrary;
use auth::{Pool, Sessions, Throttle, is_hash, source_key, verify};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Create,
    Check(String),
    CheckIssued(u8),
    Remove(u8),
    Fail(u8, u16),
    Succeed(u8),
    Gate(u8, u16),
    Budget(u16),
}

#[derive(Arbitrary, Debug)]
struct Input {
    hash: String,
    password: String,
    ip: [u8; 16],
    ops: Vec<Op>,
}

fuzz_target!(|i: Input| {
    if is_hash(&i.hash) {
        // Only cheap ones: `<prefix>$<iterations>$...` up to 64.
        let cheap = i.hash.split('$').nth(1).and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n <= 64);
        if cheap {
            let _ = verify(&i.password, &i.hash);
        }
    }
    let _ = source_key(core::net::IpAddr::from(i.ip));
    let _ = source_key(core::net::IpAddr::from([i.ip[0], i.ip[1], i.ip[2], i.ip[3]]));
    let mut pool = Pool::new(b"fuzz");
    let mut s = Sessions::new(4, 1000);
    let mut t = Throttle::new(8, 4);
    let mut issued: Vec<String> = Vec::new();
    let (mut now, mut granted) = (0u64, 0u64);
    for op in i.ops.into_iter().take(512) {
        match op {
            Op::Create => issued.push(s.create(&mut pool, now)),
            Op::Check(tok) => {
                if s.check(&tok, now) {
                    assert!(issued.iter().any(|x| x.eq_ignore_ascii_case(&tok)), "accepted a token never issued");
                }
            }
            Op::CheckIssued(k) => {
                if let Some(tok) = issued.get(usize::from(k) % issued.len().max(1)) {
                    let _ = s.check(tok, now);
                }
            }
            Op::Remove(k) => {
                if let Some(tok) = issued.get(usize::from(k) % issued.len().max(1)) {
                    s.remove(tok);
                    assert!(!s.check(tok, now), "removed token still accepted");
                }
            }
            Op::Fail(k, dt) => {
                now += u64::from(dt);
                t.failed(u128::from(k), now);
            }
            Op::Succeed(k) => {
                t.succeeded(u128::from(k));
                assert_eq!(t.check(u128::from(k), now), Ok(()));
            }
            Op::Gate(k, dt) => {
                now += u64::from(dt);
                if let Err(wait) = t.check(u128::from(k), now) {
                    assert!(wait <= Throttle::MAX_BLOCK_MS);
                }
            }
            Op::Budget(dt) => {
                now += u64::from(dt);
                if t.take_hash_check(now) {
                    granted += 1;
                }
                // At most the burst (4) plus 4 per second since the start.
                assert!(granted <= 4 + now * 4 / 1000 + 1, "budget exceeded");
            }
        }
        assert!(s.len() <= 4);
        assert!(t.tracked() <= 8);
    }
});
