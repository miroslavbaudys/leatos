//! The kernel's entropy pool (`auth::Pool`) for password salts and
//! session tokens. Everything mixed in goes through SHA-256: the timer at
//! boot and at every call, the boot arguments, the NICs' MAC addresses,
//! the arrival times of management requests, and, where there is one, a
//! hardware RNG: the AMD CCP's TRNG on the apu4 (`drivers::ccp`), 64
//! health-checked words at boot and 4 more at every use. It is only ever
//! one input: a failing hardware source makes the pool no weaker than the
//! timing sources alone. Without one (QEMU), this is best effort.

use crate::drivers::ccp::CcpTrng;
use spin::Mutex;

static POOL: Mutex<Option<auth::Pool>> = Mutex::new(None);
static HW: Mutex<Option<CcpTrng>> = Mutex::new(None);

/// Words of hardware randomness mixed in per use.
const WORDS_PER_USE: usize = 4;

/// A hardware source (after its startup test): mix in what it gave and
/// keep it for later uses.
pub fn add_hardware(mut t: CcpTrng) {
    let mut buf = alloc::vec::Vec::new();
    for _ in 0..64 {
        match t.read() {
            Some(v) => buf.extend_from_slice(&v.to_le_bytes()),
            None => break,
        }
    }
    mix(&buf);
    crate::println!("  entropy         : {}", describe(Some(&t)));
    *HW.lock() = Some(t);
}

fn describe(t: Option<&CcpTrng>) -> alloc::string::String {
    match t {
        None => "timing and boot data only (no hardware RNG)".into(),
        Some(t) => match t.failure() {
            None => alloc::format!("AMD CCP TRNG, {} checked words, plus timing", t.words()),
            Some(why) => alloc::format!("AMD CCP TRNG switched off ({why}); timing only"),
        },
    }
}

/// The sources (status page).
pub fn status() -> alloc::string::String {
    describe(HW.lock().as_ref())
}

fn stir(pool: &mut auth::Pool, data: &[u8]) {
    pool.mix(&crate::timer::ticks().to_le_bytes());
    pool.mix(data);
}

/// Mix `data` (and the current time) into the pool.
pub fn mix(data: &[u8]) {
    let mut g = POOL.lock();
    let p = g.get_or_insert_with(|| auth::Pool::new(b"rrouter entropy"));
    stir(p, data);
}

/// Use the pool (salts, tokens); the time, and fresh hardware words if
/// there is a healthy source, are mixed in first.
pub fn with<R>(f: impl FnOnce(&mut auth::Pool) -> R) -> R {
    let mut fresh = [0u8; 4 * WORDS_PER_USE];
    let mut n = 0;
    if let Some(t) = HW.lock().as_mut() {
        for chunk in fresh.chunks_mut(4) {
            match t.read() {
                Some(v) => {
                    chunk.copy_from_slice(&v.to_le_bytes());
                    n += 4;
                }
                None => break,
            }
        }
    }
    let mut g = POOL.lock();
    let p = g.get_or_insert_with(|| auth::Pool::new(b"rrouter entropy"));
    stir(p, b"use");
    p.mix(&fresh[..n]);
    f(p)
}
