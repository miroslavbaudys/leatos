//! The kernel's entropy pool (`auth::Pool`) for password salts and
//! session tokens. Everything mixed in goes through SHA-256: the timer at
//! boot and at every call, the boot arguments, the NICs' MAC addresses,
//! and the arrival times of management requests. There is no hardware RNG
//! in use: the apu4's AMD CCP TRNG is disabled by its firmware (no AMD PSP
//! firmware in PC Engines coreboot, queue mask 0), and Jaguar's RDRAND is
//! not trusted (family 15h/16h RNGs have returned constants). So this is
//! best effort (timing jitter at nanosecond resolution), not a seeded
//! CSPRNG.

use spin::Mutex;

static POOL: Mutex<Option<auth::Pool>> = Mutex::new(None);

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

/// Use the pool (salts, tokens); the time is mixed in first.
pub fn with<R>(f: impl FnOnce(&mut auth::Pool) -> R) -> R {
    let mut g = POOL.lock();
    let p = g.get_or_insert_with(|| auth::Pool::new(b"rrouter entropy"));
    stir(p, b"use");
    f(p)
}

/// The sources (status page).
pub fn status() -> &'static str {
    "timing and boot data only (no hardware RNG)"
}
