//! Management authentication (docs/config-and-storage.md "Secrets"):
//!
//! - [`hash_password`] / [`verify`]: PBKDF2-HMAC-SHA256 hashes as one
//!   string, `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`, what
//!   `[mgmt] password_hash` holds. The cost is in the string, so it can
//!   be raised later without breaking stored hashes.
//! - [`Pool`]: an entropy pool (SHA-256 over everything mixed in) for
//!   salts and session tokens. The kernel mixes in what it has: boot
//!   time, MAC addresses, the arrival times of requests and packets in
//!   nanoseconds. There is no hardware RNG on the apu4's CPU, so this is
//!   best effort, not a CSPRNG seeded from a trusted source.
//! - [`Sessions`]: login tokens with an idle timeout, so the web page
//!   sends a token instead of the password, and PBKDF2 runs once per
//!   login instead of once per request.
//! - [`Cache`]: remembers the last password that verified (as an HMAC
//!   under a random key), so HTTP Basic clients (scripts) pay PBKDF2 only
//!   once.
//!
//! `#![no_std]` + `alloc`, sans-IO (the caller passes `now` and the
//! entropy), no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// PBKDF2 iterations for new hashes: about 0.1 s on the apu4 (1 GHz
/// Jaguar), once per login.
pub const ITERATIONS: u32 = 20_000;
const SALT: usize = 16;
const HASH: usize = 32;
const PREFIX: &str = "pbkdf2-sha256";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Equal without an early exit (no timing hint about where they differ).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn derive(password: &str, salt: &[u8], iterations: u32) -> [u8; HASH] {
    let mut out = [0u8; HASH];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out);
    out
}

/// A stored hash of `password` with a fresh salt from `pool`.
pub fn hash_password(password: &str, pool: &mut Pool, iterations: u32) -> String {
    let mut salt = [0u8; SALT];
    pool.fill(&mut salt);
    encode(password, &salt, iterations)
}

fn encode(password: &str, salt: &[u8], iterations: u32) -> String {
    format!(
        "{PREFIX}${iterations}${}${}",
        hex(salt),
        hex(&derive(password, salt, iterations))
    )
}

/// The parts of a stored hash, if it is well formed.
fn decode(encoded: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let mut it = encoded.split('$');
    if it.next()? != PREFIX {
        return None;
    }
    let iterations: u32 = it.next()?.parse().ok()?;
    let salt = unhex(it.next()?)?;
    let hash = unhex(it.next()?)?;
    if it.next().is_some() || !(1..=10_000_000).contains(&iterations) || salt.is_empty() || hash.len() != HASH {
        return None;
    }
    Some((iterations, salt, hash))
}

/// A stored hash is well formed (config validation).
pub fn is_hash(encoded: &str) -> bool {
    decode(encoded).is_some()
}

/// Does `password` match the stored hash? (`false` for a malformed one.)
pub fn verify(password: &str, encoded: &str) -> bool {
    match decode(encoded) {
        Some((iterations, salt, hash)) => ct_eq(&derive(password, &salt, iterations), &hash),
        None => false,
    }
}

/// An entropy pool: everything mixed in goes through SHA-256 into the
/// state; output is SHA-256 of the state and a counter, and the state
/// moves on after each use (backtracking resistance).
pub struct Pool {
    state: [u8; 32],
    counter: u64,
}

impl Pool {
    pub fn new(seed: &[u8]) -> Self {
        let mut p = Pool {
            state: [0; 32],
            counter: 0,
        };
        p.mix(seed);
        p
    }

    /// Add entropy (or anything: it never hurts).
    pub fn mix(&mut self, data: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.state);
        h.update(data);
        self.state = h.finalize().into();
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            self.counter += 1;
            let mut h = Sha256::new();
            h.update(self.state);
            h.update(self.counter.to_le_bytes());
            h.update(b"out");
            let block: [u8; 32] = h.finalize().into();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        let mut h = Sha256::new();
        h.update(self.state);
        h.update(self.counter.to_le_bytes());
        h.update(b"next");
        self.state = h.finalize().into();
    }
}

/// Login sessions: random tokens, valid while used at least every
/// `idle_ms`, at most `max` at once (the oldest goes).
pub struct Sessions {
    tokens: Vec<([u8; 16], u64)>,
    max: usize,
    idle_ms: u64,
}

impl Sessions {
    pub fn new(max: usize, idle_ms: u64) -> Self {
        Sessions {
            tokens: Vec::new(),
            max: max.max(1),
            idle_ms,
        }
    }

    /// A new session: its token (32 hex digits).
    pub fn create(&mut self, pool: &mut Pool, now_ms: u64) -> String {
        self.expire(now_ms);
        let mut t = [0u8; 16];
        pool.fill(&mut t);
        if self.tokens.len() >= self.max {
            // The least recently used goes.
            if let Some(i) = (0..self.tokens.len()).min_by_key(|&i| self.tokens[i].1) {
                self.tokens.remove(i);
            }
        }
        self.tokens.push((t, now_ms));
        hex(&t)
    }

    /// A valid token: refreshes it.
    pub fn check(&mut self, token: &str, now_ms: u64) -> bool {
        self.expire(now_ms);
        let Some(t) = unhex(token).filter(|t| t.len() == 16) else {
            return false;
        };
        // Compare against every token without an early exit.
        let mut hit = None;
        for (i, (k, _)) in self.tokens.iter().enumerate() {
            if ct_eq(k, &t) {
                hit = Some(i);
            }
        }
        match hit {
            Some(i) => {
                self.tokens[i].1 = now_ms;
                true
            }
            None => false,
        }
    }

    /// Log out.
    pub fn remove(&mut self, token: &str) {
        if let Some(t) = unhex(token) {
            self.tokens.retain(|(k, _)| !ct_eq(k, &t));
        }
    }

    /// All sessions end (the password changed).
    pub fn clear(&mut self) {
        self.tokens.clear();
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    fn expire(&mut self, now_ms: u64) {
        let idle = self.idle_ms;
        self.tokens.retain(|(_, used)| now_ms.saturating_sub(*used) <= idle);
    }
}

/// The last password that verified against a stored hash, as
/// HMAC-SHA256(random key, password): a repeat costs one HMAC, not PBKDF2.
pub struct Cache {
    key: [u8; 32],
    last: Option<([u8; 32], String)>,
}

impl Cache {
    pub fn new(pool: &mut Pool) -> Self {
        let mut key = [0u8; 32];
        pool.fill(&mut key);
        Cache { key, last: None }
    }

    fn tag(&self, password: &str) -> [u8; 32] {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.key).expect("any key length");
        m.update(password.as_bytes());
        m.finalize().into_bytes().into()
    }

    /// [`verify`], remembering a success for `encoded`.
    pub fn verify(&mut self, password: &str, encoded: &str) -> bool {
        let tag = self.tag(password);
        if let Some((t, e)) = &self.last
            && e == encoded
            && ct_eq(t, &tag)
        {
            return true;
        }
        let ok = verify(password, encoded);
        if ok {
            self.last = Some((tag, encoded.into()));
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc7914() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1.
        let h = derive("passwd", b"salt", 1);
        assert_eq!(hex(&h), "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
    }

    #[test]
    fn hashes_verify_and_differ_by_salt() {
        let mut pool = Pool::new(b"test");
        let a = hash_password("s3cret", &mut pool, 1000);
        let b = hash_password("s3cret", &mut pool, 1000);
        assert_ne!(a, b, "fresh salt");
        assert!(a.starts_with("pbkdf2-sha256$1000$"));
        assert!(is_hash(&a));
        assert!(verify("s3cret", &a) && verify("s3cret", &b));
        assert!(!verify("s3cret ", &a) && !verify("", &a));
        for bad in ["", "pbkdf2-sha256$1000$zz$00", "md5$1$00$00", &a[..a.len() - 2], &alloc::format!("{a}$x")] {
            assert!(!is_hash(bad) && !verify("s3cret", bad), "{bad}");
        }
    }

    #[test]
    fn pool_output_depends_on_everything_mixed_in() {
        let (mut a, mut b) = (Pool::new(b"x"), Pool::new(b"x"));
        let (mut x, mut y) = ([0u8; 40], [0u8; 40]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y, "deterministic");
        a.fill(&mut x);
        assert_ne!(x, y, "moves on");
        b.mix(b"jitter");
        b.fill(&mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn sessions_expire_cap_and_log_out() {
        let mut pool = Pool::new(b"s");
        let mut s = Sessions::new(2, 1000);
        let t1 = s.create(&mut pool, 0);
        assert_eq!(t1.len(), 32);
        assert!(s.check(&t1, 900));
        assert!(s.check(&t1, 1800), "sliding: used at 900");
        assert!(!s.check(&t1, 3000), "idle too long");
        let t2 = s.create(&mut pool, 3000);
        let t3 = s.create(&mut pool, 3001);
        assert!(s.check(&t2, 3002));
        let t4 = s.create(&mut pool, 3003);
        assert!(!s.check(&t3, 3004), "least recently used dropped");
        assert!(s.check(&t2, 3004) && s.check(&t4, 3004));
        s.remove(&t2);
        assert!(!s.check(&t2, 3005));
        assert!(!s.check("not hex", 3005) && !s.check(&"0".repeat(32), 3005));
        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn cache_skips_pbkdf2_for_a_known_password_only() {
        let mut pool = Pool::new(b"c");
        let h = hash_password("pw", &mut pool, 500);
        let mut c = Cache::new(&mut pool);
        assert!(!c.verify("nope", &h));
        assert!(c.verify("pw", &h));
        assert!(c.verify("pw", &h));
        assert!(!c.verify("pw2", &h));
        let other = hash_password("other", &mut pool, 500);
        assert!(!c.verify("pw", &other), "cached for another hash only");
    }
}
