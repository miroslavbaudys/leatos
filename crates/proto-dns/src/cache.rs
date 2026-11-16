//! Bounded response cache with TTL aging.
//!
//! Entries store the upstream response bytes plus the offsets of every TTL
//! field; on a hit the TTLs are rewritten with the remaining lifetime, so
//! clients never see stale TTLs. Eviction removes the soonest-expiring
//! entry when full (O(log n)).
//!
//! Entries are keyed by the question and the client's DNSSEC flags
//! ([`Key`]): an answer for a client without DO has no RRSIGs, and one for
//! a client with CD may have failed validation upstream; neither may reach
//! a client asking otherwise.
//!
//! Prefetch: each entry keeps the upstream query that filled it. A hit in
//! the last [`PREFETCH_DIVISOR`]th of the entry's lifetime is marked
//! [`Hit::refresh`], and the resolver sends that query again, so popular
//! names are renewed before they expire. Resending the same query (EDNS
//! included) means the answer fits as the cached one did: a truncated
//! answer is never cached, so the query that filled an entry got a whole
//! one.

use crate::wire::{self, Question};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Upper bound for any cached TTL (seconds).
pub const MAX_TTL: u32 = 86_400;
/// Negative answers (NXDOMAIN / NODATA) without SOA are cached this long.
pub const DEFAULT_NEGATIVE_TTL: u32 = 60;
/// A hit with less than 1/`PREFETCH_DIVISOR` of the TTL left asks for a
/// refresh.
pub const PREFETCH_DIVISOR: u64 = 10;
/// Entries with a shorter TTL (seconds) are never refreshed early.
pub const PREFETCH_MIN_TTL: u32 = 10;

/// What a cached answer is for: the question, and the DNSSEC flags of the
/// query that got it (they change what the upstream puts in the answer).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub question: Question,
    /// DO (RFC 3225): DNSSEC records wanted.
    pub dnssec_ok: bool,
    /// CD (RFC 4035): unvalidated answers accepted.
    pub checking_disabled: bool,
}

impl Key {
    /// The key of `query` (a client's or an upstream query), whose question
    /// is `question`.
    pub fn of(query: &[u8], question: Question) -> Self {
        Key {
            question,
            dnssec_ok: wire::dnssec_ok(query),
            checking_disabled: wire::Header::parse(query).is_ok_and(|h| h.checking_disabled()),
        }
    }
}

struct Entry {
    response: Vec<u8>,
    /// The upstream query that got `response` (for prefetch).
    query: Vec<u8>,
    ttl_offsets: Vec<usize>,
    stored_ms: u64,
    expires_ms: u64,
}

/// A cache hit.
#[derive(Debug)]
pub struct Hit {
    /// The response with the client's ID and aged TTLs.
    pub data: Vec<u8>,
    /// Close to expiry: the upstream query to renew the entry with (the
    /// ID still the old one's).
    pub refresh: Option<Vec<u8>>,
}

pub struct Cache {
    max_entries: usize,
    entries: BTreeMap<Key, Entry>,
    by_expiry: BTreeSet<(u64, Key)>,
    pub hits: u64,
    pub misses: u64,
}

impl Cache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            entries: BTreeMap::new(),
            by_expiry: BTreeSet::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Change the size limit; when it shrinks, the soonest-expiring
    /// entries go first.
    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries.max(1);
        while self.entries.len() > self.max_entries {
            let Some(oldest) = self.by_expiry.pop_first() else {
                break;
            };
            self.entries.remove(&oldest.1);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn remove(&mut self, q: &Key) {
        if let Some(e) = self.entries.remove(q) {
            self.by_expiry.remove(&(e.expires_ms, q.clone()));
        }
    }

    /// Store an upstream response (already validated for `q`) and the
    /// upstream `query` it answered.
    pub fn insert(&mut self, now_ms: u64, q: Key, response: &[u8], query: &[u8]) {
        let Ok(recs) = wire::records(response) else {
            return;
        };
        let Ok(h) = wire::Header::parse(response) else {
            return;
        };
        if wire::is_truncated(response) {
            return;
        }
        let ttl = match (h.rcode(), h.ancount) {
            (wire::RCODE_NOERROR, n) if n > 0 => recs
                .iter()
                .filter(|r| r.section == 0)
                .map(|r| r.ttl)
                .min()
                .unwrap_or(0),
            (wire::RCODE_NOERROR | wire::RCODE_NXDOMAIN, _) => recs
                .iter()
                .find(|r| r.section == 1 && r.rtype == wire::TYPE_SOA)
                .map(|r| r.ttl)
                .unwrap_or(DEFAULT_NEGATIVE_TTL),
            _ => return, // never cache SERVFAIL, REFUSED, …
        }
        .min(MAX_TTL);
        if ttl == 0 {
            return;
        }
        let ttl_offsets = recs
            .iter()
            .filter(|r| r.rtype != wire::TYPE_OPT)
            .map(|r| r.ttl_offset)
            .collect();
        self.remove(&q);
        while self.entries.len() >= self.max_entries {
            let Some(oldest) = self.by_expiry.pop_first() else {
                break;
            };
            self.entries.remove(&oldest.1);
        }
        let expires_ms = now_ms + ttl as u64 * 1000;
        self.by_expiry.insert((expires_ms, q.clone()));
        self.entries.insert(
            q,
            Entry {
                response: response.to_vec(),
                query: query.to_vec(),
                ttl_offsets,
                stored_ms: now_ms,
                expires_ms,
            },
        );
    }

    /// A cached response for `q` with `id` and aged TTLs, if still valid.
    pub fn get(&mut self, now_ms: u64, q: &Key, id: u16) -> Option<Hit> {
        let Some(e) = self.entries.get(q) else {
            self.misses += 1;
            return None;
        };
        if e.expires_ms <= now_ms {
            self.remove(q);
            self.misses += 1;
            return None;
        }
        let elapsed = ((now_ms - e.stored_ms) / 1000) as u32;
        let mut out = e.response.clone();
        for &off in &e.ttl_offsets {
            let old = u32::from_be_bytes([out[off], out[off + 1], out[off + 2], out[off + 3]]);
            out[off..off + 4].copy_from_slice(&old.saturating_sub(elapsed).max(1).to_be_bytes());
        }
        wire::set_id(&mut out, id);
        self.hits += 1;
        let lifetime = e.expires_ms - e.stored_ms;
        let left = e.expires_ms - now_ms;
        let refresh = (lifetime >= PREFETCH_MIN_TTL as u64 * 1000 && left * PREFETCH_DIVISOR < lifetime)
            .then(|| e.query.clone());
        Some(Hit { data: out, refresh })
    }
}
