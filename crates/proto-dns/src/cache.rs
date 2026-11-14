//! Bounded response cache with TTL aging.
//!
//! Entries store the upstream response bytes plus the offsets of every TTL
//! field; on a hit the TTLs are rewritten with the remaining lifetime, so
//! clients never see stale TTLs. Eviction removes the soonest-expiring
//! entry when full (O(log n)).

use crate::wire::{self, Question};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Upper bound for any cached TTL (seconds).
pub const MAX_TTL: u32 = 86_400;
/// Negative answers (NXDOMAIN / NODATA) without SOA are cached this long.
pub const DEFAULT_NEGATIVE_TTL: u32 = 60;

struct Entry {
    response: Vec<u8>,
    ttl_offsets: Vec<usize>,
    stored_ms: u64,
    expires_ms: u64,
}

pub struct Cache {
    max_entries: usize,
    entries: BTreeMap<Question, Entry>,
    by_expiry: BTreeSet<(u64, Question)>,
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

    fn remove(&mut self, q: &Question) {
        if let Some(e) = self.entries.remove(q) {
            self.by_expiry.remove(&(e.expires_ms, q.clone()));
        }
    }

    /// Store an upstream response (already validated for `q`).
    pub fn insert(&mut self, now_ms: u64, q: Question, response: &[u8]) {
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
                ttl_offsets,
                stored_ms: now_ms,
                expires_ms,
            },
        );
    }

    /// A cached response for `q` with `id` and aged TTLs, if still valid.
    pub fn get(&mut self, now_ms: u64, q: &Question, id: u16) -> Option<Vec<u8>> {
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
        Some(out)
    }
}
