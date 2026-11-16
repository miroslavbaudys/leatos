//! The DNS forwarder: local zone → cache → upstream, sans-IO.
//!
//! - **Queries** from LAN clients: [`Resolver::handle_query`].
//! - **Responses** from upstream servers: [`Resolver::handle_upstream`].
//! - **Timers**: call [`Resolver::poll`] at [`Resolver::next_deadline`].
//!
//! Every call returns [`Action`]s: datagrams to send to a client or an
//! upstream server. Upstream queries get a fresh random transaction ID;
//! responses are accepted only from the server that was asked and only if
//! the question matches. Identical in-flight questions are merged (one
//! upstream query, many waiters). Pending queries are bounded.
//!
//! DNSSEC is passed through, not validated: queries keep their DO bit and
//! CD flag upstream, answers keep their RRSIGs and AD flag. Merging and the
//! cache are per question *and* those flags ([`Key`]), so a validating
//! client never gets an answer fetched without DNSSEC records, and a
//! client without CD never one that failed validation upstream.
//!
//! Prefetch ([`Config::prefetch`]): a cache hit close to expiry
//! ([`crate::cache`]) is answered from the cache and the entry renewed by
//! an upstream query without waiters, at most one per question and on at
//! most a quarter of [`Config::max_pending`], so client queries always find
//! room. A client asking once the entry has expired joins the renewal.
//! A failed renewal changes nothing: the old entry expires as it would
//! have.
//!
//! Known gap: one fixed upstream source port (chosen by the caller), so
//! spoofing resistance relies on the 16-bit ID only. Per-query source ports
//! are planned.

use crate::cache::{Cache, Key};
use crate::wire::{self, Rdata};
use crate::zone::{Lookup, Zone};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};

/// TTL for answers from the local zone.
pub const LOCAL_TTL: u32 = 60;

/// Largest answer to a client: one datagram on a 1500-byte link (IP and
/// UDP headers off). Larger ones (an EDNS client's, or anything from a
/// TCP/TLS upstream) are cut to the question with TC set
/// ([`wire::fit`]).
pub const MAX_UDP_REPLY: usize = 1472;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send `data` to the LAN client `to`.
    Reply { to: SocketAddr, data: Vec<u8> },
    /// Send `data` to upstream server `server`, port 53.
    Upstream { server: Ipv4Addr, data: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub cache_entries: usize,
    /// Drop upstream answers that point public names at private addresses.
    pub rebind_protection: bool,
    pub timeout_ms: u64,
    /// Total attempts per query (rotating through upstreams).
    pub max_tries: u8,
    /// Bound on concurrently pending upstream queries.
    pub max_pending: usize,
    /// Renew popular cache entries shortly before they expire.
    pub prefetch: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cache_entries: 4096,
            rebind_protection: true,
            timeout_ms: 1500,
            max_tries: 3,
            max_pending: 256,
            prefetch: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub queries: u64,
    pub local_answers: u64,
    pub cache_hits: u64,
    pub forwarded: u64,
    pub merged: u64,
    pub timeouts: u64,
    pub servfails: u64,
    pub rebind_blocked: u64,
    pub ignored_responses: u64,
    /// Renewals sent ([`Config::prefetch`]); not counted in `forwarded`.
    pub prefetches: u64,
    /// Renewals that timed out or got an answer that is not cached.
    pub prefetch_failed: u64,
}

struct Pending {
    /// The question and the client's DNSSEC flags: queries are merged and
    /// answers cached per key.
    key: Key,
    /// The upstream query (with our ID).
    query: Vec<u8>,
    /// Client, its query ID, the largest answer it takes.
    waiters: Vec<(SocketAddr, u16, usize)>,
    sent_ms: u64,
    tries: u8,
    upstream: usize,
    /// A renewal of a cache entry (clients may have joined since).
    prefetch: bool,
}

pub struct Resolver {
    cfg: Config,
    zone: Zone,
    cache: Cache,
    upstreams: Vec<Ipv4Addr>,
    pending: BTreeMap<u16, Pending>,
    by_question: BTreeMap<Key, u16>,
    rng: u32,
    pub stats: Stats,
}

/// RFC 1918, loopback, link-local, "this network".
fn is_private(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private() || a.is_loopback() || a.is_link_local() || o[0] == 0
}

impl Resolver {
    /// `seed` initialises the transaction-ID generator (use a hardware
    /// counter or RNG; never 0).
    pub fn new(cfg: Config, zone: Zone, seed: u32) -> Self {
        let cache = Cache::new(cfg.cache_entries);
        Self {
            cfg,
            zone,
            cache,
            upstreams: Vec::new(),
            pending: BTreeMap::new(),
            by_question: BTreeMap::new(),
            rng: seed | 1,
            stats: Stats::default(),
        }
    }

    /// New settings without a restart: the cache keeps what fits the new
    /// size; pending queries continue.
    pub fn reconfigure(&mut self, cfg: Config) {
        self.cache.set_max_entries(cfg.cache_entries);
        self.cfg = cfg;
    }

    pub fn zone_mut(&mut self) -> &mut Zone {
        &mut self.zone
    }

    pub fn set_upstreams(&mut self, servers: &[Ipv4Addr]) {
        self.upstreams = servers.to_vec();
    }

    pub fn upstreams(&self) -> &[Ipv4Addr] {
        &self.upstreams
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    fn next_id(&mut self) -> u16 {
        loop {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 17;
            self.rng ^= self.rng << 5;
            let id = (self.rng >> 8) as u16;
            if !self.pending.contains_key(&id) {
                return id;
            }
        }
    }

    fn reply_error(&mut self, to: SocketAddr, query: &[u8], rcode: u8) -> Vec<Action> {
        if rcode == wire::RCODE_SERVFAIL {
            self.stats.servfails += 1;
        }
        wire::error_response(query, rcode)
            .map(|data| Action::Reply { to, data })
            .into_iter()
            .collect()
    }

    /// A query datagram from a LAN client.
    pub fn handle_query(&mut self, now_ms: u64, client: SocketAddr, query: &[u8]) -> Vec<Action> {
        let Ok(h) = wire::Header::parse(query) else {
            return Vec::new();
        };
        if h.is_response() {
            return Vec::new();
        }
        self.stats.queries += 1;
        if h.opcode() != 0 {
            return self.reply_error(client, query, wire::RCODE_NOTIMP);
        }
        let (q, q_end) = match wire::parse_query(query) {
            Ok((_, q, end)) => (q, end),
            Err(_) => return self.reply_error(client, query, wire::RCODE_FORMERR),
        };
        if q.qclass != wire::CLASS_IN {
            return self.reply_error(client, query, wire::RCODE_REFUSED);
        }

        // 1. Local zone (authoritative, never forwarded).
        let local = match self.zone.lookup(&q.name, q.qtype) {
            Lookup::A(ips) => Some((
                wire::RCODE_NOERROR,
                ips.into_iter().map(|a| (Rdata::A(a), LOCAL_TTL)).collect(),
            )),
            Lookup::Ptr(names) => Some((
                wire::RCODE_NOERROR,
                names
                    .into_iter()
                    .map(|n| (Rdata::Ptr(n), LOCAL_TTL))
                    .collect(),
            )),
            Lookup::NoData => Some((wire::RCODE_NOERROR, Vec::new())),
            Lookup::NxDomain => Some((wire::RCODE_NXDOMAIN, Vec::new())),
            Lookup::NotLocal => None,
        };
        if let Some((rcode, answers)) = local {
            self.stats.local_answers += 1;
            let data = wire::build_response(query, q_end, rcode, &answers, true);
            return alloc::vec![Action::Reply { to: client, data }];
        }

        // 2. Cache, per question and DNSSEC flags.
        let key = Key::of(query, q);
        let limit = wire::udp_limit(query, MAX_UDP_REPLY);
        if let Some(hit) = self.cache.get(now_ms, &key, h.id) {
            self.stats.cache_hits += 1;
            let data = wire::fit(&hit.data, limit);
            let mut out = alloc::vec![Action::Reply { to: client, data }];
            if let Some(query) = hit.refresh {
                out.extend(self.prefetch(now_ms, key, query));
            }
            return out;
        }

        // 3. Upstream (merge identical in-flight questions with the same
        // DNSSEC flags).
        if let Some(id) = self.by_question.get(&key)
            && let Some(p) = self.pending.get_mut(id)
        {
            p.waiters.push((client, h.id, limit));
            self.stats.merged += 1;
            return Vec::new();
        }
        if self.upstreams.is_empty() || self.pending.len() >= self.cfg.max_pending {
            return self.reply_error(client, query, wire::RCODE_SERVFAIL);
        }
        let id = self.next_id();
        let mut up = query.to_vec();
        wire::set_id(&mut up, id);
        let server = self.upstreams[0];
        self.by_question.insert(key.clone(), id);
        self.pending.insert(
            id,
            Pending {
                key,
                query: up.clone(),
                waiters: alloc::vec![(client, h.id, limit)],
                sent_ms: now_ms,
                tries: 1,
                upstream: 0,
                prefetch: false,
            },
        );
        self.stats.forwarded += 1;
        alloc::vec![Action::Upstream { server, data: up }]
    }

    /// Renew the cache entry for `q` with its upstream `query`, unless
    /// switched off, already under way, or the pending queries are a
    /// quarter full.
    fn prefetch(&mut self, now_ms: u64, key: Key, mut query: Vec<u8>) -> Option<Action> {
        let busy = self.pending.values().filter(|p| p.prefetch).count();
        if !self.cfg.prefetch
            || self.upstreams.is_empty()
            || self.by_question.contains_key(&key)
            || busy >= (self.cfg.max_pending / 4).max(1)
            || self.pending.len() >= self.cfg.max_pending
        {
            return None;
        }
        let id = self.next_id();
        wire::set_id(&mut query, id);
        let server = self.upstreams[0];
        self.by_question.insert(key.clone(), id);
        self.pending.insert(
            id,
            Pending {
                key,
                query: query.clone(),
                waiters: Vec::new(),
                sent_ms: now_ms,
                tries: 1,
                upstream: 0,
                prefetch: true,
            },
        );
        self.stats.prefetches += 1;
        Some(Action::Upstream { server, data: query })
    }

    /// A response datagram from upstream server `from` (source port 53).
    pub fn handle_upstream(&mut self, now_ms: u64, from: Ipv4Addr, response: &[u8]) -> Vec<Action> {
        let Ok(h) = wire::Header::parse(response) else {
            return Vec::new();
        };
        let Some(p) = self.pending.get(&h.id) else {
            self.stats.ignored_responses += 1;
            return Vec::new();
        };
        // Anti-spoofing: right server, right question.
        let asked = self.upstreams.get(p.upstream).copied();
        let matches = wire::parse_query(response).is_ok_and(|(_, q, _)| q == p.key.question);
        if !h.is_response() || asked != Some(from) || !matches {
            self.stats.ignored_responses += 1;
            return Vec::new();
        }
        let p = self.pending.remove(&h.id).expect("checked above");
        self.by_question.remove(&p.key);

        if p.prefetch && !matches!(h.rcode(), wire::RCODE_NOERROR | wire::RCODE_NXDOMAIN) {
            self.stats.prefetch_failed += 1;
        }
        let mut data = response.to_vec();
        let in_local_domain = self.zone.is_local_name(&p.key.question.name);
        if self.cfg.rebind_protection && !in_local_domain {
            let recs = wire::records(response).unwrap_or_default();
            if wire::answer_ipv4s(response, &recs)
                .into_iter()
                .any(is_private)
            {
                self.stats.rebind_blocked += 1;
                data = wire::error_response(&p.query, wire::RCODE_REFUSED).unwrap_or_default();
            } else {
                self.cache.insert(now_ms, p.key.clone(), response, &p.query);
            }
        } else {
            self.cache.insert(now_ms, p.key.clone(), response, &p.query);
        }

        p.waiters
            .into_iter()
            .map(|(to, id, limit)| {
                let mut d = wire::fit(&data, limit);
                wire::set_id(&mut d, id);
                Action::Reply { to, data: d }
            })
            .collect()
    }

    /// Retry or fail timed-out queries.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Action> {
        let timeout = self.cfg.timeout_ms;
        let due: Vec<u16> = self
            .pending
            .iter()
            .filter(|(_, p)| p.sent_ms + timeout <= now_ms)
            .map(|(&id, _)| id)
            .collect();
        let mut out = Vec::new();
        for id in due {
            // A renewal nobody waits for is not a client's timeout.
            if self.pending.get(&id).is_some_and(|p| !p.prefetch || !p.waiters.is_empty()) {
                self.stats.timeouts += 1;
            }
            let retry = self
                .pending
                .get(&id)
                .is_some_and(|p| p.tries < self.cfg.max_tries)
                && !self.upstreams.is_empty();
            if retry {
                let n = self.upstreams.len();
                let p = self.pending.get_mut(&id).expect("due id");
                p.tries += 1;
                p.upstream = (p.upstream + 1) % n;
                p.sent_ms = now_ms;
                out.push(Action::Upstream {
                    server: self.upstreams[p.upstream],
                    data: p.query.clone(),
                });
            } else if let Some(p) = self.pending.remove(&id) {
                self.by_question.remove(&p.key);
                if p.prefetch {
                    self.stats.prefetch_failed += 1;
                }
                for (to, orig, _) in p.waiters {
                    let mut q = p.query.clone();
                    wire::set_id(&mut q, orig);
                    out.extend(self.reply_error(to, &q, wire::RCODE_SERVFAIL));
                }
            }
        }
        out
    }

    /// When [`Self::poll`] next needs to run, if anything is pending.
    pub fn next_deadline(&self) -> Option<u64> {
        self.pending
            .values()
            .map(|p| p.sent_ms + self.cfg.timeout_ms)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_A, TYPE_PTR, build_query,
    };
    use crate::zone::Source;
    use alloc::vec;
    use core::net::SocketAddrV4;

    const UP1: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
    const UP2: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

    fn client(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), port))
    }

    fn resolver() -> Resolver {
        let mut z = Zone::new(
            "lan",
            Ipv4Addr::new(192, 168, 1, 1),
            (Ipv4Addr::new(192, 168, 1, 0), 24),
        );
        z.add("nas", Ipv4Addr::new(192, 168, 1, 10), Source::Static);
        let mut r = Resolver::new(Config::default(), z, 0xdead_beef);
        r.set_upstreams(&[UP1, UP2]);
        r
    }

    fn reply(actions: &[Action]) -> (&SocketAddr, &[u8]) {
        match actions {
            [Action::Reply { to, data }] => (to, data),
            other => panic!("expected one reply, got {other:?}"),
        }
    }

    fn upstream(actions: &[Action]) -> (Ipv4Addr, Vec<u8>) {
        match actions {
            [Action::Upstream { server, data }] => (*server, data.clone()),
            other => panic!("expected one upstream query, got {other:?}"),
        }
    }

    /// Fake upstream answer to `q` with one A record.
    fn answer(q: &[u8], ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let (_, _, end) = wire::parse_query(q).unwrap();
        wire::build_response(q, end, RCODE_NOERROR, &[(Rdata::A(ip), ttl)], false)
    }

    fn rcode(data: &[u8]) -> u8 {
        wire::Header::parse(data).unwrap().rcode()
    }

    #[test]
    fn local_names_are_answered_and_never_forwarded() {
        let mut r = resolver();
        let a = r.handle_query(0, client(1), &build_query(1, "NAS.lan", TYPE_A));
        let (_, d) = reply(&a);
        let recs = wire::records(d).unwrap();
        assert_eq!(
            wire::answer_ipv4s(d, &recs),
            vec![Ipv4Addr::new(192, 168, 1, 10)]
        );
        let a = r.handle_query(0, client(1), &build_query(2, "nope.lan", TYPE_A));
        assert_eq!(rcode(reply(&a).1), RCODE_NXDOMAIN);
        let a = r.handle_query(
            0,
            client(1),
            &build_query(3, "10.1.168.192.in-addr.arpa", TYPE_PTR),
        );
        assert_eq!(wire::Header::parse(reply(&a).1).unwrap().ancount, 1);
        assert_eq!(r.stats.forwarded, 0);
    }

    #[test]
    fn forward_rewrites_id_and_caches_with_aged_ttl() {
        let mut r = resolver();
        let q = build_query(0x1111, "example.com", TYPE_A);
        let (server, up) = upstream(&r.handle_query(0, client(5), &q));
        assert_eq!(server, UP1);
        let up_id = wire::Header::parse(&up).unwrap().id;
        assert_ne!(up_id, 0x1111);

        let a = r.handle_upstream(10, UP1, &answer(&up, Ipv4Addr::new(93, 184, 216, 34), 300));
        let (to, d) = reply(&a);
        assert_eq!(
            (*to, wire::Header::parse(d).unwrap().id),
            (client(5), 0x1111)
        );

        // Cache hit 100 s later: no upstream traffic, TTL aged.
        let a = r.handle_query(
            100_010,
            client(6),
            &build_query(0x2222, "EXAMPLE.com", TYPE_A),
        );
        let (_, d) = reply(&a);
        assert_eq!(wire::Header::parse(d).unwrap().id, 0x2222);
        assert_eq!(wire::records(d).unwrap()[0].ttl, 200);
        assert_eq!(r.stats.cache_hits, 1);
        // Expired after the TTL.
        assert!(matches!(
            &r.handle_query(301_000, client(6), &q)[..],
            [Action::Upstream { .. }]
        ));
    }

    #[test]
    fn identical_inflight_questions_are_merged() {
        let mut r = resolver();
        let (_, up) = upstream(&r.handle_query(0, client(1), &build_query(1, "a.com", TYPE_A)));
        assert!(
            r.handle_query(0, client(2), &build_query(2, "a.com", TYPE_A))
                .is_empty()
        );
        let a = r.handle_upstream(5, UP1, &answer(&up, Ipv4Addr::new(1, 1, 1, 1), 60));
        assert_eq!(a.len(), 2);
        assert_eq!(r.stats.merged, 1);
    }

    #[test]
    fn spoofed_or_mismatched_responses_are_ignored() {
        let mut r = resolver();
        let (_, up) = upstream(&r.handle_query(0, client(1), &build_query(1, "bank.com", TYPE_A)));
        let good = answer(&up, Ipv4Addr::new(1, 2, 3, 4), 60);
        assert!(
            r.handle_upstream(1, Ipv4Addr::new(6, 6, 6, 6), &good)
                .is_empty(),
            "wrong server"
        );
        let mut other = build_query(wire::Header::parse(&up).unwrap().id, "evil.com", TYPE_A);
        other = answer(&other, Ipv4Addr::new(6, 6, 6, 6), 60);
        assert!(
            r.handle_upstream(1, UP1, &other).is_empty(),
            "wrong question"
        );
        assert_eq!(r.stats.ignored_responses, 2);
        assert_eq!(r.handle_upstream(2, UP1, &good).len(), 1);
    }

    #[test]
    fn timeout_rotates_upstreams_then_servfails() {
        let mut r = resolver();
        r.handle_query(0, client(1), &build_query(7, "slow.com", TYPE_A));
        assert_eq!(r.next_deadline(), Some(1500));
        assert!(r.poll(1499).is_empty());
        assert_eq!(upstream(&r.poll(1500)).0, UP2);
        assert_eq!(upstream(&r.poll(3000)).0, UP1);
        let a = r.poll(4500);
        let (_, d) = reply(&a);
        assert_eq!(
            (rcode(d), wire::Header::parse(d).unwrap().id),
            (RCODE_SERVFAIL, 7)
        );
        assert_eq!(r.next_deadline(), None);
    }

    #[test]
    fn reconfigure_resizes_the_cache_and_switches_rebind_protection() {
        let mut r = resolver();
        for (i, name) in ["a.com", "b.com", "c.com"].iter().enumerate() {
            let (_, up) = upstream(&r.handle_query(0, client(1), &build_query(1, name, TYPE_A)));
            // Shorter TTL = expires sooner = evicted first.
            r.handle_upstream(
                1,
                UP1,
                &answer(&up, Ipv4Addr::new(93, 0, 0, 1), 100 + i as u32),
            );
        }
        assert_eq!(r.cache_len(), 3);
        r.reconfigure(Config {
            cache_entries: 1,
            rebind_protection: false,
            ..Default::default()
        });
        assert_eq!(r.cache_len(), 1);
        // c.com (longest TTL) is the one kept: answered from the cache.
        let a = r.handle_query(2, client(2), &build_query(9, "c.com", TYPE_A));
        assert_eq!(wire::Header::parse(reply(&a).1).unwrap().id, 9);
        // Rebind protection off: a private answer passes.
        let (_, up) = upstream(&r.handle_query(3, client(1), &build_query(1, "intra.com", TYPE_A)));
        let a = r.handle_upstream(4, UP1, &answer(&up, Ipv4Addr::new(192, 168, 1, 5), 60));
        assert_eq!(rcode(reply(&a).1), RCODE_NOERROR);
    }

    #[test]
    fn rebind_protection_blocks_private_answers_for_public_names() {
        let mut r = resolver();
        let (_, up) =
            upstream(&r.handle_query(0, client(1), &build_query(1, "attacker.com", TYPE_A)));
        let a = r.handle_upstream(1, UP1, &answer(&up, Ipv4Addr::new(192, 168, 1, 1), 60));
        assert_eq!(rcode(reply(&a).1), RCODE_REFUSED);
        assert_eq!((r.stats.rebind_blocked, r.cache_len()), (1, 0));
    }

    #[test]
    fn no_upstream_or_too_many_pending_gives_servfail() {
        let mut r = resolver();
        r.set_upstreams(&[]);
        let a = r.handle_query(0, client(1), &build_query(1, "x.com", TYPE_A));
        assert_eq!(rcode(reply(&a).1), RCODE_SERVFAIL);

        let mut r = Resolver::new(
            Config {
                max_pending: 2,
                ..Default::default()
            },
            Zone::new(
                "lan",
                Ipv4Addr::new(192, 168, 1, 1),
                (Ipv4Addr::new(192, 168, 1, 0), 24),
            ),
            7,
        );
        r.set_upstreams(&[UP1]);
        r.handle_query(0, client(1), &build_query(1, "a.com", TYPE_A));
        r.handle_query(0, client(1), &build_query(2, "b.com", TYPE_A));
        let a = r.handle_query(0, client(1), &build_query(3, "c.com", TYPE_A));
        assert_eq!(rcode(reply(&a).1), RCODE_SERVFAIL);
    }

    #[test]
    fn negative_answers_are_cached() {
        let mut r = resolver();
        let (_, up) =
            upstream(&r.handle_query(0, client(1), &build_query(1, "missing.com", TYPE_A)));
        let (_, _, end) = wire::parse_query(&up).unwrap();
        let nx = wire::build_response(&up, end, RCODE_NXDOMAIN, &[], false);
        r.handle_upstream(1, UP1, &nx);
        let a = r.handle_query(2, client(1), &build_query(9, "missing.com", TYPE_A));
        assert_eq!(rcode(reply(&a).1), RCODE_NXDOMAIN);
        assert_eq!(r.stats.cache_hits, 1);
    }

    #[test]
    fn garbage_and_responses_from_clients_are_dropped() {
        let mut r = resolver();
        assert!(r.handle_query(0, client(1), b"x").is_empty());
        let q = build_query(1, "a.com", TYPE_A);
        assert!(
            r.handle_query(0, client(1), &answer(&q, Ipv4Addr::new(1, 1, 1, 1), 5))
                .is_empty()
        );
        let mut bad = q.clone();
        bad.truncate(15);
        assert_eq!(
            rcode(reply(&r.handle_query(0, client(1), &bad)).1),
            wire::RCODE_FORMERR
        );
    }

    /// Query `name` at t = 0 and answer it with TTL `ttl`.
    fn fill(r: &mut Resolver, q: &[u8], ttl: u32) {
        let (_, up) = upstream(&r.handle_query(0, client(1), q));
        let a = r.handle_upstream(0, UP1, &answer(&up, Ipv4Addr::new(1, 2, 3, 4), ttl));
        reply(&a);
    }

    fn with_edns(name: &str) -> Vec<u8> {
        let mut q = build_query(0x4242, name, TYPE_A);
        q[11] = 1; // ARCOUNT
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]); // OPT, 1232
        q
    }

    #[test]
    fn prefetch_renews_popular_entries_before_expiry() {
        let mut r = resolver();
        let q = with_edns("cdn.example");
        fill(&mut r, &q, 100);
        // Early in the TTL: from the cache only.
        reply(&r.handle_query(50_000, client(2), &q));
        // Last 10 %: answered from the cache and renewed, with the query
        // that filled the entry (EDNS kept), under a new ID.
        let a = r.handle_query(95_000, client(2), &q);
        let [Action::Reply { to, .. }, Action::Upstream { server, data: up }] = &a[..] else {
            panic!("expected reply + renewal, got {a:?}");
        };
        assert_eq!((*to, *server), (client(2), UP1));
        assert_eq!(up[12..], q[12..], "same question and EDNS");
        assert_eq!(wire::udp_limit(up, 1472), 1232);
        // One renewal per question.
        reply(&r.handle_query(96_000, client(3), &q));
        assert_eq!((r.stats.prefetches, r.stats.forwarded, r.stats.cache_hits), (1, 1, 3));
        // The answer goes to nobody and renews the entry.
        let up = up.clone();
        assert!(r.handle_upstream(96_500, UP1, &answer(&up, Ipv4Addr::new(1, 2, 3, 5), 100)).is_empty());
        let a = r.handle_query(150_000, client(4), &q);
        let (_, d) = reply(&a);
        let recs = wire::records(d).unwrap();
        assert_eq!(recs[0].ttl, 47, "aged from the renewal at 96.5 s");
        assert_eq!(wire::answer_ipv4s(d, &recs), vec![Ipv4Addr::new(1, 2, 3, 5)]);
        assert_eq!((r.stats.forwarded, r.stats.prefetch_failed), (1, 0));
    }

    #[test]
    fn clients_join_a_renewal_once_the_entry_expired() {
        let mut r = resolver();
        let q = build_query(7, "short.example", TYPE_A);
        fill(&mut r, &q, 100);
        let a = r.handle_query(95_000, client(2), &q);
        let up = match &a[..] {
            [Action::Reply { .. }, Action::Upstream { data, .. }] => data.clone(),
            other => panic!("expected reply + renewal, got {other:?}"),
        };
        // Expired before the renewal returned: the client waits for it.
        assert!(r.handle_query(100_500, client(3), &q).is_empty());
        assert_eq!(r.stats.merged, 1);
        let a = r.handle_upstream(100_600, UP1, &answer(&up, Ipv4Addr::new(1, 2, 3, 4), 100));
        let (to, d) = reply(&a);
        assert_eq!((*to, wire::Header::parse(d).unwrap().id), (client(3), 7));
    }

    #[test]
    fn a_failed_renewal_changes_nothing() {
        let mut r = resolver();
        let q = build_query(7, "down.example", TYPE_A);
        fill(&mut r, &q, 100);
        let a = r.handle_query(95_000, client(2), &q);
        assert_eq!(a.len(), 2);
        // Every try times out: retried like a client query, then dropped
        // without replies and without counting as a client timeout.
        let mut t = 95_000;
        for server in [UP2, UP1] {
            t += 1500;
            assert_eq!(upstream(&r.poll(t)).0, server);
        }
        t += 1500;
        assert!(r.poll(t).is_empty());
        assert_eq!((r.stats.timeouts, r.stats.prefetch_failed), (0, 1));
        // The old entry still answers until it expires (and the next hit
        // tries a renewal again); once expired, a client query waits for
        // that renewal.
        let a = r.handle_query(99_900, client(2), &q);
        assert!(matches!(&a[..], [Action::Reply { .. }, Action::Upstream { .. }]));
        assert_eq!(r.stats.prefetches, 2);
        assert!(r.handle_query(100_000, client(2), &q).is_empty());
        assert_eq!(r.stats.merged, 1);
        // SERVFAIL from upstream: counted, not cached.
        let mut r = resolver();
        fill(&mut r, &q, 100);
        let a = r.handle_query(95_000, client(2), &q);
        let [_, Action::Upstream { data: up, .. }] = &a[..] else { panic!() };
        let (_, _, end) = wire::parse_query(up).unwrap();
        let fail = wire::build_response(up, end, RCODE_SERVFAIL, &[], false);
        assert!(r.handle_upstream(95_100, UP1, &fail).is_empty());
        assert_eq!(r.stats.prefetch_failed, 1);
        let a = r.handle_query(99_000, client(2), &q);
        let Action::Reply { data, .. } = &a[0] else { panic!("{a:?}") };
        assert_eq!(rcode(data), RCODE_NOERROR, "still the cached answer");
    }

    #[test]
    fn prefetch_skips_short_ttls_and_can_be_switched_off() {
        let mut r = resolver();
        let q = build_query(7, "tiny.example", TYPE_A);
        fill(&mut r, &q, 9);
        reply(&r.handle_query(8_500, client(2), &q));
        let mut r = Resolver::new(
            Config {
                prefetch: false,
                ..Config::default()
            },
            Zone::new("lan", Ipv4Addr::new(192, 168, 1, 1), (Ipv4Addr::new(192, 168, 1, 0), 24)),
            1,
        );
        r.set_upstreams(&[UP1]);
        fill(&mut r, &q, 100);
        reply(&r.handle_query(95_000, client(2), &q));
        assert_eq!(r.stats.prefetches, 0);
    }

    #[test]
    fn renewals_take_at_most_a_quarter_of_the_pending_slots() {
        let mut r = Resolver::new(
            Config {
                max_pending: 8,
                ..Config::default()
            },
            Zone::new("lan", Ipv4Addr::new(192, 168, 1, 1), (Ipv4Addr::new(192, 168, 1, 0), 24)),
            1,
        );
        r.set_upstreams(&[UP1]);
        let names = ["a.example", "b.example", "c.example"];
        for n in names {
            fill(&mut r, &build_query(1, n, TYPE_A), 100);
        }
        let sent: usize = names
            .iter()
            .map(|n| r.handle_query(95_000, client(2), &build_query(2, n, TYPE_A)).len() - 1)
            .sum();
        assert_eq!((sent, r.stats.prefetches), (2, 2));
        // Client queries still get the remaining slots.
        for i in 0..6 {
            let q = build_query(3, &alloc::format!("n{i}.example"), TYPE_A);
            upstream(&r.handle_query(95_000, client(2), &q));
        }
    }

    /// `name` with EDNS (1232 B) and the DO bit when `dnssec_ok`, CD set
    /// when `cd`.
    fn dnssec_query(id: u16, name: &str, dnssec_ok: bool, cd: bool) -> Vec<u8> {
        let mut q = build_query(id, name, TYPE_A);
        if cd {
            q[3] |= 0x10;
        }
        q[11] = 1; // ARCOUNT
        let flags = if dnssec_ok { 0x80 } else { 0 };
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, flags, 0, 0, 0]);
        q
    }

    #[test]
    fn dnssec_flags_keep_queries_and_cache_entries_apart() {
        let mut r = resolver();
        let plain = dnssec_query(1, "signed.example", false, false);
        let dnssec = dnssec_query(2, "signed.example", true, false);
        let cd = dnssec_query(3, "signed.example", true, true);
        assert!(!wire::dnssec_ok(&plain) && wire::dnssec_ok(&dnssec));
        assert!(wire::Header::parse(&cd).unwrap().checking_disabled());
        // Three in-flight queries, not merged: the upstream answers each
        // differently (with and without RRSIGs, validated or not).
        let mut ups = Vec::new();
        for (i, q) in [&plain, &dnssec, &cd].into_iter().enumerate() {
            let (_, up) = upstream(&r.handle_query(0, client(i as u16), q));
            assert_eq!(wire::dnssec_ok(&up), wire::dnssec_ok(q), "DO kept upstream");
            assert_eq!(up[2..4], q[2..4], "flags (CD) kept upstream");
            ups.push(up);
        }
        assert_eq!((r.stats.forwarded, r.stats.merged), (3, 0));
        for (i, up) in ups.iter().enumerate() {
            reply(&r.handle_upstream(10, UP1, &answer(up, Ipv4Addr::new(93, 184, 216, i as u8), 300)));
        }
        // Each kind of client gets its own answer from the cache.
        for (i, q) in [&plain, &dnssec, &cd].into_iter().enumerate() {
            let a = r.handle_query(1000, client(9), q);
            let (_, d) = reply(&a);
            let recs = wire::records(d).unwrap();
            assert_eq!(wire::answer_ipv4s(d, &recs), vec![Ipv4Addr::new(93, 184, 216, i as u8)], "client kind {i}");
        }
        assert_eq!(r.stats.cache_hits, 3);
        // Same flags: merged as before.
        let other = dnssec_query(4, "other.example", true, false);
        upstream(&r.handle_query(0, client(1), &other));
        assert!(r.handle_query(0, client(2), &dnssec_query(5, "other.example", true, false)).is_empty());
        assert_eq!(r.stats.merged, 1);
    }
}
