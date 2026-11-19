//! Connection tracking with source NAT (NAPT / masquerade).
//!
//! - A connection has an **original** tuple (as sent by the initiator) and a
//!   **reply** tuple (what the responder's packets look like). Both are
//!   indexed, so a lookup tells the direction.
//! - **NAT**: when a LAN host opens a connection out of the WAN, the reply
//!   tuple targets `wan_ip:nat_port`. Mappings are **endpoint-independent**
//!   (RFC 4787 EIM): one internal `ip:port` keeps the same external port for
//!   every destination (good for games/VoIP), while filtering stays
//!   endpoint-dependent (only replies from contacted peers get in).
//! - **DNAT** (port forwards, [`Conntrack::create_dnat`]): a connection to
//!   the WAN address is sent on to an internal target; with hairpin, the
//!   source is translated to the router too, so the target answers through
//!   it. Forwarded ports are reserved: NAPT never allocates them, except
//!   to the forward's own target ([`Conntrack::create_from`]): its
//!   connections out keep the forwarded port, so a peer it contacted that
//!   then connects to the forward meets the same connection.
//! - Bounded: at most `max_conns` entries, and with a shared [`Budget`] at
//!   most its `max` across all shards (one endpoint's connections all live
//!   in one shard: a torrent client's listen port). A new connection that
//!   finds the table full (or the shard's NAT ports taken) **early-drops**
//!   one connection that is not assured: a few slots after the last
//!   eviction are sampled ([`EVICT_SCAN`]) and the one closest to expiry
//!   goes, so a host flooding the table with connections that never get an
//!   answer (a scan, a SYN flood to a port forward) makes room for everyone
//!   else instead of locking them out. Only when the sample holds assured
//!   connections only is the new one refused. Expired connections not yet
//!   removed count as unassured, and a packet that finds one
//!   ([`Conntrack::lookup_live`]) removes it, so [`Conntrack::expire_some`]
//!   may bound its work per pass (it holds the shard's lock).
//! - Per host: with [`Budget::with_host_limit`], one initiator (the
//!   original source: a LAN host going out, an outside host connecting to
//!   a port forward) holds at most `per_host` connections across all
//!   shards, so even answered connections of one host cannot fill the
//!   table. Beyond it the host's own unassured connections are
//!   early-dropped, else the new one is refused (`host_limit`). Counted in
//!   [`HOST_BUCKETS`] keyed buckets: hosts sharing a bucket share a limit.
//! - TCP state is tracked loosely (enough for timeouts): SYN → established
//!   on the initiator's ACK after the reply SYN+ACK, FIN/RST → closing.

use crate::wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// Buckets of the per-host connection counts (16 KiB of counters).
pub const HOST_BUCKETS: usize = 4096;

/// A connection limit shared by the shards of one table
/// ([`Conntrack::set_budget`]), optionally with a limit per initiating
/// host. Checked before a connection is created, so concurrent shards may
/// overshoot either by a connection each.
#[derive(Debug)]
pub struct Budget {
    used: AtomicUsize,
    max: usize,
    /// Connections per initiating host (0: no limit).
    per_host: usize,
    /// Per bucket of [`Budget::bucket`]: connections whose original source
    /// falls in it (empty without a host limit).
    hosts: Vec<AtomicU32>,
    key: u64,
}

impl Budget {
    pub fn new(max: usize) -> Arc<Self> {
        Self::with_host_limit(max, 0, 0)
    }

    /// At most `max` connections, and at most `per_host` (0: no limit)
    /// initiated by one source address. `key` (random per boot) keeps
    /// outside hosts from choosing which bucket they share.
    pub fn with_host_limit(max: usize, per_host: usize, key: u64) -> Arc<Self> {
        let n = if per_host > 0 { HOST_BUCKETS } else { 0 };
        Arc::new(Self {
            used: AtomicUsize::new(0),
            max,
            per_host,
            hosts: (0..n).map(|_| AtomicU32::new(0)).collect(),
            key,
        })
    }

    /// Connections tracked by all shards.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// The per-host limit (0: none).
    pub fn per_host(&self) -> usize {
        self.per_host
    }

    fn bucket(&self, host: Ipv4Addr) -> Option<&AtomicU32> {
        let n = self.hosts.len();
        (n > 0).then(|| &self.hosts[mix(self.key ^ 0x6a09_e667, u32::from(host) as u64) as usize % n])
    }

    /// Connections counted for `host`'s bucket (0 without a host limit).
    pub fn host_used(&self, host: Ipv4Addr) -> usize {
        self.bucket(host).map_or(0, |b| b.load(Ordering::Relaxed) as usize)
    }

    fn host_at_limit(&self, host: Ipv4Addr) -> bool {
        self.per_host > 0 && self.host_used(host) >= self.per_host
    }

    fn count(&self, host: Ipv4Addr, add: bool) {
        if add {
            self.used.fetch_add(1, Ordering::Relaxed);
        } else {
            self.used.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(b) = self.bucket(host) {
            if add {
                b.fetch_add(1, Ordering::Relaxed);
            } else {
                b.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// Inclusive NAT port range. Router-local sockets use ports >= 60000
/// (`forwarder::ROUTER_CLIENT_PORTS`); port forwards may use the rest.
pub const NAT_PORTS: (u16, u16) = (10_000, 39_999);

/// Connection slots an early drop looks at (from where the last one
/// stopped), so a full table costs a bounded scan per new connection.
pub const EVICT_SCAN: usize = 64;

/// Timeouts in milliseconds.
pub mod timeout {
    pub const TCP_SYN: u64 = 120_000;
    pub const TCP_ESTABLISHED: u64 = 7_200_000;
    pub const TCP_CLOSING: u64 = 120_000;
    pub const TCP_CLOSED: u64 = 10_000;
    pub const UDP_UNREPLIED: u64 = 30_000;
    pub const UDP_ASSURED: u64 = 180_000;
    pub const ICMP: u64 = 30_000;
}

/// Protocol + addresses + ports. For ICMP echo, both ports hold the identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tuple {
    pub proto: u8,
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
}

impl Tuple {
    pub fn inverse(&self) -> Tuple {
        Tuple {
            proto: self.proto,
            src: self.dst,
            sport: self.dport,
            dst: self.src,
            dport: self.sport,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Original,
    Reply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    Established,
    Closing,
    Closed,
}

#[derive(Clone, Debug)]
pub struct Conn {
    pub orig: Tuple,
    pub reply: Tuple,
    /// Translated in some way (packets are rewritten to [`Conn::translated`]).
    pub nat: bool,
    /// Holds a reference on the endpoint-independent mapping of
    /// `(proto, orig.src, orig.sport)` (masquerade, hairpin).
    pub mapped: bool,
    pub tcp: Option<TcpState>,
    /// TCP: the side that answered the SYN with SYN+ACK in this handshake;
    /// a plain ACK from the other side then establishes the connection.
    pub synack_from: Option<Dir>,
    /// A reply has been seen.
    pub replied: bool,
    pub expires: u64,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    /// Hashes for CAKE (pre-NAT): flow and the two hosts of the original tuple.
    pub flow_hash: u32,
    pub orig_src_hash: u16,
    pub orig_dst_hash: u16,
}

impl Conn {
    /// Both sides have spoken: TCP established (a reply, then the
    /// initiator's ACK), UDP/ICMP replied. Others are early-drop candidates.
    pub fn assured(&self) -> bool {
        match self.tcp {
            Some(st) => st == TcpState::Established,
            None => self.replied,
        }
    }

    /// The tuple a packet in `dir` must be rewritten to (for NAT).
    pub fn translated(&self, dir: Dir) -> Tuple {
        match dir {
            Dir::Original => self.reply.inverse(),
            Dir::Reply => self.orig.inverse(),
        }
    }
}

pub type ConnId = usize;

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub created: u64,
    pub expired: u64,
    pub table_full: u64,
    pub nat_exhausted: u64,
    /// New connections refused because a tracked one already has one of
    /// their tuples.
    pub clashes: u64,
    /// Connections that were not assured, removed to make room for a new
    /// one (full table, NAT ports taken or the host at its limit).
    pub early_drops: u64,
    /// New connections refused: their host is at the per-host limit.
    pub host_limit: u64,
}

/// Endpoint-independent NAT mapping: internal endpoint → external port.
#[derive(Clone, Copy, Debug)]
struct Mapping {
    port: u16,
    refs: u32,
}

pub struct Conntrack {
    conns: Vec<Option<Conn>>,
    free: Vec<ConnId>,
    index: BTreeMap<Tuple, (ConnId, Dir)>,
    /// (proto, internal ip, internal port) → mapping
    mappings: BTreeMap<(u8, Ipv4Addr, u16), Mapping>,
    /// (proto, external port) in use
    used_ports: BTreeMap<(u8, u16), ()>,
    /// (proto, lo, hi): ports never allocated (port forwards).
    reserved: Vec<(u8, u16, u16)>,
    max_conns: usize,
    budget: Option<Arc<Budget>>,
    /// Slot where the next early drop starts looking.
    evict_cursor: usize,
    /// Slot where the next bounded expiry pass continues.
    expire_cursor: usize,
    hash_key: u64,
    /// This table is shard `shard` of `shards` (`forwarder::shard_of`): it
    /// only allocates NAT ports `p` with `p % shards == shard`, so a reply
    /// to an external port finds its shard without a lookup.
    shards: u16,
    shard: u16,
    pub stats: Stats,
}

/// Keyed 64-bit mix (splitmix64 finaliser). The key is random per boot so
/// remote hosts cannot aim for CAKE hash collisions.
pub fn mix(key: u64, v: u64) -> u64 {
    let mut z = v ^ key;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn tuple_hash(key: u64, t: &Tuple) -> u32 {
    let a = (u32::from(t.src) as u64) << 32 | u32::from(t.dst) as u64;
    let b = (t.sport as u64) << 32 | (t.dport as u64) << 8 | t.proto as u64;
    mix(key, mix(key, a) ^ b) as u32
}

fn host_hash(key: u64, a: Ipv4Addr) -> u16 {
    mix(key ^ 0x5bd1_e995, u32::from(a) as u64) as u16
}

impl Conntrack {
    pub fn new(max_conns: usize, hash_key: u64) -> Self {
        Self::new_shard(max_conns, hash_key, 1, 0)
    }

    /// Shard `shard` of `shards` (all shards share `hash_key`).
    pub fn new_shard(max_conns: usize, hash_key: u64, shards: u16, shard: u16) -> Self {
        assert!(
            shards >= 1 && shard < shards,
            "conntrack: bad shard {shard}/{shards}"
        );
        Self {
            conns: Vec::new(),
            free: Vec::new(),
            index: BTreeMap::new(),
            mappings: BTreeMap::new(),
            used_ports: BTreeMap::new(),
            reserved: Vec::new(),
            max_conns,
            budget: None,
            evict_cursor: 0,
            expire_cursor: 0,
            hash_key,
            shards,
            shard,
            stats: Stats::default(),
        }
    }

    /// Also count against `budget` (shared with the other shards). Call
    /// before the first connection.
    pub fn set_budget(&mut self, budget: Arc<Budget>) {
        debug_assert!(self.is_empty(), "conntrack: budget set on a used table");
        self.budget = Some(budget);
    }

    /// No room for another connection initiated by `host`: at its limit
    /// even after early-dropping one of its own (counted as host-limit), or
    /// the table full even after an early drop (counted as table-full).
    fn no_room(&mut self, now: u64, host: Ipv4Addr) -> bool {
        let at_limit = |ct: &Self| ct.budget.as_ref().is_some_and(|b| b.host_at_limit(host));
        if at_limit(self) && !(self.evict_where(now, |_, c| c.orig.src == host) && !at_limit(self)) {
            self.stats.host_limit += 1;
            return true;
        }
        self.full(now)
    }

    /// No room for another connection, even after an early drop (counted
    /// as table-full).
    fn full(&mut self, now: u64) -> bool {
        let at_max = |ct: &Self| ct.len() >= ct.max_conns || ct.budget.as_ref().is_some_and(|b| b.used() >= b.max);
        if !at_max(self) || (self.evict_one(now, None) && !at_max(self)) {
            return false;
        }
        self.stats.table_full += 1;
        true
    }

    /// Early drop: of the [`EVICT_SCAN`] slots from the cursor, remove the
    /// connection that is not assured (or expired) and expires first. With `nat_proto`,
    /// only one whose removal frees an external port of that protocol (the
    /// last connection of its mapping). False if the sample has none.
    fn evict_one(&mut self, now: u64, nat_proto: Option<u8>) -> bool {
        match nat_proto {
            None => self.evict_where(now, |_, _| true),
            Some(proto) => self.evict_where(now, |ct, c| {
                c.mapped
                    && c.orig.proto == proto
                    && ct.mappings.get(&(c.orig.proto, c.orig.src, c.orig.sport)).is_some_and(|m| m.refs == 1)
            }),
        }
    }

    /// Early drop among the sampled connections that are not assured (or
    /// have expired) and pass `pick`: the one that expires first.
    fn evict_where(&mut self, now: u64, pick: impl Fn(&Self, &Conn) -> bool) -> bool {
        let n = self.conns.len();
        if n == 0 {
            return false;
        }
        let start = self.evict_cursor % n;
        let mut best: Option<(u64, ConnId)> = None;
        for i in 0..EVICT_SCAN.min(n) {
            let id = (start + i) % n;
            let Some(c) = &self.conns[id] else { continue };
            if (c.assured() && c.expires > now) || !pick(self, c) {
                continue;
            }
            if best.is_none_or(|(e, _)| c.expires < e) {
                best = Some((c.expires, id));
            }
        }
        self.evict_cursor = (start + EVICT_SCAN) % n;
        let Some((_, id)) = best else { return false };
        self.remove(id);
        self.stats.early_drops += 1;
        true
    }

    /// `(shards, shard)` of this table.
    pub fn shard(&self) -> (u16, u16) {
        (self.shards, self.shard)
    }

    pub fn len(&self) -> usize {
        self.index.len() / 2
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn lookup(&self, t: &Tuple) -> Option<(ConnId, Dir)> {
        self.index.get(t).copied()
    }

    /// [`Conntrack::lookup`], but a connection that has expired (and the
    /// bounded expiry has not reached yet) is removed and not found.
    pub fn lookup_live(&mut self, now: u64, t: &Tuple) -> Option<(ConnId, Dir)> {
        let (id, dir) = self.lookup(t)?;
        if self.conns[id].as_ref().is_some_and(|c| c.expires <= now) {
            self.remove(id);
            self.stats.expired += 1;
            return None;
        }
        Some((id, dir))
    }

    pub fn get(&self, id: ConnId) -> Option<&Conn> {
        self.conns.get(id).and_then(Option::as_ref)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Conn> {
        self.conns.iter().flatten()
    }

    /// Every connection with its id (for [`Conntrack::remove`]).
    pub fn iter_ids(&self) -> impl Iterator<Item = (ConnId, &Conn)> {
        self.conns.iter().enumerate().filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
    }

    fn alloc_port(&mut self, proto: u8, preferred: u16) -> Option<u16> {
        let (lo, hi) = NAT_PORTS;
        let span = (hi - lo) as u32 + 1;
        let start = if (lo..=hi).contains(&preferred) {
            preferred
        } else {
            lo + (mix(self.hash_key, preferred as u64) as u32 % span) as u16
        };
        // Only this shard's ports (`p % shards == shard`): the first one
        // at or above `start`, then upwards, wrapping around.
        let (n, k) = (self.shards as u32, self.shard as u32);
        let first = lo as u32 + (k + n - lo as u32 % n) % n;
        if first > hi as u32 {
            return None;
        }
        let count = (hi as u32 - first) / n + 1;
        let skip = (start as u32).saturating_sub(first).div_ceil(n) % count;
        (0..count)
            .map(|i| (first + ((skip + i) % count) * n) as u16)
            .filter(|p| !self.reserved.iter().any(|&(rp, lo, hi)| rp == proto && (lo..=hi).contains(p)))
            .find(|p| !self.used_ports.contains_key(&(proto, *p)))
    }

    /// [`Conntrack::alloc_port`], early-dropping a connection to free a
    /// port when they are all taken.
    fn alloc_port_or_evict(&mut self, now: u64, proto: u8, preferred: u16) -> Option<u16> {
        self.alloc_port(proto, preferred)
            .or_else(|| self.evict_one(now, Some(proto)).then(|| self.alloc_port(proto, preferred)).flatten())
    }

    /// Ports NAPT must not allocate: `(proto, lo, hi)` (the WAN ports of
    /// port forwards). Existing mappings are kept.
    pub fn set_reserved(&mut self, reserved: Vec<(u8, u16, u16)>) {
        self.reserved = reserved;
    }

    /// The external port of `(proto, ip, port)`'s mapping, allocating one.
    fn map_port(&mut self, now: u64, orig: &Tuple) -> Option<u16> {
        let key = (orig.proto, orig.src, orig.sport);
        match self.mappings.get(&key) {
            Some(m) => Some(m.port),
            None => self.alloc_port_or_evict(now, orig.proto, orig.sport),
        }
    }

    fn insert(&mut self, now: u64, orig: Tuple, reply: Tuple, nat: bool, mapped: bool, tcp_flags: u8) -> Option<ConnId> {
        if self.index.contains_key(&orig) || self.index.contains_key(&reply) {
            self.stats.clashes += 1;
            return None; // clash (e.g. two internal hosts, same remote, same EIM port race)
        }
        if mapped {
            let key = (orig.proto, orig.src, orig.sport);
            let m = self.mappings.entry(key).or_insert(Mapping {
                port: reply.dport,
                refs: 0,
            });
            m.refs += 1;
            self.used_ports.insert((orig.proto, reply.dport), ());
        }
        let conn = Conn {
            orig,
            reply,
            nat,
            mapped,
            tcp: (orig.proto == PROTO_TCP).then_some(TcpState::SynSent),
            synack_from: None,
            replied: false,
            expires: now + initial_timeout(orig.proto, tcp_flags),
            packets: [0; 2],
            bytes: [0; 2],
            flow_hash: tuple_hash(self.hash_key, &orig),
            orig_src_hash: host_hash(self.hash_key, orig.src),
            orig_dst_hash: host_hash(self.hash_key, orig.dst),
        };
        let id = match self.free.pop() {
            Some(id) => {
                self.conns[id] = Some(conn);
                id
            }
            None => {
                self.conns.push(Some(conn));
                self.conns.len() - 1
            }
        };
        self.index.insert(orig, (id, Dir::Original));
        self.index.insert(reply, (id, Dir::Reply));
        if let Some(b) = &self.budget {
            b.count(orig.src, true);
        }
        self.stats.created += 1;
        Some(id)
    }

    /// Track a new connection to a port forward: `orig` (to the router's
    /// WAN address) goes on to `to` (internal ip, port). `masq` (hairpin:
    /// the client is internal too): its source becomes `masq:<mapped
    /// port>`, so the target answers through the router.
    pub fn create_dnat(
        &mut self,
        now: u64,
        orig: Tuple,
        to: (Ipv4Addr, u16),
        masq: Option<Ipv4Addr>,
        tcp_flags: u8,
    ) -> Option<ConnId> {
        if self.no_room(now, orig.src) {
            return None;
        }
        let (dst, dport) = match masq {
            Some(ip) => match self.map_port(now, &orig) {
                Some(p) => (ip, p),
                None => {
                    self.stats.nat_exhausted += 1;
                    return None;
                }
            },
            None => (orig.src, orig.sport),
        };
        let reply = Tuple {
            proto: orig.proto,
            src: to.0,
            sport: to.1,
            dst,
            dport,
        };
        self.insert(now, orig, reply, true, masq.is_some(), tcp_flags)
    }

    /// Track a new connection whose first packet is `orig`. With `nat_ip`
    /// set, the source is translated to `nat_ip:<allocated port>`.
    pub fn create(
        &mut self,
        now: u64,
        orig: Tuple,
        nat_ip: Option<Ipv4Addr>,
        tcp_flags: u8,
    ) -> Option<ConnId> {
        self.create_from(now, orig, nat_ip, None, tcp_flags)
    }

    /// [`Conntrack::create`], and with NAT a new mapping takes external
    /// port `fixed` when it is free, reserved or not (a port forward's
    /// target going out: the forwarded port). The source's existing mapping
    /// wins; a taken `port` falls back to allocation.
    pub fn create_from(
        &mut self,
        now: u64,
        orig: Tuple,
        nat_ip: Option<Ipv4Addr>,
        fixed: Option<u16>,
        tcp_flags: u8,
    ) -> Option<ConnId> {
        if self.no_room(now, orig.src) {
            return None;
        }
        let (reply, nat) = match nat_ip {
            Some(ip) => {
                let key = (orig.proto, orig.src, orig.sport);
                let free = fixed.filter(|p| !self.used_ports.contains_key(&(orig.proto, *p)));
                let port = match (self.mappings.get(&key), free) {
                    (Some(m), _) => m.port,
                    (None, Some(p)) => p,
                    (None, None) => match self.alloc_port_or_evict(now, orig.proto, orig.sport) {
                        Some(p) => p,
                        None => {
                            self.stats.nat_exhausted += 1;
                            return None;
                        }
                    },
                };
                let mut r = Tuple {
                    proto: orig.proto,
                    src: orig.dst,
                    sport: orig.dport,
                    dst: ip,
                    dport: port,
                };
                if orig.proto == PROTO_ICMP {
                    r.sport = port; // echo replies carry the (translated) identifier
                }
                (r, true)
            }
            None => (orig.inverse(), false),
        };
        self.insert(now, orig, reply, nat, nat, tcp_flags)
    }

    /// Account a packet and advance state/timeouts.
    pub fn update(&mut self, now: u64, id: ConnId, dir: Dir, tcp_flags: u8, bytes: usize) {
        let Some(c) = self.conns.get_mut(id).and_then(Option::as_mut) else {
            return;
        };
        let d = dir as usize;
        c.packets[d] += 1;
        c.bytes[d] += bytes as u64;
        if dir == Dir::Reply {
            c.replied = true;
        }
        let t = match c.orig.proto {
            PROTO_TCP => {
                let st = c.tcp.get_or_insert(TcpState::SynSent);
                if tcp_flags & (TCP_SYN | TCP_ACK | TCP_RST) == TCP_SYN
                    && matches!(*st, TcpState::Closing | TcpState::Closed)
                {
                    // The tuple reused by a new connection (a peer
                    // reconnecting from the same port): start over, else
                    // it lives on the closing timeout and its packets are
                    // invalid once that runs out while it idles.
                    *st = TcpState::SynSent;
                    c.replied = dir == Dir::Reply;
                    c.synack_from = None;
                }
                if tcp_flags & TCP_RST != 0 {
                    *st = TcpState::Closed;
                } else if tcp_flags & TCP_FIN != 0 {
                    *st = TcpState::Closing;
                } else if *st == TcpState::SynSent {
                    let syn_ack = tcp_flags & (TCP_SYN | TCP_ACK);
                    if syn_ack == (TCP_SYN | TCP_ACK) {
                        c.synack_from = Some(dir);
                    } else if syn_ack == TCP_ACK && c.synack_from.is_some_and(|d| d != dir) {
                        // The initiator's ACK after the SYN+ACK: the
                        // handshake is complete. Not the SYN+ACK alone, else
                        // a spoofed SYN flood to an answering port forward
                        // would pin entries for the established timeout.
                        *st = TcpState::Established;
                    }
                }
                match *st {
                    TcpState::SynSent => timeout::TCP_SYN,
                    TcpState::Established => timeout::TCP_ESTABLISHED,
                    TcpState::Closing => timeout::TCP_CLOSING,
                    TcpState::Closed => timeout::TCP_CLOSED,
                }
            }
            PROTO_UDP if c.replied => timeout::UDP_ASSURED,
            PROTO_UDP => timeout::UDP_UNREPLIED,
            _ => timeout::ICMP,
        };
        c.expires = now + t;
    }

    /// Forget a connection (and release its NAT mapping reference).
    pub fn remove(&mut self, id: ConnId) {
        let Some(c) = self.conns.get_mut(id).and_then(Option::take) else {
            return;
        };
        self.index.remove(&c.orig);
        self.index.remove(&c.reply);
        if let Some(b) = &self.budget {
            b.count(c.orig.src, false);
        }
        if c.mapped {
            let key = (c.orig.proto, c.orig.src, c.orig.sport);
            if let Some(m) = self.mappings.get_mut(&key) {
                m.refs -= 1;
                if m.refs == 0 {
                    self.used_ports.remove(&(c.orig.proto, m.port));
                    self.mappings.remove(&key);
                }
            }
        }
        self.free.push(id);
    }

    /// Remove expired connections; returns how many. O(n): call about once a second.
    pub fn expire(&mut self, now: u64) -> usize {
        self.expire_some(now, usize::MAX)
    }

    /// Remove at most `max` expired connections, continuing where the last
    /// pass stopped; returns how many. Scans the whole table at most once
    /// (cheap); removals are what cost, so `max` bounds the lock hold.
    pub fn expire_some(&mut self, now: u64, max: usize) -> usize {
        let len = self.conns.len();
        let mut n = 0;
        let mut i = 0;
        while i < len && n < max {
            let id = (self.expire_cursor + i) % len;
            if self.conns[id].as_ref().is_some_and(|c| c.expires <= now) {
                self.remove(id);
                n += 1;
            }
            i += 1;
        }
        if len > 0 {
            self.expire_cursor = (self.expire_cursor + i) % len;
        }
        self.stats.expired += n as u64;
        n
    }

    /// Drop all NAT state for an external address (e.g. the WAN lease changed).
    pub fn flush_nat(&mut self) {
        for id in 0..self.conns.len() {
            if self.conns[id].as_ref().is_some_and(|c| c.nat) {
                self.remove(id);
            }
        }
    }
}

fn initial_timeout(proto: u8, _tcp_flags: u8) -> u64 {
    match proto {
        PROTO_TCP => timeout::TCP_SYN,
        PROTO_UDP => timeout::UDP_UNREPLIED,
        _ => timeout::ICMP,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const LAN_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const LAN_B: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 101);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const REMOTE2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
    const WAN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    fn t(proto: u8, src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16) -> Tuple {
        Tuple {
            proto,
            src,
            sport,
            dst,
            dport,
        }
    }

    #[test]
    fn nat_creates_reply_tuple_and_preserves_port_when_possible() {
        let mut ct = Conntrack::new(100, 1);
        let o = t(PROTO_UDP, LAN_A, 12345, REMOTE, 53);
        let id = ct.create(0, o, Some(WAN), 0).unwrap();
        let c = ct.get(id).unwrap();
        assert_eq!(c.reply, t(PROTO_UDP, REMOTE, 53, WAN, 12345));
        assert_eq!(ct.lookup(&c.reply), Some((id, Dir::Reply)));
        assert_eq!(
            c.translated(Dir::Original),
            t(PROTO_UDP, WAN, 12345, REMOTE, 53)
        );
        assert_eq!(
            c.translated(Dir::Reply),
            t(PROTO_UDP, REMOTE, 53, LAN_A, 12345)
        );
    }

    #[test]
    fn endpoint_independent_mapping_and_unique_ports() {
        let mut ct = Conntrack::new(100, 1);
        let a1 = ct
            .create(0, t(PROTO_UDP, LAN_A, 20000, REMOTE, 1000), Some(WAN), 0)
            .unwrap();
        let a2 = ct
            .create(0, t(PROTO_UDP, LAN_A, 20000, REMOTE2, 2000), Some(WAN), 0)
            .unwrap();
        assert_eq!(
            ct.get(a1).unwrap().reply.dport,
            ct.get(a2).unwrap().reply.dport,
            "same mapping for both peers"
        );
        // A second host using the same source port gets a different external port.
        let b = ct
            .create(0, t(PROTO_UDP, LAN_B, 20000, REMOTE, 1000), Some(WAN), 0)
            .unwrap();
        assert_ne!(ct.get(b).unwrap().reply.dport, 20000);
        let p = ct.get(b).unwrap().reply.dport;
        assert!((NAT_PORTS.0..=NAT_PORTS.1).contains(&p));
    }

    #[test]
    fn mapping_is_released_with_the_last_connection() {
        let mut ct = Conntrack::new(100, 1);
        ct.create(0, t(PROTO_UDP, LAN_A, 20000, REMOTE, 1), Some(WAN), 0)
            .unwrap();
        ct.create(0, t(PROTO_UDP, LAN_A, 20000, REMOTE2, 1), Some(WAN), 0)
            .unwrap();
        assert_eq!(ct.expire(timeout::UDP_UNREPLIED), 2);
        assert!(ct.is_empty() && ct.mappings.is_empty() && ct.used_ports.is_empty());
    }

    #[test]
    fn tcp_state_drives_timeouts() {
        let mut ct = Conntrack::new(100, 1);
        let id = ct
            .create(
                0,
                t(PROTO_TCP, LAN_A, 40000, REMOTE, 80),
                Some(WAN),
                TCP_SYN,
            )
            .unwrap();
        assert_eq!(ct.get(id).unwrap().expires, timeout::TCP_SYN);
        // The SYN+ACK alone is half-open (SYN timeout, early-droppable).
        ct.update(10, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
        assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::SynSent));
        assert_eq!(ct.get(id).unwrap().expires, 10 + timeout::TCP_SYN);
        assert!(!ct.get(id).unwrap().assured());
        ct.update(15, id, Dir::Original, TCP_ACK, 60);
        assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::Established));
        assert_eq!(ct.get(id).unwrap().expires, 15 + timeout::TCP_ESTABLISHED);
        assert!(ct.get(id).unwrap().assured());
        ct.update(20, id, Dir::Original, TCP_FIN | TCP_ACK, 60);
        assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::Closing));
        ct.update(30, id, Dir::Reply, TCP_RST, 60);
        assert_eq!(ct.get(id).unwrap().expires, 30 + timeout::TCP_CLOSED);
        assert_eq!(ct.get(id).unwrap().packets, [2, 2]);
    }

    #[test]
    fn a_new_syn_reopens_a_closed_connection() {
        let mut ct = Conntrack::new(100, 1);
        for end in [TCP_RST, TCP_FIN | TCP_ACK] {
            let id = ct
                .create(0, t(PROTO_TCP, LAN_A, 40000, REMOTE, 6881), Some(WAN), TCP_SYN)
                .unwrap();
            ct.update(0, id, Dir::Original, TCP_SYN, 60);
            ct.update(1, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
            ct.update(2, id, Dir::Original, end, 60);
            assert_ne!(ct.get(id).unwrap().tcp, Some(TcpState::Established));
            // The same tuple again: SYN, SYN+ACK, ACK.
            ct.update(3, id, Dir::Original, TCP_SYN, 60);
            assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::SynSent));
            ct.update(4, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
            ct.update(5, id, Dir::Original, TCP_ACK, 60);
            let c = ct.get(id).unwrap();
            assert_eq!(c.tcp, Some(TcpState::Established));
            assert_eq!(c.expires, 5 + timeout::TCP_ESTABLISHED);
            ct.remove(id);
        }
        // A SYN arriving from the other side (the responder now connects).
        let id = ct
            .create(0, t(PROTO_TCP, LAN_A, 40000, REMOTE, 6881), Some(WAN), TCP_SYN)
            .unwrap();
        ct.update(0, id, Dir::Original, TCP_RST, 40);
        ct.update(1, id, Dir::Reply, TCP_SYN, 60);
        ct.update(2, id, Dir::Original, TCP_SYN | TCP_ACK, 60);
        ct.update(3, id, Dir::Reply, TCP_ACK, 60);
        assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::Established));
    }

    #[test]
    fn udp_becomes_assured_after_reply() {
        let mut ct = Conntrack::new(100, 1);
        let id = ct
            .create(0, t(PROTO_UDP, LAN_A, 1, REMOTE, 2), Some(WAN), 0)
            .unwrap();
        ct.update(5, id, Dir::Reply, 0, 10);
        assert_eq!(ct.get(id).unwrap().expires, 5 + timeout::UDP_ASSURED);
    }

    #[test]
    fn icmp_echo_identifier_is_translated() {
        let mut ct = Conntrack::new(100, 1);
        ct.create(0, t(PROTO_ICMP, LAN_A, 7, REMOTE, 7), Some(WAN), 0)
            .unwrap();
        let id = ct
            .create(0, t(PROTO_ICMP, LAN_B, 7, REMOTE, 7), Some(WAN), 0)
            .unwrap();
        let r = ct.get(id).unwrap().reply;
        assert_eq!(
            r.sport, r.dport,
            "echo reply tuple uses the id in both port slots"
        );
        assert_ne!(r.dport, 7);
    }

    #[test]
    fn table_is_bounded() {
        // Assured (replied) connections are never early-dropped: a full
        // table of them refuses new ones.
        let mut ct = Conntrack::new(2, 1);
        for p in 1..=2 {
            let id = ct.create(0, t(PROTO_UDP, LAN_A, p, REMOTE, 1), Some(WAN), 0).unwrap();
            ct.update(0, id, Dir::Reply, 0, 10);
        }
        assert!(
            ct.create(0, t(PROTO_UDP, LAN_A, 3, REMOTE, 1), Some(WAN), 0)
                .is_none()
        );
        assert_eq!((ct.stats.table_full, ct.stats.early_drops), (1, 0));
    }

    /// Every index, mapping, port and budget count agrees with the
    /// connections (after any sequence of operations).
    fn check_invariants(ct: &Conntrack, budget: Option<&Budget>) {
        let live: Vec<(ConnId, &Conn)> = ct.iter_ids().collect();
        assert_eq!(ct.index.len(), 2 * live.len(), "two index entries per connection");
        assert!(live.len() <= ct.max_conns);
        let mut refs: BTreeMap<(u8, Ipv4Addr, u16), u32> = BTreeMap::new();
        for &(id, c) in &live {
            assert_eq!(ct.index.get(&c.orig), Some(&(id, Dir::Original)));
            assert_eq!(ct.index.get(&c.reply), Some(&(id, Dir::Reply)));
            if c.mapped {
                *refs.entry((c.orig.proto, c.orig.src, c.orig.sport)).or_default() += 1;
            }
        }
        assert_eq!(ct.mappings.len(), refs.len(), "a mapping per mapped endpoint");
        for (k, m) in &ct.mappings {
            assert_eq!(refs.get(k), Some(&m.refs), "mapping refs of {k:?}");
            assert!(ct.used_ports.contains_key(&(k.0, m.port)));
            assert_eq!(m.port % ct.shards, ct.shard, "NAT port from this shard");
        }
        assert_eq!(ct.used_ports.len(), ct.mappings.len());
        for &id in &ct.free {
            assert!(ct.conns[id].is_none(), "free slot {id} in use");
        }
        assert_eq!(ct.free.len() + live.len(), ct.conns.len());
        if let Some(b) = budget {
            assert_eq!(b.used(), live.len());
            check_host_counts(&[ct], b);
        }
    }

    /// The budget's per-host buckets count exactly the connections of
    /// `shards` (all of its users), none above the limit.
    fn check_host_counts(shards: &[&Conntrack], b: &Budget) {
        if b.per_host() == 0 {
            return;
        }
        let bucket = |ip: Ipv4Addr| b.bucket(ip).unwrap() as *const AtomicU32 as usize;
        let mut per_bucket: BTreeMap<usize, usize> = BTreeMap::new();
        for c in shards.iter().flat_map(|s| s.iter()) {
            *per_bucket.entry(bucket(c.orig.src)).or_default() += 1;
        }
        for c in shards.iter().flat_map(|s| s.iter()) {
            assert_eq!(b.host_used(c.orig.src), per_bucket[&bucket(c.orig.src)], "bucket of {}", c.orig.src);
            assert!(b.host_used(c.orig.src) <= b.per_host(), "{} above its limit", c.orig.src);
        }
        let total: usize = b.hosts.iter().map(|h| h.load(Ordering::Relaxed) as usize).sum();
        assert_eq!(total, b.used());
    }

    #[test]
    fn a_flood_of_unanswered_connections_does_not_lock_others_out() {
        // A LAN host scanning (UDP and SYNs nobody answers) fills the table
        // over and over; another host's connections still get in, and the
        // ones that are answered survive the whole flood.
        const MAX: usize = 1024;
        let mut ct = Conntrack::new(MAX, 7);
        let mut kept = Vec::new();
        for i in 0..50_000u32 {
            let (proto, port) = if i % 2 == 0 { (PROTO_UDP, 0) } else { (PROTO_TCP, 0) };
            let dst = Ipv4Addr::from(0x0a00_0000 + i);
            let _ = ct.create(i as u64, t(proto, LAN_A, 1024 + (i % 50_000) as u16 + port, dst, 80), Some(WAN), TCP_SYN);
            if i % 100 == 0 {
                let o = t(PROTO_TCP, LAN_B, 40_000 + (i / 100) as u16, REMOTE, 443);
                let id = ct.create(i as u64, o, Some(WAN), TCP_SYN).expect("room for the other host");
                ct.update(i as u64, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
                ct.update(i as u64, id, Dir::Original, TCP_ACK, 60);
                kept.push(o);
            }
        }
        check_invariants(&ct, None);
        assert_eq!(ct.len(), MAX);
        assert_eq!(ct.stats.table_full, 0);
        assert!(ct.stats.early_drops > 40_000);
        for o in &kept {
            assert!(ct.lookup(o).is_some(), "an established connection was dropped: {o:?}");
        }
    }

    #[test]
    fn one_host_cannot_fill_the_table_with_answered_connections() {
        let budget = Budget::with_host_limit(100, 10, 3);
        let mut ct = Conntrack::new(100, 3);
        ct.set_budget(budget.clone());
        for p in 0..10 {
            let id = ct.create(0, t(PROTO_TCP, LAN_A, 1000 + p, REMOTE, 443), Some(WAN), TCP_SYN).unwrap();
            ct.update(0, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
            ct.update(0, id, Dir::Original, TCP_ACK, 60);
        }
        assert!(ct.create(0, t(PROTO_TCP, LAN_A, 2000, REMOTE, 443), Some(WAN), TCP_SYN).is_none());
        assert_eq!((ct.stats.host_limit, ct.stats.table_full, ct.stats.early_drops), (1, 0, 0));
        assert_eq!(budget.host_used(LAN_A), 10);
        // Others are not affected; when the host closes one it may open one.
        assert!(ct.create(0, t(PROTO_TCP, LAN_B, 2000, REMOTE, 443), Some(WAN), TCP_SYN).is_some());
        let (id, _) = ct.iter_ids().find(|(_, c)| c.orig.src == LAN_A).unwrap();
        ct.remove(id);
        assert!(ct.create(0, t(PROTO_TCP, LAN_A, 2000, REMOTE, 443), Some(WAN), TCP_SYN).is_some());
        check_invariants(&ct, Some(&budget));
    }

    #[test]
    fn at_its_limit_a_host_early_drops_its_own_connections_only() {
        let budget = Budget::with_host_limit(100, 10, 3);
        let mut ct = Conntrack::new(100, 3);
        ct.set_budget(budget.clone());
        // LAN_B: unanswered connections that must survive A's flood.
        let b: Vec<Tuple> = (0..5).map(|p| t(PROTO_UDP, LAN_B, 3000 + p, REMOTE, 53)).collect();
        for o in &b {
            ct.create(0, *o, Some(WAN), 0).unwrap();
        }
        for p in 0..1000u16 {
            assert!(ct.create(p as u64, t(PROTO_UDP, LAN_A, 1000 + p, REMOTE, 53), Some(WAN), 0).is_some());
        }
        assert_eq!((budget.host_used(LAN_A), ct.stats.host_limit), (10, 0));
        assert_eq!(ct.stats.early_drops, 990);
        assert!(b.iter().all(|o| ct.lookup(o).is_some()), "the other host's connections were dropped");
        check_invariants(&ct, Some(&budget));
    }

    #[test]
    fn the_host_limit_spans_the_shards() {
        let budget = Budget::with_host_limit(1000, 8, 3);
        let mut shards: Vec<Conntrack> = (0..4).map(|k| Conntrack::new_shard(1000, 3, 4, k)).collect();
        for s in &mut shards {
            s.set_budget(budget.clone());
        }
        let mut ok = 0;
        for p in 0..40u16 {
            let ct = &mut shards[p as usize % 4];
            if let Some(id) = ct.create(0, t(PROTO_UDP, LAN_A, 1000 + p, REMOTE, 53), Some(WAN), 0) {
                ct.update(0, id, Dir::Reply, 0, 10);
                ok += 1;
            }
        }
        assert_eq!(ok, 8);
        assert_eq!(shards.iter().map(|s| s.stats.host_limit).sum::<u64>(), 32);
        assert_eq!(budget.host_used(LAN_A), 8);
    }

    #[test]
    fn expired_connections_are_gone_before_the_pass_removes_them() {
        let mut ct = Conntrack::new(2, 1);
        let mut ids = Vec::new();
        for p in 1..=2 {
            let id = ct.create(0, t(PROTO_UDP, LAN_A, p, REMOTE, 53), Some(WAN), 0).unwrap();
            ct.update(0, id, Dir::Reply, 0, 10);
            ids.push(id);
        }
        let later = timeout::UDP_ASSURED + 1;
        // A packet of an expired connection does not find it (and removes it).
        let reply = ct.get(ids[0]).unwrap().reply;
        assert_eq!(ct.lookup_live(later, &reply), None);
        assert_eq!(ct.len(), 1);
        // A full table of assured but expired connections: early-droppable.
        assert!(ct.create(later, t(PROTO_UDP, LAN_B, 9, REMOTE, 53), Some(WAN), 0).is_some());
        assert!(ct.create(later, t(PROTO_UDP, LAN_B, 10, REMOTE, 53), Some(WAN), 0).is_some());
        assert_eq!((ct.stats.early_drops, ct.stats.table_full), (1, 0));
        check_invariants(&ct, None);
    }

    #[test]
    fn a_bounded_expiry_pass_resumes_where_it_stopped() {
        let mut ct = Conntrack::new(1000, 1);
        for p in 0..1000u16 {
            ct.create(0, t(PROTO_UDP, LAN_A, 1000 + p, REMOTE, 53), Some(WAN), 0).unwrap();
        }
        // Every other one answered (lives on).
        let ids: Vec<ConnId> = ct.iter_ids().map(|(id, _)| id).step_by(2).collect();
        for id in ids {
            ct.update(0, id, Dir::Reply, 0, 10);
        }
        let now = timeout::UDP_UNREPLIED;
        let mut passes = 0;
        while ct.expire_some(now, 64) > 0 {
            passes += 1;
            check_invariants(&ct, None);
        }
        assert_eq!((ct.len(), passes), (500, 8));
        assert!(ct.iter().all(|c| c.replied));
    }

    #[test]
    fn a_syn_flood_to_a_port_forward_is_early_dropped() {
        // Spoofed SYNs to a forward: the target answers each with SYN+ACK,
        // the third packet never comes; still not assured.
        let mut ct = Conntrack::new(64, 3);
        for i in 0..1000u32 {
            let o = t(PROTO_TCP, Ipv4Addr::from(0xc633_6400 + i), 1000 + i as u16, WAN, 8080);
            if let Some(id) = ct.create_dnat(i as u64, o, (LAN_A, 80), None, TCP_SYN) {
                ct.update(i as u64, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
            }
        }
        assert_eq!((ct.len(), ct.stats.table_full), (64, 0));
        check_invariants(&ct, None);
    }

    #[test]
    fn early_drop_frees_nat_ports_of_a_shard() {
        // One of 16 shards owns ~1875 NAT ports per protocol. A host using
        // a new source port per packet takes them all; another host's
        // connection then early-drops one instead of failing.
        let mut ct = Conntrack::new_shard(100_000, 5, 16, 3);
        let mut n = 0;
        for p in 1..=5000u16 {
            if ct.create(0, t(PROTO_UDP, LAN_A, p, REMOTE, 53), Some(WAN), 0).is_some() {
                n += 1;
            }
        }
        assert_eq!(n, 5000, "ports freed by early drops");
        assert_eq!(ct.stats.nat_exhausted, 0);
        assert!(ct.stats.early_drops >= 5000 - 1875);
        let id = ct.create(0, t(PROTO_UDP, LAN_B, 7, REMOTE, 53), Some(WAN), 0).unwrap();
        assert_eq!(ct.get(id).unwrap().reply.dport % 16, 3);
        check_invariants(&ct, None);

        // All ports held by answered connections: refused, counted.
        let mut ct = Conntrack::new_shard(100_000, 5, 16, 3);
        for p in 1..=1875u16 {
            let id = ct.create(0, t(PROTO_UDP, LAN_A, p, REMOTE, 53), Some(WAN), 0).unwrap();
            ct.update(0, id, Dir::Reply, 0, 10);
        }
        assert!(ct.create(0, t(PROTO_UDP, LAN_B, 7, REMOTE, 53), Some(WAN), 0).is_none());
        assert_eq!((ct.stats.nat_exhausted, ct.stats.early_drops), (1, 0));
    }

    #[test]
    fn port_allocation_matches_a_linear_scan() {
        // The shard-stepping allocator picks what walking every port from
        // `start` upwards (wrapping) and keeping this shard's would.
        fn linear(ct: &Conntrack, proto: u8, start: u16) -> Option<u16> {
            let (lo, hi) = NAT_PORTS;
            let span = (hi - lo) as u32 + 1;
            (0..span)
                .map(|i| lo + ((start - lo) as u32 + i).rem_euclid(span) as u16)
                .filter(|p| p % ct.shards == ct.shard)
                .filter(|p| !ct.reserved.iter().any(|&(rp, lo, hi)| rp == proto && (lo..=hi).contains(p)))
                .find(|p| !ct.used_ports.contains_key(&(proto, *p)))
        }
        for (shards, shard) in [(1, 0), (2, 1), (3, 2), (16, 0), (16, 15), (7, 4)] {
            let mut ct = Conntrack::new_shard(10, 9, shards, shard);
            ct.set_reserved(vec![(PROTO_UDP, 39_990, 39_999), (PROTO_UDP, 10_000, 10_020)]);
            for &p in &[10_000, 10_001, 10_017, 25_000, 39_983, 39_999, 39_998] {
                ct.used_ports.insert((PROTO_UDP, p), ());
            }
            for start in (NAT_PORTS.0..=NAT_PORTS.1).step_by(97).chain([10_000, 10_001, 39_984, 39_985, 39_999]) {
                assert_eq!(ct.alloc_port(PROTO_UDP, start), linear(&ct, PROTO_UDP, start), "{shards}/{shard} from {start}");
            }
        }
    }

    #[test]
    fn churn_keeps_the_table_consistent() {
        // Random creates (NAT, plain, DNAT, hairpin), replies, closes,
        // removals and expiry across two shards sharing a small budget.
        let budget = Budget::with_host_limit(300, 60, 11);
        let mut shards: Vec<Conntrack> = (0..2).map(|k| Conntrack::new_shard(300, 11, 2, k)).collect();
        for s in &mut shards {
            s.set_budget(budget.clone());
            s.set_reserved(vec![(PROTO_TCP, 20_000, 20_100)]);
        }
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let protos = [PROTO_TCP, PROTO_UDP, PROTO_ICMP];
        let mut now = 0;
        for round in 0..200_000u32 {
            now += rnd() % 50;
            let r = rnd();
            let ct = &mut shards[(r & 1) as usize];
            let proto = protos[(r >> 1) as usize % 3];
            let host = Ipv4Addr::new(192, 168, 1, 100 + (r >> 8) as u8 % 8);
            let remote = Ipv4Addr::new(198, 51, 100, (r >> 16) as u8 % 4);
            let sport = 1000 + (r >> 24) as u16 % 64;
            match (r >> 40) % 8 {
                0..=2 => {
                    let _ = ct.create(now, t(proto, host, sport, remote, 80), Some(WAN), TCP_SYN);
                }
                3 => {
                    let _ = ct.create(now, t(proto, host, sport, remote, 80), None, TCP_SYN);
                }
                4 => {
                    let masq = (r >> 50) & 1 == 1;
                    let o = t(proto, if masq { host } else { remote }, sport, WAN, 20_000 + (r >> 52) as u16 % 100);
                    let _ = ct.create_dnat(now, o, (LAN_A, 80), masq.then_some(WAN), TCP_SYN);
                }
                5 | 6 => {
                    let ids: Vec<ConnId> = ct.iter_ids().map(|(id, _)| id).collect();
                    if !ids.is_empty() {
                        let id = ids[(r >> 44) as usize % ids.len()];
                        let dir = if (r >> 50) & 1 == 0 { Dir::Reply } else { Dir::Original };
                        let flags = [TCP_SYN | TCP_ACK, TCP_ACK, TCP_FIN | TCP_ACK, TCP_RST, TCP_SYN][(r >> 51) as usize % 5];
                        ct.update(now, id, dir, flags, 100);
                        if (r >> 58) % 2 == 0 {
                            // A whole handshake (UDP/ICMP: a reply): assured.
                            ct.update(now, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
                            ct.update(now, id, Dir::Original, TCP_ACK, 60);
                        }
                        if (r >> 54) % 16 == 0 {
                            ct.remove(id);
                        }
                    }
                }
                _ => {
                    ct.expire(now);
                }
            }
            if round % 1000 == 0 {
                check_invariants(&shards[0], None);
                check_invariants(&shards[1], None);
                assert_eq!(budget.used(), shards[0].len() + shards[1].len());
                assert!(budget.used() <= 300);
                check_host_counts(&[&shards[0], &shards[1]], &budget);
            }
        }
        let early: u64 = shards.iter().map(|s| s.stats.early_drops).sum();
        assert!(early > 0, "early drops exercised");
        // Every connection assured, then the budget filled: refused.
        for ct in &mut shards {
            let ids: Vec<ConnId> = ct.iter_ids().map(|(id, _)| id).collect();
            for id in ids {
                ct.update(now, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
                ct.update(now, id, Dir::Original, TCP_ACK, 60);
                ct.update(now, id, Dir::Reply, TCP_ACK, 60);
            }
        }
        for i in 0..1000u16 {
            let ct = &mut shards[(i & 1) as usize];
            if let Some(id) = ct.create(now, t(PROTO_UDP, LAN_B, 2000 + i, REMOTE, 53), Some(WAN), 0) {
                ct.update(now, id, Dir::Reply, 0, 10);
            }
        }
        assert_eq!(budget.used(), 300);
        assert!(shards.iter().all(|s| s.stats.table_full > 0));
        check_host_counts(&[&shards[0], &shards[1]], &budget);
        // Emptied: one new host fills its limit across both shards.
        for s in &mut shards {
            s.expire(u64::MAX);
        }
        let host = Ipv4Addr::new(10, 9, 8, 7);
        let mut ok = 0;
        for i in 0..100u16 {
            let ct = &mut shards[(i & 1) as usize];
            if let Some(id) = ct.create(now, t(PROTO_UDP, host, 3000 + i, REMOTE, 53), Some(WAN), 0) {
                ct.update(now, id, Dir::Reply, 0, 10);
                ok += 1;
            }
        }
        assert_eq!(ok, 60);
        assert_eq!(shards.iter().map(|s| s.stats.host_limit).sum::<u64>(), 40);
        check_host_counts(&[&shards[0], &shards[1]], &budget);
        check_invariants(&shards[0], None);
        check_invariants(&shards[1], None);
        for s in &mut shards {
            s.expire(u64::MAX);
            s.flush_nat();
            check_invariants(s, None);
            assert!(s.is_empty() && s.mappings.is_empty() && s.used_ports.is_empty());
        }
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn shards_share_one_budget() {
        // Each shard may take the whole table (one endpoint's connections
        // all go to one shard), the shards together no more than it.
        let budget = Budget::new(3);
        let mut a = Conntrack::new_shard(3, 1, 2, 0);
        let mut b = Conntrack::new_shard(3, 1, 2, 1);
        a.set_budget(budget.clone());
        b.set_budget(budget.clone());
        let ids: Vec<_> = (0..3)
            .map(|i| a.create(0, t(PROTO_UDP, LAN_A, 5000, REMOTE, 1000 + i), Some(WAN), 0).unwrap())
            .collect();
        assert!(b.create(0, t(PROTO_UDP, LAN_B, 1, REMOTE, 1), Some(WAN), 0).is_none());
        assert_eq!((b.stats.table_full, budget.used()), (1, 3));
        a.remove(ids[0]);
        assert!(b.create(0, t(PROTO_UDP, LAN_B, 1, REMOTE, 1), Some(WAN), 0).is_some());
        assert_eq!(a.expire(timeout::UDP_UNREPLIED) + b.expire(timeout::UDP_UNREPLIED), 3);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn flow_hashes_are_keyed() {
        let o = t(PROTO_TCP, LAN_A, 1, REMOTE, 2);
        let mut a = Conntrack::new(10, 1);
        let mut b = Conntrack::new(10, 2);
        let ia = a.create(0, o, None, 0).unwrap();
        let ib = b.create(0, o, None, 0).unwrap();
        assert_ne!(a.get(ia).unwrap().flow_hash, b.get(ib).unwrap().flow_hash);
    }
}
