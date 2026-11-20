//! The filtered reflector (docs/mdns.md §3).
//!
//! A [`Rule`] makes the services of one network (`from`) discoverable on
//! others (`to`): queries for them go `to` → `from`, answers and
//! announcements `from` → `to`. Each copy is rebuilt with only the
//! questions and records the rules allow:
//! - names under an allowed service type (`<instance>._ipp._tcp.local`,
//!   `_ipp._tcp.local`, subtypes);
//! - names of hosts learned from allowed SRV records (their A/AAAA/NSEC),
//!   per source network and service type, for the SRV's TTL;
//! - never link-local addresses (169.254/16, fe80::/10).
//!
//! Questions lose the QU bit (answers come back by multicast, so they can
//! be reflected), queries lose their authority section (probes become plain
//! questions: a name in use on the other network is still defended) and
//! additional records. Received messages are dropped when they come from a
//! port other than 5353 (legacy unicast, not handled), from outside the
//! network's subnet (IPv6: link-local or the network's /64s) or from the
//! router itself, when the source network is over its rate, and when they
//! equal a message sent within the last second (another reflector echoing
//! ours). Each copy goes out in the family its message came in on
//! ([`Output::v6`]: to ff02::fb instead of 224.0.0.251).

use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::wire::{CLASS_TOP_BIT, Message, PORT, Record, TYPE_SRV};

/// Index of a network in [`Config::nets`].
pub type NetId = usize;

/// Messages per second a network may send through the reflector, and the
/// burst it may use up at once (a device joining announces many services).
pub const RATE_PER_SEC: u64 = 50;
pub const BURST: u64 = 100;
/// A received message equal to one sent within this window is an echo.
pub const DUP_WINDOW_MS: u64 = 1000;
/// Learned host names (all networks).
pub const MAX_HOSTS: usize = 128;
/// Largest message sent: one unfragmented IPv4 UDP datagram at MTU 1500.
pub const MAX_OUTPUT: usize = 1472;
/// The same over IPv6 (40 bytes of header instead of 20).
pub const MAX_OUTPUT_V6: usize = 1452;
/// Cap on how long a learned host stays (RFC 6762 §10: 75 min for most
/// records).
const MAX_HOST_TTL_SECS: u64 = 4500;
const MAX_RECENT: usize = 64;
/// Distinct service types across all rules (one bit each); more are ignored.
pub const MAX_SERVICES: usize = 128;

/// A DNS-SD service type such as `_ipp._tcp`, stored lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceType {
    service: Vec<u8>,
    proto: Vec<u8>,
}

impl ServiceType {
    /// `_name._tcp` or `_name._udp`; the name is 1–15 letters, digits and
    /// hyphens (RFC 6335 §5.1).
    pub fn parse(s: &str) -> Option<Self> {
        let (service, proto) = s.split_once('.')?;
        let name = service.strip_prefix('_')?;
        let ok = (1..=15).contains(&name.len())
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && name.bytes().any(|c| c.is_ascii_alphabetic())
            && !name.starts_with('-')
            && !name.ends_with('-');
        let proto = proto.to_ascii_lowercase();
        (ok && (proto == "_tcp" || proto == "_udp"))
            .then(|| Self { service: service.to_ascii_lowercase().into_bytes(), proto: proto.into_bytes() })
    }

    /// Whether `name` is this type or below it, in `.local`.
    fn covers(&self, name: &crate::wire::Name) -> bool {
        name.ends_with_ignore_case(&[&self.service, &self.proto, b"local"])
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn s(b: &[u8]) -> &str {
            core::str::from_utf8(b).unwrap_or("?")
        }
        write!(f, "{}.{}", s(&self.service), s(&self.proto))
    }
}

/// The router's address on a network and the network's prefix length;
/// with IPv6, its addresses there (link-local, unique local, global: the
/// last two name the network's /64s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub addrs6: [Option<Ipv6Addr>; 3],
}

impl Net {
    /// An IPv4-only network.
    pub const fn v4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Net { addr, prefix_len, addrs6: [None; 3] }
    }

    fn contains(&self, a: IpAddr) -> bool {
        match a {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix_len.min(32))).unwrap_or(0);
                u32::from(a) & mask == u32::from(self.addr) & mask
            }
            // On the link (link-local) or in one of the network's /64s.
            IpAddr::V6(a) => {
                a.segments()[0] & 0xffc0 == 0xfe80
                    || self.addrs6[1..].iter().flatten().any(|&p| u128::from(p) >> 64 == u128::from(a) >> 64)
            }
        }
    }

    fn is_mine(&self, a: IpAddr) -> bool {
        match a {
            IpAddr::V4(a) => a == self.addr,
            IpAddr::V6(a) => self.addrs6.contains(&Some(a)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The network the services are on.
    pub from: NetId,
    /// The networks they become discoverable on.
    pub to: Vec<NetId>,
    pub services: Vec<ServiceType>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Indexed by [`NetId`]; `None` = not taking part (no address yet).
    pub nets: Vec<Option<Net>>,
    pub rules: Vec<Rule>,
}

/// Counters per network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Messages received on this network.
    pub received: u64,
    /// Messages sent on this network (reflected from others).
    pub sent: u64,
    /// Received, but nothing in it was allowed anywhere.
    pub filtered: u64,
    /// Received, equal to a message sent within [`DUP_WINDOW_MS`].
    pub duplicate: u64,
    pub rate_limited: u64,
    pub malformed: u64,
    /// From a port other than 5353, outside the subnet, or the router.
    pub foreign: u64,
    /// A rebuilt copy for another network larger than [`MAX_OUTPUT`].
    pub oversize: u64,
}

/// A message to send to `224.0.0.251:5353` on `net` (`v6`: to
/// `[ff02::fb]:5353`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub net: NetId,
    pub msg: Vec<u8>,
    pub v6: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    /// In thousandths of a message.
    milli: u64,
    last_ms: u64,
}

#[derive(Clone, Debug)]
struct Host {
    net: NetId,
    service: usize,
    name: crate::wire::Name,
    expires_ms: u64,
}

pub struct Reflector {
    cfg: Config,
    /// Every service type of the rules, deduplicated; hosts refer to it.
    services: Vec<ServiceType>,
    stats: Vec<Stats>,
    buckets: Vec<Bucket>,
    hosts: Vec<Host>,
    /// Hashes of recently sent messages, with when.
    recent: Vec<(u64, u64)>,
}

impl Reflector {
    pub fn new(cfg: Config) -> Self {
        let mut r = Self {
            cfg: Config::default(),
            services: Vec::new(),
            stats: Vec::new(),
            buckets: Vec::new(),
            hosts: Vec::new(),
            recent: Vec::new(),
        };
        r.reconfigure(cfg);
        r
    }

    /// New rules or addresses. Counters stay; learned hosts are forgotten
    /// (network indices may mean other networks now).
    pub fn reconfigure(&mut self, cfg: Config) {
        let n = cfg.nets.len();
        self.stats.resize(n, Stats::default());
        self.buckets.resize(n, Bucket { milli: BURST * 1000, last_ms: 0 });
        self.services.clear();
        for s in cfg.rules.iter().flat_map(|r| &r.services) {
            if !self.services.contains(s) && self.services.len() < MAX_SERVICES {
                self.services.push(s.clone());
            }
        }
        self.hosts.clear();
        self.cfg = cfg;
    }

    pub fn stats(&self, net: NetId) -> Stats {
        self.stats.get(net).copied().unwrap_or_default()
    }

    /// Whether any rule involves `net` (the caller joins 224.0.0.251 there).
    pub fn takes_part(&self, net: NetId) -> bool {
        self.cfg.rules.iter().any(|r| r.from == net || r.to.contains(&net))
    }

    /// One message received on `from` from `src`. Returns the copies to send.
    pub fn handle(&mut self, now_ms: u64, from: NetId, src: impl Into<SocketAddr>, msg: &[u8]) -> Vec<Output> {
        let src: SocketAddr = src.into();
        let v6 = src.is_ipv6();
        let Some(Some(net)) = self.cfg.nets.get(from).copied() else {
            return Vec::new();
        };
        self.stats[from].received += 1;
        let own = self.cfg.nets.iter().flatten().any(|n| n.is_mine(src.ip()));
        if src.port() != PORT || own || !net.contains(src.ip()) {
            self.stats[from].foreign += 1;
            return Vec::new();
        }
        if !self.take_token(from, now_ms) {
            self.stats[from].rate_limited += 1;
            return Vec::new();
        }
        self.recent.retain(|&(_, t)| now_ms.saturating_sub(t) < DUP_WINDOW_MS);
        let hash = fnv1a(msg) ^ u64::from(v6);
        if self.recent.iter().any(|&(h, _)| h == hash) {
            self.stats[from].duplicate += 1;
            return Vec::new();
        }
        let m = match Message::parse(msg) {
            Ok(m) if m.opcode() == 0 && m.rcode() == 0 => m,
            _ => {
                self.stats[from].malformed += 1;
                return Vec::new();
            }
        };
        self.hosts.retain(|h| h.expires_ms > now_ms);
        let copies = if m.is_response() { self.responses(now_ms, from, &m) } else { self.queries(from, &m) };

        let mut out = Vec::new();
        for (net, copy) in copies {
            match copy.to_bytes() {
                Ok(b) if b.len() <= if v6 { MAX_OUTPUT_V6 } else { MAX_OUTPUT } => {
                    self.remember_sent(now_ms, fnv1a(&b) ^ u64::from(v6));
                    self.stats[net].sent += 1;
                    out.push(Output { net, msg: b, v6 });
                }
                _ => self.stats[from].oversize += 1,
            }
        }
        if out.is_empty() {
            self.stats[from].filtered += 1;
        }
        out
    }

    fn take_token(&mut self, net: NetId, now_ms: u64) -> bool {
        let b = &mut self.buckets[net];
        let elapsed = now_ms.saturating_sub(b.last_ms);
        b.milli = (b.milli + elapsed * RATE_PER_SEC).min(BURST * 1000);
        b.last_ms = now_ms;
        if b.milli < 1000 {
            return false;
        }
        b.milli -= 1000;
        true
    }

    fn remember_sent(&mut self, now_ms: u64, hash: u64) {
        if self.recent.len() >= MAX_RECENT {
            self.recent.remove(0);
        }
        self.recent.push((hash, now_ms));
    }

    /// Indices into `self.services` a rule `from` → `to` allows, as a mask.
    fn allowed(&self, from: NetId, to: NetId) -> u128 {
        let mut mask = 0;
        for r in self.cfg.rules.iter().filter(|r| r.from == from && r.to.contains(&to)) {
            for s in &r.services {
                if let Some(i) = self.services.iter().position(|x| x == s) {
                    mask |= 1u128 << i;
                }
            }
        }
        mask
    }

    /// The networks other than `net` that exist, ascending.
    fn others(&self, net: NetId) -> impl Iterator<Item = NetId> + '_ {
        (0..self.cfg.nets.len()).filter(move |&n| n != net && self.cfg.nets[n].is_some())
    }

    /// Whether a name falls under the services in `mask`, or is a host
    /// learned on `net` from one of them.
    fn name_allowed(&self, name: &crate::wire::Name, net: NetId, mask: u128) -> bool {
        let svc = |i: usize| mask & (1u128 << i) != 0;
        self.services.iter().enumerate().any(|(i, s)| svc(i) && s.covers(name))
            || self.hosts.iter().any(|h| h.net == net && svc(h.service) && h.name.eq_ignore_case(name))
    }

    fn record_allowed(&self, r: &Record, net: NetId, mask: u128) -> bool {
        !r.is_link_local_address() && self.name_allowed(&r.name, net, mask)
    }

    /// Answers and announcements from `from` to the networks its rules
    /// reach.
    fn responses(&mut self, now_ms: u64, from: NetId, m: &Message) -> Vec<(NetId, Message)> {
        // Learn SRV targets first, so the A records in the same message pass.
        for r in m.answers.iter().chain(&m.additional).filter(|r| r.rtype == TYPE_SRV && r.ttl > 0) {
            let Some(target) = &r.rdata.name else { continue };
            for (i, s) in self.services.iter().enumerate() {
                let reachable = self.cfg.rules.iter().any(|x| x.from == from && x.services.contains(s));
                if reachable && s.covers(&r.name) {
                    let expires_ms = now_ms + u64::from(r.ttl).min(MAX_HOST_TTL_SECS) * 1000;
                    learn(&mut self.hosts, Host { net: from, service: i, name: target.clone(), expires_ms });
                }
            }
        }
        let mut out = Vec::new();
        for to in self.others(from) {
            let mask = self.allowed(from, to);
            if mask == 0 {
                continue;
            }
            let keep = |rs: &[Record]| -> Vec<Record> {
                rs.iter().filter(|r| self.record_allowed(r, from, mask)).cloned().collect()
            };
            let answers = keep(&m.answers);
            if answers.is_empty() {
                continue;
            }
            let additional = keep(&m.additional);
            out.push((to, Message { id: m.id, flags: m.flags, answers, additional, ..Default::default() }));
        }
        out
    }

    /// Queries from `from` to the networks whose services it may discover.
    fn queries(&self, from: NetId, m: &Message) -> Vec<(NetId, Message)> {
        let mut out = Vec::new();
        for to in self.others(from) {
            let mask = self.allowed(to, from);
            if mask == 0 {
                continue;
            }
            let questions: Vec<_> = m
                .questions
                .iter()
                .filter(|q| self.name_allowed(&q.name, to, mask))
                .map(|q| {
                    let mut q = q.clone();
                    q.qclass &= !CLASS_TOP_BIT;
                    q
                })
                .collect();
            if questions.is_empty() {
                continue;
            }
            // Known answers (RFC 6762 §7.1) about the services there.
            let answers = m.answers.iter().filter(|r| self.record_allowed(r, to, mask)).cloned().collect();
            out.push((to, Message { id: m.id, flags: m.flags, questions, answers, ..Default::default() }));
        }
        out
    }
}

/// Add or refresh a learned host; when full, drop the one expiring first.
fn learn(hosts: &mut Vec<Host>, h: Host) {
    if let Some(e) = hosts.iter_mut().find(|e| e.net == h.net && e.service == h.service && e.name.eq_ignore_case(&h.name)) {
        e.expires_ms = e.expires_ms.max(h.expires_ms);
        return;
    }
    if hosts.len() >= MAX_HOSTS
        && let Some(i) = (0..hosts.len()).min_by_key(|&i| hosts[i].expires_ms)
    {
        hosts.swap_remove(i);
    }
    hosts.push(h);
}

fn fnv1a(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325, |h, &c| (h ^ u64::from(c)).wrapping_mul(0x0000_0100_0000_01b3))
}
