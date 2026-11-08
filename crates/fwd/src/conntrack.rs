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
//! - Bounded: at most `max_conns` entries; new connections beyond that are refused.
//! - TCP state is tracked loosely (enough for timeouts): SYN → established
//!   on the reply SYN+ACK, FIN/RST → closing.

use crate::wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

/// Inclusive NAT port range. Router-local sockets use ports >= 40000.
pub const NAT_PORTS: (u16, u16) = (10_000, 39_999);

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
    pub nat: bool,
    pub tcp: Option<TcpState>,
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
    max_conns: usize,
    hash_key: u64,
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
        Self {
            conns: Vec::new(),
            free: Vec::new(),
            index: BTreeMap::new(),
            mappings: BTreeMap::new(),
            used_ports: BTreeMap::new(),
            max_conns,
            hash_key,
            stats: Stats::default(),
        }
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

    pub fn get(&self, id: ConnId) -> Option<&Conn> {
        self.conns.get(id).and_then(Option::as_ref)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Conn> {
        self.conns.iter().flatten()
    }

    fn alloc_port(&mut self, proto: u8, preferred: u16) -> Option<u16> {
        let (lo, hi) = NAT_PORTS;
        let span = (hi - lo) as u32 + 1;
        let start = if (lo..=hi).contains(&preferred) {
            preferred
        } else {
            lo + (mix(self.hash_key, preferred as u64) as u32 % span) as u16
        };
        (0..span)
            .map(|i| lo + ((start - lo) as u32 + i).rem_euclid(span) as u16)
            .find(|p| !self.used_ports.contains_key(&(proto, *p)))
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
        if self.len() >= self.max_conns {
            self.stats.table_full += 1;
            return None;
        }
        let (reply, nat) = match nat_ip {
            Some(ip) => {
                let key = (orig.proto, orig.src, orig.sport);
                let port = match self.mappings.get(&key) {
                    Some(m) => m.port,
                    None => match self.alloc_port(orig.proto, orig.sport) {
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
        if self.index.contains_key(&orig) || self.index.contains_key(&reply) {
            return None; // clash (e.g. two internal hosts, same remote, same EIM port race)
        }
        if nat {
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
            tcp: (orig.proto == PROTO_TCP).then_some(TcpState::SynSent),
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
        self.stats.created += 1;
        Some(id)
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
                if tcp_flags & TCP_RST != 0 {
                    *st = TcpState::Closed;
                } else if tcp_flags & TCP_FIN != 0 {
                    *st = TcpState::Closing;
                } else if *st == TcpState::SynSent
                    && ((dir == Dir::Reply
                        && tcp_flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK))
                        || (dir == Dir::Original && c.replied && tcp_flags & TCP_ACK != 0))
                {
                    // SYN+ACK from the responder, or the initiator's ACK after a reply.
                    *st = TcpState::Established;
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

    fn remove(&mut self, id: ConnId) {
        let Some(c) = self.conns.get_mut(id).and_then(Option::take) else {
            return;
        };
        self.index.remove(&c.orig);
        self.index.remove(&c.reply);
        if c.nat {
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
        let dead: Vec<ConnId> = self
            .conns
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().filter(|c| c.expires <= now).map(|_| i))
            .collect();
        for &id in &dead {
            self.remove(id);
        }
        self.stats.expired += dead.len() as u64;
        dead.len()
    }

    /// Drop all NAT state for an external address (e.g. the WAN lease changed).
    pub fn flush_nat(&mut self) {
        let ids: Vec<ConnId> = self
            .conns
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().filter(|c| c.nat).map(|_| i))
            .collect();
        for id in ids {
            self.remove(id);
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
        ct.update(10, id, Dir::Reply, TCP_SYN | TCP_ACK, 60);
        assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::Established));
        assert_eq!(ct.get(id).unwrap().expires, 10 + timeout::TCP_ESTABLISHED);
        ct.update(20, id, Dir::Original, TCP_FIN | TCP_ACK, 60);
        assert_eq!(ct.get(id).unwrap().tcp, Some(TcpState::Closing));
        ct.update(30, id, Dir::Reply, TCP_RST, 60);
        assert_eq!(ct.get(id).unwrap().expires, 30 + timeout::TCP_CLOSED);
        assert_eq!(ct.get(id).unwrap().packets, [1, 2]);
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
        let mut ct = Conntrack::new(2, 1);
        assert!(
            ct.create(0, t(PROTO_UDP, LAN_A, 1, REMOTE, 1), Some(WAN), 0)
                .is_some()
        );
        assert!(
            ct.create(0, t(PROTO_UDP, LAN_A, 2, REMOTE, 1), Some(WAN), 0)
                .is_some()
        );
        assert!(
            ct.create(0, t(PROTO_UDP, LAN_A, 3, REMOTE, 1), Some(WAN), 0)
                .is_none()
        );
        assert_eq!(ct.stats.table_full, 1);
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
