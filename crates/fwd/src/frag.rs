//! IP fragments through NAT and the firewall, without reassembly.
//!
//! Only the first fragment of a datagram (offset 0) carries the ports, so
//! it alone can be looked up in conntrack, translated and checked by the
//! firewall. Its decision is kept per datagram (source, destination,
//! protocol, IP ID) in a small [`Table`]; the later fragments take the
//! same egress, next hop and address rewrite at once, in the order they
//! arrive. Nothing waits for a whole datagram and nothing is
//! refragmented: fragments leave as they came (latency-first datapath,
//! docs/bufferbloat-cake.md: the qdisc is the only queue).
//!
//! A later fragment that arrives before its first one is held
//! ([`Table::park`]: at most [`MAX_PARKED`] per table, for [`PARK_MS`])
//! and released when the first fragment's decision is recorded; this is
//! the only place outside the qdisc a forwarded packet may wait, bounded
//! like the ARP pending queue ([`crate::neigh`]).
//!
//! Refused (RFC 1858, RFC 3128): a first fragment too short to hold its
//! L4 header (ports, TCP flags), and a TCP fragment at offset 8 bytes (it
//! could overwrite the flags the firewall checked).
//!
//! One table per ingress port: a datagram's fragments arrive on one port,
//! so each datapath direction owns its table without sharing it.
//!
//! IPv6 the same way (docs/ipv6.md step 2c): a datagram is (source,
//! destination, Fragment header ID); the first fragment must hold the
//! whole header chain and its upper-layer header (RFC 7112, RFC 8200
//! §4.5), and is decided like a whole packet; later ones take its egress
//! and next hop (no translation). Atomic fragments (offset 0, no more)
//! are whole packets.

use crate::IfIndex;
use crate::conntrack::{ConnId, Dir, Tuple};
use crate::forwarder::Classification;
use crate::wire::{self, ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Ipv4View, Ipv6View, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

/// Datagrams whose decision is kept, per table. A full table forgets the
/// entry closest to expiry.
pub const MAX_ENTRIES: usize = 64;
/// How long a decision is kept (ms): fragments of one datagram arrive
/// within a moment of each other.
pub const ENTRY_MS: u64 = 2_000;
/// Later fragments held while their first one has not arrived, per table.
pub const MAX_PARKED: usize = 16;
/// How long such a fragment is held (ms) before it is dropped.
pub const PARK_MS: u64 = 250;

/// One IPv4 datagram: the fields its fragments share (RFC 791).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub id: u16,
}

/// One IPv6 datagram (RFC 8200 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key6 {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub id: u32,
}

/// A datagram of either family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    V4(Key4),
    V6(Key6),
}

/// What a frame is, fragment-wise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Not a fragment (or not IPv4, or malformed: the forwarder decides).
    Whole,
    /// Offset 0, more fragments follow: forwarded through the normal
    /// pipeline, its decision recorded.
    First(Key),
    /// A fragment after the first: the recorded decision applies.
    Later(Key),
    /// Refused outright: a first fragment without its whole L4 header, or
    /// a TCP fragment at offset 1 (8 bytes).
    Bad,
}

/// Smallest L4 header a first fragment must carry in full.
fn min_l4(proto: u8) -> usize {
    match proto {
        PROTO_TCP => 20,
        PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6 => 8,
        _ => 0,
    }
}

/// Classify an Ethernet frame. Cheap for the common case: a frame that is
/// not an IPv4 fragment is decided from the flags field alone.
pub fn classify(frame: &[u8]) -> Kind {
    match wire::ethertype(frame) {
        Some(ETHERTYPE_IPV4) => {}
        Some(ETHERTYPE_IPV6) => return classify6(frame),
        _ => return Kind::Whole,
    }
    // MF or a nonzero offset (DF alone is not a fragment).
    match frame.get(ETH_HDR + 6..ETH_HDR + 8) {
        Some(b) if wire::get16(b, 0) & 0x3fff != 0 => {}
        _ => return Kind::Whole,
    }
    let Some(v) = Ipv4View::parse(frame, ETH_HDR) else {
        return Kind::Whole; // malformed: the forwarder counts it
    };
    let key = Key::V4(Key4 {
        src: v.src(frame),
        dst: v.dst(frame),
        proto: v.proto,
        id: v.id(frame),
    });
    match v.frag_offset {
        0 if v.l4_len < min_l4(v.proto) => Kind::Bad,
        0 => Kind::First(key),
        1 if v.proto == PROTO_TCP => Kind::Bad,
        _ => Kind::Later(key),
    }
}

/// [`classify`] for IPv6: cheap unless an extension header follows the
/// fixed one (a Fragment header may only sit behind those).
fn classify6(frame: &[u8]) -> Kind {
    if !frame.get(ETH_HDR + 6).is_some_and(|nh| matches!(nh, 0 | 43 | 44 | 60)) {
        return Kind::Whole;
    }
    let Some(v) = Ipv6View::parse(frame, ETH_HDR) else {
        return Kind::Whole; // malformed: the forwarder counts it
    };
    if !v.is_fragment {
        return Kind::Whole; // none, or atomic
    }
    let key = Key::V6(Key6 { src: v.src(frame), dst: v.dst(frame), id: v.frag_id });
    match v.frag_offset {
        // The header chain ended at an upper-layer header; it must be whole.
        0 if !matches!(v.proto, PROTO_TCP | PROTO_UDP | PROTO_ICMPV6) || v.l4_len < min_l4(v.proto) => Kind::Bad,
        0 => Kind::First(key),
        1 if v.proto == PROTO_TCP => Kind::Bad,
        _ => Kind::Later(key),
    }
}

/// What forwarding the first fragment decided, as the later ones need it
/// ([`crate::forwarder::Forwarder::take_fragment`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    V4(Decision4),
    V6(Decision6),
}

/// An IPv6 first fragment's decision: no translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision6 {
    pub(crate) conn: ConnId,
    pub(crate) dir: Dir,
    pub(crate) orig: Tuple<Ipv6Addr>,
    pub egress: IfIndex,
    pub next_hop: Ipv6Addr,
    pub class: Classification,
}

/// An IPv4 first fragment's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision4 {
    /// The connection (checked again per fragment: it may have ended).
    pub(crate) conn: ConnId,
    pub(crate) dir: Dir,
    pub(crate) orig: Tuple,
    pub egress: IfIndex,
    pub next_hop: Ipv4Addr,
    /// Addresses after translation.
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub class: Classification,
}

/// A recorded datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Forward through conntrack shard `shard` with this decision.
    Forward { shard: usize, decision: Decision },
    /// The first fragment was dropped, refused or not forwarded (local):
    /// so are the others.
    Drop,
}

/// The translated datagram of `d` already belongs to another one: two
/// inside hosts, one IP ID, one destination, behind one WAN address. The
/// receiver could not tell their fragments apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clash;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Later fragments forwarded with a recorded decision.
    pub forwarded: u64,
    /// Later fragments held for their first one.
    pub parked: u64,
    /// Held fragments dropped: the first one never came, or no room.
    pub park_drops: u64,
    /// Datagrams refused by [`Clash`].
    pub clashes: u64,
    /// Decisions forgotten early to make room.
    pub evicted: u64,
}

/// Decisions per datagram and the fragments waiting for one. `P` is the
/// packet buffer (the kernel's pool buffer; anything in tests).
pub struct Table<P> {
    entries: Vec<(Key, Lookup, u64)>,
    parked: Vec<(Key, P, u64)>,
    pub stats: Stats,
}

impl<P> Default for Table<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Table<P> {
    pub fn new() -> Self {
        Table {
            entries: Vec::with_capacity(MAX_ENTRIES),
            parked: Vec::with_capacity(MAX_PARKED),
            stats: Stats::default(),
        }
    }

    /// The decision for a later fragment of `key`, if its first one came.
    pub fn lookup(&self, key: &Key, now: u64) -> Option<Lookup> {
        self.entries
            .iter()
            .find(|(k, _, exp)| k == key && *exp > now)
            .map(|(_, l, _)| *l)
    }

    /// Count a later fragment forwarded with [`Self::lookup`]'s decision.
    pub fn count_forwarded(&mut self) {
        self.stats.forwarded += 1;
    }

    /// Record what the first fragment of `key` got: forwarded with `d`
    /// through `shard`. Refused when another datagram translates to the
    /// same one ([`Clash`]; record [`Self::record_drop`] then).
    pub fn record_forward(&mut self, key: Key, shard: usize, d: Decision, now: u64) -> Result<(), Clash> {
        // Only IPv4 translates datagrams onto one another (NAT).
        let clash = match (key, d) {
            (Key::V4(key4), Decision::V4(d)) => self.entries.iter().any(|(k, l, exp)| {
                *exp > now
                    && *k != key
                    && matches!((k, l), (Key::V4(k), Lookup::Forward { decision: Decision::V4(o), .. })
                        if o.src == d.src && o.dst == d.dst && k.proto == key4.proto && k.id == key4.id)
            }),
            _ => false,
        };
        if clash {
            self.stats.clashes += 1;
            return Err(Clash);
        }
        self.put(key, Lookup::Forward { shard, decision: d }, now);
        Ok(())
    }

    /// The first fragment of `key` was not forwarded: neither are the
    /// others.
    pub fn record_drop(&mut self, key: Key, now: u64) {
        self.put(key, Lookup::Drop, now);
    }

    fn put(&mut self, key: Key, l: Lookup, now: u64) {
        let exp = now + ENTRY_MS;
        if let Some(e) = self.entries.iter_mut().find(|(k, _, _)| *k == key) {
            *e = (key, l, exp);
            return;
        }
        self.entries.retain(|(_, _, e)| *e > now);
        if self.entries.len() >= MAX_ENTRIES
            && let Some(i) = (0..self.entries.len()).min_by_key(|&i| self.entries[i].2)
        {
            self.entries.swap_remove(i);
            self.stats.evicted += 1;
        }
        self.entries.push((key, l, exp));
    }

    /// Hold a later fragment whose first one has not come yet. Full:
    /// handed back, to be dropped.
    pub fn park(&mut self, key: Key, pkt: P, now: u64) -> Result<(), P> {
        if self.parked.len() >= MAX_PARKED {
            self.stats.park_drops += 1;
            return Err(pkt);
        }
        self.stats.parked += 1;
        self.parked.push((key, pkt, now + PARK_MS));
        Ok(())
    }

    /// The fragments held for `key`, in arrival order, into `out` (after
    /// recording its first fragment's decision).
    pub fn take_parked(&mut self, key: &Key, out: &mut Vec<P>) {
        let mut i = 0;
        while i < self.parked.len() {
            if self.parked[i].0 == *key {
                out.push(self.parked.remove(i).1);
            } else {
                i += 1;
            }
        }
    }

    /// Forget expired decisions; held fragments past [`PARK_MS`] go into
    /// `dropped`.
    pub fn expire(&mut self, now: u64, dropped: &mut Vec<P>) {
        self.entries.retain(|(_, _, e)| *e > now);
        let mut i = 0;
        while i < self.parked.len() {
            if self.parked[i].2 <= now {
                dropped.push(self.parked.remove(i).1);
                self.stats.park_drops += 1;
            } else {
                i += 1;
            }
        }
    }

    /// Held fragments right now.
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key4(id: u16) -> Key4 {
        Key4 {
            src: Ipv4Addr::new(192, 168, 1, 100),
            dst: Ipv4Addr::new(203, 0, 113, 1),
            proto: PROTO_UDP,
            id,
        }
    }

    fn key(id: u16) -> Key {
        Key::V4(key4(id))
    }

    fn decision(src: Ipv4Addr) -> Decision {
        Decision::V4(Decision4 {
            conn: 0,
            dir: Dir::Original,
            orig: Tuple {
                proto: PROTO_UDP,
                src: Ipv4Addr::new(192, 168, 1, 100),
                sport: 5000,
                dst: Ipv4Addr::new(203, 0, 113, 1),
                dport: 53,
            },
            egress: 0,
            next_hop: Ipv4Addr::new(203, 0, 113, 1),
            src,
            dst: Ipv4Addr::new(203, 0, 113, 1),
            class: Classification::default(),
        })
    }

    /// An Ethernet + IPv4 frame with the given flags/offset word and L4 bytes.
    fn frame(proto: u8, flags_off: u16, l4: usize) -> alloc::vec::Vec<u8> {
        let mut f = alloc::vec![0u8; ETH_HDR + 20 + l4];
        f[12] = 0x08;
        let ip = ETH_HDR;
        f[ip] = 0x45;
        let total = (20 + l4) as u16;
        f[ip + 2..ip + 4].copy_from_slice(&total.to_be_bytes());
        f[ip + 4..ip + 6].copy_from_slice(&0x1234u16.to_be_bytes());
        f[ip + 6..ip + 8].copy_from_slice(&flags_off.to_be_bytes());
        f[ip + 8] = 64;
        f[ip + 9] = proto;
        f[ip + 12..ip + 16].copy_from_slice(&[192, 168, 1, 100]);
        f[ip + 16..ip + 20].copy_from_slice(&[203, 0, 113, 1]);
        let c = wire::checksum(&f[ip..ip + 20]);
        f[ip + 10..ip + 12].copy_from_slice(&c.to_be_bytes());
        f
    }

    #[test]
    fn classify_kinds() {
        let k = key(0x1234);
        assert_eq!(classify(&frame(PROTO_UDP, 0, 8)), Kind::Whole);
        assert_eq!(classify(&frame(PROTO_UDP, 0x4000, 8)), Kind::Whole, "DF alone");
        assert_eq!(classify(&frame(PROTO_UDP, 0x2000, 8)), Kind::First(k));
        assert_eq!(classify(&frame(PROTO_UDP, 185, 8)), Kind::Later(k));
        assert_eq!(classify(&frame(PROTO_UDP, 0x2000 | 185, 8)), Kind::Later(k));
        // RFC 1858 / 3128.
        assert_eq!(classify(&frame(PROTO_UDP, 0x2000, 4)), Kind::Bad, "no room for the ports");
        assert_eq!(classify(&frame(PROTO_TCP, 0x2000, 16)), Kind::Bad, "no room for the flags");
        assert_eq!(classify(&frame(PROTO_TCP, 0x2000 | 1, 8)), Kind::Bad, "overlaps the TCP flags");
        assert!(matches!(classify(&frame(PROTO_UDP, 0x2000 | 1, 8)), Kind::Later(_)));
        // Not IPv4 / broken header: the forwarder's business.
        let mut arp = frame(PROTO_UDP, 0x2000, 8);
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(classify(&arp), Kind::Whole);
        let mut bad = frame(PROTO_UDP, 0x2000, 8);
        bad[ETH_HDR + 10] ^= 1;
        assert_eq!(classify(&bad), Kind::Whole);
        assert_eq!(classify(&[0u8; 20]), Kind::Whole);
    }

    #[test]
    fn decisions_expire_and_evict() {
        let mut t: Table<u32> = Table::new();
        let wan = Ipv4Addr::new(198, 51, 100, 2);
        t.record_forward(key(1), 3, decision(wan), 0).unwrap();
        assert_eq!(t.lookup(&key(1), 100), Some(Lookup::Forward { shard: 3, decision: decision(wan) }));
        assert_eq!(t.lookup(&key(2), 100), None);
        assert_eq!(t.lookup(&key(1), ENTRY_MS), None, "expired");
        t.record_drop(key(2), 0);
        assert_eq!(t.lookup(&key(2), 1), Some(Lookup::Drop));
        // Full: the oldest goes.
        let mut t: Table<u32> = Table::new();
        for i in 0..MAX_ENTRIES as u16 + 1 {
            t.record_drop(key(i), u64::from(i));
        }
        assert_eq!(t.lookup(&key(0), 70), None);
        assert_eq!(t.lookup(&key(MAX_ENTRIES as u16), 70), Some(Lookup::Drop));
        assert_eq!(t.stats.evicted, 1);
        assert!(t.entries.len() <= MAX_ENTRIES);
    }

    #[test]
    fn clash_on_the_translated_datagram() {
        let mut t: Table<u32> = Table::new();
        let wan = Ipv4Addr::new(198, 51, 100, 2);
        t.record_forward(key(7), 0, decision(wan), 0).unwrap();
        // Another inside host, same ID, same server, same WAN address.
        let other = Key::V4(Key4 { src: Ipv4Addr::new(192, 168, 1, 101), ..key4(7) });
        assert_eq!(t.record_forward(other, 0, decision(wan), 1), Err(Clash));
        assert_eq!(t.stats.clashes, 1);
        // Another ID, or the first one again: fine.
        t.record_forward(Key::V4(Key4 { src: Ipv4Addr::new(192, 168, 1, 101), ..key4(8) }), 0, decision(wan), 1).unwrap();
        t.record_forward(key(7), 0, decision(wan), 1).unwrap();
        // Once the first has expired, the ID is free again.
        t.record_forward(other, 0, decision(wan), ENTRY_MS + 1).unwrap();
    }

    /// An Ethernet + IPv6 frame: `hdrs` extension headers (kind, bytes,
    /// first byte patched with the next header), then `proto` and `l4` bytes.
    fn frame6(hdrs: &[(u8, alloc::vec::Vec<u8>)], proto: u8, l4: usize) -> alloc::vec::Vec<u8> {
        let mut body = alloc::vec::Vec::new();
        for (i, (_, h)) in hdrs.iter().enumerate() {
            let mut h = h.clone();
            h[0] = hdrs.get(i + 1).map_or(proto, |n| n.0);
            body.extend_from_slice(&h);
        }
        body.resize(body.len() + l4, 0);
        let mut f = alloc::vec![0u8; ETH_HDR];
        f[12] = 0x86;
        f[13] = 0xdd;
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&(body.len() as u16).to_be_bytes());
        f.push(hdrs.first().map_or(proto, |h| h.0));
        f.push(64);
        f.extend_from_slice(&"2001:db8:100::10".parse::<Ipv6Addr>().unwrap().octets());
        f.extend_from_slice(&"2001:db8:9::1".parse::<Ipv6Addr>().unwrap().octets());
        f.extend_from_slice(&body);
        f
    }

    fn fh(off: u16, more: bool, id: u32) -> (u8, alloc::vec::Vec<u8>) {
        let mut h = alloc::vec![0u8; 8];
        h[2..4].copy_from_slice(&((off << 3) | u16::from(more)).to_be_bytes());
        h[4..8].copy_from_slice(&id.to_be_bytes());
        (44, h)
    }

    #[test]
    fn classify_ipv6_kinds() {
        let k = Key::V6(Key6 { src: "2001:db8:100::10".parse().unwrap(), dst: "2001:db8:9::1".parse().unwrap(), id: 0xabcd });
        assert_eq!(classify(&frame6(&[], PROTO_UDP, 8)), Kind::Whole);
        assert_eq!(classify(&frame6(&[fh(0, false, 0xabcd)], PROTO_UDP, 8)), Kind::Whole, "atomic");
        assert_eq!(classify(&frame6(&[fh(0, true, 0xabcd)], PROTO_UDP, 8)), Kind::First(k));
        assert_eq!(classify(&frame6(&[fh(181, true, 0xabcd)], PROTO_UDP, 8)), Kind::Later(k));
        assert_eq!(classify(&frame6(&[fh(181, false, 0xabcd)], PROTO_UDP, 8)), Kind::Later(k));
        // Behind a Destination Options header too.
        let dest = (60u8, alloc::vec![0u8; 8]);
        assert_eq!(classify(&frame6(&[dest, fh(0, true, 0xabcd)], PROTO_UDP, 8)), Kind::First(k));
        // RFC 7112: the first fragment holds the upper-layer header whole.
        assert_eq!(classify(&frame6(&[fh(0, true, 1)], PROTO_UDP, 4)), Kind::Bad);
        assert_eq!(classify(&frame6(&[fh(0, true, 1)], PROTO_TCP, 16)), Kind::Bad);
        assert_eq!(classify(&frame6(&[fh(0, true, 1)], 59, 0)), Kind::Bad, "no upper-layer header");
        assert_eq!(classify(&frame6(&[fh(1, true, 1)], PROTO_TCP, 8)), Kind::Bad, "overlaps the TCP flags");
    }

    #[test]
    fn ipv6_decisions_never_clash() {
        let mut t: Table<u32> = Table::new();
        let k = |id| Key::V6(Key6 { src: "2001:db8:100::10".parse().unwrap(), dst: "2001:db8:9::1".parse().unwrap(), id });
        let d = Decision::V6(Decision6 {
            conn: 0,
            dir: Dir::Original,
            orig: Tuple { proto: PROTO_UDP, src: "2001:db8:100::10".parse().unwrap(), sport: 1, dst: "2001:db8:9::1".parse().unwrap(), dport: 2 },
            egress: 0,
            next_hop: "fe80::1".parse().unwrap(),
            class: Classification::default(),
        });
        t.record_forward(k(1), 2, d, 0).unwrap();
        t.record_forward(k(2), 2, d, 0).unwrap();
        assert_eq!(t.lookup(&k(1), 1), Some(Lookup::Forward { shard: 2, decision: d }));
        assert_eq!(t.lookup(&key(1), 1), None, "families apart");
    }

    #[test]
    fn parked_fragments_wait_bounded() {
        let mut t: Table<u32> = Table::new();
        for i in 0..MAX_PARKED as u32 {
            t.park(key(1 + (i % 2) as u16), i, 0).unwrap();
        }
        assert_eq!(t.park(key(1), 99, 0), Err(99), "full");
        let mut out = Vec::new();
        t.take_parked(&key(1), &mut out);
        assert_eq!(out, (0..MAX_PARKED as u32).step_by(2).collect::<Vec<_>>(), "in arrival order");
        assert_eq!(t.parked_len(), MAX_PARKED / 2);
        let mut dropped = Vec::new();
        t.expire(PARK_MS - 1, &mut dropped);
        assert!(dropped.is_empty());
        t.expire(PARK_MS, &mut dropped);
        assert_eq!(dropped.len(), MAX_PARKED / 2);
        assert_eq!(t.parked_len(), 0);
        assert_eq!(t.stats.park_drops, 1 + MAX_PARKED as u64 / 2);
    }
}
