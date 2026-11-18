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

use crate::IfIndex;
use crate::conntrack::{ConnId, Dir, Tuple};
use crate::forwarder::Classification;
use crate::wire::{self, ETH_HDR, ETHERTYPE_IPV4, Ipv4View, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use alloc::vec::Vec;
use core::net::Ipv4Addr;

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

/// One datagram: the fields its fragments share (RFC 791).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub id: u16,
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
        PROTO_UDP | PROTO_ICMP => 8,
        _ => 0,
    }
}

/// Classify an Ethernet frame. Cheap for the common case: a frame that is
/// not an IPv4 fragment is decided from the flags field alone.
pub fn classify(frame: &[u8]) -> Kind {
    if wire::ethertype(frame) != Some(ETHERTYPE_IPV4) {
        return Kind::Whole;
    }
    // MF or a nonzero offset (DF alone is not a fragment).
    match frame.get(ETH_HDR + 6..ETH_HDR + 8) {
        Some(b) if wire::get16(b, 0) & 0x3fff != 0 => {}
        _ => return Kind::Whole,
    }
    let Some(v) = Ipv4View::parse(frame, ETH_HDR) else {
        return Kind::Whole; // malformed: the forwarder counts it
    };
    let key = Key {
        src: v.src(frame),
        dst: v.dst(frame),
        proto: v.proto,
        id: v.id(frame),
    };
    match v.frag_offset {
        0 if v.l4_len < min_l4(v.proto) => Kind::Bad,
        0 => Kind::First(key),
        1 if v.proto == PROTO_TCP => Kind::Bad,
        _ => Kind::Later(key),
    }
}

/// What forwarding the first fragment decided, as the later ones need it
/// ([`crate::forwarder::Forwarder::take_fragment`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
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
        let clash = self.entries.iter().any(|(k, l, exp)| {
            *exp > now
                && *k != key
                && matches!(l, Lookup::Forward { decision: o, .. }
                    if o.src == d.src && o.dst == d.dst && k.proto == key.proto && k.id == key.id)
        });
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

    fn key(id: u16) -> Key {
        Key {
            src: Ipv4Addr::new(192, 168, 1, 100),
            dst: Ipv4Addr::new(203, 0, 113, 1),
            proto: PROTO_UDP,
            id,
        }
    }

    fn decision(src: Ipv4Addr) -> Decision {
        Decision {
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
        }
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
        let k = Key { id: 0x1234, ..key(0) };
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
        let other = Key { src: Ipv4Addr::new(192, 168, 1, 101), ..key(7) };
        assert_eq!(t.record_forward(other, 0, decision(wan), 1), Err(Clash));
        assert_eq!(t.stats.clashes, 1);
        // Another ID, or the first one again: fine.
        t.record_forward(Key { id: 8, ..other }, 0, decision(wan), 1).unwrap();
        t.record_forward(key(7), 0, decision(wan), 1).unwrap();
        // Once the first has expired, the ID is free again.
        t.record_forward(other, 0, decision(wan), ENTRY_MS + 1).unwrap();
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
