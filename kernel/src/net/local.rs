//! The router's own UDP without smoltcp (docs/local-stack.md §3.1–3.2,
//! started in step 2b for the WAN's DHCPv4 client; the other services
//! follow in step 3).
//!
//! - Receive: [`Udp`], a port table per link. On an IP-only link
//!   (`LinkShared::ip_only`) the router-stack device
//!   (`net::device::PortDevice`) offers every frame to [`Udp::take`]
//!   before smoltcp; UDP (IPv4 or IPv6) to a bound port is parsed
//!   (`fwd::udp::parse4` / `parse6`: lengths and checksums) and queued for
//!   its service, bounded (the oldest is kept, a new one dropped and
//!   counted). Cheap for the rest: the destination port is looked at
//!   before any checksum.
//! - Send: [`send`] builds the headers (`fwd::udp::build4` / `build6`)
//!   into a pool buffer and hands it to `Datapath::send_local` (next hop
//!   by `fwd::local`: broadcast, multicast, or a neighbor through the
//!   datapath's table). The source address is the caller's
//!   (`fwd::local::LocalLink::source6` for IPv6).
//!
//! Payloads are copied out of the packet buffer (one allocation per
//! datagram): fine for DHCP's few; the DNS path (step 3) will want slices.

use crate::net::datapath::Touched;
use crate::net::packet::PacketBuf;
use crate::net::shared::{MAX_PORTS, Shared};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use fwd::IfIndex;
use fwd::wire::{ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, PROTO_UDP};

/// The ends of a datagram, either family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ends {
    V4(fwd::udp::Ends),
    V6(fwd::udp::Ends6),
}

impl Ends {
    pub fn sport(&self) -> u16 {
        match self {
            Ends::V4(e) => e.sport,
            Ends::V6(e) => e.sport,
        }
    }
}

/// Datagrams waiting per bound port.
const QUEUE: usize = 8;

/// A received datagram: its ends and payload.
pub struct Datagram {
    pub ends: Ends,
    pub payload: Vec<u8>,
}

struct Bound {
    ifx: IfIndex,
    port: u16,
    q: VecDeque<Datagram>,
}

/// The router's bound UDP ports (IPv4), per link.
#[derive(Default)]
pub struct Udp {
    bound: Vec<Bound>,
    /// Datagrams dropped because their port's queue was full.
    pub dropped: u64,
}

impl Udp {
    pub fn bind(&mut self, ifx: IfIndex, port: u16) {
        if !self.bound.iter().any(|b| b.ifx == ifx && b.port == port) {
            self.bound.push(Bound { ifx, port, q: VecDeque::with_capacity(QUEUE) });
        }
    }

    pub fn unbind(&mut self, ifx: IfIndex, port: u16) {
        self.bound.retain(|b| !(b.ifx == ifx && b.port == port));
    }

    /// The frame (Ethernet header, then IP) if it is UDP to a port bound
    /// on `ifx`: queued (or dropped when the queue is full) and `true`;
    /// anything else `false` (smoltcp's).
    pub fn take(&mut self, ifx: IfIndex, frame: &[u8]) -> bool {
        if self.bound.is_empty() {
            return false;
        }
        // The port before any checksum: most frames are not for us.
        let dport = match fwd::wire::ethertype(frame) {
            Some(ETHERTYPE_IPV4) => {
                let ihl = usize::from(frame.get(ETH_HDR).copied().unwrap_or(0) & 0x0f) * 4;
                if frame.get(ETH_HDR + 9) != Some(&PROTO_UDP) {
                    return false;
                }
                frame.get(ETH_HDR + ihl + 2..ETH_HDR + ihl + 4)
            }
            // UDP right behind the header; behind extension headers (rare
            // for the router's own traffic) only after the full parse.
            Some(ETHERTYPE_IPV6) => match frame.get(ETH_HDR + 6) {
                Some(&PROTO_UDP) => frame.get(ETH_HDR + 40 + 2..ETH_HDR + 40 + 4),
                Some(&(0 | 43 | 44 | 60)) => match fwd::udp::parse6(frame) {
                    Some(d) => return self.queue(ifx, d.ends.dport, Some((Ends::V6(d.ends), d.payload)), frame),
                    None => return false,
                },
                _ => return false,
            },
            _ => return false,
        };
        let Some(dport) = dport.map(|p| u16::from_be_bytes([p[0], p[1]])) else {
            return false;
        };
        if !self.bound.iter().any(|b| b.ifx == ifx && b.port == dport) {
            return false;
        }
        // Bound: ours even if malformed (smoltcp has no socket there).
        let parsed = match fwd::wire::ethertype(frame) {
            Some(ETHERTYPE_IPV4) => fwd::udp::parse4(frame).map(|d| (Ends::V4(d.ends), d.payload)),
            _ => fwd::udp::parse6(frame).map(|d| (Ends::V6(d.ends), d.payload)),
        };
        self.queue(ifx, dport, parsed, frame)
    }

    /// Queue a parsed datagram for a bound port (`false`: not bound).
    fn queue(&mut self, ifx: IfIndex, dport: u16, parsed: Option<(Ends, (usize, usize))>, frame: &[u8]) -> bool {
        let Some(b) = self.bound.iter_mut().find(|b| b.ifx == ifx && b.port == dport) else {
            return false;
        };
        let Some((ends, (from, to))) = parsed else { return true };
        if b.q.len() >= QUEUE {
            self.dropped += 1;
        } else {
            b.q.push_back(Datagram { ends, payload: frame[from..to].to_vec() });
        }
        true
    }

    /// Datagrams are waiting for a service.
    pub fn pending(&self) -> bool {
        self.bound.iter().any(|b| !b.q.is_empty())
    }

    /// The next datagram for `port` on `ifx`.
    pub fn recv(&mut self, ifx: IfIndex, port: u16) -> Option<Datagram> {
        self.bound.iter_mut().find(|b| b.ifx == ifx && b.port == port)?.q.pop_front()
    }
}

/// Send `payload` on link `ifx` from `e`'s source to its destination
/// (IPv4: the source may be 0.0.0.0, the destination 255.255.255.255;
/// IPv6 with hop limit `hop6`). False if no buffer, too large, or no next
/// hop (`send_local` counts that).
pub fn send(sh: &Shared, ifx: IfIndex, e: &Ends, hop6: u8, payload: &[u8]) -> bool {
    let Some(dp) = crate::net::stack::datapath() else { return false };
    let overhead = match e {
        Ends::V4(_) => fwd::udp::OVERHEAD,
        Ends::V6(_) => fwd::udp::OVERHEAD6,
    };
    // Within one buffer's receive area (no router payload comes close).
    if overhead + payload.len() > crate::net::packet::RX_AREA {
        return false;
    }
    let Some(mut pkt) = PacketBuf::alloc() else { return false };
    pkt.set_len(overhead + payload.len());
    let n = match e {
        Ends::V4(e) => fwd::udp::build4(pkt.data_mut(), e, payload),
        Ends::V6(e) => fwd::udp::build6(pkt.data_mut(), e, hop6, payload),
    };
    let Some(n) = n else { return false };
    pkt.set_len(n);
    let mut touched: Touched = [false; MAX_PORTS];
    let sent = dp.send_local(ifx, pkt, &mut touched);
    for (i, t) in touched.iter().enumerate() {
        if *t && let Some(k) = sh.tx_kick.get(i) {
            k.signal();
        }
    }
    sent
}
