//! The router's own UDP without smoltcp (docs/local-stack.md §3.1–3.2,
//! started in step 2b for the WAN's DHCPv4 client; the other services
//! follow in step 3).
//!
//! - Receive: [`Udp`], a port table per link. On an IP-only link
//!   (`LinkShared::ip_only`) the router-stack device
//!   (`net::device::PortDevice`) offers every frame to [`Udp::take`]
//!   before smoltcp; IPv4 UDP to a bound port is parsed
//!   (`fwd::udp::parse4`: lengths and checksums) and queued for its
//!   service, bounded (the oldest is kept, a new one dropped and counted).
//!   Cheap for the rest: the destination port is looked at before any
//!   checksum.
//! - Send: [`send4`] builds the headers (`fwd::udp::build4`) into a pool
//!   buffer and hands it to `Datapath::send_local` (next hop by
//!   `fwd::local`: broadcast, or a neighbor through the datapath's table).
//!
//! Payloads are copied out of the packet buffer (one allocation per
//! datagram): fine for DHCP's few; the DNS path (step 3) will want slices.

use crate::net::datapath::Touched;
use crate::net::packet::PacketBuf;
use crate::net::shared::{MAX_PORTS, Shared};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use fwd::IfIndex;
use fwd::udp::Ends;
use fwd::wire::{ETH_HDR, ETHERTYPE_IPV4, PROTO_UDP};

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

    /// The frame (Ethernet header, then IP) if it is IPv4 UDP to a port
    /// bound on `ifx`: queued (or dropped when the queue is full) and
    /// `true`; anything else `false` (smoltcp's).
    pub fn take(&mut self, ifx: IfIndex, frame: &[u8]) -> bool {
        if self.bound.is_empty() || fwd::wire::ethertype(frame) != Some(ETHERTYPE_IPV4) {
            return false;
        }
        // The port before any checksum: most frames are not for us.
        let ihl = usize::from(frame.get(ETH_HDR).copied().unwrap_or(0) & 0x0f) * 4;
        let (Some(&proto), Some(dport)) = (frame.get(ETH_HDR + 9), frame.get(ETH_HDR + ihl + 2..ETH_HDR + ihl + 4)) else {
            return false;
        };
        let dport = u16::from_be_bytes([dport[0], dport[1]]);
        if proto != PROTO_UDP {
            return false;
        }
        let Some(b) = self.bound.iter_mut().find(|b| b.ifx == ifx && b.port == dport) else {
            return false;
        };
        // Bound: ours even if malformed (smoltcp has no socket there).
        let Some(d) = fwd::udp::parse4(frame) else {
            return true;
        };
        if b.q.len() >= QUEUE {
            self.dropped += 1;
        } else {
            b.q.push_back(Datagram { ends: d.ends, payload: frame[d.payload.0..d.payload.1].to_vec() });
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

/// Send `payload` on link `ifx` from `e.src:e.sport` to `e.dst:e.dport`
/// (`e.src` may be 0.0.0.0, `e.dst` 255.255.255.255). False if no buffer,
/// too large, or no next hop (`send_local` counts that).
pub fn send4(sh: &Shared, ifx: IfIndex, e: &Ends, payload: &[u8]) -> bool {
    let Some(dp) = crate::net::stack::datapath() else { return false };
    // Within one buffer's receive area (no router payload comes close).
    if fwd::udp::OVERHEAD + payload.len() > crate::net::packet::RX_AREA {
        return false;
    }
    let Some(mut pkt) = PacketBuf::alloc() else { return false };
    pkt.set_len(fwd::udp::OVERHEAD + payload.len());
    let Some(n) = fwd::udp::build4(pkt.data_mut(), e, payload) else { return false };
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
