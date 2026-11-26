//! The router's own UDP without smoltcp (docs/local-stack.md §3.1–3.2,
//! started in step 2b for the WAN's DHCPv4 client; the other services
//! follow in step 3).
//!
//! - Receive: one port table per link ([`bind`], [`recv`]), owned here
//!   (only the services task uses it). The router-stack device
//!   (`net::device::PortDevice`) offers every frame of a link to [`take`]
//!   before smoltcp; UDP (IPv4 or IPv6) to a bound port is parsed
//!   (`fwd::udp::parse4` / `parse6`: lengths and checksums) and queued for
//!   its service, bounded (the oldest is kept, a new one dropped and
//!   counted). Cheap for the rest: the destination port is looked at
//!   before any checksum.
//! - Send: [`send`] builds the headers (`fwd::udp::build4` / `build6`)
//!   into a pool buffer and hands it to `Datapath::send_local` (next hop
//!   by `fwd::local`: broadcast, multicast, or a neighbor through the
//!   datapath's table); on a PPPoE WAN straight into the port's qdisc,
//!   where the datapath puts the session's headers on. The source address
//!   is the caller's, [`source`] picks one (`fwd::local::LocalLink`).
//!
//! Payloads are copied out of the packet buffer (one allocation per
//! datagram): fine for DHCP's few; the DNS path (step 3) will want slices.

use crate::net::datapath::Touched;
use crate::net::packet::PacketBuf;
use crate::net::shared::{MAX_PORTS, Shared};
use core::net::IpAddr;
use qdisc::Qdisc;
use spin::Mutex;
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

/// The router's bound UDP ports, per link.
struct Udp {
    bound: Vec<Bound>,
    /// Datagrams dropped because their port's queue was full.
    dropped: u64,
}

static UDP: Mutex<Udp> = Mutex::new(Udp { bound: Vec::new(), dropped: 0 });

/// Bind `port` on link `ifx` (again: nothing changes).
pub fn bind(ifx: IfIndex, port: u16) {
    UDP.lock().bind(ifx, port);
}

/// Free `port` on link `ifx`; its waiting datagrams go.
pub fn unbind(ifx: IfIndex, port: u16) {
    UDP.lock().unbind(ifx, port);
}

/// The next datagram for `port` on `ifx`.
pub fn recv(ifx: IfIndex, port: u16) -> Option<Datagram> {
    UDP.lock().recv(ifx, port)
}

/// Datagrams are waiting for a service.
pub fn pending() -> bool {
    UDP.lock().pending()
}

/// Datagrams dropped for a full queue (status).
pub fn dropped() -> u64 {
    UDP.lock().dropped
}

/// A frame of link `ifx` for the router (Ethernet header, then IP):
/// `true` if it was UDP to a bound port (queued, or dropped when the
/// queue is full or it is malformed), else smoltcp's.
pub fn take(ifx: IfIndex, frame: &[u8]) -> bool {
    UDP.lock().take(ifx, frame)
}

/// The router's source address toward `dst` on link `ifx`, as the
/// datapath knows the link (`fwd::local::LocalLink::source4` / `source6`).
pub fn source(ifx: IfIndex, dst: IpAddr) -> Option<IpAddr> {
    crate::net::stack::datapath()?.local_source(ifx, dst)
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
/// (IPv4: the source may be 0.0.0.0, the destination 255.255.255.255),
/// with time to live / hop limit `ttl` (`fwd::udp::TTL`; 255 for mDNS).
/// False if no buffer, too large, or no next hop (`send_local` counts
/// that).
pub fn send(sh: &Shared, ifx: IfIndex, e: &Ends, ttl: u8, payload: &[u8]) -> bool {
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
        Ends::V4(e) => fwd::udp::build4(pkt.data_mut(), e, ttl, payload),
        Ends::V6(e) => fwd::udp::build6(pkt.data_mut(), e, ttl, payload),
    };
    let Some(n) = n else { return false };
    pkt.set_len(n);
    let Some(link) = sh.links.get(ifx as usize) else { return false };
    let port = link.port();
    if sh.ports[port].is_pppoe() {
        // No link layer: into the qdisc as the router stack's own
        // frames go (`net::device`); the datapath adds the session.
        if let Some(tci) = link.tci() {
            pkt.push_vlan(tci);
        }
        let now = crate::net::datapath::now_ns();
        pkt.meta.wire_len = pkt.len() as u32;
        pkt.meta.enqueue_ts = now;
        let ok = sh.ports[port].qdisc.lock().enqueue(pkt, now).is_ok();
        sh.tx_kick[port].signal();
        return ok;
    }
    let mut touched: Touched = [false; MAX_PORTS];
    let sent = dp.send_local(ifx, pkt, &mut touched);
    for (i, t) in touched.iter().enumerate() {
        if *t && let Some(k) = sh.tx_kick.get(i) {
            k.signal();
        }
    }
    sent
}
