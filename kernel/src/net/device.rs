//! smoltcp `Device` for one link (the WAN, or a network on `lan0`),
//! sitting **behind the datapath**:
//!
//! - RX: frames the forwarder classified as `Local` (addressed to the
//!   router), from the link's small bounded `local_rx` queue.
//! - TX: frames from the router's own stack go into the port's **qdisc**,
//!   the same queue as forwarded traffic, so CAKE sees all egress traffic;
//!   a network on a VLAN gets its tag first. smoltcp only gets a TX token
//!   while the qdisc has room.
//!
//! On a PPPoE port the device is IP-only (`Medium::Ip`: no ARP, the
//! session is point to point): RX hands smoltcp the IP packet of the
//! decapsulated Ethernet frame, TX puts an Ethernet header in front, which
//! the datapath turns into the session's headers (`datapath::flush_port`).
//!
//! The device is used by the services task (`net::svc`); queue and qdisc
//! are the port's shared, locked ones (`net::shared::PortShared`). Each
//! frame takes the lock briefly; `queued` counts frames put into the qdisc
//! so the caller can wake the datapath.

use crate::config::{AqmKind, Qos};
use crate::net::packet::PacketBuf;
use crate::net::shared::{LinkShared, PortShared};
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use qdisc::Qdisc;
use qdisc::cake::{Cake, CakeParams};
use qdisc::fq_codel::{FqCodel, FqParams};
use qdisc::shaper::Shaper;
use qdisc::{Dequeue, Stats};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Frames smoltcp produced that could not be queued (pool empty or qdisc full).
static TX_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn tx_drops() -> u64 {
    TX_DROPS.load(Ordering::Relaxed)
}

/// Egress on every port: optional rate shaper around the AQM.
pub type PortQdisc = Shaper<Aqm>;

/// The egress AQM, chosen by boot argument (`qdisc=`) for A/B tests.
pub enum Aqm {
    Cake(Cake<PacketBuf>),
    /// FQ-CoDel; with one flow queue it is plain CoDel.
    FqCodel(FqCodel<PacketBuf>),
}

impl Aqm {
    pub fn new(qos: &Qos, ecn: bool, max_packets: usize, limit_bytes: usize, seed: u64) -> Self {
        let codel = qdisc::codel::Params {
            max_packets,
            limit_bytes,
            ecn,
            ..Default::default()
        };
        match qos.aqm {
            AqmKind::Cake => Self::Cake(Cake::new(CakeParams {
                codel,
                isolation: qos.isolation,
                seed,
                ..Default::default()
            })),
            AqmKind::FqCodel | AqmKind::Codel => Self::FqCodel(FqCodel::new(FqParams {
                codel,
                flows: if qos.aqm == AqmKind::Codel { 1 } else { 1024 },
                ..Default::default()
            })),
        }
    }

    /// For the boot log, e.g. "CAKE (Triple, 1024 flows, 8-way, COBALT) + ECN".
    pub fn describe(&self, ecn: bool) -> String {
        let kind = match self {
            Self::Cake(c) => {
                let p = c.params();
                format!(
                    "CAKE ({:?}, {} flows, {}-way, COBALT)",
                    p.isolation, p.flows, p.ways
                )
            }
            Self::FqCodel(f) if f.flows() == 1 => String::from("CoDel (single queue)"),
            Self::FqCodel(f) => format!("FQ-CoDel ({} flows)", f.flows()),
        };
        format!("{kind}{}", if ecn { " + ECN" } else { " (drop only)" })
    }

    /// The shared byte limit over all flows.
    pub fn limit_bytes(&self) -> usize {
        match self {
            Self::Cake(c) => c.params().codel.limit_bytes,
            Self::FqCodel(f) => f.limit_bytes(),
        }
    }

    /// Change the byte limit in place (live shaping change, queue kept).
    pub fn set_limit_bytes(&mut self, bytes: usize) {
        match self {
            Self::Cake(c) => c.set_limit_bytes(bytes),
            Self::FqCodel(f) => f.set_limit_bytes(bytes),
        }
    }

    pub fn take_max_sojourn_ns(&mut self) -> u64 {
        match self {
            Self::Cake(c) => c.take_max_sojourn_ns(),
            Self::FqCodel(f) => f.take_max_sojourn_ns(),
        }
    }

    /// AQM-specific part of the periodic stats line.
    pub fn diag(&self) -> String {
        match self {
            Self::Cake(c) => {
                let (n, o) = c.active_flows();
                let (sh, dh) = c.active_hosts();
                format!(
                    "flows {n} new + {o} old (activations {}, collisions {}), hosts {sh} src / {dh} dst, blue drops {}, ",
                    c.new_flow_count, c.way_collisions, c.blue_drops
                )
            }
            Self::FqCodel(f) => {
                let (n, o) = f.active_flows();
                format!(
                    "flows {n} new + {o} old (activations {}), ",
                    f.new_flow_count
                )
            }
        }
    }
}

impl Qdisc<PacketBuf> for Aqm {
    fn enqueue(&mut self, p: PacketBuf, now_ns: u64) -> Result<(), PacketBuf> {
        match self {
            Self::Cake(c) => c.enqueue(p, now_ns),
            Self::FqCodel(f) => f.enqueue(p, now_ns),
        }
    }
    fn dequeue(&mut self, now_ns: u64) -> Dequeue<PacketBuf> {
        match self {
            Self::Cake(c) => c.dequeue(now_ns),
            Self::FqCodel(f) => f.dequeue(now_ns),
        }
    }
    fn has_room(&self) -> bool {
        match self {
            Self::Cake(c) => c.has_room(),
            Self::FqCodel(f) => f.has_room(),
        }
    }
    fn stats(&self) -> Stats {
        match self {
            Self::Cake(c) => c.stats(),
            Self::FqCodel(f) => f.stats(),
        }
    }
}

pub struct PortDevice<'a> {
    pub link: &'a LinkShared,
    pub port: &'a PortShared,
    pub now_ns: u64,
    /// Frames put into the qdisc (the datapath must be woken to send them).
    pub queued: &'a mut u32,
}

/// A received frame; `skip` = 14 on an IP-only port (the Ethernet header).
pub struct RxToken(PacketBuf, usize);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0.data().get(self.1..).unwrap_or(&[]))
    }
}

pub struct TxToken<'a> {
    link: &'a LinkShared,
    port: &'a PortShared,
    now_ns: u64,
    queued: &'a mut u32,
}

impl TxToken<'_> {
    /// Into the port's qdisc, with the link's VLAN tag.
    fn enqueue(self, mut pkt: PacketBuf) {
        if let Some(tci) = self.link.tci() {
            pkt.push_vlan(tci);
        }
        pkt.meta.wire_len = pkt.len() as u32;
        pkt.meta.enqueue_ts = self.now_ns;
        if self.port.qdisc.lock().enqueue(pkt, self.now_ns).is_err() {
            TX_DROPS.fetch_add(1, Ordering::Relaxed);
        } else {
            *self.queued += 1;
        }
    }
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        match PacketBuf::alloc() {
            Some(mut pkt) if self.port.is_pppoe() => {
                // IP only: an Ethernet header for the datapath to replace.
                let eth = fwd::wire::ETH_HDR;
                pkt.set_len(eth + len);
                let d = pkt.data_mut();
                d[..12].fill(0);
                fwd::wire::put16(d, 12, fwd::wire::ETHERTYPE_IPV4);
                let r = f(&mut d[eth..]);
                self.enqueue(pkt);
                r
            }
            Some(mut pkt) => {
                pkt.set_len(len);
                let r = f(pkt.data_mut());
                self.enqueue(pkt);
                r
            }
            None => {
                // No buffer: let smoltcp build the frame into scratch, then drop it.
                TX_DROPS.fetch_add(1, Ordering::Relaxed);
                let mut scratch = [0u8; 1514];
                f(&mut scratch[..len.min(1514)])
            }
        }
    }
}

impl Device for PortDevice<'_> {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: Instant) -> Option<(RxToken, TxToken<'_>)> {
        let pkt = self.link.local_rx.lock().pop_front()?;
        let skip = if self.port.is_pppoe() {
            fwd::wire::ETH_HDR
        } else {
            0
        };
        Some((
            RxToken(pkt, skip),
            TxToken {
                link: self.link,
                port: self.port,
                now_ns: self.now_ns,
                queued: self.queued,
            },
        ))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<TxToken<'_>> {
        let now_ns = self.now_ns;
        let room = self.port.qdisc.lock().has_room();
        room.then_some(TxToken {
            link: self.link,
            port: self.port,
            now_ns,
            queued: self.queued,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        if self.port.is_pppoe() {
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = self.port.mtu() as usize;
        } else {
            caps.medium = Medium::Ethernet;
            caps.max_transmission_unit = 1514;
        }
        caps.max_burst_size = Some(1);
        caps
    }
}
