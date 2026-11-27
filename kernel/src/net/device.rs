//! The ports' queues and the router stack's view of its frames:
//!
//! - [`PortQdisc`] / [`Aqm`]: every port's egress (CAKE or FQ-CoDel in a
//!   shaper), the one place packets wait; the router's own frames go into
//!   the same queue as forwarded traffic, so CAKE sees all egress traffic.
//! - [`tap`]: what the services look at in the frames for the router (the
//!   WAN's RA, router solicitations) before `net::svc` hands them to
//!   `net::local` or the link's TCP (docs/own-tcp.md).

use crate::config::{AqmKind, Qos};
use crate::net::packet::PacketBuf;
use crate::net::shared::LinkShared;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use qdisc::Qdisc;
use qdisc::cake::{Cake, CakeParams};
use qdisc::fq_codel::{FqCodel, FqParams};
use qdisc::shaper::Shaper;
use qdisc::{Dequeue, Stats};

/// The router's TCP segments that could not be queued (pool empty, no next
/// hop, qdisc full).
static TX_DROPS: AtomicU64 = AtomicU64::new(0);

pub fn tx_drops() -> u64 {
    TX_DROPS.load(Ordering::Relaxed)
}

/// Egress on every port: optional rate shaper around the AQM.
pub type PortQdisc = Shaper<Aqm>;

/// The egress AQM, chosen by boot argument (`qdisc=`) for A/B tests, and
/// the time its packets waited.
pub struct Aqm {
    q: AqmQ,
    pub delay: Delay,
}

enum AqmQ {
    Cake(Cake<PacketBuf>),
    /// FQ-CoDel; with one flow queue it is plain CoDel.
    FqCodel(FqCodel<PacketBuf>),
}

/// Time packets waited in a queue (shaping included), summed since boot:
/// all of them, and pings (ICMP / ICMPv6 echo, `fwd::wire::is_echo`)
/// apart. A ping next to a download is a sparse flow, so with flow
/// isolation it waits far less than the download's packets; the
/// difference over a load phase is the lab's latency-under-load check,
/// independent of how fast the machine is (`/api/status` `delay`).
#[derive(Clone, Copy, Default)]
pub struct Delay {
    pub pkts: u64,
    pub us: u64,
    pub echo_pkts: u64,
    pub echo_us: u64,
}

impl Delay {
    pub fn json(&self) -> String {
        format!(
            "{{\"pkts\":{},\"us\":{},\"echo_pkts\":{},\"echo_us\":{}}}",
            self.pkts, self.us, self.echo_pkts, self.echo_us
        )
    }
}

impl Aqm {
    /// `ack_filter`: CAKE's ACK filter (WAN egress only; FQ-CoDel has none).
    pub fn new(qos: &Qos, ecn: bool, ack_filter: bool, max_packets: usize, limit_bytes: usize, seed: u64) -> Self {
        let codel = qdisc::codel::Params {
            max_packets,
            limit_bytes,
            ecn,
            ..Default::default()
        };
        let q = match qos.aqm {
            AqmKind::Cake => AqmQ::Cake(Cake::new(CakeParams {
                codel,
                isolation: qos.isolation,
                seed,
                ack_filter,
                ..Default::default()
            })),
            AqmKind::FqCodel | AqmKind::Codel => AqmQ::FqCodel(FqCodel::new(FqParams {
                codel,
                flows: if qos.aqm == AqmKind::Codel { 1 } else { 1024 },
                ..Default::default()
            })),
        };
        Self { q, delay: Delay::default() }
    }

    /// For the boot log, e.g. "CAKE (Triple, 1024 flows, 8-way, COBALT) + ECN".
    pub fn describe(&self, ecn: bool) -> String {
        let kind = match &self.q {
            AqmQ::Cake(c) => {
                let p = c.params();
                format!(
                    "CAKE ({:?}, {} flows, {}-way, COBALT{})",
                    p.isolation,
                    p.flows,
                    p.ways,
                    if p.ack_filter { ", ACK filter" } else { "" }
                )
            }
            AqmQ::FqCodel(f) if f.flows() == 1 => String::from("CoDel (single queue)"),
            AqmQ::FqCodel(f) => format!("FQ-CoDel ({} flows)", f.flows()),
        };
        format!("{kind}{}", if ecn { " + ECN" } else { " (drop only)" })
    }

    /// The shared byte limit over all flows.
    pub fn limit_bytes(&self) -> usize {
        match &self.q {
            AqmQ::Cake(c) => c.params().codel.limit_bytes,
            AqmQ::FqCodel(f) => f.limit_bytes(),
        }
    }

    /// Switch the ACK filter in place (live shaping change, queue kept).
    pub fn set_ack_filter(&mut self, on: bool) {
        if let AqmQ::Cake(c) = &mut self.q {
            c.set_ack_filter(on);
        }
    }

    /// Redundant ACKs the ACK filter dropped (part of `stats().dropped`).
    pub fn ack_drops(&self) -> u64 {
        match &self.q {
            AqmQ::Cake(c) => c.ack_drops,
            AqmQ::FqCodel(_) => 0,
        }
    }

    /// BLUE's drops (CAKE only; part of the AQM drops).
    pub fn blue_drops(&self) -> u64 {
        match &self.q {
            AqmQ::Cake(c) => c.blue_drops,
            AqmQ::FqCodel(_) => 0,
        }
    }

    /// The drops by cause, for `/api/status`: (AQM incl. BLUE, BLUE,
    /// overflow = the queue full). ACK filter drops are the rest.
    pub fn drop_split(&self) -> (u64, u64, u64) {
        let s = self.stats();
        let aqm = s.aqm_actions - s.marked;
        (aqm, self.blue_drops(), s.dropped - aqm - self.ack_drops())
    }

    /// Change the byte limit in place (live shaping change, queue kept).
    pub fn set_limit_bytes(&mut self, bytes: usize) {
        match &mut self.q {
            AqmQ::Cake(c) => c.set_limit_bytes(bytes),
            AqmQ::FqCodel(f) => f.set_limit_bytes(bytes),
        }
    }

    pub fn take_max_sojourn_ns(&mut self) -> u64 {
        match &mut self.q {
            AqmQ::Cake(c) => c.take_max_sojourn_ns(),
            AqmQ::FqCodel(f) => f.take_max_sojourn_ns(),
        }
    }

    /// AQM-specific part of the periodic stats line.
    pub fn diag(&self) -> String {
        match &self.q {
            AqmQ::Cake(c) => {
                let (n, o) = c.active_flows();
                let (sh, dh) = c.active_hosts();
                format!(
                    "flows {n} new + {o} old (activations {}, collisions {}), hosts {sh} src / {dh} dst, blue drops {}, ack drops {}, ",
                    c.new_flow_count, c.way_collisions, c.blue_drops, c.ack_drops
                )
            }
            AqmQ::FqCodel(f) => {
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
        match &mut self.q {
            AqmQ::Cake(c) => c.enqueue(p, now_ns),
            AqmQ::FqCodel(f) => f.enqueue(p, now_ns),
        }
    }
    fn dequeue(&mut self, now_ns: u64) -> Dequeue<PacketBuf> {
        let (d, soj_ns) = match &mut self.q {
            AqmQ::Cake(c) => {
                let d = c.dequeue(now_ns);
                (d, c.last_sojourn_ns())
            }
            AqmQ::FqCodel(f) => {
                let d = f.dequeue(now_ns);
                (d, f.last_sojourn_ns())
            }
        };
        if let Dequeue::Packet(p) = &d {
            let us = soj_ns / 1000;
            self.delay.pkts += 1;
            self.delay.us += us;
            if fwd::wire::is_echo(p.data()) {
                self.delay.echo_pkts += 1;
                self.delay.echo_us += us;
            }
        }
        d
    }
    fn has_room(&self) -> bool {
        match &self.q {
            AqmQ::Cake(c) => c.has_room(),
            AqmQ::FqCodel(f) => f.has_room(),
        }
    }
    fn stats(&self) -> Stats {
        match &self.q {
            AqmQ::Cake(c) => c.stats(),
            AqmQ::FqCodel(f) => f.stats(),
        }
    }
}

/// An ICMPv6 Router Solicitation in an untagged Ethernet frame (the
/// datapath removed the VLAN tag; the forwarder checked the hop limit and
/// the extension headers: an RS behind one is not answered at once, only
/// by the periodic RAs).
fn is_router_solicitation(f: &[u8]) -> bool {
    let ip = fwd::wire::ETH_HDR;
    fwd::wire::ethertype(f) == Some(fwd::wire::ETHERTYPE_IPV6)
        && f.get(ip + 6) == Some(&fwd::wire::PROTO_ICMPV6)
        && f.get(ip + 40) == Some(&fwd::wire::ICMPV6_ROUTER_SOLICIT)
}

/// Frames of a link the services look at before the router stack takes
/// them: the last Router Advertisement (the WAN's: `net::wan6`, which
/// parses it with `proto_dhcp::v6::ra::parse_frame`).
#[derive(Default)]
pub struct RxTap {
    last_ra: Option<alloc::vec::Vec<u8>>,
}

impl RxTap {
    /// The last RA received, once.
    pub fn take_ra(&mut self) -> Option<alloc::vec::Vec<u8>> {
        self.last_ra.take()
    }
}

/// A frame for the router on `link` (Ethernet header, then IP): an RA is
/// kept for `net::wan6`, an RS noted for the network's advertiser
/// (`LinkShared::rs_seen`).
pub fn tap(tap: &mut RxTap, link: &LinkShared, f: &[u8]) {
    if fwd::wire::ethertype(f) != Some(fwd::wire::ETHERTYPE_IPV6) {
        return;
    }
    if f.get(fwd::wire::ETH_HDR + 6) == Some(&fwd::wire::PROTO_ICMPV6) && f.get(fwd::wire::ETH_HDR + 40) == Some(&134) {
        tap.last_ra = Some(f.to_vec());
    }
    if is_router_solicitation(f) {
        link.rs_seen.store(true, Ordering::Relaxed);
    }
}

/// A TCP segment of the router's own that could not be sent (no buffer,
/// no next hop, qdisc full): the retransmission timer covers it.
pub fn count_tx_drop() {
    TX_DROPS.fetch_add(1, Ordering::Relaxed);
}
