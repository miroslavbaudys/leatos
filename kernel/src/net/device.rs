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
//! smoltcp runs on `Medium::Ip` on every link: RX hands it the IP packet
//! of the frame, TX puts an Ethernet header in front (IPv4 or IPv6 by the
//! packet's version). On an Ethernet link the datapath does the link
//! layer (`Datapath::send_local`, its ARP / ND answers); on a PPPoE port
//! the frame goes into the qdisc and the datapath turns the header into
//! the session's (`datapath::flush_port`).
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

pub struct PortDevice<'a> {
    pub link: &'a LinkShared,
    pub port: &'a PortShared,
    /// The link's index (the forwarder's `IfIndex`).
    pub ifx: fwd::IfIndex,
    pub now_ns: u64,
    /// Frames put into the qdisc (the datapath must be woken to send them).
    pub queued: &'a mut u32,
    /// What the services want to see of the link's frames (`None`: only
    /// making the interface).
    pub tap: Option<&'a mut RxTap>,
    /// The datapath, for a link without a link layer (`ip_only`; `None`
    /// while only making the interface).
    pub dp: Option<crate::net::stack::SharedDatapath>,
    /// The link's link layer is the datapath's (every LAN link, a DHCP or
    /// static WAN; docs/lan-neighbors.md, docs/local-stack.md step 2): RX
    /// strips the Ethernet header and passes IP only, TX goes through
    /// [`crate::net::datapath::Datapath::send_local`]. Otherwise PPPoE.
    pub ip_only: bool,
    /// Offer frames to the router's own UDP ports first (`net::local`;
    /// false while only making the interface).
    pub local_udp: bool,
}

/// Frames of a link the services look at before smoltcp: the last
/// Router Advertisement (the WAN's: `net::wan6`, which parses it with
/// `proto_dhcp::v6::ra::parse_frame`; smoltcp, a host, ignores RAs).
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

/// A received frame: smoltcp gets what follows its 14-byte Ethernet
/// header (every link is IP-only to smoltcp).
pub struct RxToken(PacketBuf);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0.data().get(fwd::wire::ETH_HDR..).unwrap_or(&[]))
    }
}

pub struct TxToken<'a> {
    link: &'a LinkShared,
    port: &'a PortShared,
    ifx: fwd::IfIndex,
    now_ns: u64,
    queued: &'a mut u32,
    dp: Option<crate::net::stack::SharedDatapath>,
    ip_only: bool,
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
        let Some(mut pkt) = PacketBuf::alloc() else {
            // No buffer: let smoltcp build the frame into scratch, then drop it.
            TX_DROPS.fetch_add(1, Ordering::Relaxed);
            let mut scratch = [0u8; 1514];
            return f(&mut scratch[..len.min(1514)]);
        };
        // An Ethernet header in front of smoltcp's IP packet (EtherType
        // by the version): the datapath fills in the addresses, or turns
        // it into the PPPoE session's headers (`datapath::flush_port`).
        let eth = fwd::wire::ETH_HDR;
        pkt.set_len(eth + len);
        let d = pkt.data_mut();
        d[..12].fill(0);
        let r = f(&mut d[eth..]);
        let t = if d[eth] >> 4 == 6 { fwd::wire::ETHERTYPE_IPV6 } else { fwd::wire::ETHERTYPE_IPV4 };
        fwd::wire::put16(d, 12, t);
        if self.ip_only {
            // The datapath finds the destination MAC (its neighbor table).
            if let Some(dp) = self.dp {
                let mut touched = [false; crate::net::shared::MAX_PORTS];
                if dp.send_local(self.ifx, pkt, &mut touched) {
                    *self.queued += 1;
                }
            }
        } else {
            self.enqueue(pkt);
        }
        r
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
        // IP only: the datapath answered ARP / ND itself; anything not IP
        // is not for a `Medium::Ip` stack. The router's own UDP ports
        // (`net::local`) take theirs first.
        let pkt = loop {
            let pkt = self.link.local_rx.lock().pop_front()?;
            let ip = matches!(
                fwd::wire::ethertype(pkt.data()),
                Some(fwd::wire::ETHERTYPE_IPV4 | fwd::wire::ETHERTYPE_IPV6)
            );
            let taken = ip && self.local_udp && crate::net::local::take(self.ifx, pkt.data());
            if ip && !taken {
                break pkt;
            }
        };
        if let Some(tap) = self.tap.as_deref_mut()
            && fwd::wire::ethertype(pkt.data()) == Some(fwd::wire::ETHERTYPE_IPV6)
        {
            let d = pkt.data();
            if d.get(fwd::wire::ETH_HDR + 6) == Some(&fwd::wire::PROTO_ICMPV6) && d.get(fwd::wire::ETH_HDR + 40) == Some(&134) {
                tap.last_ra = Some(d.to_vec());
            }
        }
        if is_router_solicitation(pkt.data()) {
            // smoltcp ignores it (a host); the network's advertiser answers.
            self.link.rs_seen.store(true, Ordering::Relaxed);
        }
        Some((
            RxToken(pkt),
            TxToken {
                link: self.link,
                port: self.port,
                ifx: self.ifx,
                now_ns: self.now_ns,
                queued: self.queued,
                dp: self.dp,
                ip_only: self.ip_only,
            },
        ))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<TxToken<'_>> {
        let now_ns = self.now_ns;
        let room = self.port.qdisc.lock().has_room();
        room.then_some(TxToken {
            link: self.link,
            port: self.port,
            ifx: self.ifx,
            now_ns,
            queued: self.queued,
            dp: self.dp,
            ip_only: self.ip_only,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = if self.port.is_pppoe() { self.port.mtu() as usize } else { 1500 };
        caps.max_burst_size = Some(1);
        caps
    }
}
