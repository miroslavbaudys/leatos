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
//! decapsulated Ethernet frame, TX puts an Ethernet header in front (IPv4
//! or IPv6 by the packet's version), which the datapath turns into the
//! session's headers (`datapath::flush_port`).
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
    /// The link's IPv6 neighbor hints (`None`: only making the interface).
    pub nd: Option<&'a mut NdHints>,
    /// The datapath, for a link without a link layer (`ip_only`; `None`
    /// while only making the interface).
    pub dp: Option<crate::net::stack::SharedDatapath>,
    /// A link whose stack runs on `Medium::Ip` over Ethernet (the LANs,
    /// docs/lan-neighbors.md; a static WAN, docs/local-stack.md step 2a):
    /// RX strips the Ethernet header and passes IP only, TX goes through
    /// [`crate::net::datapath::Datapath::send_local`], no neighbor hints.
    pub ip_only: bool,
}

/// smoltcp (0.14) learns IPv6 neighbors only from neighbor discovery and
/// drops the packet that makes it resolve one. A client that knows our
/// MAC from the Router Advertisement never solicits us, so the first
/// answer to it after a quiet minute (smoltcp's entry lifetime) was lost.
/// Before such a client's frame, smoltcp gets a neighbor solicitation
/// from it ([`fwd::wire::ipv6_neighbor_hint`]: to our unicast address,
/// so recorded, not answered), at most every [`Self::EVERY_NS`] per
/// neighbor. And unicast solicitations (reachability probes) go to the
/// solicited-node group instead ([`fwd::wire::ipv6_ns_to_solicited`]):
/// not needed after all (smoltcp 0.14 answers them, docs/lan-neighbors.md
/// step 0), harmless; goes with the other LAN workarounds in step 4.
///
/// IPv4 the same way: smoltcp learns new neighbors only from ARP aimed at
/// it (traffic only refreshes entries it still has), and a client that
/// knows our MAC sends none, so the first answer (DNS, ping, the web
/// interface) to an address it has not seen, or evicted, or forgot when
/// the interface was readdressed, was dropped while it asked, and other
/// clients' answers in that second too (one rate limit for the whole
/// cache). Before such a client's frame, smoltcp gets an ARP reply from it
/// ([`fwd::wire::ipv4_neighbor_hint`]: recorded, not answered), at most
/// every [`Self::EVERY_NS`] per client. Boot argument `arp_hints=0` turns
/// that off. The cache itself is sized for a home LAN (kernel feature
/// `neigh-cache-256`; smoltcp's default of 8 evicted entries constantly).
#[derive(Default)]
pub struct NdHints {
    recent: alloc::vec::Vec<(core::net::IpAddr, [u8; 6], u64)>,
    /// IPv4 hints on (`config::arp_hints`, read once).
    arp: Option<bool>,
    /// WAN IPv6 hints from every source (`config::wan_hints6_all`, read
    /// once).
    wan6_all: Option<bool>,
    /// The last Router Advertisement the link received (the WAN's:
    /// `net::wan6`).
    last_ra: Option<alloc::vec::Vec<u8>>,
}

impl NdHints {
    /// The last RA received, once.
    pub fn take_ra(&mut self) -> Option<alloc::vec::Vec<u8>> {
        self.last_ra.take()
    }
}

impl NdHints {
    /// Within smoltcp's 60 s neighbor lifetime.
    const EVERY_NS: u64 = 20_000_000_000;
    /// Clients remembered per link, both families (the oldest is forgotten).
    const MAX: usize = 128;

    /// `ip` at `mac` should be told (again) at `now_ns`.
    fn due(&mut self, ip: core::net::IpAddr, mac: [u8; 6], now_ns: u64) -> bool {
        if let Some(e) = self.recent.iter_mut().find(|e| e.0 == ip) {
            if e.1 == mac && now_ns.saturating_sub(e.2) < Self::EVERY_NS {
                return false;
            }
            (e.1, e.2) = (mac, now_ns);
            return true;
        }
        if self.recent.len() >= Self::MAX
            && let Some(i) = (0..self.recent.len()).min_by_key(|&i| self.recent[i].2)
        {
            self.recent.swap_remove(i);
        }
        self.recent.push((ip, mac, now_ns));
        true
    }
}

/// Whether an IPv6 hint from `src` may reach smoltcp on `link`. smoltcp
/// fills its cache from any NS, with no subnet check (unlike ARP), and
/// evicts the entry closest to expiry when full. On the WAN, frames from
/// the internet carry remote sources (ICMPv6 errors to the router pass
/// from anyone): hints from them would map those to the gateway's MAC
/// and, past the cache's size within its 60 s lifetime, evict the
/// gateway itself. The WAN's only on-link neighbors are link-local, so
/// only those get hints there (docs/security-audit.md §4.2). `all`: the
/// old behaviour (boot argument `wan_hints6=all`, a negative control).
fn hint6_on_link(link: &LinkShared, src: core::net::Ipv6Addr, all: bool) -> bool {
    all || link.port() >= crate::net::shared::FIRST_LAN_PORT || src.is_unicast_link_local()
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
        match PacketBuf::alloc() {
            Some(mut pkt) if self.ip_only => {
                // IP only: the datapath finds the destination MAC (its
                // neighbor table) and sends it.
                let eth = fwd::wire::ETH_HDR;
                pkt.set_len(eth + len);
                let d = pkt.data_mut();
                d[..12].fill(0);
                let r = f(&mut d[eth..]);
                let t = if d[eth] >> 4 == 6 { fwd::wire::ETHERTYPE_IPV6 } else { fwd::wire::ETHERTYPE_IPV4 };
                fwd::wire::put16(d, 12, t);
                if let Some(dp) = self.dp {
                    let mut touched = [false; crate::net::shared::MAX_PORTS];
                    if dp.send_local(self.ifx, pkt, &mut touched) {
                        *self.queued += 1;
                    }
                }
                r
            }
            Some(mut pkt) if self.port.is_pppoe() => {
                // IP only: an Ethernet header for the datapath to replace.
                let eth = fwd::wire::ETH_HDR;
                pkt.set_len(eth + len);
                let d = pkt.data_mut();
                d[..12].fill(0);
                let r = f(&mut d[eth..]);
                let t = if d[eth] >> 4 == 6 { fwd::wire::ETHERTYPE_IPV6 } else { fwd::wire::ETHERTYPE_IPV4 };
                fwd::wire::put16(d, 12, t);
                self.enqueue(pkt);
                r
            }
            Some(mut pkt) => {
                pkt.set_len(len);
                let r = f(pkt.data_mut());
                // smoltcp is a host: its NAs say "not a router", which
                // makes clients drop us as their default router.
                fwd::wire::ipv6_na_set_router(pkt.data_mut());
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
        let mut pkt = self.link.local_rx.lock().pop_front()?;
        if self.ip_only {
            // IP only: the datapath answered ARP / ND itself; anything not
            // IP is not for a `Medium::Ip` stack.
            while !matches!(
                fwd::wire::ethertype(pkt.data()),
                Some(fwd::wire::ETHERTYPE_IPV4 | fwd::wire::ETHERTYPE_IPV6)
            ) {
                pkt = self.link.local_rx.lock().pop_front()?;
            }
        }
        if let Some(nd) = self.nd.as_deref_mut()
            && fwd::wire::ethertype(pkt.data()) == Some(fwd::wire::ETHERTYPE_IPV6)
        {
            let d = pkt.data();
            if d.get(fwd::wire::ETH_HDR + 6) == Some(&fwd::wire::PROTO_ICMPV6) && d.get(fwd::wire::ETH_HDR + 40) == Some(&134) {
                nd.last_ra = Some(d.to_vec());
            }
        }
        // Neighbor discovery help (Ethernet only: PPP has no link layer,
        // and an IP-only link's neighbors are the datapath's).
        if let Some(nd) = self.nd.as_deref_mut()
            && !self.port.is_pppoe()
            && !self.ip_only
            && fwd::wire::ethertype(pkt.data()) == Some(fwd::wire::ETHERTYPE_IPV6)
        {
            fwd::wire::ipv6_ns_to_solicited(pkt.data_mut());
            let mut hint = [0u8; fwd::wire::NEIGHBOR_HINT_LEN];
            if let Some((ip, mac)) = fwd::wire::ipv6_neighbor_hint(pkt.data(), &mut hint)
                && hint6_on_link(self.link, ip, *nd.wan6_all.get_or_insert_with(crate::config::wan_hints6_all))
                && nd.due(ip.into(), mac, self.now_ns)
                && let Some(mut h) = PacketBuf::alloc()
            {
                h.set_len(hint.len());
                h.data_mut().copy_from_slice(&hint);
                // The frame itself comes next.
                self.link.local_rx.lock().push_front(pkt);
                pkt = h;
            }
        }
        if let Some(nd) = self.nd.as_deref_mut()
            && !self.port.is_pppoe()
            && !self.ip_only
            && fwd::wire::ethertype(pkt.data()) == Some(fwd::wire::ETHERTYPE_IPV4)
            && *nd.arp.get_or_insert_with(crate::config::arp_hints)
        {
            let mut hint = [0u8; fwd::wire::ARP_HINT_LEN];
            if let Some((ip, mac)) = fwd::wire::ipv4_neighbor_hint(pkt.data(), &mut hint)
                && nd.due(ip.into(), mac, self.now_ns)
                && let Some(mut h) = PacketBuf::alloc()
            {
                h.set_len(hint.len());
                h.data_mut().copy_from_slice(&hint);
                self.link.local_rx.lock().push_front(pkt);
                pkt = h;
            }
        }
        if is_router_solicitation(pkt.data()) {
            // smoltcp ignores it (a host); the network's advertiser answers.
            self.link.rs_seen.store(true, Ordering::Relaxed);
        }
        let skip = if self.port.is_pppoe() || self.ip_only {
            fwd::wire::ETH_HDR
        } else {
            0
        };
        Some((
            RxToken(pkt, skip),
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
        if self.port.is_pppoe() {
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = self.port.mtu() as usize;
        } else if self.ip_only {
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = 1500;
        } else {
            caps.medium = Medium::Ethernet;
            caps.max_transmission_unit = 1514;
        }
        caps.max_burst_size = Some(1);
        caps
    }
}
