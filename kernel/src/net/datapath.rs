//! The forwarding datapath: drivers ↔ `fwd::Forwarder` ↔ qdiscs.
//!
//! ```text
//!  NIC RX ─► Forwarder::process ─┬─ Local ───► port.local_rx ─► smoltcp (router stack)
//!                                ├─ Forward ─► neigh resolve ─► egress qdisc
//!                                └─ Drop
//!  smoltcp TX ─────────────────────────────────────────────────► port qdisc
//!  port qdisc ─► (pull, while the NIC has room) ─► NIC TX
//! ```
//!
//! The qdisc (a bounded FIFO until CAKE lands in M6) is the only place
//! packets wait; the neighbor table holds at most 3 packets per unresolved
//! next hop. RX is drained with a per-port budget so one busy port cannot
//! starve the other.

use crate::config;
use crate::net::packet::{PacketBuf, PacketMeta};
use crate::net::stack::NetIf;
use crate::timer;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU64, Ordering};
use fwd::forwarder::{Classification, Forwarder, Interface, Role, Verdict};
use fwd::neigh::{NeighTable, Resolve};
use fwd::{IfIndex, wire};
use qdisc::{Dequeue, Qdisc};

/// Frames handled per port per loop iteration.
const RX_BUDGET: usize = 64;
/// Bound on frames waiting for the router stack (drained every iteration).
pub const LOCAL_RX_MAX: usize = 64;
const MAX_CONNS: usize = 16_384;
const HOUSEKEEPING_MS: u64 = 1_000;

pub const WAN: IfIndex = 0;
#[allow(dead_code)] // documents the port layout; used by tests and stats
pub const LAN: IfIndex = 1;

/// Counters for diagnostics (read by the self-test / stats output).
pub static FORWARDED: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);

pub struct Datapath {
    pub fwd: Forwarder,
    neigh: NeighTable<PacketBuf>,
    next_housekeeping: u64,
    /// RX budget was exhausted: more frames are waiting.
    pub more_rx: bool,
    pub local_rx_drops: u64,
    pub qdisc_drops: u64,
    next_stats: u64,
    last_dequeued: [u64; 2],
    /// Per ingress port: forwarded IPv4 packets by ECN codepoint
    /// [Not-ECT, ECT(1), ECT(0), CE], and TCP packets with ECE / CWR set.
    ecn_seen: [[u64; 4]; 2],
    tcp_ece: [u64; 2],
    tcp_cwr: [u64; 2],
    ecn_reported: [u64; 2],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FlushResult {
    /// Earliest time (uptime ns) a shaper will release its next packet.
    pub shaper_wake_ns: Option<u64>,
    /// A qdisc has packets but the NIC ring is full (wait for TX completion).
    pub ring_full_backlog: bool,
}

/// Print per-port qdisc statistics every this many ms (only if there was traffic).
const STATS_MS: u64 = 10_000;

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

pub fn now_ns() -> u64 {
    timer::uptime().as_nanos() as u64
}

fn meta_from(class: &Classification, ingress: IfIndex, len: usize, now: u64) -> PacketMeta {
    PacketMeta {
        enqueue_ts: now,
        flow_hash: class.flow_hash,
        src_host_hash: class.src_host_hash,
        dst_host_hash: class.dst_host_hash,
        dscp: class.dscp,
        tin: 0,
        ecn_capable: class.ecn_capable,
        wire_len: len as u32,
        is_pure_ack: class.is_pure_ack,
        ingress_if: ingress,
    }
}

impl Datapath {
    /// `ifs[0]` is the WAN, `ifs[1]` the LAN.
    pub fn new(ifs: &[NetIf]) -> Self {
        let mut fwd = Forwarder::new(MAX_CONNS, timer::ticks() ^ 0x9e37_79b9_7f4a_7c15);
        for (i, nif) in ifs.iter().enumerate() {
            let (role, addr) = if i as IfIndex == WAN {
                (Role::Wan, None)
            } else {
                let lan = config::lan();
                (Role::Lan, Some((lan.addr, lan.prefix)))
            };
            fwd.add_interface(Interface {
                mac: nif.dev.mac(),
                addr,
                role,
            });
        }
        Self {
            fwd,
            neigh: NeighTable::new(),
            next_housekeeping: 0,
            more_rx: false,
            local_rx_drops: 0,
            qdisc_drops: 0,
            next_stats: STATS_MS,
            last_dequeued: [0; 2],
            ecn_seen: [[0; 4]; 2],
            tcp_ece: [0; 2],
            tcp_cwr: [0; 2],
            ecn_reported: [0; 2],
        }
    }

    /// The WAN lease changed.
    pub fn set_wan(&mut self, addr: Option<(Ipv4Addr, u8)>, gateway: Option<Ipv4Addr>) {
        self.fwd.set_addr(WAN, addr);
        self.fwd
            .set_default_route(gateway.filter(|_| addr.is_some()).map(|gw| (WAN, gw)));
    }

    fn enqueue(&mut self, ifs: &mut [NetIf], egress: IfIndex, pkt: PacketBuf) {
        let now = now_ns();
        if ifs[egress as usize].qdisc.enqueue(pkt, now).is_err() {
            self.qdisc_drops += 1;
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Fill in the Ethernet addresses and queue for transmission.
    fn send_resolved(
        &mut self,
        ifs: &mut [NetIf],
        egress: IfIndex,
        mac: wire::Mac,
        mut pkt: PacketBuf,
    ) {
        let src = self.fwd.interface(egress).mac;
        wire::set_macs(pkt.data_mut(), mac, src);
        self.enqueue(ifs, egress, pkt);
    }

    fn send_arp_request(&mut self, ifs: &mut [NetIf], ifx: IfIndex, target: Ipv4Addr) {
        let iface = *self.fwd.interface(ifx);
        let (Some((my_ip, _)), Some(mut pkt)) = (iface.addr, PacketBuf::alloc()) else {
            return;
        };
        pkt.set_len(60); // minimum Ethernet frame
        pkt.data_mut().fill(0);
        wire::build_arp_request(pkt.data_mut(), iface.mac, my_ip, target);
        self.enqueue(ifs, ifx, pkt);
    }

    /// ECN diagnostics on a forwarded frame (before NAT/egress): codepoint
    /// counts, and the TCP ECE (receiver saw CE) / CWR (sender reacted) flags.
    fn observe_ecn(&mut self, ingress: IfIndex, frame: &[u8]) {
        let i = ingress as usize;
        if i >= 2 {
            return;
        }
        let Some(v) = wire::Ipv4View::parse(frame, wire::ETH_HDR) else {
            return;
        };
        self.ecn_seen[i][(v.tos(frame) & 3) as usize] += 1;
        if v.proto == wire::PROTO_TCP && v.l4_len >= 14 {
            let flags = frame[v.l4 + 13];
            if flags & 0x40 != 0 {
                self.tcp_ece[i] += 1;
            }
            if flags & 0x80 != 0 {
                self.tcp_cwr[i] += 1;
            }
        }
    }

    /// Learn neighbors from ARP and release packets waiting for them.
    fn snoop_arp(&mut self, ifs: &mut [NetIf], ifx: IfIndex, frame: &[u8], now: u64) {
        let Some(arp) = wire::parse_arp(frame) else {
            return;
        };
        let iface = self.fwd.interface(ifx);
        let in_subnet = iface.addr.is_some_and(|(a, l)| {
            let m = if l == 0 {
                0
            } else {
                u32::MAX << (32 - l as u32)
            };
            u32::from(arp.sender_ip) & m == u32::from(a) & m && arp.sender_ip != a
        });
        if !in_subnet {
            return;
        }
        for pkt in self.neigh.learn(ifx, arp.sender_ip, arp.sender_mac, now) {
            self.send_resolved(ifs, ifx, arp.sender_mac, pkt);
        }
    }

    /// Drain every NIC's RX ring (up to the budget) through the forwarder.
    pub fn rx(&mut self, ifs: &mut [NetIf]) {
        let now = now_ms();
        self.more_rx = false;
        for i in 0..ifs.len() {
            let ifx = i as IfIndex;
            for n in 0.. {
                if n == RX_BUDGET {
                    self.more_rx = true;
                    break;
                }
                let Some(mut pkt) = ifs[i].dev.receive() else {
                    break;
                };
                if wire::ethertype(pkt.data()) == Some(wire::ETHERTYPE_ARP) {
                    self.snoop_arp(ifs, ifx, pkt.data(), now);
                }
                let len = pkt.len();
                match self
                    .fwd
                    .process(now, ifx, pkt.data_with_tailroom_mut(), len)
                {
                    Verdict::Local => {
                        let q = &mut ifs[i].local_rx;
                        if q.len() < LOCAL_RX_MAX {
                            q.push_back(pkt);
                        } else {
                            self.local_rx_drops += 1;
                        }
                    }
                    Verdict::Forward {
                        egress,
                        next_hop,
                        len,
                        class,
                    } => {
                        pkt.set_len(len);
                        self.observe_ecn(ifx, pkt.data());
                        pkt.meta = meta_from(&class, ifx, len, now_ns());
                        FORWARDED.fetch_add(1, Ordering::Relaxed);
                        match self.neigh.resolve(egress, next_hop, pkt, now) {
                            Resolve::Ready(mac, pkt) => self.send_resolved(ifs, egress, mac, pkt),
                            Resolve::Queued { send_arp: true } => {
                                self.send_arp_request(ifs, egress, next_hop)
                            }
                            Resolve::Queued { send_arp: false } => {}
                        }
                    }
                    Verdict::Drop(_) => {
                        DROPPED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Once a second: expire connections, retry ARP.
    pub fn housekeeping(&mut self, ifs: &mut [NetIf]) {
        let now = now_ms();
        if now < self.next_housekeeping {
            return;
        }
        self.next_housekeeping = now + HOUSEKEEPING_MS;
        self.fwd.expire(now);
        if now >= self.next_stats {
            self.next_stats = now + STATS_MS;
            self.print_qdisc_stats(ifs);
        }
        for (ifx, ip) in self.neigh.poll(now) {
            self.send_arp_request(ifs, ifx, ip);
        }
    }

    /// Move packets from each qdisc to its NIC while the NIC has room and
    /// the shaper allows.
    pub fn flush_tx(&mut self, ifs: &mut [NetIf]) -> FlushResult {
        let now = now_ns();
        let mut r = FlushResult::default();
        for nif in ifs.iter_mut() {
            nif.dev.reap_tx();
            let mut shaper_wait = None;
            while nif.dev.can_transmit() {
                match nif.qdisc.dequeue(now) {
                    Dequeue::Packet(p) => {
                        if nif.dev.transmit(p).is_err() {
                            self.qdisc_drops += 1;
                        }
                    }
                    Dequeue::WaitUntil(t) => {
                        shaper_wait = Some(t);
                        break;
                    }
                    Dequeue::Empty => break,
                }
            }
            if let Some(t) = shaper_wait {
                r.shaper_wake_ns = Some(r.shaper_wake_ns.map_or(t, |w: u64| w.min(t)));
            } else if nif.qdisc.stats().backlog_packets > 0 {
                r.ring_full_backlog = true;
            }
        }
        r
    }

    /// One console line per port that sent traffic since the last report.
    fn print_qdisc_stats(&mut self, ifs: &mut [NetIf]) {
        for (i, nif) in ifs.iter().enumerate().take(2) {
            let total: u64 = self.ecn_seen[i].iter().sum();
            if total == self.ecn_reported[i] {
                continue;
            }
            self.ecn_reported[i] = total;
            let e = self.ecn_seen[i];
            crate::println!(
                "  ecn rx {}      : not-ect {}, ect0 {}, ect1 {}, ce {} | tcp ece {}, cwr {}",
                nif.name,
                e[0],
                e[2],
                e[1],
                e[3],
                self.tcp_ece[i],
                self.tcp_cwr[i]
            );
        }
        for (i, nif) in ifs.iter_mut().enumerate().take(2) {
            let s = nif.qdisc.stats();
            if s.dequeued == self.last_dequeued[i] {
                continue;
            }
            self.last_dequeued[i] = s.dequeued;
            let max_sojourn = nif.qdisc.inner_mut().take_max_sojourn_ns();
            let shaped = match nif.qdisc.rate() {
                Some(r) => alloc::format!(
                    "shaped {} kbit/s, throttled {}, ",
                    r.bits_per_sec / 1000,
                    nif.qdisc.throttled
                ),
                None => alloc::string::String::new(),
            };
            crate::println!(
                "  qdisc {}       : {shaped}sent {}, aqm drops {}, ecn marks {}, overflow drops {}, backlog {} pkts, max sojourn {}.{:03} ms",
                nif.name,
                s.dequeued,
                s.aqm_actions - s.marked,
                s.marked,
                s.dropped - (s.aqm_actions - s.marked),
                s.backlog_packets,
                max_sojourn / 1_000_000,
                (max_sojourn / 1_000) % 1_000
            );
        }
    }

    pub fn next_housekeeping(&self) -> u64 {
        self.next_housekeeping
    }
}
