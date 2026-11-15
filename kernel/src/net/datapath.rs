//! The forwarding datapath: drivers ↔ `fwd::Forwarder` ↔ qdiscs.
//!
//! ```text
//!  NIC RX ─► VLAN ─► shard_of ─► Forwarder shard ─┬─ Local ───► port.local_rx ─► smoltcp (router stack)
//!                                         ├─ Forward ─► neigh[egress] ─► egress qdisc
//!                                         └─ Drop
//!  smoltcp TX ──────────────────────────────────────────────────────────► port qdisc
//!  port qdisc ─► (pull, while the NIC has room) ─► VLAN ─► NIC TX
//! ```
//!
//! 802.1Q tags (the port's [`PortShared::vlan`]) exist only at the two
//! ends: removed first thing on RX (`wire::vlan_rx`: wrong or missing tags
//! are dropped and counted in [`VLAN_DROPS`]), added last on TX. The
//! forwarder, ARP, the neighbor tables, smoltcp and the qdiscs see untagged
//! frames; the WAN shaper adds the tag's 4 bytes (`config::Qos::port_rate`).
//!
//! The qdisc is the only place packets wait; the neighbor table holds at
//! most 3 packets per unresolved next hop.
//!
//! Shared by both direction tasks (`net::stack::run_dir`) without an outer
//! lock (M11): the forwarder is split into [`SHARDS`] shards
//! (`fwd::forwarder::shard_of`: both directions of a connection hit the
//! same one), each behind its own lock; the neighbor table and the
//! interface address are per port; counters are atomics. A frame takes one
//! shard lock, then the egress port's neighbor lock, then its qdisc lock,
//! one after the other (never nested), so the two directions only meet
//! when they touch the same connection or port.

use crate::config;
use crate::drivers::Nic;
use crate::net::packet::{PacketBuf, PacketMeta};
use crate::net::shared::PortShared;
use crate::net::shared::{LOCAL_RX_MAX, Shared};
use crate::timer;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU64, Ordering};
use fwd::forwarder::{Classification, Forwarder, Interface, Role, Verdict, shard_of};
use fwd::neigh::{NeighTable, Resolve};
use fwd::{IfIndex, wire};
use qdisc::{Dequeue, Qdisc};
use spin::Mutex;

/// Frames handled per port per loop iteration.
pub const RX_BUDGET: usize = 64;
/// Forwarder (conntrack) shards.
pub const SHARDS: usize = 16;
const MAX_CONNS: usize = 16_384;
const HOUSEKEEPING_MS: u64 = 1_000;

pub const WAN: IfIndex = 0;
#[allow(dead_code)] // documents the port layout; used by tests and stats
pub const LAN: IfIndex = 1;

/// Counters for diagnostics (read by the self-test / stats output).
pub static FORWARDED: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Received frames with the wrong VLAN tag for their port (or none).
pub static VLAN_DROPS: AtomicU64 = AtomicU64::new(0);

/// Bookkeeping only the primary direction task touches.
struct Hk {
    next_housekeeping: u64,
    next_stats: u64,
    last_dequeued: [u64; 2],
    ecn_reported: [u64; 2],
    vlan_reported: u64,
}

pub struct Datapath {
    sh: &'static Shared,
    hash_key: u64,
    shards: Vec<Mutex<Forwarder>>,
    /// Per port: neighbors on that port.
    neigh: Vec<Mutex<NeighTable<PacketBuf>>>,
    /// Per port: the interface address (the WAN one changes with the lease).
    addrs: Vec<Mutex<Option<(Ipv4Addr, u8)>>>,
    hk: Mutex<Hk>,
    local_rx_drops: AtomicU64,
    /// Per ingress port: forwarded IPv4 packets by ECN codepoint
    /// [Not-ECT, ECT(1), ECT(0), CE], and TCP packets with ECE / CWR set.
    ecn_seen: [[AtomicU64; 4]; 2],
    tcp_ece: [AtomicU64; 2],
    tcp_cwr: [AtomicU64; 2],
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

fn relaxed(a: &AtomicU64) -> u64 {
    a.load(Ordering::Relaxed)
}

impl Datapath {
    /// `sh.ports[0]` is the WAN, `sh.ports[1]` the LAN.
    pub fn new(sh: &'static Shared) -> Self {
        let hash_key = timer::ticks() ^ 0x9e37_79b9_7f4a_7c15;
        let ifaces: Vec<Interface> = sh
            .ports
            .iter()
            .enumerate()
            .map(|(i, port)| {
                let (role, addr) = if i as IfIndex == WAN {
                    (Role::Wan, None)
                } else {
                    let lan = config::lan();
                    (Role::Lan, Some((lan.addr, lan.prefix)))
                };
                Interface {
                    mac: port.mac,
                    addr,
                    role,
                }
            })
            .collect();
        let shards = (0..SHARDS)
            .map(|k| {
                let mut f =
                    Forwarder::new_shard(MAX_CONNS / SHARDS, hash_key, SHARDS as u16, k as u16);
                for iface in &ifaces {
                    f.add_interface(*iface);
                }
                Mutex::new(f)
            })
            .collect();
        Self {
            sh,
            hash_key,
            shards,
            neigh: ifaces
                .iter()
                .map(|_| Mutex::new(NeighTable::new()))
                .collect(),
            addrs: ifaces.iter().map(|i| Mutex::new(i.addr)).collect(),
            hk: Mutex::new(Hk {
                next_housekeeping: 0,
                next_stats: STATS_MS,
                last_dequeued: [0; 2],
                ecn_reported: [0; 2],
                vlan_reported: 0,
            }),
            local_rx_drops: AtomicU64::new(0),
            ecn_seen: [const { [const { AtomicU64::new(0) }; 4] }; 2],
            tcp_ece: [const { AtomicU64::new(0) }; 2],
            tcp_cwr: [const { AtomicU64::new(0) }; 2],
        }
    }

    /// The WAN lease changed: every shard, and the WAN address copy.
    pub fn set_wan(&self, addr: Option<(Ipv4Addr, u8)>, gateway: Option<Ipv4Addr>) {
        for s in &self.shards {
            let mut f = s.lock();
            f.set_addr(WAN, addr);
            f.set_default_route(gateway.filter(|_| addr.is_some()).map(|gw| (WAN, gw)));
        }
        *self.addrs[WAN as usize].lock() = addr;
    }

    fn enqueue(&self, egress: IfIndex, pkt: PacketBuf, touched: &mut [bool; 2]) {
        let now = now_ns();
        if let Some(t) = touched.get_mut(egress as usize) {
            *t = true;
        }
        if self.sh.ports[egress as usize]
            .qdisc
            .lock()
            .enqueue(pkt, now)
            .is_err()
        {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Fill in the Ethernet addresses and queue for transmission.
    fn send_resolved(
        &self,
        egress: IfIndex,
        mac: wire::Mac,
        mut pkt: PacketBuf,
        touched: &mut [bool; 2],
    ) {
        let src = self.sh.ports[egress as usize].mac;
        wire::set_macs(pkt.data_mut(), mac, src);
        self.enqueue(egress, pkt, touched);
    }

    fn send_arp_request(&self, ifx: IfIndex, target: Ipv4Addr, touched: &mut [bool; 2]) {
        let addr = *self.addrs[ifx as usize].lock();
        let (Some((my_ip, _)), Some(mut pkt)) = (addr, PacketBuf::alloc()) else {
            return;
        };
        pkt.set_len(60); // minimum Ethernet frame
        pkt.data_mut().fill(0);
        wire::build_arp_request(
            pkt.data_mut(),
            self.sh.ports[ifx as usize].mac,
            my_ip,
            target,
        );
        self.enqueue(ifx, pkt, touched);
    }

    /// ECN diagnostics on a forwarded frame (before NAT/egress): codepoint
    /// counts, and the TCP ECE (receiver saw CE) / CWR (sender reacted) flags.
    fn observe_ecn(&self, ingress: IfIndex, frame: &[u8]) {
        let i = ingress as usize;
        if i >= 2 {
            return;
        }
        let Some(v) = wire::Ipv4View::parse(frame, wire::ETH_HDR) else {
            return;
        };
        self.ecn_seen[i][(v.tos(frame) & 3) as usize].fetch_add(1, Ordering::Relaxed);
        if v.proto == wire::PROTO_TCP && v.l4_len >= 14 {
            let flags = frame[v.l4 + 13];
            if flags & 0x40 != 0 {
                self.tcp_ece[i].fetch_add(1, Ordering::Relaxed);
            }
            if flags & 0x80 != 0 {
                self.tcp_cwr[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Learn neighbors from ARP and release packets waiting for them.
    fn snoop_arp(&self, ifx: IfIndex, frame: &[u8], now: u64, touched: &mut [bool; 2]) {
        let Some(arp) = wire::parse_arp(frame) else {
            return;
        };
        let addr = *self.addrs[ifx as usize].lock();
        let in_subnet = addr.is_some_and(|(a, l)| {
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
        let released =
            self.neigh[ifx as usize]
                .lock()
                .learn(ifx, arp.sender_ip, arp.sender_mac, now);
        for pkt in released {
            self.send_resolved(ifx, arp.sender_mac, pkt, touched);
        }
    }

    /// Run one port's received frames (taken from its NIC by the caller,
    /// at most [`RX_BUDGET`]) through the forwarder. Drains `batch`; marks
    /// in `touched` the egress ports whose qdisc got packets.
    pub fn rx_batch(&self, ifx: IfIndex, batch: &mut Vec<PacketBuf>, touched: &mut [bool; 2]) {
        let now = now_ms();
        let role = if ifx == WAN { Role::Wan } else { Role::Lan };
        let want_vid = self.sh.ports[ifx as usize].vlan().map(|tci| tci & 0x0fff);
        let mut local = false;
        for mut pkt in batch.drain(..) {
            match wire::vlan_rx(pkt.data(), want_vid) {
                wire::VlanRx::Accept { strip: false } => {}
                wire::VlanRx::Accept { strip: true } => pkt.pop_vlan(),
                wire::VlanRx::Drop => {
                    VLAN_DROPS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            if wire::ethertype(pkt.data()) == Some(wire::ETHERTYPE_ARP) {
                self.snoop_arp(ifx, pkt.data(), now, touched);
            }
            let len = pkt.len();
            let k = shard_of(role, pkt.data(), SHARDS, self.hash_key);
            let verdict =
                self.shards[k]
                    .lock()
                    .process(now, ifx, pkt.data_with_tailroom_mut(), len);
            match verdict {
                Verdict::Local => {
                    let mut q = self.sh.ports[ifx as usize].local_rx.lock();
                    if q.len() < LOCAL_RX_MAX {
                        q.push_back(pkt);
                        local = true;
                    } else {
                        self.local_rx_drops.fetch_add(1, Ordering::Relaxed);
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
                    let r = self.neigh[egress as usize]
                        .lock()
                        .resolve(egress, next_hop, pkt, now);
                    match r {
                        Resolve::Ready(mac, pkt) => self.send_resolved(egress, mac, pkt, touched),
                        Resolve::Queued { send_arp: true } => {
                            self.send_arp_request(egress, next_hop, touched)
                        }
                        Resolve::Queued { send_arp: false } => {}
                    }
                }
                Verdict::Drop(_) => {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if local {
            self.sh.svc_kick.signal();
        }
    }

    /// Once a second (primary task): expire connections, retry ARP, print
    /// statistics. No NIC access.
    pub fn housekeeping(&self, touched: &mut [bool; 2]) {
        let now = now_ms();
        let print = {
            let mut hk = self.hk.lock();
            if now < hk.next_housekeeping {
                return;
            }
            hk.next_housekeeping = now + HOUSEKEEPING_MS;
            let p = now >= hk.next_stats;
            if p {
                hk.next_stats = now + STATS_MS;
            }
            p
        };
        let mut conns = 0;
        for s in &self.shards {
            let mut f = s.lock();
            f.expire(now);
            conns += f.ct.len();
        }
        self.sh.conntrack.store(conns, Ordering::Relaxed);
        for (i, n) in self.neigh.iter().enumerate() {
            let retries = n.lock().poll(now);
            for (ifx, ip) in retries {
                debug_assert_eq!(ifx as usize, i);
                self.send_arp_request(ifx, ip, touched);
            }
        }
        if print {
            self.print_qdisc_stats();
        }
    }

    /// One console line per port that sent traffic since the last report.
    fn print_qdisc_stats(&self) {
        let mut printed = false;
        let vlan_drops = relaxed(&VLAN_DROPS);
        let new_vlan_drops = {
            let mut hk = self.hk.lock();
            core::mem::replace(&mut hk.vlan_reported, vlan_drops) != vlan_drops
        };
        if new_vlan_drops {
            crate::println!("  vlan            : {vlan_drops} frames dropped (wrong or missing tag)");
        }
        for (i, nif) in self.sh.ports.iter().enumerate().take(2) {
            let e: [u64; 4] = core::array::from_fn(|c| relaxed(&self.ecn_seen[i][c]));
            let total: u64 = e.iter().sum();
            {
                let mut hk = self.hk.lock();
                if total == hk.ecn_reported[i] {
                    continue;
                }
                hk.ecn_reported[i] = total;
            }
            crate::println!(
                "  ecn rx {}      : not-ect {}, ect0 {}, ect1 {}, ce {} | tcp ece {}, cwr {}",
                nif.name,
                e[0],
                e[2],
                e[1],
                e[3],
                relaxed(&self.tcp_ece[i]),
                relaxed(&self.tcp_cwr[i])
            );
        }
        for i in 0..self.sh.ports.len().min(2) {
            let nif = &self.sh.ports[i];
            let mut qdisc = nif.qdisc.lock();
            let s = qdisc.stats();
            {
                let mut hk = self.hk.lock();
                if s.dequeued == hk.last_dequeued[i] {
                    continue;
                }
                hk.last_dequeued[i] = s.dequeued;
            }
            printed = true;
            let throttled = qdisc.throttled;
            let rate = qdisc.rate();
            let aqm = qdisc.inner_mut();
            let max_sojourn = aqm.take_max_sojourn_ns();
            let flows = aqm.diag();
            drop(qdisc); // the console is slow: print without holding the lock
            let shaped = match rate {
                Some(r) => alloc::format!(
                    "shaped {} kbit/s, throttled {}, ",
                    r.bits_per_sec / 1000,
                    throttled
                ),
                None => alloc::string::String::new(),
            };
            crate::println!(
                "  qdisc {}       : {shaped}{flows}sent {}, aqm drops {}, ecn marks {}, overflow drops {}, backlog {} pkts, max sojourn {}.{:03} ms",
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
        // Cumulative CPU time by task, and where device interrupts land
        // (scripts/lab-test.sh checks both).
        if printed {
            let t = crate::executor::cpu_ticks(0);
            let ms = |ticks: u64| timer::ticks_to_duration(ticks).as_millis();
            let mut tasks = alloc::string::String::new();
            crate::executor::task_ticks(|name, core, ticks| {
                use core::fmt::Write;
                let _ = write!(tasks, ", {name}@{core} {} ms", ms(ticks));
            });
            let irqs: Vec<u64> = (0..crate::smp::online())
                .map(crate::irq::dev_irqs)
                .collect();
            crate::println!(
                "  cpu             : core 0 idle {} ms, uptime {} ms{tasks}, dev irqs {irqs:?}",
                ms(t.idle),
                timer::uptime().as_millis()
            );
        }
    }

    pub fn next_housekeeping(&self) -> u64 {
        self.hk.lock().next_housekeeping
    }
}

/// Move packets from a port's qdisc to its NIC while the NIC has room and
/// the shaper allows (the port's TX task, with the NIC locked).
pub fn flush_port(port: &PortShared, dev: &mut Nic) -> FlushResult {
    let now = now_ns();
    let mut r = FlushResult::default();
    dev.reap_tx();
    let tag = port.vlan();
    let mut qdisc = port.qdisc.lock();
    while dev.can_transmit() {
        match qdisc.dequeue(now) {
            Dequeue::Packet(mut p) => {
                if let Some(tci) = tag {
                    p.push_vlan(tci);
                }
                if dev.transmit(p).is_err() {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
            Dequeue::WaitUntil(t) => {
                r.shaper_wake_ns = Some(t);
                return r;
            }
            Dequeue::Empty => break,
        }
    }
    r.ring_full_backlog = qdisc.stats().backlog_packets > 0;
    r
}
