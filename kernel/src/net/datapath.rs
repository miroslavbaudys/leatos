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
//! Links (`net::shared::LinkShared`) are the forwarder's interfaces: link
//! 0 is the WAN on port 0, links 1.. the networks on port 1 (`lan0`),
//! untagged or on a VLAN. On RX a `lan0` frame's VID picks its link (no
//! link for it: dropped, [`VLAN_DROPS`]); a frame for a network on a VLAN
//! gets its tag when it is queued on the port (forwarded, ARP, or from
//! smoltcp), so the qdisc holds tagged frames and counts the 4 bytes.
//!
//! The WAN's 802.1Q tag (the port's [`PortShared::vlan`]) exists only at
//! the two ends: removed first thing on RX (`wire::vlan_rx`: wrong or
//! missing tags are dropped and counted in [`VLAN_DROPS`]), added last on
//! TX; the WAN shaper adds the tag's 4 bytes (`config::Qos::port_rate`).
//!
//! PPPoE (a port in PPPoE mode, [`PortShared::is_pppoe`]) works the same
//! way, inside the VLAN tag: IPv4 of the current session is decapsulated
//! right after the tag is removed and encapsulated right before it is
//! added (`proto_pppoe::wire`), so everything in between sees Ethernet/IPv4
//! with the access concentrator's MAC as the only neighbor (no ARP).
//! Discovery and PPP control frames go to the PPPoE client in svc through
//! [`PortShared::ctrl_rx`]; other frames are dropped ([`PPPOE_DROPS`]).
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

use crate::drivers::Nic;
use crate::net::packet::{PacketBuf, PacketMeta};
use crate::net::shared::{Networks, PortShared};
use crate::net::shared::{CTRL_RX_MAX, LOCAL_RX_MAX, Shared};
use crate::timer;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU64, Ordering};
use fwd::forwarder::{
    Classification, Forwarder, Interface, PortForward, Redirect, Role, ShardHints, Verdict, shard_of,
};
use fwd::neigh::{NeighTable, Resolve};
use fwd::{IfIndex, wire};
use qdisc::{Dequeue, Qdisc};
use spin::Mutex;

/// Frames handled per port per loop iteration.
pub const RX_BUDGET: usize = 64;
/// Forwarder (conntrack) shards.
pub const SHARDS: usize = 16;
/// Tracked connections, all shards together (`fwd::conntrack::Budget`).
const MAX_CONNS: usize = 16_384;
const HOUSEKEEPING_MS: u64 = 1_000;

/// The WAN link (on port 0); the networks are links 1.. on port 1.
pub const WAN: IfIndex = 0;

/// Counters for diagnostics (read by the self-test / stats output).
pub static FORWARDED: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
/// The forwarder's drops by reason (`fwd::forwarder::DropReason::index`),
/// part of `DROPPED` (the web interface's firewall page).
pub static DROP_REASONS: [AtomicU64; fwd::forwarder::DROP_REASONS] =
    [const { AtomicU64::new(0) }; fwd::forwarder::DROP_REASONS];
/// Received frames with the wrong VLAN tag for their port (or none).
pub static VLAN_DROPS: AtomicU64 = AtomicU64::new(0);
/// Tracked connections removed because a new firewall policy refused them
/// (`Forwarder::recheck`).
pub static REVOKED: AtomicU64 = AtomicU64::new(0);
/// Refused packets answered with a RST / port unreachable (`reject`),
/// summed over the shards once a second (not in `DROP_REASONS`).
pub static REJECTED: AtomicU64 = AtomicU64::new(0);
/// On a PPPoE port: received frames that are not PPPoE, control frames
/// that found the client's queue full, and IPv4 to send while there is no
/// session.
pub static PPPOE_DROPS: AtomicU64 = AtomicU64::new(0);

/// What a PPPoE port does with a received frame.
enum PppoeRx {
    /// IPv4 of the session, now a plain Ethernet/IPv4 frame.
    Ipv4,
    /// For the PPPoE client.
    Control,
    Drop,
}

/// Decapsulate session IPv4 in place, or say where the frame goes.
fn pppoe_rx(pkt: &mut PacketBuf, session: Option<proto_pppoe::Session>) -> PppoeRx {
    use proto_pppoe::wire::{self as pw, SessionRx};
    match wire::ethertype(pkt.data()) {
        Some(pw::ETHERTYPE_DISCOVERY) => PppoeRx::Control,
        Some(pw::ETHERTYPE_SESSION) => match pw::classify_session(pkt.data(), session) {
            SessionRx::Ipv4 { len } => {
                pw::decap_ipv4(pkt.data_mut());
                pkt.pull_front(pw::SESSION_OVERHEAD);
                pkt.set_len(pw::ETH_HDR + len);
                PppoeRx::Ipv4
            }
            SessionRx::Control => PppoeRx::Control,
        },
        _ => PppoeRx::Drop,
    }
}

/// Encapsulate for a PPPoE port: IPv4 goes into the session (none: `false`,
/// drop it); the client's own PPPoE frames go as they are; anything else
/// (no ARP on PPPoE) is dropped.
fn pppoe_tx(pkt: &mut PacketBuf, session: Option<proto_pppoe::Session>, mac: wire::Mac) -> bool {
    use proto_pppoe::wire as pw;
    match wire::ethertype(pkt.data()) {
        Some(pw::ETHERTYPE_DISCOVERY | pw::ETHERTYPE_SESSION) => true,
        Some(wire::ETHERTYPE_IPV4) => match session {
            Some(s) => {
                pkt.push_front(pw::SESSION_OVERHEAD);
                pw::encap_ipv4(pkt.data_mut(), s, mac);
                true
            }
            None => false,
        },
        _ => false,
    }
}

/// A PADT for the port's PPPoE session, if there is one (sent directly at
/// shutdown, so the ISP does not keep a stale session).
pub fn padt(port: &PortShared) -> Option<PacketBuf> {
    let s = port.pppoe_session()?;
    let mut pkt = PacketBuf::alloc()?;
    pkt.set_len(proto_pppoe::wire::MIN_FRAME);
    let n = proto_pppoe::wire::write_padt(pkt.data_mut(), s, port.mac);
    pkt.set_len(n);
    if let Some(tci) = port.vlan() {
        pkt.push_vlan(tci);
    }
    Some(pkt)
}

/// Bookkeeping only the primary direction task touches.
struct Hk {
    next_housekeeping: u64,
    next_stats: u64,
    last_dequeued: [u64; 2],
    ecn_reported: [u64; 2],
    vlan_reported: u64,
}

/// The networks as the receive path needs them.
#[derive(Default)]
struct Topo {
    /// Per port: (VID, link) of the active links on it (VID 0 = untagged).
    port_links: Vec<Vec<(u16, IfIndex)>>,
    /// The networks' prefixes (`shard_of`: flows between them).
    internal: Vec<(Ipv4Addr, u8)>,
    /// Subnets routed through a router on a network (`shard_of`: inside).
    routed: Vec<(Ipv4Addr, u8)>,
    /// The port forwards (`shard_of`: DNAT and hairpin connections live in
    /// their target's shard).
    forwards: Vec<PortForward>,
    /// The redirects (`shard_of`: their connections live in their
    /// target's shard).
    redirects: Vec<Redirect>,
}

/// `ip` is in the subnet of the interface address `(a, l)`.
fn fwd_inside((a, l): (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    let m = if l == 0 { 0 } else { u32::MAX << (32 - l as u32) };
    u32::from(a) & m == u32::from(ip) & m
}

pub struct Datapath {
    sh: &'static Shared,
    hash_key: u64,
    shards: Vec<Mutex<Forwarder>>,
    /// Per link: neighbors on that link.
    neigh: Vec<Mutex<NeighTable<PacketBuf>>>,
    /// Per link: the interface address (the WAN one changes with the lease).
    addrs: Vec<Mutex<Option<(Ipv4Addr, u8)>>>,
    /// Which link a frame belongs to and what `shard_of` needs: replaced
    /// whole by [`Self::apply`], read once per batch.
    topo: Mutex<alloc::sync::Arc<Topo>>,
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
    /// `sh.links[0]` is the WAN, the others network slots; `initial`
    /// puts the config's networks into them ([`Self::apply`]).
    pub fn new(sh: &'static Shared, initial: Networks) -> Self {
        let hash_key = timer::ticks() ^ 0x9e37_79b9_7f4a_7c15;
        // Every slot is an interface from the start; inactive ones have
        // no address (no route) and no VID (nothing arrives on them).
        let ifaces: Vec<Interface> = sh
            .links
            .iter()
            .enumerate()
            .map(|(i, link)| Interface {
                mac: sh.ports[link.port].mac,
                addr: None,
                role: if i == WAN as usize { Role::Wan } else { Role::Lan },
                zone: if i == WAN as usize { 0 } else { 1 },
            })
            .collect();
        // One budget for all shards: every connection of one endpoint (a
        // torrent client's forwarded port: inbound peers, uTP, DHT) lives in
        // one shard, which may therefore take the whole table.
        let budget = fwd::conntrack::Budget::new(MAX_CONNS);
        let shards = (0..SHARDS)
            .map(|k| {
                let mut f = Forwarder::new_shard(MAX_CONNS, hash_key, SHARDS as u16, k as u16);
                f.set_conn_budget(budget.clone());
                for iface in &ifaces {
                    f.add_interface(*iface);
                }
                f.wan_antispoof = crate::config::wan_antispoof();
                Mutex::new(f)
            })
            .collect();
        let dp = Self {
            sh,
            hash_key,
            shards,
            neigh: ifaces
                .iter()
                .map(|_| Mutex::new(NeighTable::new()))
                .collect(),
            addrs: ifaces.iter().map(|i| Mutex::new(i.addr)).collect(),
            topo: Mutex::new(alloc::sync::Arc::new(Topo::default())),
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
        };
        dp.apply(initial);
        dp
    }

    /// The WAN lease changed: every shard, and the WAN address copy.
    pub fn set_wan(&self, addr: Option<(Ipv4Addr, u8)>, gateway: Option<Ipv4Addr>, mtu: u16) {
        for s in &self.shards {
            let mut f = s.lock();
            f.set_addr(WAN, addr);
            f.set_mtu(WAN, mtu);
            f.set_default_route(gateway.filter(|_| addr.is_some()).map(|gw| (WAN, gw)));
        }
        *self.addrs[WAN as usize].lock() = addr;
        self.publish_routes();
    }

    /// The routing table for status pages (every shard has the same).
    fn publish_routes(&self) {
        if let Some(s) = self.shards.first() {
            let table = s.lock().routes.iter().copied().collect();
            *self.sh.routes.lock() = table;
        }
    }

    /// Put networks and the firewall into effect (boot, or a saved config,
    /// live): each network slot gets its VID, address and zone, or is
    /// switched off; a slot that changed forgets its neighbors. Tracked
    /// connections the new firewall would not start are removed
    /// (`Forwarder::recheck`); ones through a slot that went away find no
    /// route and expire.
    pub fn apply(&self, n: Networks) {
        for (i, link) in self.sh.links.iter().enumerate().skip(1) {
            let want = n.nets.iter().find(|x| x.link == i);
            let addr = want.map(|x| x.addr);
            let vid = want.map_or(0, |x| x.vid);
            let changed = *self.addrs[i].lock() != addr || link.vid() != vid || link.is_active() != want.is_some();
            for s in &self.shards {
                let mut f = s.lock();
                f.set_addr(i as IfIndex, addr);
                f.set_zone(i as IfIndex, want.map_or(1, |x| x.zone));
            }
            *self.addrs[i].lock() = addr;
            link.set(want.is_some(), vid);
            if changed {
                *self.neigh[i].lock() = NeighTable::new();
            }
        }
        let mut revoked = 0;
        for s in &self.shards {
            let mut f = s.lock();
            f.set_static_routes(&n.routes);
            f.set_policy(Some(n.policy.clone()));
            if crate::config::fw_recheck() {
                revoked += f.recheck();
            }
        }
        REVOKED.fetch_add(revoked as u64, Ordering::Relaxed);
        self.publish_routes();
        if revoked > 0 {
            crate::println!("fwd   : {revoked} tracked connections refused by the new policy, removed");
        }
        let mut port_links = alloc::vec![Vec::new(); self.sh.ports.len()];
        for (i, link) in self.sh.links.iter().enumerate() {
            if link.is_active() {
                port_links[link.port].push((link.vid(), i as IfIndex));
            }
        }
        *self.topo.lock() = alloc::sync::Arc::new(Topo {
            port_links,
            internal: n.nets.iter().map(|x| x.addr).collect(),
            routed: n
                .routes
                .iter()
                .filter(|&&(_, _, via)| n.nets.iter().any(|x| fwd_inside(x.addr, via)))
                .map(|&(dst, len, _)| (dst, len))
                .collect(),
            forwards: n.policy.forwards,
            redirects: n.policy.redirects,
        });
    }

    /// Into the qdisc of the link's port, with the link's VLAN tag.
    fn enqueue(&self, egress: IfIndex, mut pkt: PacketBuf, touched: &mut [bool; 2]) {
        let now = now_ns();
        let link = &self.sh.links[egress as usize];
        if let Some(tci) = link.tci() {
            pkt.push_vlan(tci);
            pkt.meta.wire_len += wire::VLAN_HDR as u32;
        }
        if let Some(t) = touched.get_mut(link.port) {
            *t = true;
        }
        if self.sh.ports[link.port]
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
        let src = self.sh.ports[self.sh.links[egress as usize].port].mac;
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
        pkt.meta.wire_len = 60;
        wire::build_arp_request(
            pkt.data_mut(),
            self.sh.ports[self.sh.links[ifx as usize].port].mac,
            my_ip,
            target,
        );
        self.enqueue(ifx, pkt, touched);
    }

    /// ECN diagnostics on a forwarded frame (before NAT/egress), by
    /// ingress port: codepoint counts, and the TCP ECE (receiver saw CE) /
    /// CWR (sender reacted) flags.
    fn observe_ecn(&self, port: usize, frame: &[u8]) {
        let i = port;
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

    /// The link a frame received on `port` belongs to, and its VID to
    /// strip: the port's own tag (the WAN), or the VID naming a network.
    fn link_of(&self, topo: &Topo, port: usize, frame: &[u8]) -> Option<(IfIndex, Option<u16>)> {
        let links = topo.port_links.get(port)?;
        if let [(0, ifx)] = links.as_slice()
            && let Some(tci) = self.sh.ports[port].vlan()
        {
            return Some((*ifx, Some(tci & 0x0fff)));
        }
        let vid = wire::vlan_tci(frame).map_or(0, |t| t & 0x0fff);
        links
            .iter()
            .find(|(v, _)| *v == vid)
            .map(|&(v, ifx)| (ifx, (v != 0).then_some(v)))
    }

    /// Run one port's received frames (taken from its NIC by the caller,
    /// at most [`RX_BUDGET`]) through the forwarder. Drains `batch`; marks
    /// in `touched` the egress ports whose qdisc got packets.
    pub fn rx_batch(&self, port_ix: usize, batch: &mut Vec<PacketBuf>, touched: &mut [bool; 2]) {
        let now = now_ms();
        let port = &self.sh.ports[port_ix];
        let pppoe = port.is_pppoe();
        let session = port.pppoe_session();
        let mut local = false;
        let topo = self.topo.lock().clone();
        let hints = ShardHints {
            internal: &topo.internal,
            routed: &topo.routed,
            wan: self.addrs[WAN as usize].lock().map(|(a, _)| a),
            forwards: &topo.forwards,
            redirects: &topo.redirects,
        };
        for mut pkt in batch.drain(..) {
            let Some((ifx, want_vid)) = self.link_of(&topo, port_ix, pkt.data()) else {
                VLAN_DROPS.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let role = if ifx == WAN { Role::Wan } else { Role::Lan };
            match wire::vlan_rx(pkt.data(), want_vid) {
                wire::VlanRx::Accept { strip: false } => {}
                wire::VlanRx::Accept { strip: true } => pkt.pop_vlan(),
                wire::VlanRx::Drop => {
                    VLAN_DROPS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            if pppoe {
                match pppoe_rx(&mut pkt, session) {
                    PppoeRx::Ipv4 => {}
                    PppoeRx::Control => {
                        let mut q = port.ctrl_rx.lock();
                        if q.len() < CTRL_RX_MAX {
                            q.push_back(pkt);
                            local = true;
                        } else {
                            PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    PppoeRx::Drop => {
                        PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
            }
            if wire::ethertype(pkt.data()) == Some(wire::ETHERTYPE_ARP) {
                self.snoop_arp(ifx, pkt.data(), now, touched);
            }
            let len = pkt.len();
            let k = shard_of(role, pkt.data(), SHARDS, self.hash_key, &hints);
            let verdict =
                self.shards[k]
                    .lock()
                    .process(now, ifx, pkt.data_with_tailroom_mut(), len);
            match verdict {
                Verdict::Local => {
                    let mut q = self.sh.links[ifx as usize].local_rx.lock();
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
                    self.observe_ecn(port_ix, pkt.data());
                    pkt.meta = meta_from(&class, ifx, len, now_ns());
                    FORWARDED.fetch_add(1, Ordering::Relaxed);
                    let out = &self.sh.ports[self.sh.links[egress as usize].port];
                    if out.is_pppoe() {
                        // Point to point: the access concentrator is the
                        // only neighbor.
                        match out.pppoe_session() {
                            Some(s) => self.send_resolved(egress, s.peer, pkt, touched),
                            None => {
                                PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        continue;
                    }
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
                Verdict::Drop(r) => {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                    DROP_REASONS[r.index()].fetch_add(1, Ordering::Relaxed);
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
        let mut hits: Vec<u64> = Vec::new();
        let mut fhits: Vec<u64> = Vec::new();
        let mut rhits: Vec<u64> = Vec::new();
        let mut rejected = 0;
        let add = |into: &mut Vec<u64>, from: &[u64]| {
            into.resize(into.len().max(from.len()), 0);
            for (h, n) in into.iter_mut().zip(from) {
                *h += n;
            }
        };
        for s in &self.shards {
            let mut f = s.lock();
            f.expire(now);
            conns += f.ct.len();
            add(&mut hits, &f.rule_hits);
            add(&mut fhits, &f.forward_hits);
            add(&mut rhits, &f.redirect_hits);
            rejected += f.stats.rejected;
        }
        REJECTED.store(rejected, Ordering::Relaxed);
        self.sh.conntrack.store(conns, Ordering::Relaxed);
        *self.sh.rule_hits.lock() = hits;
        *self.sh.forward_hits.lock() = fhits;
        *self.sh.redirect_hits.lock() = rhits;
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
    let pppoe = port.is_pppoe();
    let session = port.pppoe_session();
    let mut qdisc = port.qdisc.lock();
    while dev.can_transmit() {
        match qdisc.dequeue(now) {
            Dequeue::Packet(mut p) => {
                if pppoe && !pppoe_tx(&mut p, session, port.mac) {
                    PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
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
