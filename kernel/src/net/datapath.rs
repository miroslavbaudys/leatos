//! The forwarding datapath: drivers ↔ `fwd::Forwarder` ↔ qdiscs.
//!
//! ```text
//!  NIC RX ─► VLAN ─► shard_of ─► Forwarder shard ─┬─ Local ───► port.local_rx ─► svc (router stack)
//!                                         ├─ Forward ─► neigh[egress] ─► egress qdisc
//!                                         │  (from the WAN: ─► ingress qdisc ─► (shaper) ─► neigh[egress] ─► …)
//!                                         └─ Drop
//!  svc TX ──────────────────────────────────────────────────────────────► port qdisc
//!  port qdisc ─► (pull, while the NIC has room) ─► VLAN ─► NIC TX
//! ```
//!
//! **WAN ingress stage** (docs/bufferbloat-cake.md §3.4): the download is
//! shaped where it arrives, not on LAN egress. Forwarded packets from the
//! WAN wait in [`Shared::ingress`] (CAKE behind an ingress-mode shaper at
//! the download rate) with their egress and next hop in `PacketMeta`;
//! [`Datapath::drain_ingress`] (the task receiving on the WAN) releases
//! them to the neighbor table and the egress port's qdisc. Every other WAN
//! frame (for the router, dropped, PPPoE control) is charged to the
//! shaper, since it used the downlink too. LAN egress is then unshaped
//! CAKE, so traffic between networks is not held to the download rate.
//! Without a download rate (or with `shape_ingress=0`) the stage is
//! skipped.
//!
//! Links (`net::shared::LinkShared`) are the forwarder's interfaces: link
//! 0 is the WAN on port 0, links 1.. the networks on port 1 (`lan0`),
//! untagged or on a VLAN. On RX a `lan0` frame's VID picks its link (no
//! link for it: dropped, [`VLAN_DROPS`]); a frame for a network on a VLAN
//! gets its tag when it is queued on the port (forwarded, ARP, or from
//! the router stack), so the qdisc holds tagged frames and counts the 4
//! bytes.
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
use crate::net::device::PortQdisc;
use crate::net::shared::{CTRL_RX_MAX, LOCAL_RX_MAX, MAX_PORTS, Shared};
use crate::timer;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::sync::atomic::{AtomicU64, Ordering};
use fwd::forwarder::{
    Classification, DropReason, Forwarder, Interface, PortForward, Redirect, Role, ShardHints, Verdict,
    shard_of,
};
use fwd::frag::{self, Kind as FragKind, Lookup as FragLookup, Table as FragTable};
use fwd::neigh::{NeighTable, Resolve};
use fwd::{IfIndex, wire};
use qdisc::{Dequeue, Qdisc};
use spin::Mutex;

/// Frames handled per port per loop iteration.
pub const RX_BUDGET: usize = 64;
/// Forwarder (conntrack) shards.
pub const SHARDS: usize = 16;
/// Tracked connections, all shards together (`fwd::conntrack::Budget`).
pub const MAX_CONNS: usize = 16_384;
const HOUSEKEEPING_MS: u64 = 1_000;
/// Expired connections removed per housekeeping pass, all shards together
/// (M9: removing 16k at once held a shard's lock, and this task, for
/// milliseconds). More wait for the next pass: they are early-droppable
/// and invisible to packets meanwhile (`Conntrack::lookup_live`).
pub const EXPIRE_PER_PASS: usize = 256;
/// ... and at most this many in one shard, so one shard's lock (packets of
/// the other direction task wait on it) is held for an eighth of a full
/// pass; the rotating first shard keeps the 256 per second.
pub const EXPIRE_PER_SHARD: usize = 32;

/// The WAN link (on port 0); the networks are links 1.. on port 1.
pub const WAN: IfIndex = 0;
/// The WAN's port.
pub const WAN_PORT: usize = 0;

/// Per port: its qdisc got packets (its TX task must be woken).
pub type Touched = [bool; MAX_PORTS];

/// Counters for diagnostics (read by the self-test / stats output).
pub static FORWARDED: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
/// The router stack's packets on a link without a link layer that had no
/// next hop there ([`Datapath::send_local`]).
pub static LOCAL_NO_ROUTE: AtomicU64 = AtomicU64::new(0);
/// The datapath's ARP / ND answers for the router on IP-only LAN links
/// (`fwd::nd`, docs/lan-neighbors.md): replies sent, and another MAC
/// claiming or probing for one of the router's addresses.
pub static ARP_REPLIES: AtomicU64 = AtomicU64::new(0);
pub static NA_SENT: AtomicU64 = AtomicU64::new(0);
/// The same on the WAN (an IP-only static WAN, docs/local-stack.md step
/// 2a; `/api/status` `wan_nd`).
pub static WAN_ARP_REPLIES: AtomicU64 = AtomicU64::new(0);
pub static WAN_NA_SENT: AtomicU64 = AtomicU64::new(0);
pub static ND_CONFLICTS: AtomicU64 = AtomicU64::new(0);
/// The router stack's unicast packets on those links that waited in the
/// neighbor table's pending queue (the neighbor was not resolved), and the
/// packets the table dropped when one was queued (that one, or an older
/// pending one: forwarded or local) ([`Datapath::send_local`]).
pub static LOCAL_QUEUED: AtomicU64 = AtomicU64::new(0);
pub static LOCAL_DROPPED: AtomicU64 = AtomicU64::new(0);
/// The forwarder's drops by reason (`fwd::forwarder::DropReason::index`),
/// part of `DROPPED` (the web interface's firewall page).
pub static DROP_REASONS: [AtomicU64; fwd::forwarder::DROP_REASONS] =
    [const { AtomicU64::new(0) }; fwd::forwarder::DROP_REASONS];
/// Requests sent to neighbors in use past their lifetime (`fwd::neigh`
/// probes), both families.
pub static NEIGH_PROBES: AtomicU64 = AtomicU64::new(0);
/// Packets the NIC refused after `can_transmit` (part of `DROPPED`).
pub static TX_FAILED: AtomicU64 = AtomicU64::new(0);
/// Received frames with the wrong VLAN tag for their port (or none).
pub static VLAN_DROPS: AtomicU64 = AtomicU64::new(0);
/// Tracked connections removed because a new firewall policy refused them
/// (`Forwarder::recheck`).
pub static REVOKED: AtomicU64 = AtomicU64::new(0);
/// Refused packets answered with a RST / port unreachable (`reject`),
/// summed over the shards once a second (not in `DROP_REASONS`).
pub static REJECTED: AtomicU64 = AtomicU64::new(0);
/// ICMP and ICMPv6 errors the router sent (time exceeded, fragmentation
/// needed, packet too big, port unreachable), summed over the shards once
/// a second.
pub static ICMP_ERRORS: AtomicU64 = AtomicU64::new(0);
/// IPv6 to the delegated prefix's unused part (no network there), refused
/// with destination unreachable or dropped (RFC 7084 WPD-5), summed over
/// the shards once a second.
pub static UNREACHABLE6: AtomicU64 = AtomicU64::new(0);
/// Connections that were not assured, removed to make room for new ones
/// (full table or a shard's NAT ports taken), summed over the shards once
/// a second.
pub static EARLY_DROPS: AtomicU64 = AtomicU64::new(0);
/// The once-a-second conntrack pass (expire + counters) per shard, while
/// its lock is held: the longest in the last pass and since boot (µs).
/// Packets of that shard wait meanwhile (M9: measured on the apu4).
pub static EXPIRE_LAST_US: AtomicU64 = AtomicU64::new(0);
pub static EXPIRE_MAX_US: AtomicU64 = AtomicU64::new(0);
/// The whole once-a-second housekeeping pass (every shard, fragments,
/// neighbors, stats): the primary direction task forwards nothing
/// meanwhile. Last and longest since boot (µs).
pub static HOUSEKEEPING_LAST_US: AtomicU64 = AtomicU64::new(0);
pub static HOUSEKEEPING_MAX_US: AtomicU64 = AtomicU64::new(0);
/// On a PPPoE port: received frames that are not PPPoE, control frames
/// that found the client's queue full, and IPv4 to send while there is no
/// session.
/// IP fragments ([`fwd::frag`]): later fragments forwarded with their
/// first one's decision, held for it, and held ones dropped.
pub static FRAGS_FORWARDED: AtomicU64 = AtomicU64::new(0);
pub static FRAGS_PARKED: AtomicU64 = AtomicU64::new(0);
pub static FRAGS_PARK_DROPS: AtomicU64 = AtomicU64::new(0);
/// Packets split for a smaller egress MTU (`wire::SplitPlan`), and ones
/// dropped because the pool had no buffer for every piece.
pub static SPLIT: AtomicU64 = AtomicU64::new(0);
pub static SPLIT_DROPS: AtomicU64 = AtomicU64::new(0);
/// A frame (≤ 2048 B) splits into at most this many pieces at MTU ≥ 576.
const MAX_PIECES: usize = 4;
pub static PPPOE_DROPS: AtomicU64 = AtomicU64::new(0);

/// What a PPPoE port does with a received frame.
enum PppoeRx {
    /// IPv4 or IPv6 of the session, now a plain Ethernet frame.
    Ip,
    /// For the PPPoE client.
    Control,
    Drop,
}

/// Decapsulate session IPv4/IPv6 in place, or say where the frame goes.
fn pppoe_rx(pkt: &mut PacketBuf, session: Option<proto_pppoe::Session>) -> PppoeRx {
    use proto_pppoe::wire::{self as pw, SessionRx};
    match wire::ethertype(pkt.data()) {
        Some(pw::ETHERTYPE_DISCOVERY) => PppoeRx::Control,
        Some(pw::ETHERTYPE_SESSION) => match pw::classify_session(pkt.data(), session) {
            SessionRx::Ipv4 { len } => {
                pw::decap_ipv4(pkt.data_mut());
                pkt.pull_front(pw::SESSION_OVERHEAD);
                pkt.set_len(pw::ETH_HDR + len);
                PppoeRx::Ip
            }
            SessionRx::Ipv6 { len } => {
                pw::decap_ipv6(pkt.data_mut());
                pkt.pull_front(pw::SESSION_OVERHEAD);
                pkt.set_len(pw::ETH_HDR + len);
                PppoeRx::Ip
            }
            SessionRx::Control => PppoeRx::Control,
        },
        _ => PppoeRx::Drop,
    }
}

/// Encapsulate for a PPPoE port: IPv4 and IPv6 go into the session (none: `false`,
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
        Some(wire::ETHERTYPE_IPV6) => match session {
            Some(s) => {
                pkt.push_front(pw::SESSION_OVERHEAD);
                pw::encap_ipv6(pkt.data_mut(), s, mac);
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
    /// Buffers housekeeping reuses each second (no allocation in the
    /// datapath task once they have grown).
    scratch: HkScratch,
    /// Per port, then the ingress stage.
    last_dequeued: Vec<u64>,
    /// Per port.
    ecn_reported: Vec<u64>,
    vlan_reported: u64,
}

/// [`Hk::scratch`]: summed hit counters and expired fragments.
#[derive(Default)]
struct HkScratch {
    hits: Vec<u64>,
    fhits: Vec<u64>,
    rhits: Vec<u64>,
    stale: Vec<PacketBuf>,
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

/// IPv6 neighbors being resolved at once, per link (RFC 6583: a scan of
/// a /64 must not fill the table).
const NEIGH6_INCOMPLETE: usize = 64;

pub struct Datapath {
    sh: &'static Shared,
    hash_key: u64,
    shards: Vec<Mutex<Forwarder>>,
    /// Per link: neighbors on that link.
    neigh: Vec<Mutex<NeighTable<PacketBuf>>>,
    /// Per link: IPv6 neighbors (neighbor discovery), at most
    /// [`NEIGH6_INCOMPLETE`] being resolved at once (RFC 6583).
    neigh6: Vec<Mutex<NeighTable<PacketBuf, Ipv6Addr>>>,
    /// Per link: the interface address (the WAN one changes with the lease).
    addrs: Vec<Mutex<Option<(Ipv4Addr, u8)>>>,
    /// Per link: the router stack's addresses and routes there, for its
    /// own packets on a link without a link layer ([`Self::send_local`],
    /// docs/lan-neighbors.md).
    local: Vec<Mutex<fwd::local::LocalLink>>,
    /// Changes of `local` ([`Self::local_gen`]).
    local_gen: AtomicU64,
    /// ARP / ND answers on links whose router stack is IP-only
    /// ([`crate::net::shared::LinkShared::ip_only`]), with these switches.
    nd_cfg: fwd::nd::Config,
    /// Note the targets of duplicate address detection probes as the
    /// clients' addresses (`client6_dad=0`: not; [`Self::snoop_nd`]).
    client6_dad: bool,
    /// Which link a frame belongs to and what `shard_of` needs: replaced
    /// whole by [`Self::apply`], read once per batch.
    topo: Mutex<alloc::sync::Arc<Topo>>,
    hk: Mutex<Hk>,
    /// Per ingress port: datagrams whose first fragment came through
    /// ([`fwd::frag`]); each port's RX runs in one direction task, so the
    /// lock is never contended.
    frags: Vec<Mutex<FragTable<PacketBuf>>>,
    /// Forward IP fragments (boot argument `fw_frag=0`: dropped).
    fragments: bool,
    local_rx_drops: AtomicU64,
    /// Per ingress port: forwarded IPv4 packets by ECN codepoint
    /// [Not-ECT, ECT(1), ECT(0), CE], and TCP packets with ECE / CWR set.
    ecn_seen: Vec<[AtomicU64; 4]>,
    tcp_ece: Vec<AtomicU64>,
    tcp_cwr: Vec<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FlushResult {
    /// Earliest time (uptime ns) a shaper will release its next packet.
    pub shaper_wake_ns: Option<u64>,
    /// A qdisc has packets but the NIC ring is full (wait for TX completion).
    pub ring_full_backlog: bool,
    /// ... and the NIC's TX completion interrupt is armed to say when
    /// (`Nic::arm_tx_irq`), so no polling is needed.
    pub tx_armed: bool,
}

/// Print per-port qdisc statistics every this many ms (only if there was traffic).
const STATS_MS: u64 = 10_000;

fn neigh_table() -> NeighTable<PacketBuf> {
    let (ms, probe) = crate::config::neigh_timing();
    NeighTable::new().with_timing(ms, probe).with_pending(crate::config::neigh_pending())
}

fn neigh6_table() -> NeighTable<PacketBuf, Ipv6Addr> {
    let (ms, probe) = crate::config::neigh_timing();
    NeighTable::with_incomplete_cap(NEIGH6_INCOMPLETE).with_timing(ms, probe).with_pending(crate::config::neigh_pending())
}

/// Packets a neighbor table dropped (`dropped` went from `before` to
/// `after`): the drop reason `neighbor`.
fn poll_neigh<A: Copy + Ord>(n: &mut NeighTable<PacketBuf, A>, now: u64) -> Vec<(IfIndex, A)> {
    let (dropped, probes) = (n.dropped, n.probes);
    let r = n.poll(now);
    count_neigh_drops(dropped, n.dropped);
    NEIGH_PROBES.fetch_add(n.probes - probes, Ordering::Relaxed);
    r
}

fn count_neigh_drops(before: u64, after: u64) -> u64 {
    let n = after.saturating_sub(before);
    if n > 0 {
        DROPPED.fetch_add(n, Ordering::Relaxed);
        DROP_REASONS[DropReason::Neighbor.index()].fetch_add(n, Ordering::Relaxed);
    }
    n
}

/// What [`Datapath::to_next_hop`] / [`Datapath::to_next_hop6`] did with a
/// packet: it waits for its neighbor, and how many packets the neighbor
/// table dropped meanwhile (it or an older pending one).
#[derive(Clone, Copy, Default)]
struct Hop {
    queued: bool,
    dropped: u64,
}

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

pub fn now_ns() -> u64 {
    timer::uptime().as_nanos() as u64
}

fn meta_from(class: &Classification, ingress: IfIndex, len: usize, now: u64) -> PacketMeta {
    PacketMeta {
        egress_if: 0,
        next_hop: 0,
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

/// One received batch's bookkeeping, passed down the receive path.
struct Batch<'a> {
    /// Egress ports whose qdisc got packets.
    touched: &'a mut Touched,
    /// Frames went to a `local_rx` / `ctrl_rx` (wake svc).
    local: bool,
    /// The batch is from the WAN and the ingress stage is on: forwarded
    /// packets go into it, everything else is charged to its shaper.
    ingress: bool,
    /// WAN frames that used the downlink without entering the ingress
    /// queue: (bytes, frames).
    charge: (usize, usize),
}

impl Batch<'_> {
    /// A WAN frame that bypasses the ingress queue.
    fn bypass(&mut self, len: usize) {
        if self.ingress {
            self.charge.0 += len;
            self.charge.1 += 1;
        }
    }
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
                mac: sh.ports[link.port()].mac,
                addr: None,
                role: if i == WAN as usize { Role::Wan } else { Role::Lan },
                zone: if i == WAN as usize { 0 } else { 1 },
            })
            .collect();
        // One budget for all shards: every connection of one endpoint (a
        // torrent client's forwarded port: inbound peers, uTP, DHT) lives in
        // one shard, which may therefore take the whole table.
        // One host (initiator) at most `conn_per_host=` of them.
        let budget = fwd::conntrack::Budget::with_host_limit(
            MAX_CONNS,
            crate::config::conn_per_host(MAX_CONNS),
            hash_key,
        );
        let shards = (0..SHARDS)
            .map(|k| {
                let mut f = Forwarder::new_shard(MAX_CONNS, hash_key, SHARDS as u16, k as u16);
                f.set_conn_budget(budget.clone());
                for iface in &ifaces {
                    f.add_interface(*iface);
                }
                f.wan_antispoof = crate::config::wan_antispoof();
                f.lan_antispoof = crate::config::lan_antispoof();
                f.fragments = crate::config::fw_fragments();
                f.split = crate::config::fw_split();
                if crate::config::fw_client_ports() {
                    f.set_client_ports(&crate::net::shared::CLIENT_PORTS);
                }
                Mutex::new(f)
            })
            .collect();
        let n = sh.ports.len();
        let dp = Self {
            sh,
            hash_key,
            shards,
            neigh: ifaces
                .iter()
                .map(|_| Mutex::new(neigh_table()))
                .collect(),
            neigh6: ifaces
                .iter()
                .map(|_| Mutex::new(neigh6_table()))
                .collect(),
            addrs: ifaces.iter().map(|i| Mutex::new(i.addr)).collect(),
            local: ifaces.iter().map(|_| Mutex::new(fwd::local::LocalLink::default())).collect(),
            local_gen: AtomicU64::new(0),
            nd_cfg: crate::config::nd_config(),
            client6_dad: crate::config::client6_dad(),
            topo: Mutex::new(alloc::sync::Arc::new(Topo::default())),
            hk: Mutex::new(Hk {
                next_housekeeping: 0,
                next_stats: STATS_MS,
                scratch: HkScratch::default(),
                last_dequeued: alloc::vec![0; n + 1],
                ecn_reported: alloc::vec![0; n],
                vlan_reported: 0,
            }),
            frags: (0..n).map(|_| Mutex::new(FragTable::new())).collect(),
            fragments: crate::config::fw_fragments(),
            local_rx_drops: AtomicU64::new(0),
            ecn_seen: (0..n).map(|_| [const { AtomicU64::new(0) }; 4]).collect(),
            tcp_ece: (0..n).map(|_| AtomicU64::new(0)).collect(),
            tcp_cwr: (0..n).map(|_| AtomicU64::new(0)).collect(),
        };
        dp.apply(initial);
        dp
    }

    /// The WAN lease changed: every shard, and the WAN address copy.
    pub fn set_wan(&self, addr: Option<(Ipv4Addr, u8)>, gateway: Option<Ipv4Addr>, mtu: u16) {
        // `wan_mtu=` replaces the lease's (Ethernet only: PPPoE negotiates).
        let mtu = match crate::config::wan_mtu() {
            Some(m) if !self.sh.ports[WAN as usize].is_pppoe() => m,
            _ => mtu,
        };
        for s in &self.shards {
            let mut f = s.lock();
            f.set_addr(WAN, addr);
            f.set_mtu(WAN, mtu);
            f.set_default_route(gateway.filter(|_| addr.is_some()).map(|gw| (WAN, gw)));
        }
        *self.addrs[WAN as usize].lock() = addr;
        self.publish_routes();
    }

    /// The routing tables for status pages (every shard has the same).
    fn publish_routes(&self) {
        if let Some(s) = self.shards.first() {
            let (v4, v6) = {
                let f = s.lock();
                (f.routes.iter().copied().collect(), f.routes6.iter().copied().collect())
            };
            *self.sh.routes.lock() = v4;
            *self.sh.routes6.lock() = v6;
        }
    }

    /// Put networks and the firewall into effect (boot, or a saved config,
    /// live): each network slot gets its port, VID, address and zone, or is
    /// switched off; a slot that changed forgets its neighbors. Tracked
    /// connections the new firewall would not start are removed
    /// (`Forwarder::recheck`); ones through a slot that went away find no
    /// route and expire.
    pub fn apply(&self, n: Networks) {
        for (i, link) in self.sh.links.iter().enumerate().skip(1) {
            let want = n.nets.iter().find(|x| x.link == i);
            let addr = want.map(|x| x.addr);
            let vid = want.map_or(0, |x| x.vid);
            let port = want.map_or(link.port(), |x| x.port);
            let changed = *self.addrs[i].lock() != addr
                || link.vid() != vid
                || link.port() != port
                || link.is_active() != want.is_some();
            for s in &self.shards {
                let mut f = s.lock();
                f.set_addr(i as IfIndex, addr);
                f.set_zone(i as IfIndex, want.map_or(1, |x| x.zone));
                f.set_mac(i as IfIndex, self.sh.ports[port].mac);
                f.set_ula6(i as IfIndex, want.and_then(|x| x.ula));
                f.set_gua6(i as IfIndex, want.and_then(|x| x.gua).map(|a| (a, 64)));
            }
            *self.addrs[i].lock() = addr;
            link.set(want.is_some(), port, vid);
            if changed {
                *self.neigh[i].lock() = neigh_table();
                *self.neigh6[i].lock() = neigh6_table();
            }
        }
        let mut revoked = 0;
        let ipv6 = crate::config::ipv6();
        // The WAN's IPv6 (development: `wan6_ip=`, `wan6_gw=`).
        let wan6 = crate::config::wan6();
        for s in &self.shards {
            let mut f = s.lock();
            f.ipv6 = ipv6;
            f.set_gua6(WAN, wan6.and_then(|w| w.addr));
            // PPPoE: IPv6CP's link-local address, not the MAC's.
            f.set_ll6(WAN, crate::net::wan6::ppp_link().map(|l| l.0).filter(|_| self.sh.ports[0].is_pppoe()));
            f.set_default_route6(wan6.map(|w| (WAN, w.gateway)));
            f.set_delegated6(crate::config::delegated6().filter(|_| crate::config::v6_unreachable()));
            f.set_static_routes(&n.routes);
            f.set_static_routes6(&n.routes6);
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
                port_links[link.port()].push((link.vid(), i as IfIndex));
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
    fn enqueue(&self, egress: IfIndex, mut pkt: PacketBuf, touched: &mut Touched) {
        let now = now_ns();
        let link = &self.sh.links[egress as usize];
        if let Some(tci) = link.tci() {
            pkt.push_vlan(tci);
            pkt.meta.wire_len += wire::VLAN_HDR as u32;
        }
        let port = link.port();
        if let Some(t) = touched.get_mut(port) {
            *t = true;
        }
        if self.sh.ports[port]
            .qdisc
            .lock()
            .enqueue(pkt, now)
            .is_err()
        {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The router stack's addresses and routes on link `ifx`
    /// ([`Self::send_local`]).
    pub fn set_local_link(&self, ifx: IfIndex, l: fwd::local::LocalLink) {
        if let Some(m) = self.local.get(ifx as usize) {
            let mut cur = m.lock();
            if *cur != l {
                *cur = l;
                self.local_gen.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The router's addresses on link `ifx` (IPv4, IPv6): `net::groups`.
    pub fn local_addrs(&self, ifx: IfIndex) -> (Option<Ipv4Addr>, Vec<Ipv6Addr>) {
        let Some(l) = self.local.get(ifx as usize) else { return (None, Vec::new()) };
        let l = l.lock();
        (l.v4.map(|(a, _)| a), l.addrs6().collect())
    }

    /// Bumped by every [`Self::set_local_link`]: the services recompute
    /// what depends on the links' addresses (`net::groups`) only then.
    pub fn local_gen(&self) -> u64 {
        self.local_gen.load(Ordering::Relaxed)
    }

    /// What the datapath shares with the services (`net::local` sends
    /// through it from the device, which has no `Shared` at hand).
    pub fn shared(&self) -> &'static Shared {
        self.sh
    }

    /// `ip` is one of the router's own unicast addresses on link `ifx`
    /// (an echo request to it is answered: `net::local`).
    pub fn is_local_addr(&self, ifx: IfIndex, ip: core::net::IpAddr) -> bool {
        let Some(l) = self.local.get(ifx as usize) else { return false };
        let l = l.lock();
        match ip {
            core::net::IpAddr::V4(a) => l.v4.is_some_and(|(me, _)| me == a),
            core::net::IpAddr::V6(a) => l.addrs6().any(|me| me == a),
        }
    }

    /// The router's source address toward `dst` on link `ifx`
    /// (`fwd::local::LocalLink::source4` / `source6`; `net::local`).
    pub fn local_source(&self, ifx: IfIndex, dst: core::net::IpAddr) -> Option<core::net::IpAddr> {
        let l = self.local.get(ifx as usize)?.lock();
        match dst {
            core::net::IpAddr::V4(_) => l.source4().map(Into::into),
            core::net::IpAddr::V6(d) => l.source6(d).map(Into::into),
        }
    }

    /// A packet from the router's own stack on link `ifx`, whose stack has
    /// no link layer (`net::local`, docs/lan-neighbors.md):
    /// `pkt` is 14 bytes of Ethernet header (EtherType set) and the IP
    /// packet. Broadcast and multicast go out at once; unicast goes to the
    /// destination or a `[[route]]`'s gateway through the neighbor table,
    /// as forwarded packets do (waiting in its bounded pending queue while
    /// resolved). Called from the services task; takes the link's lock,
    /// then the neighbor table's and the qdisc's (the datapath's order).
    /// Returns false if it was dropped for want of a next hop.
    pub fn send_local(&self, ifx: IfIndex, mut pkt: PacketBuf, touched: &mut Touched) -> bool {
        let Some(link) = self.local.get(ifx as usize) else {
            return false;
        };
        let hop = link.lock().next_hop(pkt.data());
        pkt.meta.wire_len = pkt.len() as u32;
        pkt.meta.enqueue_ts = now_ns();
        let now = now_ms();
        let h = match hop {
            fwd::local::NextHop::Mac(mac) => {
                self.send_resolved(ifx, mac, pkt, touched);
                Hop::default()
            }
            fwd::local::NextHop::Neighbor4(a) => self.to_next_hop(ifx, a, pkt, now, touched),
            fwd::local::NextHop::Neighbor6(a) => self.to_next_hop6(ifx, a, pkt, now, touched),
            fwd::local::NextHop::NoRoute => {
                LOCAL_NO_ROUTE.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        if h.queued {
            LOCAL_QUEUED.fetch_add(1, Ordering::Relaxed);
        }
        if h.dropped > 0 {
            LOCAL_DROPPED.fetch_add(h.dropped, Ordering::Relaxed);
        }
        true
    }

    /// ARP and ND on a link whose router stack has no link layer
    /// (docs/lan-neighbors.md; the WAN in static mode, docs/local-stack.md
    /// step 2a): answered here for the router's addresses
    /// (`fwd::nd`), never passed on (the stack could not read them).
    /// Learning from them happened before ([`Self::snoop_arp`] /
    /// [`Self::snoop_nd`]). Returns true for those frames.
    fn link_layer(&self, ifx: IfIndex, frame: &[u8], touched: &mut Touched) -> bool {
        let arp = match wire::ethertype(frame) {
            Some(wire::ETHERTYPE_ARP) => true,
            Some(wire::ETHERTYPE_IPV6)
                if frame.get(wire::ETH_HDR + 6) == Some(&wire::PROTO_ICMPV6)
                    && frame.get(wire::ETH_HDR + 40).is_some_and(|&t| t == 135 || t == 136) =>
            {
                false
            }
            _ => return false,
        };
        let mac = self.sh.ports[self.sh.links[ifx as usize].port()].mac;
        let mut v6 = [Ipv6Addr::UNSPECIFIED; 4];
        let mut n6 = 0;
        let v4 = {
            let l = self.local[ifx as usize].lock();
            for a in l.addrs6().take(v6.len()) {
                v6[n6] = a;
                n6 += 1;
            }
            l.v4
        };
        let me = fwd::nd::Link { mac, v4, v6: &v6[..n6] };
        let mut out = [0u8; fwd::nd::REPLY_LEN];
        let o = fwd::nd::answer(frame, &me, self.nd_cfg, &mut out);
        if o.conflict.is_some() {
            ND_CONFLICTS.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(n) = o.reply
            && let Some(mut pkt) = PacketBuf::alloc()
        {
            pkt.set_len(n);
            pkt.data_mut().copy_from_slice(&out[..n]);
            pkt.meta.wire_len = n as u32;
            pkt.meta.enqueue_ts = now_ns();
            let n = match (ifx == WAN, arp) {
                (false, true) => &ARP_REPLIES,
                (false, false) => &NA_SENT,
                (true, true) => &WAN_ARP_REPLIES,
                (true, false) => &WAN_NA_SENT,
            };
            n.fetch_add(1, Ordering::Relaxed);
            self.enqueue(ifx, pkt, touched);
        }
        true
    }

    /// Fill in the Ethernet addresses and queue for transmission.
    fn send_resolved(
        &self,
        egress: IfIndex,
        mac: wire::Mac,
        mut pkt: PacketBuf,
        touched: &mut Touched,
    ) {
        let src = self.sh.ports[self.sh.links[egress as usize].port()].mac;
        wire::set_macs(pkt.data_mut(), mac, src);
        self.enqueue(egress, pkt, touched);
    }

    fn send_arp_request(&self, ifx: IfIndex, target: Ipv4Addr, touched: &mut Touched) {
        let addr = *self.addrs[ifx as usize].lock();
        let (Some((my_ip, _)), Some(mut pkt)) = (addr, PacketBuf::alloc()) else {
            return;
        };
        pkt.set_len(60); // minimum Ethernet frame
        pkt.data_mut().fill(0);
        pkt.meta.wire_len = 60;
        wire::build_arp_request(
            pkt.data_mut(),
            self.sh.ports[self.sh.links[ifx as usize].port()].mac,
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
        if i >= self.ecn_seen.len() {
            return;
        }
        let (ecn, proto, l4, l4_len) = match wire::Ipv4View::parse(frame, wire::ETH_HDR) {
            Some(v) => (v.tos(frame) & 3, v.proto, v.l4, v.l4_len),
            None => match wire::Ipv6View::parse(frame, wire::ETH_HDR) {
                Some(v) => (v.traffic_class(frame) & 3, v.proto, v.l4, v.l4_len),
                None => return,
            },
        };
        self.ecn_seen[i][ecn as usize].fetch_add(1, Ordering::Relaxed);
        if proto == wire::PROTO_TCP && l4_len >= 14 {
            let flags = frame[l4 + 13];
            if flags & 0x40 != 0 {
                self.tcp_ece[i].fetch_add(1, Ordering::Relaxed);
            }
            if flags & 0x80 != 0 {
                self.tcp_cwr[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Learn neighbors from ARP and release packets waiting for them.
    fn snoop_arp(&self, ifx: IfIndex, frame: &[u8], now: u64, touched: &mut Touched) {
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
    pub fn rx_batch(&self, port_ix: usize, batch: &mut Vec<PacketBuf>, touched: &mut Touched) {
        let now = now_ms();
        let port = &self.sh.ports[port_ix];
        let pppoe = port.is_pppoe();
        let session = port.pppoe_session();
        let mut b = Batch {
            touched,
            local: false,
            ingress: port_ix == WAN_PORT && self.sh.ingress.lock().rate().is_some(),
            charge: (0, 0),
        };
        let topo = self.topo.lock().clone();
        let hints = ShardHints {
            internal: &topo.internal,
            routed: &topo.routed,
            wan: self.addrs[WAN as usize].lock().map(|(a, _)| a),
            forwards: &topo.forwards,
            redirects: &topo.redirects,
        };
        // Fragments held for a first fragment that just came (rare: the
        // Vec stays empty and unallocated otherwise).
        let mut released: Vec<PacketBuf> = Vec::new();
        let mut released_key = None;
        for mut pkt in batch.drain(..) {
            let Some((ifx, want_vid)) = self.link_of(&topo, port_ix, pkt.data()) else {
                VLAN_DROPS.fetch_add(1, Ordering::Relaxed);
                b.bypass(pkt.len());
                continue;
            };
            let role = if ifx == WAN { Role::Wan } else { Role::Lan };
            match wire::vlan_rx(pkt.data(), want_vid) {
                wire::VlanRx::Accept { strip: false } => {}
                wire::VlanRx::Accept { strip: true } => pkt.pop_vlan(),
                wire::VlanRx::Drop => {
                    VLAN_DROPS.fetch_add(1, Ordering::Relaxed);
                    b.bypass(pkt.len());
                    continue;
                }
            }
            if pppoe {
                match pppoe_rx(&mut pkt, session) {
                    PppoeRx::Ip => {}
                    PppoeRx::Control => {
                        b.bypass(pkt.len());
                        let mut q = port.ctrl_rx.lock();
                        if q.len() < CTRL_RX_MAX {
                            q.push_back(pkt);
                            b.local = true;
                        } else {
                            PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    PppoeRx::Drop => {
                        PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                        b.bypass(pkt.len());
                        continue;
                    }
                }
            }
            match wire::ethertype(pkt.data()) {
                Some(wire::ETHERTYPE_ARP) => self.snoop_arp(ifx, pkt.data(), now, b.touched),
                // Only RA, NS, NA (a cheap look before the parse).
                Some(wire::ETHERTYPE_IPV6)
                    if pkt.data().get(wire::ETH_HDR + 6) == Some(&wire::PROTO_ICMPV6)
                        && pkt.data().get(wire::ETH_HDR + 40).is_some_and(|t| (134..=136).contains(t)) =>
                {
                    self.snoop_nd(ifx, pkt.data(), now, b.touched)
                }
                _ => {}
            }
            if self.sh.links[ifx as usize].ip_only() && self.link_layer(ifx, pkt.data(), b.touched) {
                continue;
            }
            let len = pkt.len();
            let kind = if self.fragments && port_ix < self.frags.len() {
                frag::classify(pkt.data())
            } else {
                FragKind::Whole
            };
            let verdict = match kind {
                // A later fragment: its first one's decision, or held for it.
                FragKind::Later(key) => {
                    let hit = self.frags[port_ix].lock().lookup(&key, now);
                    match hit {
                        Some(FragLookup::Forward { shard, decision }) => {
                            let v = self.shards[shard].lock().forward_fragment(
                                now,
                                ifx,
                                pkt.data_with_tailroom_mut(),
                                len,
                                &decision,
                            );
                            if matches!(v, Verdict::Forward { .. } | Verdict::Forward6 { .. }) {
                                FRAGS_FORWARDED.fetch_add(1, Ordering::Relaxed);
                            }
                            v
                        }
                        Some(FragLookup::Drop) => Verdict::Drop(DropReason::Fragment),
                        None => match self.frags[port_ix].lock().park(key, pkt, now) {
                            Ok(()) => {
                                FRAGS_PARKED.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            Err(p) => {
                                pkt = p;
                                FRAGS_PARK_DROPS.fetch_add(1, Ordering::Relaxed);
                                Verdict::Drop(DropReason::Fragment)
                            }
                        },
                    }
                }
                FragKind::Bad => Verdict::Drop(DropReason::Fragment),
                FragKind::Whole | FragKind::First(_) => {
                    let k = shard_of(role, pkt.data(), SHARDS, self.hash_key, &hints);
                    let mut shard = self.shards[k].lock();
                    let mut v = shard.process(now, ifx, pkt.data_with_tailroom_mut(), len);
                    if let FragKind::First(key) = kind {
                        let decision = shard.take_fragment();
                        drop(shard);
                        let mut t = self.frags[port_ix].lock();
                        match decision {
                            Some(d) if matches!(v, Verdict::Forward { .. } | Verdict::Forward6 { .. }) => {
                                if t.record_forward(key, k, d, now).is_err() {
                                    t.record_drop(key, now);
                                    v = Verdict::Drop(DropReason::Clash);
                                }
                            }
                            _ => t.record_drop(key, now),
                        }
                        // Fragments that came before it go right after it.
                        t.take_parked(&key, &mut released);
                        released_key = Some(key);
                    }
                    v
                }
            };
            self.deliver(verdict, pkt, ifx, port_ix, now, &mut b);
            if let Some(key) = released_key.take() {
                let hit = self.frags[port_ix].lock().lookup(&key, now);
                for mut p in released.drain(..) {
                    let len = p.len();
                    let v = match hit {
                        Some(FragLookup::Forward { shard, decision }) => self.shards[shard]
                            .lock()
                            .forward_fragment(now, ifx, p.data_with_tailroom_mut(), len, &decision),
                        _ => Verdict::Drop(DropReason::Fragment),
                    };
                    if matches!(v, Verdict::Forward { .. } | Verdict::Forward6 { .. }) {
                        FRAGS_FORWARDED.fetch_add(1, Ordering::Relaxed);
                    }
                    self.deliver(v, p, ifx, port_ix, now, &mut b);
                }
            }
        }
        if b.charge.1 > 0 {
            self.sh.ingress.lock().charge(b.charge.0, b.charge.1, now_ns());
        }
        if b.local {
            self.sh.svc_kick.signal();
        }
    }

    /// Act on the forwarder's verdict for a received frame: to the router
    /// stack, out through the neighbor table into the qdisc, or dropped.
    fn deliver(&self, verdict: Verdict, mut pkt: PacketBuf, ifx: IfIndex, port_ix: usize, now: u64, b: &mut Batch) {
        if !matches!(verdict, Verdict::Forward { .. } | Verdict::Forward6 { .. }) {
            b.bypass(pkt.len());
        }
        match verdict {
            Verdict::Local => {
                let mut q = self.sh.links[ifx as usize].local_rx.lock();
                if q.len() < LOCAL_RX_MAX {
                    q.push_back(pkt);
                    b.local = true;
                } else {
                    self.local_rx_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
            Verdict::Forward {
                egress,
                next_hop,
                len,
                class,
                split,
            } => {
                pkt.set_len(len);
                self.observe_ecn(port_ix, pkt.data());
                FORWARDED.fetch_add(1, Ordering::Relaxed);
                if split == 0 {
                    self.send_out(egress, next_hop, &class, ifx, pkt, now, b);
                    return;
                }
                // Larger than the egress MTU, no DF: split (RFC 791).
                let Some(plan) = wire::SplitPlan::new(pkt.data(), split).filter(|p| p.pieces() <= MAX_PIECES)
                else {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                    DROP_REASONS[DropReason::TooBig.index()].fetch_add(1, Ordering::Relaxed);
                    b.bypass(pkt.len());
                    return;
                };
                // Every piece or none: a datagram missing one is useless.
                let mut rest: [Option<PacketBuf>; MAX_PIECES - 1] = [const { None }; MAX_PIECES - 1];
                for i in 1..plan.pieces() {
                    let Some(mut p) = PacketBuf::alloc() else {
                        DROPPED.fetch_add(1, Ordering::Relaxed);
                        SPLIT_DROPS.fetch_add(1, Ordering::Relaxed);
                        b.bypass(pkt.len());
                        return;
                    };
                    p.set_len(plan.piece_len(i));
                    let n = plan.write_piece(pkt.data(), i, p.data_mut());
                    p.set_len(n);
                    rest[i - 1] = Some(p);
                }
                let n = plan.truncate_first(pkt.data_mut());
                pkt.set_len(n);
                SPLIT.fetch_add(1, Ordering::Relaxed);
                // In order, one after the other, into the same CAKE flow.
                self.send_out(egress, next_hop, &class, ifx, pkt, now, b);
                for p in rest.into_iter().flatten() {
                    self.send_out(egress, next_hop, &class, ifx, p, now, b);
                }
            }
            Verdict::Forward6 {
                egress,
                next_hop,
                len,
                class,
            } => {
                pkt.set_len(len);
                self.observe_ecn(port_ix, pkt.data());
                FORWARDED.fetch_add(1, Ordering::Relaxed);
                self.send_out6(egress, next_hop, &class, ifx, pkt, now, b);
            }
            Verdict::Drop(r) => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
                DROP_REASONS[r.index()].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A forwarded frame (or piece of one) into the WAN ingress stage (if
    /// it came from the WAN and the stage is on), else to its next hop.
    #[allow(clippy::too_many_arguments)]
    fn send_out(
        &self,
        egress: IfIndex,
        next_hop: Ipv4Addr,
        class: &Classification,
        ifx: IfIndex,
        mut pkt: PacketBuf,
        now: u64,
        b: &mut Batch,
    ) {
        let t = now_ns();
        pkt.meta = meta_from(class, ifx, pkt.len(), t);
        if b.ingress {
            pkt.meta.egress_if = egress;
            pkt.meta.next_hop = u128::from(u32::from(next_hop));
            // An overflow drop is charged by the shaper itself.
            if self.sh.ingress.lock().enqueue(pkt, t).is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        self.to_next_hop(egress, next_hop, pkt, now, b.touched);
    }

    /// [`Self::send_out`] for IPv6.
    #[allow(clippy::too_many_arguments)]
    fn send_out6(
        &self,
        egress: IfIndex,
        next_hop: Ipv6Addr,
        class: &Classification,
        ifx: IfIndex,
        mut pkt: PacketBuf,
        now: u64,
        b: &mut Batch,
    ) {
        let t = now_ns();
        pkt.meta = meta_from(class, ifx, pkt.len(), t);
        if b.ingress {
            pkt.meta.egress_if = egress;
            pkt.meta.next_hop = u128::from(next_hop);
            if self.sh.ingress.lock().enqueue(pkt, t).is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        self.to_next_hop6(egress, next_hop, pkt, now, b.touched);
    }

    /// [`Self::to_next_hop`] for IPv6: neighbor discovery. Not over PPPoE
    /// yet (IPv6CP: docs/ipv6.md step 4).
    fn to_next_hop6(&self, egress: IfIndex, next_hop: Ipv6Addr, pkt: PacketBuf, now: u64, touched: &mut Touched) -> Hop {
        let out = &self.sh.ports[self.sh.links[egress as usize].port()];
        if out.is_pppoe() {
            // Point to point, as for IPv4: no neighbor discovery.
            match out.pppoe_session() {
                Some(s) => self.send_resolved(egress, s.peer, pkt, touched),
                None => {
                    PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Hop::default();
        }
        let (r, dropped) = {
            let mut n = self.neigh6[egress as usize].lock();
            let before = n.dropped;
            let r = n.resolve(egress, next_hop, pkt, now);
            (r, count_neigh_drops(before, n.dropped))
        };
        let queued = match r {
            Resolve::Ready(mac, pkt) => {
                self.send_resolved(egress, mac, pkt, touched);
                false
            }
            Resolve::Queued { send_arp: true } => {
                self.send_ns(egress, next_hop, touched);
                true
            }
            Resolve::Queued { send_arp: false } => true,
        };
        Hop { queued, dropped }
    }

    /// A neighbor solicitation for `target` from our link-local address.
    fn send_ns(&self, ifx: IfIndex, target: Ipv6Addr, touched: &mut Touched) {
        let Some(mut pkt) = PacketBuf::alloc() else {
            return;
        };
        let mac = self.sh.ports[self.sh.links[ifx as usize].port()].mac;
        let mut ns = [0u8; wire::NS_LEN];
        wire::build_ns(&mut ns, mac, wire::link_local(mac), target);
        pkt.set_len(ns.len());
        pkt.data_mut().copy_from_slice(&ns);
        pkt.meta.wire_len = ns.len() as u32;
        self.enqueue(ifx, pkt, touched);
    }

    /// Learn IPv6 neighbors from neighbor discovery (NA, NS, RA with a
    /// link-layer option) and release packets waiting for them; note DAD
    /// probes' targets as the clients' addresses.
    fn snoop_nd(&self, ifx: IfIndex, frame: &[u8], now: u64, touched: &mut Touched) {
        let Some((ip, mac)) = wire::parse_nd(frame) else {
            // A host about to use an address (DAD): its only announcement
            // of a SLAAC address it may never use through the router. Not
            // a neighbor to send to yet; only for the Clients page and the
            // AAAA names, which `net::services` keeps up by probing it.
            if self.client6_dad
                && let Some((ip, mac)) = wire::parse_dad(frame)
            {
                self.sh.links[ifx as usize].note_neigh6(ip, mac, now);
            }
            return;
        };
        let waiting = self.neigh6[ifx as usize].lock().learn(ifx, ip, mac, now);
        // For the names of the networks' clients (AAAA, `net::services`).
        self.sh.links[ifx as usize].note_neigh6(ip, mac, now);
        for pkt in waiting {
            self.send_resolved(ifx, mac, pkt, touched);
        }
    }

    /// To the next hop: the PPPoE AC, or through the neighbor table, into
    /// the egress qdisc.
    fn to_next_hop(&self, egress: IfIndex, next_hop: Ipv4Addr, pkt: PacketBuf, now: u64, touched: &mut Touched) -> Hop {
        let out = &self.sh.ports[self.sh.links[egress as usize].port()];
        if out.is_pppoe() {
            // Point to point: the access concentrator is the only neighbor.
            match out.pppoe_session() {
                Some(s) => self.send_resolved(egress, s.peer, pkt, touched),
                None => {
                    PPPOE_DROPS.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Hop::default();
        }
        let (r, dropped) = {
            let mut n = self.neigh[egress as usize].lock();
            let before = n.dropped;
            let r = n.resolve(egress, next_hop, pkt, now);
            (r, count_neigh_drops(before, n.dropped))
        };
        let queued = match r {
            Resolve::Ready(mac, pkt) => {
                self.send_resolved(egress, mac, pkt, touched);
                false
            }
            Resolve::Queued { send_arp: true } => {
                self.send_arp_request(egress, next_hop, touched);
                true
            }
            Resolve::Queued { send_arp: false } => true,
        };
        Hop { queued, dropped }
    }

    /// Release what the WAN ingress stage's shaper allows now to the
    /// neighbor table and egress qdiscs (the task receiving on the WAN, each
    /// pass). Returns when the shaper releases the next packet, if it holds
    /// some back.
    pub fn drain_ingress(&self, touched: &mut Touched) -> Option<u64> {
        let now = now_ns();
        let ms = now / 1_000_000;
        loop {
            // One packet per lock: the neighbor and qdisc locks come after.
            let d = self.sh.ingress.lock().dequeue(now);
            match d {
                Dequeue::Packet(p) => {
                    let egress = p.meta.egress_if;
                    if wire::ethertype(p.data()) == Some(wire::ETHERTYPE_IPV6) {
                        let next_hop = Ipv6Addr::from(p.meta.next_hop);
                        self.to_next_hop6(egress, next_hop, p, ms, touched);
                    } else {
                        let next_hop = Ipv4Addr::from(p.meta.next_hop as u32);
                        self.to_next_hop(egress, next_hop, p, ms, touched);
                    }
                }
                Dequeue::WaitUntil(t) => return Some(t),
                Dequeue::Empty => return None,
            }
        }
    }

    /// Once a second (primary task): expire connections, retry ARP, print
    /// statistics. No NIC access.
    pub fn housekeeping(&self, touched: &mut Touched) {
        let now = now_ms();
        let (print, mut sc) = {
            let mut hk = self.hk.lock();
            if now < hk.next_housekeeping {
                return;
            }
            hk.next_housekeeping = now + HOUSEKEEPING_MS;
            let p = now >= hk.next_stats;
            if p {
                hk.next_stats = now + STATS_MS;
            }
            (p, core::mem::take(&mut hk.scratch))
        };
        let started = timer::Instant::now();
        let mut conns = 0;
        sc.hits.clear();
        sc.fhits.clear();
        sc.rhits.clear();
        let mut rejected = 0;
        let mut icmp_errors = 0;
        let mut unreachable6 = 0;
        let mut early_drops = 0;
        let add = |into: &mut Vec<u64>, from: &[u64]| {
            into.resize(into.len().max(from.len()), 0);
            for (h, n) in into.iter_mut().zip(from) {
                *h += n;
            }
        };
        let mut longest = 0;
        let mut removals = EXPIRE_PER_PASS;
        let first = (now / HOUSEKEEPING_MS) as usize % self.shards.len();
        for k in 0..self.shards.len() {
            let s = &self.shards[(first + k) % self.shards.len()];
            let mut f = s.lock();
            let held = timer::Instant::now();
            removals -= f.expire_some(now, removals.min(EXPIRE_PER_SHARD));
            conns += f.ct.len();
            add(&mut sc.hits, &f.rule_hits);
            add(&mut sc.fhits, &f.forward_hits);
            add(&mut sc.rhits, &f.redirect_hits);
            rejected += f.stats.rejected;
            icmp_errors += f.stats.icmp_errors_sent;
            unreachable6 += f.stats.unreachable6;
            early_drops += f.ct.stats.early_drops;
            drop(f);
            longest = longest.max(held.elapsed().as_micros() as u64);
        }
        EXPIRE_LAST_US.store(longest, Ordering::Relaxed);
        EXPIRE_MAX_US.fetch_max(longest, Ordering::Relaxed);
        REJECTED.store(rejected, Ordering::Relaxed);
        ICMP_ERRORS.store(icmp_errors, Ordering::Relaxed);
        UNREACHABLE6.store(unreachable6, Ordering::Relaxed);
        EARLY_DROPS.store(early_drops, Ordering::Relaxed);
        self.sh.conntrack.store(conns, Ordering::Relaxed);
        // Copied into the shared vectors, which keep their capacity.
        let publish = |to: &Mutex<Vec<u64>>, from: &[u64]| {
            let mut to = to.lock();
            to.clear();
            to.extend_from_slice(from);
        };
        publish(&self.sh.rule_hits, &sc.hits);
        publish(&self.sh.forward_hits, &sc.fhits);
        publish(&self.sh.redirect_hits, &sc.rhits);
        // Fragments held too long for a first fragment that never came.
        for t in &self.frags {
            t.lock().expire(now, &mut sc.stale);
        }
        for _ in sc.stale.drain(..) {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            DROP_REASONS[DropReason::Fragment.index()].fetch_add(1, Ordering::Relaxed);
            FRAGS_PARK_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        for (i, n) in self.neigh.iter().enumerate() {
            let retries = poll_neigh(&mut n.lock(), now);
            for (ifx, ip) in retries {
                debug_assert_eq!(ifx as usize, i);
                self.send_arp_request(ifx, ip, touched);
            }
        }
        for n in &self.neigh6 {
            let retries = poll_neigh(&mut n.lock(), now);
            for (ifx, ip) in retries {
                self.send_ns(ifx, ip, touched);
            }
        }
        self.hk.lock().scratch = sc;
        if print {
            self.print_qdisc_stats();
        }
        let took = started.elapsed().as_micros() as u64;
        HOUSEKEEPING_LAST_US.store(took, Ordering::Relaxed);
        HOUSEKEEPING_MAX_US.fetch_max(took, Ordering::Relaxed);
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
        for (i, nif) in self.sh.ports.iter().enumerate() {
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
        let ports = self.sh.ports.iter().map(|p| (p.name, &p.qdisc));
        for (i, (name, q)) in ports.chain([("ingress", &self.sh.ingress)]).enumerate() {
            printed |= self.print_qdisc(i, name, q);
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

    /// One qdisc's stats line (`scripts/lab-test.sh` reads it), if it sent
    /// packets since the last one; `slot` indexes `Hk::last_dequeued`.
    fn print_qdisc(&self, slot: usize, name: &str, q: &Mutex<PortQdisc>) -> bool {
        let mut qdisc = q.lock();
        let s = qdisc.stats();
        {
            let mut hk = self.hk.lock();
            if s.dequeued == hk.last_dequeued[slot] {
                return false;
            }
            hk.last_dequeued[slot] = s.dequeued;
        }
        let throttled = qdisc.throttled;
        let charged = qdisc.is_ingress().then_some(qdisc.charged_bytes);
        let rate = qdisc.rate();
        let aqm = qdisc.inner_mut();
        let max_sojourn = aqm.take_max_sojourn_ns();
        let flows = aqm.diag();
        let ack_drops = aqm.ack_drops();
        drop(qdisc); // the console is slow: print without holding the lock
        let shaped = match rate {
            Some(r) => alloc::format!(
                "shaped {} kbit/s, throttled {}{}, ",
                r.bits_per_sec / 1000,
                throttled,
                charged.map(|c| alloc::format!(", charged {c} B")).unwrap_or_default()
            ),
            None => alloc::string::String::new(),
        };
        crate::println!(
            "  qdisc {name:<11}: {shaped}{flows}sent {}, aqm drops {}, ecn marks {}, overflow drops {}, backlog {} pkts, max sojourn {}.{:03} ms",
            s.dequeued,
            s.aqm_actions - s.marked,
            s.marked,
            s.dropped - (s.aqm_actions - s.marked) - ack_drops,
            s.backlog_packets,
            max_sojourn / 1_000_000,
            (max_sojourn / 1_000) % 1_000
        );
        true
    }

    pub fn next_housekeeping(&self) -> u64 {
        self.hk.lock().next_housekeeping
    }
}

/// Move packets from a port's qdisc to its NIC while the NIC has room and
/// the shaper allows (the port's TX task, with the NIC locked).
pub fn flush_port(port: &PortShared, dev: &mut Nic) -> FlushResult {
    let r = flush_port_batch(port, dev);
    dev.kick_tx();
    r
}

/// [`flush_port`] without the final doorbell.
fn flush_port_batch(port: &PortShared, dev: &mut Nic) -> FlushResult {
    let now = now_ns();
    let mut r = FlushResult::default();
    dev.reap_tx();
    let tag = port.vlan();
    let pppoe = port.is_pppoe();
    let session = port.pppoe_session();
    let mut qdisc = port.qdisc.lock();
    loop {
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
                        TX_FAILED.fetch_add(1, Ordering::Relaxed);
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
        if !r.ring_full_backlog || dev.can_transmit() {
            return r;
        }
        // Blocked on the NIC: arm its TX interrupt, or go on if that
        // freed room.
        if dev.arm_tx_irq() {
            r.tx_armed = true;
            return r;
        }
        if !dev.can_transmit() {
            return r; // no TX interrupt of its own: the caller polls
        }
    }
}
