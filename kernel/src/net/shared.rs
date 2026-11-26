//! State shared between the datapath task (`net::stack::run`) and the
//! services task (`net::svc::run`), docs/architecture.md "Tasks".
//!
//! ```text
//!  datapath ── Verdict::Local ──► LinkShared::local_rx ──► svc (smoltcp)   + svc_kick
//!  svc (smoltcp TX) ─────────────► PortShared::qdisc (locked) ──► datapath + dp_kick
//!  svc ── Control (WAN lease, reboot/exec) ──────────────────► datapath   + dp_kick
//!  datapath ── PPPoE discovery/LCP/auth/IPCP ► PortShared::ctrl_rx ► svc + svc_kick
//!  svc ── PPPoE session (id, peer MAC) ► PortShared::pppoe_session ► datapath
//!  datapath ── PortSnap, conntrack count ────────────────────► svc (status page)
//!  dp_down: WAN RX ► forwarder ► Shared::ingress (download shaper) ► neighbor ► lan0 qdisc
//! ```
//!
//! A **port** is a NIC with its egress qdisc (`wan0`, then the LAN ports
//! `lan0`.., `config::PORTS`); a **link** is a router interface on a
//! port: the WAN on `wan0`, and one per network on its LAN port
//! (untagged, or a VLAN; routed ports, no bridge: a network is on one
//! port). The forwarder, ARP, smoltcp and the services work per link;
//! tags exist only between the link and its port.
//!
//! Forwarded packets never leave the datapath; the qdisc stays the only
//! place they wait. Everything here is `spin::Mutex` or atomics, so the two
//! tasks can later run on different cores unchanged (M11).

use crate::cpuload::HISTORY;
use crate::drivers;
use crate::irq::{self, IrqEvent};
use crate::net::device::PortQdisc;
use crate::net::mgmt::Action;
use crate::net::packet::PacketBuf;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, Once};

/// Bound on frames waiting for the router stack.
/// The router's bound UDP client ports (60000–65535): the forwarder lets
/// UDP from outside reach only these (docs/security-audit.md §5 item 7).
/// Set and cleared by the services task (`services::Upstream`, `ntp`).
pub static CLIENT_PORTS: fwd::forwarder::ClientPorts = fwd::forwarder::ClientPorts::new();

pub const LOCAL_RX_MAX: usize = 64;
/// Bound on PPPoE control frames waiting for the client.
pub const CTRL_RX_MAX: usize = 16;

/// What the datapath publishes about a port for the status page.
#[derive(Clone, Copy, Debug, Default)]
pub struct PortSnap {
    pub stats: drivers::Stats,
    /// (up, Mbit/s, full duplex), if the NIC reports it.
    pub link: Option<(bool, u32, bool)>,
}

/// A port's throughput over the last [`HISTORY`] samples (one per
/// `poll_links`, ~1 s), for the status page's chart: history from boot,
/// not from when the page was opened.
///
/// Lock-free, single writer (the primary datapath task) and single reader
/// (svc). Each slot packs both directions into one `AtomicU64`, so a pair
/// is never torn; a push during a read can at worst show the newest sample
/// in the oldest slot, for one poll.
pub struct RateRing {
    /// `(rx_kbit << 32) | tx_kbit`, kbit/s.
    slots: [AtomicU64; HISTORY],
    /// Samples written so far.
    written: AtomicUsize,
    /// The writer's previous reading (rx bytes, tx bytes, timer ticks);
    /// `at` = 0: none yet.
    last_rx: AtomicU64,
    last_tx: AtomicU64,
    last_at: AtomicU64,
}

impl RateRing {
    pub const fn new() -> Self {
        Self {
            slots: [const { AtomicU64::new(0) }; HISTORY],
            written: AtomicUsize::new(0),
            last_rx: AtomicU64::new(0),
            last_tx: AtomicU64::new(0),
            last_at: AtomicU64::new(0),
        }
    }

    /// Writer: the port's byte counters at `at` (timer ticks). The first
    /// reading only sets the baseline; a counter that went backwards (NIC
    /// reset) gives 0 for that sample.
    pub fn record(&self, rx_bytes: u64, tx_bytes: u64, at: u64) {
        let r = Ordering::Relaxed;
        let (prx, ptx, pat) = (self.last_rx.load(r), self.last_tx.load(r), self.last_at.load(r));
        self.last_rx.store(rx_bytes, r);
        self.last_tx.store(tx_bytes, r);
        self.last_at.store(at, r);
        if pat == 0 || at <= pat {
            return;
        }
        let us = crate::timer::ticks_to_duration(at - pat).as_micros().max(1) as u64;
        // bytes * 8 / µs = Mbit/s; * 1000 = kbit/s.
        let kbit = |now: u64, prev: u64| {
            (now.saturating_sub(prev).saturating_mul(8000) / us).min(u64::from(u32::MAX))
        };
        let w = self.written.load(r);
        let slot = kbit(rx_bytes, prx) << 32 | kbit(tx_bytes, ptx);
        self.slots[w % HISTORY].store(slot, r);
        self.written.store(w + 1, Ordering::Release);
    }

    /// Reader: (rx, tx) kbit/s, oldest first.
    pub fn for_each(&self, mut f: impl FnMut(u32, u32)) {
        let w = self.written.load(Ordering::Acquire);
        for i in w.saturating_sub(HISTORY)..w {
            let v = self.slots[i % HISTORY].load(Ordering::Relaxed);
            f((v >> 32) as u32, v as u32);
        }
    }
}

pub struct PortShared {
    pub name: &'static str,
    pub model: &'static str,
    pub mac: [u8; 6],
    /// Egress queue: forwarded traffic and the router's own traffic, of
    /// every link on the port.
    pub qdisc: Mutex<PortQdisc>,
    pub snap: Mutex<PortSnap>,
    /// Throughput history, written with `snap`.
    pub rates: RateRing,
    /// 802.1Q tag of the port ([`Self::vlan`]): `VLAN_SET | TCI`, 0 =
    /// untagged. The datapath removes it on RX and adds it on TX; svc
    /// changes it when a saved config changes `[wan]`.
    pub vlan: AtomicU32,
    /// The port runs PPPoE (`wan.mode = "pppoe"`): only PPPoE frames are
    /// accepted, IPv4 travels in the session, and the router stack's
    /// interface is IP-only (no ARP). Changed by svc together with that
    /// interface.
    pub pppoe_mode: AtomicBool,
    /// The PPPoE session ([`proto_pppoe::Session::pack`], 0 = none): the
    /// datapath decapsulates its IPv4 and encapsulates outgoing IPv4.
    pub pppoe_session: AtomicU64,
    /// Largest IP packet the router stack sends on this port.
    pub mtu: AtomicU32,
    /// PPPoE control frames (discovery and PPP other than IPv4) for the
    /// client in svc, filled by the datapath.
    pub ctrl_rx: Mutex<VecDeque<PacketBuf>>,
}

const VLAN_SET: u32 = 1 << 16;

impl PortShared {
    /// The port's tag (TCI), `None` = untagged.
    pub fn vlan(&self) -> Option<u16> {
        let v = self.vlan.load(Ordering::Relaxed);
        (v & VLAN_SET != 0).then_some(v as u16)
    }

    pub fn set_vlan(&self, tci: Option<u16>) {
        let v = tci.map_or(0, |t| VLAN_SET | u32::from(t));
        self.vlan.store(v, Ordering::Relaxed);
    }

    pub fn vlan_atomic(tci: Option<u16>) -> AtomicU32 {
        AtomicU32::new(tci.map_or(0, |t| VLAN_SET | u32::from(t)))
    }

    pub fn is_pppoe(&self) -> bool {
        self.pppoe_mode.load(Ordering::Relaxed)
    }

    pub fn pppoe_session(&self) -> Option<proto_pppoe::Session> {
        proto_pppoe::Session::unpack(self.pppoe_session.load(Ordering::Relaxed))
    }

    pub fn set_pppoe_session(&self, s: Option<proto_pppoe::Session>) {
        self.pppoe_session
            .store(s.map_or(0, |s| s.pack()), Ordering::Relaxed);
    }

    pub fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed) as u16
    }
}

/// Router interfaces: the WAN, and one slot per possible network.
pub const MAX_LINKS: usize = 1 + crate::config::schema::MAX_NETWORKS;
/// NICs used: the WAN and up to three LAN ports (the apu4's four).
pub const MAX_PORTS: usize = crate::config::PORTS.len();
/// The LAN port network slots start on (`lan0`).
pub const FIRST_LAN_PORT: usize = 1;

/// A router interface: the WAN (link 0), or a slot for a network on a
/// LAN port (docs/config-v2.md). Its index is the forwarder's `IfIndex`
/// and the services' `HostIf` index. Network slots exist from boot and
/// are switched on, moved to another port, retagged and readdressed when
/// the config changes (live), so nothing indexed by link ever moves.
pub struct LinkShared {
    /// Index into [`Shared::ports`] (set by the datapath with the VID).
    port: AtomicUsize,
    /// 802.1Q VLAN ID on the port (networks), 0 = untagged. The WAN's tag
    /// is the port's own ([`PortShared::vlan`]).
    vid: AtomicU16,
    /// The slot holds a network (the WAN: always).
    active: AtomicBool,
    /// Frames for the router stack, filled by the datapath.
    pub local_rx: Mutex<VecDeque<PacketBuf>>,
    /// A Router Solicitation came in (set as the router stack reads it,
    /// `net::device`; the network's RA advertiser answers, `net::services`).
    pub rs_seen: AtomicBool,
    /// Global and unique local IPv6 neighbors the datapath saw in
    /// neighbor discovery: (address, MAC, last seen ms). Bounded, the
    /// oldest goes; the services task names them (AAAA for DHCP clients).
    pub neigh6: Mutex<Vec<(Ipv6Addr, [u8; 6], u64)>>,
    /// The link's router stack runs on `Medium::Ip` over Ethernet: the
    /// datapath answers its ARP / ND and resolves its packets
    /// (docs/lan-neighbors.md, docs/local-stack.md step 2). Not on a
    /// PPPoE WAN, which has no link layer at all.
    ip_only: AtomicBool,
}

/// [`LinkShared::neigh6`]'s bound per link.
pub const NEIGH6_MAX: usize = 128;

impl LinkShared {
    pub fn new(port: usize, active: bool) -> Self {
        LinkShared {
            port: AtomicUsize::new(port),
            vid: AtomicU16::new(0),
            active: AtomicBool::new(active),
            local_rx: Mutex::new(VecDeque::with_capacity(LOCAL_RX_MAX)),
            rs_seen: AtomicBool::new(false),
            neigh6: Mutex::new(Vec::with_capacity(NEIGH6_MAX)),
            ip_only: AtomicBool::new(false),
        }
    }

    /// The datapath saw `ip` at `mac` (global or unique local only; no
    /// allocation: the table is made full size).
    pub fn note_neigh6(&self, ip: Ipv6Addr, mac: [u8; 6], now_ms: u64) {
        let first = ip.segments()[0];
        if !(first & 0xe000 == 0x2000 || first & 0xfe00 == 0xfc00) {
            return;
        }
        let mut t = self.neigh6.lock();
        if let Some(e) = t.iter_mut().find(|e| e.0 == ip) {
            (e.1, e.2) = (mac, now_ms);
            return;
        }
        if t.len() >= NEIGH6_MAX
            && let Some(i) = (0..t.len()).min_by_key(|&i| t[i].2)
        {
            t.swap_remove(i);
        }
        t.push((ip, mac, now_ms));
    }

    /// A placeholder (smoltcp reads only a device's capabilities when an
    /// interface is made).
    pub fn detached() -> Self {
        LinkShared {
            port: AtomicUsize::new(0),
            vid: AtomicU16::new(0),
            active: AtomicBool::new(false),
            local_rx: Mutex::new(VecDeque::new()),
            rs_seen: AtomicBool::new(false),
            neigh6: Mutex::new(Vec::new()),
            ip_only: AtomicBool::new(false),
        }
    }

    /// See [`Self::ip_only`]'s field: set when the link's router-stack
    /// interface is made (the WAN's again on a mode change).
    pub fn ip_only(&self) -> bool {
        self.ip_only.load(Ordering::Relaxed)
    }

    pub fn set_ip_only(&self, on: bool) {
        self.ip_only.store(on, Ordering::Relaxed);
    }

    pub fn port(&self) -> usize {
        self.port.load(Ordering::Relaxed)
    }

    pub fn vid(&self) -> u16 {
        self.vid.load(Ordering::Relaxed)
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// The datapath (re)configures a network slot.
    pub fn set(&self, active: bool, port: usize, vid: u16) {
        self.port.store(port, Ordering::Relaxed);
        self.vid.store(vid, Ordering::Relaxed);
        self.active.store(active, Ordering::Relaxed);
    }

    /// The tag frames of this link carry on its port (`None`: untagged,
    /// or the port's own tag applies).
    pub fn tci(&self) -> Option<u16> {
        let vid = self.vid();
        (vid != 0).then(|| fwd::wire::vlan_tci_of(vid, 0))
    }
}

/// A network in its link slot, for the datapath.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetSlot {
    pub link: usize,
    /// Its port (index into [`Shared::ports`]).
    pub port: usize,
    pub vid: u16,
    pub addr: (Ipv4Addr, u8),
    pub zone: u8,
    /// The router's ULA on it (IPv6 on).
    pub ula: Option<core::net::Ipv6Addr>,
    /// Its global address (`lan6_prefix`).
    pub gua: Option<core::net::Ipv6Addr>,
}

/// The networks and the firewall, as the datapath applies them together
/// (zone numbers belong to both).
#[derive(Clone, Debug)]
pub struct Networks {
    pub nets: Vec<NetSlot>,
    pub policy: fwd::forwarder::Policy,
    /// `[[route]]`s: (subnet, prefix length, router).
    pub routes: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
    /// IPv6 `[[route]]`s (`config::static_routes6`).
    pub routes6: Vec<(Ipv6Addr, u8, Ipv6Addr)>,
}

/// Which network each slot holds (`slots[i]` = link `1 + i`), keeping a
/// network in its slot while its name stays: `prev` is the last
/// assignment, `names` the networks now. Returns the new assignment and,
/// per network in `names`' order, its link.
pub fn assign_slots(prev: &[Option<alloc::string::String>], names: &[&str]) -> (Vec<Option<alloc::string::String>>, Vec<usize>) {
    let n = MAX_LINKS - 1;
    let mut slots: Vec<Option<alloc::string::String>> = (0..n)
        .map(|i| prev.get(i).cloned().flatten().filter(|p| names.contains(&p.as_str())))
        .collect();
    let mut links = Vec::new();
    for name in names {
        let i = match slots.iter().position(|s| s.as_deref() == Some(*name)) {
            Some(i) => i,
            None => {
                let i = slots.iter().position(Option::is_none).expect("at most MAX_NETWORKS networks");
                slots[i] = Some(alloc::string::String::from(*name));
                i
            }
        };
        links.push(1 + i);
    }
    (slots, links)
}

/// A WAN lease change for the forwarder: address/prefix and gateway.
#[derive(Clone, Copy, Debug)]
pub struct WanChange {
    pub addr: Option<(Ipv4Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
    /// Largest IP packet the WAN carries (PPPoE: the session's MTU).
    pub mtu: u16,
}

#[derive(Default)]
pub struct Control {
    pub wan: Option<WanChange>,
    /// New networks and firewall (a saved config).
    pub networks: Option<Networks>,
    pub action: Option<Action>,
}

pub struct Shared {
    /// `ports[0]` = WAN, then the LAN ports (`config::PORTS`).
    pub ports: Vec<PortShared>,
    /// `links[0]` = the WAN (port 0), then [`MAX_LINKS`]` - 1` network
    /// slots, each on its network's LAN port (none without a LAN port).
    pub links: Vec<LinkShared>,
    /// Services → the primary datapath task: a control message.
    pub dp_kick: &'static IrqEvent,
    /// Per port: frames were queued for TX (wakes the task that transmits
    /// on that port).
    pub tx_kick: Vec<&'static IrqEvent>,
    /// Datapath → services: frames in a `local_rx`.
    pub svc_kick: &'static IrqEvent,
    pub control: Mutex<Control>,
    /// Tracked connections (published by the datapath).
    pub conntrack: AtomicUsize,
    /// Packets each firewall rule decided, summed over the shards
    /// (published by the datapath once a second; `config::rule_names`).
    pub rule_hits: Mutex<Vec<u64>>,
    /// New connections each port forward took (`config::forward_names`).
    pub forward_hits: Mutex<Vec<u64>>,
    /// New connections each redirect took (`config::redirect_names`).
    pub redirect_hits: Mutex<Vec<u64>>,
    /// The forwarder's routing table (published by the datapath).
    pub routes: Mutex<Vec<fwd::route::Route>>,
    /// Its IPv6 routing table (connected /64s, `::/0`, `[[route]]`s).
    pub routes6: Mutex<Vec<fwd::route::Route<Ipv6Addr>>>,
    /// The WAN ingress stage (docs/bufferbloat-cake.md §3.4): forwarded
    /// packets that came from the WAN wait here, shaped at the download
    /// rate, before their neighbor lookup and egress qdisc. Owned by the
    /// task receiving on the WAN (`dp_down`); svc only reconfigures and
    /// reads it. A shaper without a rate = no ingress stage.
    pub ingress: Mutex<PortQdisc>,
}

/// One line of the routing table as shown (`/api/status` `routes`, CLI
/// `routes`).
pub struct RouteRow {
    pub dst: (IpAddr, u8),
    /// The next router; `None` = connected.
    pub via: Option<IpAddr>,
    /// `wan`, a network's name, or `-` (a configured route not in use).
    pub dev: alloc::string::String,
    /// `connected`, `default` or `static`.
    pub kind: &'static str,
    /// A `[[route]]`'s name.
    pub name: Option<alloc::string::String>,
    /// In the table (a configured route is not while no connected subnet
    /// holds its router, e.g. the WAN without a lease).
    pub active: bool,
}

static SHARED: Once<&'static Shared> = Once::new();

/// Create the shared state once (at bring-up).
pub fn init(ports: Vec<PortShared>, links: Vec<LinkShared>, ingress: PortQdisc) -> &'static Shared {
    SHARED.call_once(|| {
        let tx_kick = ports.iter().map(|_| irq::new_event()).collect();
        Box::leak(Box::new(Shared {
            ports,
            links,
            tx_kick,
            dp_kick: irq::new_event(),
            svc_kick: irq::new_event(),
            control: Mutex::new(Control::default()),
            conntrack: AtomicUsize::new(0),
            rule_hits: Mutex::new(Vec::new()),
            forward_hits: Mutex::new(Vec::new()),
            redirect_hits: Mutex::new(Vec::new()),
            routes: Mutex::new(Vec::new()),
            routes6: Mutex::new(Vec::new()),
            ingress: Mutex::new(ingress),
        }))
    })
}

impl Shared {
    /// Services → datapath.
    pub fn post_wan(&self, change: WanChange) {
        self.control.lock().wan = Some(change);
        self.dp_kick.signal();
    }

    pub fn post_networks(&self, networks: Networks) {
        self.control.lock().networks = Some(networks);
        self.dp_kick.signal();
    }

    pub fn post_action(&self, action: Action) {
        self.control.lock().action = Some(action);
        self.dp_kick.signal();
    }

    pub fn conntrack(&self) -> usize {
        self.conntrack.load(Ordering::Relaxed)
    }

    /// The routing table in use (longest prefix first), then the
    /// configured routes that are not in it; IPv4, then IPv6.
    pub fn route_rows(&self) -> Vec<RouteRow> {
        use fwd::route::RouteKind;
        let nets = crate::config::networks();
        let mut rows = Vec::new();
        // IPv4: the network whose subnet holds the router, or is the route.
        let table = self.routes.lock().clone();
        let named = crate::config::named_routes();
        for r in &table {
            let ip = r.gateway.unwrap_or(r.prefix);
            let dev = (r.egress != 0)
                .then(|| nets.iter().find(|n| n.contains(ip) && (r.gateway.is_some() || n.prefix == r.len)))
                .map(|n| n.map(|n| n.name.as_str()));
            let name = (r.kind == RouteKind::Static)
                .then(|| named.iter().find(|n| (n.1, n.2) == (r.prefix, r.len)).map(|n| n.0.clone()))
                .flatten();
            rows.push(row((r.prefix.into(), r.len), r.gateway.map(Into::into), dev, r.kind, name, true));
        }
        for (name, dst, len, via) in named {
            if !table.iter().any(|r| r.kind == RouteKind::Static && (r.prefix, r.len) == (dst, len)) {
                rows.push(row((dst.into(), len), Some(via.into()), Some(None), RouteKind::Static, Some(name), false));
            }
        }
        // IPv6: the network one of whose /64s (unique local, global)
        // holds the router, or is the route.
        let table = self.routes6.lock().clone();
        let named = crate::config::named_routes6();
        let on_net = |n: &crate::config::Lan, a: Ipv6Addr| {
            [n.ula, n.gua].into_iter().flatten().any(|m| (u128::from(m) ^ u128::from(a)) >> 64 == 0)
        };
        for r in &table {
            let ip = r.gateway.unwrap_or(r.prefix);
            let dev = (r.egress != 0)
                .then(|| nets.iter().find(|n| on_net(n, ip) && (r.gateway.is_some() || r.len == 64)))
                .map(|n| n.map(|n| n.name.as_str()));
            let name = (r.kind == RouteKind::Static)
                .then(|| named.iter().find(|n| (n.1, n.2) == (r.prefix, r.len)).map(|n| n.0.clone()))
                .flatten();
            rows.push(row((r.prefix.into(), r.len), r.gateway.map(Into::into), dev, r.kind, name, true));
        }
        for (name, dst, len, via, _) in named {
            if !table.iter().any(|r| r.kind == RouteKind::Static && (r.prefix, r.len) == (dst, len)) {
                rows.push(row((dst.into(), len), Some(via.into()), Some(None), RouteKind::Static, Some(name), false));
            }
        }
        rows
    }
}

/// A [`RouteRow`]; `dev`: `None` = the WAN, `Some(None)` = no network.
fn row(
    dst: (IpAddr, u8),
    via: Option<IpAddr>,
    dev: Option<Option<&str>>,
    kind: fwd::route::RouteKind,
    name: Option<alloc::string::String>,
    active: bool,
) -> RouteRow {
    RouteRow {
        dst,
        via,
        dev: match dev {
            None => "wan".into(),
            Some(Some(n)) => n.into(),
            Some(None) => "-".into(),
        },
        kind: kind.as_str(),
        name,
        active,
    }
}
