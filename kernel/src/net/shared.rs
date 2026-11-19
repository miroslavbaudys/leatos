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
//! A **port** is a NIC with its egress qdisc; a **link** is a router
//! interface on a port: the WAN on `wan0`, and one per network on `lan0`
//! (untagged, or a VLAN). The forwarder, ARP, smoltcp and the services
//! work per link; tags exist only between the link and its port.
//!
//! Forwarded packets never leave the datapath; the qdisc stays the only
//! place they wait. Everything here is `spin::Mutex` or atomics, so the two
//! tasks can later run on different cores unchanged (M11).

use crate::drivers;
use crate::irq::{self, IrqEvent};
use crate::net::device::PortQdisc;
use crate::net::mgmt::Action;
use crate::net::packet::PacketBuf;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, Once};

/// Bound on frames waiting for the router stack.
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

pub struct PortShared {
    pub name: &'static str,
    pub model: &'static str,
    pub mac: [u8; 6],
    /// Egress queue: forwarded traffic and the router's own traffic, of
    /// every link on the port.
    pub qdisc: Mutex<PortQdisc>,
    pub snap: Mutex<PortSnap>,
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

/// A router interface: the WAN (link 0), or a slot for a network on the
/// LAN port (docs/config-v2.md). Its index is the forwarder's `IfIndex`
/// and the services' `HostIf` index. Network slots exist from boot and
/// are switched on, retagged and readdressed when the config changes
/// (live), so nothing indexed by link ever moves.
pub struct LinkShared {
    /// Index into [`Shared::ports`].
    pub port: usize,
    /// 802.1Q VLAN ID on the port (networks), 0 = untagged. The WAN's tag
    /// is the port's own ([`PortShared::vlan`]).
    vid: AtomicU16,
    /// The slot holds a network (the WAN: always).
    active: AtomicBool,
    /// Frames for the router stack, filled by the datapath.
    pub local_rx: Mutex<VecDeque<PacketBuf>>,
}

impl LinkShared {
    pub fn new(port: usize, active: bool) -> Self {
        LinkShared {
            port,
            vid: AtomicU16::new(0),
            active: AtomicBool::new(active),
            local_rx: Mutex::new(VecDeque::with_capacity(LOCAL_RX_MAX)),
        }
    }

    /// A placeholder (smoltcp reads only a device's capabilities when an
    /// interface is made).
    pub fn detached() -> Self {
        LinkShared {
            port: 0,
            vid: AtomicU16::new(0),
            active: AtomicBool::new(false),
            local_rx: Mutex::new(VecDeque::new()),
        }
    }

    pub fn vid(&self) -> u16 {
        self.vid.load(Ordering::Relaxed)
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// The datapath (re)configures a network slot.
    pub fn set(&self, active: bool, vid: u16) {
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
    pub vid: u16,
    pub addr: (Ipv4Addr, u8),
    pub zone: u8,
}

/// The networks and the firewall, as the datapath applies them together
/// (zone numbers belong to both).
#[derive(Clone, Debug)]
pub struct Networks {
    pub nets: Vec<NetSlot>,
    pub policy: fwd::forwarder::Policy,
    /// `[[route]]`s: (subnet, prefix length, router).
    pub routes: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
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
    /// `ports[0]` = WAN, `ports[1]` = LAN.
    pub ports: Vec<PortShared>,
    /// `links[0]` = the WAN (port 0), then [`MAX_LINKS`]` - 1` network
    /// slots on port 1 (none without a LAN port).
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
    pub dst: (Ipv4Addr, u8),
    /// The next router; `None` = connected.
    pub via: Option<Ipv4Addr>,
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
    /// configured routes that are not in it.
    pub fn route_rows(&self) -> Vec<RouteRow> {
        use fwd::route::RouteKind;
        let table = self.routes.lock().clone();
        let nets = crate::config::networks();
        let named = crate::config::named_routes();
        let dev = |r: &fwd::route::Route| -> alloc::string::String {
            if r.egress == 0 {
                return "wan".into();
            }
            // The network whose subnet holds the router, or is the route.
            let ip = r.gateway.unwrap_or(r.prefix);
            nets.iter()
                .find(|n| n.contains(ip) && (r.gateway.is_some() || n.prefix == r.len))
                .map_or_else(|| "-".into(), |n| n.name.clone())
        };
        let mut rows: Vec<RouteRow> = table
            .iter()
            .map(|r| RouteRow {
                dst: (r.prefix, r.len),
                via: r.gateway,
                dev: dev(r),
                kind: r.kind.as_str(),
                name: (r.kind == RouteKind::Static)
                    .then(|| named.iter().find(|n| (n.1, n.2) == (r.prefix, r.len)).map(|n| n.0.clone()))
                    .flatten(),
                active: true,
            })
            .collect();
        for (name, dst, len, via) in named {
            let used = table.iter().any(|r| r.kind == RouteKind::Static && (r.prefix, r.len) == (dst, len));
            if !used {
                rows.push(RouteRow {
                    dst: (dst, len),
                    via: Some(via),
                    dev: "-".into(),
                    kind: RouteKind::Static.as_str(),
                    name: Some(name),
                    active: false,
                });
            }
        }
        rows
    }
}
