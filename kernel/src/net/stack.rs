//! Ports and the datapath task.
//!
//! - WAN (first NIC: virtio-net or igb, in PCI order), LAN (second NIC).
//! - [`bring_up`] creates per port: the NIC ([`Port`], datapath-owned), the
//!   qdisc and `local_rx` queue (`net::shared::PortShared`), and the router
//!   stack's smoltcp interface (`net::svc::HostIf`, services-owned).
//! - [`run`], the datapath task (`Priority::Datapath`): NIC RX →
//!   `net::datapath` (forward / local / drop) → qdiscs → NIC TX. The
//!   router's own stack and services run in `net::svc::run`
//!   (`Priority::Service`), so they never delay forwarding by more than
//!   one of their polls.
//!
//! Interrupts work NAPI-style: the IRQ action masks the INTx line or MSI-X
//! vector (or the device masked itself: igb with MSI-X); this task wakes,
//! clears the device's interrupt status, polls until idle, and unmasks.

use crate::drivers::{self, Nic};
use crate::irq::{self, IrqEvent, Trigger};
use crate::net::datapath::{self, Datapath};
use crate::net::device::{Aqm, PortDevice, PortQdisc};
use crate::net::mgmt::Action;
use crate::net::shared::{self, CTRL_RX_MAX, LinkShared, PortShared, PortSnap, Shared};
use crate::net::svc::HostIf;
use crate::pci::Pci;
use crate::{arch, println, timer};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use core::task::{Context, Poll};
use core::time::Duration;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant as NetInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Cidr, Ipv6Cidr};
use spin::Mutex;

/// Qdisc hard limits, per port egress and for the WAN ingress stage
/// (shared by all flows): `config::Qos::queue_pkts` packets (default
/// `config::QUEUE_PACKETS`), and at most that many full frames. The AQM
/// keeps standing queues near 5 ms; the limits only bound bursts. Full
/// queues draw on the packet pool (`net_pool_size`); when it runs dry the
/// NICs drop at RX, never grow it.
const FRAME: usize = 1514;
/// A shaped queue's byte limit follows its rate (`shaping.queue_ms`,
/// `config::Qos::queue_limit`), between this floor (bursts at very low
/// rates) and the ceiling.
const QDISC_MIN_BYTES: usize = 16 * FRAME;

/// The byte limit of a queue shaped at `rate` (unshaped: the ceiling).
fn queue_bytes(qos: &crate::config::Qos, rate: Option<qdisc::shaper::Rate>) -> usize {
    qos.queue_limit(rate, QDISC_MIN_BYTES, qos.queue_pkts * FRAME)
}

/// For the qos log lines: the limit and how long a full queue waits.
fn describe_limit(bytes: usize, rate: Option<qdisc::shaper::Rate>) -> alloc::string::String {
    match rate {
        Some(r) => alloc::format!(
            "queue {} KiB ({} ms)",
            bytes / 1024,
            (bytes as u64 * 8 * 1000) / r.bits_per_sec.max(1)
        ),
        None => alloc::format!("queue {} KiB", bytes / 1024),
    }
}

fn cidr(n: &crate::config::Lan) -> Ipv4Cidr {
    Ipv4Cidr::new(n.addr, n.prefix)
}

/// Per-port variation for the AQM's random seed.
fn mac_seed(mac: &[u8; 6]) -> u64 {
    mac.iter().fold(0, |a, &b| a << 8 | b as u64)
}

/// The datapath's half of a port: the NIC and its interrupt. Shared by the
/// two direction tasks (one receives on it, the other transmits), so the
/// NIC is locked; `None` once the NICs were stopped for a reboot/upgrade.
/// Lock order: NIC, then the datapath, then a qdisc (never the reverse).
pub struct Port {
    pub name: &'static str,
    pub dev: Mutex<Option<Nic>>,
    /// Last known link state (up, Mbit/s, full duplex), if the NIC reports one.
    pub link: Mutex<Option<(bool, u32, bool)>>,
    irq: Option<PortIrq>,
    /// TX completions on their own vector (igb MSI-X), delivered to the
    /// core that transmits on this port and armed only while it is blocked.
    tx_irq: Option<PortIrq>,
}

#[derive(Clone, Copy)]
struct PortIrq {
    intid: u32,
    ev: &'static IrqEvent,
    /// The device masks itself when it fires and is re-armed through the
    /// NIC (`Nic::unmask_irq`), not at the interrupt controller.
    self_mask: bool,
}

/// `vlan 848 (pcp 0)` for a port's tag.
pub fn vlan_text(tci: u16) -> alloc::string::String {
    alloc::format!("vlan {} (pcp {})", tci & 0x0fff, tci >> 13)
}

pub fn now() -> NetInstant {
    NetInstant::from_micros(timer::uptime().as_micros() as i64)
}

/// IRQ context: mask the (level-triggered, possibly shared) INTx line until
/// the network task has drained the device.
fn mask_intx(intid: u32) {
    arch::irqchip::disable(intid);
}

/// IRQ context, for a device that masked itself (`Nic::self_masking`):
/// nothing to touch, the event is signalled by `irq::dispatch`.
fn device_masked(_intid: u32) {}

/// Where the network tasks run (docs/smp.md): with two ports one datapath
/// task per direction, on their own cores when there are 3+, and the
/// services on the next core.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// `dp_down` (WAN RX → LAN TX), or the single task with one port.
    pub down: usize,
    /// `dp_up` (LAN RX → WAN TX).
    pub up: usize,
    pub svc: usize,
}

pub fn layout(ports: usize, cores: usize) -> Layout {
    match (ports >= 2, cores) {
        (_, 0 | 1) => Layout {
            down: 0,
            up: 0,
            svc: 0,
        },
        (true, 2) | (false, _) => Layout {
            down: 0,
            up: 0,
            svc: 1,
        },
        (true, _) => Layout {
            down: 0,
            up: 1,
            svc: 2,
        },
    }
}

/// Bring up the supported NICs in PCI order, at most
/// [`shared::MAX_PORTS`]: first = WAN (`wan0`), then the LAN ports
/// (`lan0`, `lan1`, ..: `config::PORTS`).
/// WAN egress is shaped at the upload rate; the download in the WAN
/// ingress stage (`Shared::ingress`), so LAN egress is unshaped and
/// traffic between networks runs at the line rate (`shape_ingress=0`:
/// LAN egress at the download rate instead).
/// Links: the WAN on the first, one per network (`config::networks`),
/// each on its LAN port. Returns the datapath's ports, the services' router-stack
/// interfaces (one per link) and the shared state (`None` without NICs).
pub fn bring_up(
    pci: &mut Pci,
    qos: &crate::config::Qos,
) -> Option<(&'static [Port], Vec<HostIf>, &'static Shared)> {
    let devs: Vec<_> = pci
        .devices
        .iter()
        .filter(|d| drivers::is_nic(d))
        .cloned()
        .collect();
    let mut ports = Vec::new();
    let mut shared_ports = Vec::new();
    let mut links = Vec::new();
    let mut hosts = Vec::new();
    let lay = layout(devs.len().min(shared::MAX_PORTS), crate::smp::online());
    for d in devs.iter().take(shared::MAX_PORTS) {
        // Ports are numbered by the NICs that came up.
        let i = shared_ports.len();
        // Interrupts go to the core of the task that receives on this port.
        let rx_core = if i == 0 { lay.down } else { lay.up };
        let tx_core = if i == 0 { lay.up } else { lay.down };
        let name = crate::config::PORTS[i];
        let mut dev = match Nic::new(pci, d) {
            Ok(dev) => dev,
            Err(e) => {
                println!("  net {name}: init failed: {e:?}");
                continue;
            }
        };
        let mac = dev.mac();
        crate::entropy::mix(&mac);
        let rate = qos.port_rate(i == 0);
        let ecn = if i == 0 { qos.ecn_up } else { qos.ecn_down };
        let limit = queue_bytes(qos, rate);
        let aqm = Aqm::new(
            qos,
            ecn,
            i == 0 && qos.ack_filter,
            qos.queue_pkts,
            limit,
            timer::ticks() ^ mac_seed(&mac),
        );
        let desc = aqm.describe(ecn);
        let qdisc = PortQdisc::new(aqm, rate);
        let lim = describe_limit(limit, rate);
        match rate {
            Some(r) => println!(
                "  qos {name}       : shaped {} kbit/s ({}), overhead {} B, {lim}, {desc}",
                r.bits_per_sec / 1000,
                if i == 0 { "upload" } else { "download" },
                r.overhead,
            ),
            None => println!("  qos {name}       : unshaped, {lim}, {desc}"),
        }
        let pppoe = i == 0 && crate::config::pppoe().is_some();
        let port = PortShared {
            name,
            model: dev.model(),
            mac,
            qdisc: Mutex::new(qdisc),
            snap: Mutex::new(PortSnap::default()),
            vlan: PortShared::vlan_atomic(if i == 0 { crate::config::wan_tci() } else { None }),
            pppoe_mode: AtomicBool::new(pppoe),
            pppoe_session: AtomicU64::new(0),
            mtu: AtomicU32::new(u32::from(fwd::forwarder::DEFAULT_MTU)),
            ctrl_rx: Mutex::new(VecDeque::with_capacity(CTRL_RX_MAX)),
        };
        // The port's links, each with its router-stack interface.
        let port_ix = i;
        if i == 0 {
            let link = LinkShared::new(port_ix, true);
            let iface = new_iface(&port);
            let mut sockets = SocketSet::new(Vec::new());
            if crate::config::wan_link() == crate::config::WanLink::Dhcp {
                sockets.add(dhcpv4::Socket::new());
            }
            hosts.push(HostIf { iface, sockets, nd: Default::default() });
            links.push(link);
        } else if i == shared::FIRST_LAN_PORT {
            // Every network slot, with an interface without addresses (on
            // lan0 until a network places it); `set_host_addrs` gives the
            // config's networks their addresses and port MACs.
            for _ in 1..shared::MAX_LINKS {
                links.push(LinkShared::new(port_ix, false));
                hosts.push(HostIf {
                    iface: new_iface(&port),
                    sockets: SocketSet::new(Vec::new()),
                    nd: Default::default(),
                });
            }
        }
        // Legacy INTx where the platform routes it (aarch64 DTB), otherwise
        // MSI-X (x86_64: INTx routing would need ACPI AML).
        let line = d.intx.map(|intid| (intid, Trigger::Level, "")).or_else(|| {
            let vector = arch::irqchip::msi_vector(i)?;
            dev.prepare_msix(pci, d).ok()?;
            pci.enable_msix(d, 0, vector, rx_core)?;
            Some((vector, Trigger::Edge, " (MSI-X)"))
        });
        // TX completions on MSI-X entry 1, to the transmitting core.
        let tx_irq = line
            .filter(|&(_, trigger, _)| trigger == Trigger::Edge && dev.has_tx_vector())
            .and_then(|_| {
                let intid = arch::irqchip::msi_vector(i + shared::MAX_PORTS)?;
                pci.enable_msix(d, 1, intid, tx_core)?;
                let ev = irq::new_event();
                irq::register(intid, device_masked, ev);
                Some(PortIrq { intid, ev, self_mask: true })
            });
        let irq = line.map(|(intid, trigger, kind)| {
            let ev = irq::new_event();
            // The device first (the line / MSI-X entry is still masked), so
            // the action can depend on how it masks.
            dev.enable_irq(trigger == Trigger::Edge, tx_irq.is_some());
            let self_mask = dev.self_masking();
            irq::register(intid, if self_mask { device_masked } else { mask_intx }, ev);
            arch::irqchip::enable(intid, trigger);
            (PortIrq { intid, ev, self_mask }, kind)
        });
        if let Some(t) = tx_irq {
            arch::irqchip::enable(t.intid, Trigger::Edge); // the device keeps it masked
        }
        println!(
            "  net {name}       : {} {} mac {} {}",
            dev.model(),
            d.df,
            EthernetAddress(mac),
            match irq {
                Some((irq, kind)) => {
                    let mut s = alloc::format!("intid {}{kind}", irq.intid);
                    if let Some(t) = tx_irq {
                        s += &alloc::format!(", tx intid {}", t.intid);
                    }
                    if let Some(us) = dev.rx_moderation_us() {
                        s += &alloc::format!(", rx moderation {us} us");
                    }
                    s
                }
                None => alloc::string::String::from("(no irq: polling)"),
            }
        );
        if let Some(tci) = port.vlan() {
            println!("  net {name}       : {}", vlan_text(tci));
        }
        if pppoe {
            println!("  net {name}       : PPPoE");
        }
        ports.push(Port {
            name,
            dev: Mutex::new(Some(dev)),
            irq: irq.map(|(i, _)| i),
            tx_irq,
            link: Mutex::new(None),
        });
        shared_ports.push(port);
    }
    if ports.is_empty() {
        return None;
    }
    // Networks on ports this machine lacks are left out from here on.
    crate::config::set_ports(shared_ports.len(), shared_ports.first().map_or([0; 6], |p| p.mac));
    let nets = crate::config::networks();
    let (_, placed, _) = place_networks(&[]);
    set_host_addrs(&mut hosts, &nets, &placed, &port_macs(&shared_ports));
    log_networks(&nets);
    let ingress = ingress_qdisc(qos);
    log_ingress(qos, ingress.rate(), None);
    Some((
        alloc::boxed::Box::leak(ports.into_boxed_slice()),
        hosts,
        shared::init(shared_ports, links, ingress),
    ))
}

/// The WAN ingress stage: the download's CAKE (ECN as on the download),
/// shaped in ingress mode (drops and bypassing traffic count against the
/// rate: `qdisc::shaper`).
fn ingress_qdisc(qos: &crate::config::Qos) -> PortQdisc {
    let aqm = Aqm::new(
        qos,
        qos.ecn_down,
        false,
        qos.queue_pkts,
        queue_bytes(qos, qos.ingress_rate()),
        timer::ticks() ^ 0x1a9e_55c0_de0f_0001,
    );
    PortQdisc::ingress(aqm, qos.ingress_rate())
}

/// The boot log line for the ingress stage; `what` = "queue kept" or the
/// new AQM after a live change.
fn log_ingress(qos: &crate::config::Qos, rate: Option<qdisc::shaper::Rate>, what: Option<&str>) {
    let now = if what.is_some() { "now " } else { "" };
    match rate {
        Some(r) => println!(
            "  qos ingress    : {now}shaped {} kbit/s (download), overhead {} B, {}, {}",
            r.bits_per_sec / 1000,
            r.overhead,
            describe_limit(queue_bytes(qos, rate), rate),
            what.unwrap_or("CAKE in ingress mode")
        ),
        None if !qos.ingress => println!("  qos ingress    : off (shape_ingress=0: download shaped on lan0)"),
        None => println!("  qos ingress    : {now}unshaped (no download rate)"),
    }
}

/// The router stack's interface for a link on `port`: Ethernet, or
/// IP-only on a PPPoE port ([`PortShared::is_pppoe`], set before calling).
/// smoltcp only reads the device's capabilities here.
pub fn new_iface(port: &PortShared) -> Interface {
    let link = &LinkShared::detached();
    let hw = if port.is_pppoe() {
        HardwareAddress::Ip
    } else {
        HardwareAddress::Ethernet(EthernetAddress(port.mac))
    };
    let mut config = Config::new(hw);
    config.random_seed = timer::ticks();
    let mut queued = 0;
    let mut device = PortDevice {
        link,
        port,
        now_ns: datapath::now_ns(),
        queued: &mut queued,
        nd: None,
    };
    Interface::new(config, &mut device, now())
}

/// Wait until any of `events` fires or the sleep ends.
pub struct WaitAny<'a> {
    pub events: &'a [&'static IrqEvent],
    pub sleep: timer::Sleep,
}

impl Future for WaitAny<'_> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut ready = false;
        for ev in self.events {
            // Non-consuming, and no early return: every event gets the waker,
            // and the main loop still sees (and handles) the fired flags.
            ready |= ev.poll_fired(cx).is_ready();
        }
        if ready || Pin::new(&mut self.sleep).poll(cx).is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// A set of ports (bit `i` = port `i`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortSet(pub u8);

impl PortSet {
    pub fn one(i: usize) -> Self {
        Self(1 << i)
    }

    /// Ports `from..to`.
    pub fn range(from: usize, to: usize) -> Self {
        Self((from..to).fold(0, |m, i| m | 1 << i))
    }

    pub fn has(self, i: usize) -> bool {
        i < 8 && self.0 & (1 << i) != 0
    }

    pub fn iter(self) -> impl Iterator<Item = usize> {
        (0..8).filter(move |&i| self.has(i))
    }
}

/// One direction of the datapath: receive on the ports `rx`, forward,
/// transmit the queues of the ports `tx` (download = WAN → the LAN ports,
/// upload = the LAN ports → WAN; one task for both when there is a single
/// port). The `primary` direction also handles control messages,
/// housekeeping and the status snapshot.
#[derive(Clone, Copy)]
pub struct Dir {
    pub rx: PortSet,
    pub tx: PortSet,
    pub primary: bool,
}

/// The forwarding state both directions share (locked inside, per shard
/// and per port; see `net::datapath`).
pub type SharedDatapath = &'static Datapath;

/// Apply new shaping settings without a restart. Rate and overhead change
/// in place (the queue is kept); another AQM, fairness mode or ECN setting
/// rebuilds the port's qdisc (and the ingress stage's), dropping the
/// packets queued in it (a few milliseconds' worth when it is shaped).
pub fn apply_qos(sh: &Shared, old: &crate::config::Qos, new: &crate::config::Qos) {
    {
        let rebuild = old.aqm != new.aqm || old.isolation != new.isolation || old.ecn_down != new.ecn_down;
        let what = if rebuild {
            let fresh = ingress_qdisc(new);
            let desc = fresh.inner().describe(new.ecn_down);
            // The old queue and its packets drop here, under the lock.
            *sh.ingress.lock() = fresh;
            desc
        } else {
            let mut q = sh.ingress.lock();
            q.set_rate(new.ingress_rate());
            q.inner_mut().set_limit_bytes(queue_bytes(new, new.ingress_rate()));
            alloc::string::String::from("queue kept")
        };
        log_ingress(new, new.ingress_rate(), Some(&what));
    }
    for (i, port) in sh.ports.iter().enumerate() {
        let up = i == 0;
        let rate = new.port_rate(up);
        let (ecn_old, ecn_new) = if up {
            (old.ecn_up, new.ecn_up)
        } else {
            (old.ecn_down, new.ecn_down)
        };
        let rebuild = old.aqm != new.aqm || old.isolation != new.isolation || ecn_old != ecn_new;
        let limit = queue_bytes(new, rate);
        let what = if rebuild {
            let aqm = Aqm::new(
                new,
                ecn_new,
                up && new.ack_filter,
                new.queue_pkts,
                limit,
                timer::ticks() ^ mac_seed(&port.mac),
            );
            let desc = aqm.describe(ecn_new);
            // The old qdisc and its packets drop here, under the lock.
            *port.qdisc.lock() = PortQdisc::new(aqm, rate);
            desc
        } else {
            let mut q = port.qdisc.lock();
            q.set_rate(rate);
            q.inner_mut().set_limit_bytes(limit);
            q.inner_mut().set_ack_filter(up && new.ack_filter);
            alloc::string::String::from(if up && new.ack_filter {
                "queue kept, ACK filter on"
            } else {
                "queue kept"
            })
        };
        let lim = describe_limit(limit, rate);
        match rate {
            Some(r) => println!(
                "  qos {}       : now shaped {} kbit/s, overhead {} B, {lim}, {what}",
                port.name,
                r.bits_per_sec / 1000,
                r.overhead
            ),
            None => println!("  qos {}       : now unshaped, {lim}, {what}", port.name),
        }
        // The datapath re-reads the shaper on its next pass.
        sh.tx_kick[i].signal();
    }
}

pub fn new_datapath(sh: &'static Shared) -> SharedDatapath {
    let (_, _, initial) = place_networks(&[]);
    alloc::boxed::Box::leak(alloc::boxed::Box::new(Datapath::new(sh, initial)))
}

/// The config's networks in link slots: a network keeps its slot while
/// its name stays (`prev`: the last placement, empty at boot). Returns
/// the new placement, each network's link (in `config::networks` order)
/// and the datapath's view.
pub fn place_networks(
    prev: &[Option<alloc::string::String>],
) -> (Vec<Option<alloc::string::String>>, Vec<usize>, shared::Networks) {
    let nets = crate::config::networks();
    let names: Vec<&str> = nets.iter().map(|n| n.name.as_str()).collect();
    let (slots, links) = shared::assign_slots(prev, &names);
    let msg = shared::Networks {
        nets: nets
            .iter()
            .zip(&links)
            .map(|(n, &link)| shared::NetSlot {
                link,
                port: n.port,
                vid: n.vid,
                addr: (n.addr, n.prefix),
                zone: n.zone,
                ula: n.ula,
                gua: n.gua,
            })
            .collect(),
        policy: crate::config::firewall(),
        routes: crate::config::static_routes(),
        routes6: crate::config::static_routes6(),
    };
    (slots, links, msg)
}

/// The ports' MACs by index (for [`set_host_addrs`]).
pub fn port_macs(ports: &[PortShared]) -> Vec<[u8; 6]> {
    ports.iter().map(|p| p.mac).collect()
}

/// The router stack's addresses: each network's on its slot's interface
/// (IPv4; with IPv6 on also the link-local address of the port's MAC and
/// the network's ULA /64), none on the others; the MAC of the network's
/// port; and its `[[route]]`s (the WAN's: those through a router on the
/// WAN's subnet), so the router answers hosts behind them.
pub fn set_host_addrs(hosts: &mut [HostIf], nets: &[crate::config::Lan], links: &[usize], macs: &[[u8; 6]]) {
    if let Some(wan) = hosts.first_mut() {
        set_host_routes(&mut wan.iface, &crate::config::wan_routes());
        // The router's own IPv6 traffic out (DNS to the ISP's IPv6
        // servers): a default route while the WAN has one.
        match crate::config::wan6() {
            Some(w) => {
                let _ = wan.iface.routes_mut().add_default_ipv6_route(w.gateway);
            }
            None => {
                wan.iface.routes_mut().remove_default_ipv6_route();
            }
        }
        // IPv6 on the WAN: its link-local address (the MAC's on Ethernet,
        // IPv6CP's on PPPoE while it is up), which the DHCPv6 client and
        // router solicitations use, and a static global one (development:
        // `wan6_ip=`); the IPv4 address stays the lease's.
        let pppoe = matches!(crate::config::wan_link(), crate::config::WanLink::Pppoe(_));
        let ll = if pppoe { crate::net::wan6::ppp_link().map(|l| l.0) } else { macs.first().map(|&m| fwd::wire::link_local(m)) };
        if !pppoe || crate::config::ipv6() {
            let mut want: Vec<IpCidr> = Vec::new();
            if crate::config::ipv6()
                && let Some(ll) = ll
            {
                want.push(IpCidr::Ipv6(Ipv6Cidr::new(ll, 64)));
                if let Some((ip, len)) = crate::config::wan6().and_then(|w| w.addr) {
                    want.push(IpCidr::Ipv6(Ipv6Cidr::new(ip, len)));
                }
            }
            let have: Vec<IpCidr> = wan.iface.ip_addrs().iter().filter(|c| matches!(c, IpCidr::Ipv6(_))).copied().collect();
            if have != want {
                wan.iface.update_ip_addrs(|a| {
                    a.retain(|c| matches!(c, IpCidr::Ipv4(_)));
                    for c in &want {
                        let _ = a.push(*c);
                    }
                });
            }
        }
    }
    for (i, host) in hosts.iter_mut().enumerate().skip(1) {
        let k = links.iter().position(|&l| l == i);
        if let Some(&mac) = k.and_then(|k| macs.get(nets[k].port)) {
            let hw = HardwareAddress::Ethernet(EthernetAddress(mac));
            if host.iface.hardware_addr() != hw {
                host.iface.set_hardware_addr(hw);
            }
        }
        // IPv6 [[route]]s through a router in this network's ULA /64.
        let routes6: Vec<(core::net::Ipv6Addr, u8, core::net::Ipv6Addr)> = match k.and_then(|k| nets[k].ula) {
            Some(ula) => crate::config::static_routes6()
                .into_iter()
                .filter(|&(_, _, via)| u128::from(via) >> 64 == u128::from(ula) >> 64)
                .collect(),
            None => Vec::new(),
        };
        set_host_routes46(&mut host.iface, k.map_or(&[][..], |k| &nets[k].routes), &routes6);
        let mut want: Vec<IpCidr> = Vec::new();
        if let Some(k) = k {
            want.push(IpCidr::Ipv4(cidr(&nets[k])));
            if let (Some(ula), Some(&mac)) = (nets[k].ula, macs.get(nets[k].port)) {
                want.push(IpCidr::Ipv6(Ipv6Cidr::new(fwd::wire::link_local(mac), 64)));
                want.push(IpCidr::Ipv6(Ipv6Cidr::new(ula, 64)));
                if let Some(gua) = nets[k].gua {
                    want.push(IpCidr::Ipv6(Ipv6Cidr::new(gua, 64)));
                }
            }
        }
        if host.iface.ip_addrs() != want.as_slice() {
            host.iface.update_ip_addrs(|a| {
                a.clear();
                for c in &want {
                    // iface-max-addr-count-4 (kernel/Cargo.toml) holds them.
                    let _ = a.push(*c);
                }
            });
        }
    }
}

/// An interface's routes: `routes`, plus the default route it has (the
/// WAN's, from the lease or PPPoE). smoltcp holds at most
/// `iface-max-route-count` (Cargo feature) of them.
pub fn set_host_routes(iface: &mut Interface, routes: &[(core::net::Ipv4Addr, u8, core::net::Ipv4Addr)]) {
    set_host_routes46(iface, routes, &[]);
}

/// [`set_host_routes`] with IPv6 routes too (a network's `[[route]]`s).
pub fn set_host_routes46(
    iface: &mut Interface,
    routes: &[(core::net::Ipv4Addr, u8, core::net::Ipv4Addr)],
    routes6: &[(core::net::Ipv6Addr, u8, core::net::Ipv6Addr)],
) {
    use smoltcp::iface::Route;
    use smoltcp::wire::IpAddress;
    iface.routes_mut().update(|table| {
        table.retain(|r| r.cidr.prefix_len() == 0);
        for &(dst, len, via) in routes {
            let route = Route {
                cidr: IpCidr::Ipv4(Ipv4Cidr::new(dst, len)),
                via_router: IpAddress::Ipv4(via),
                preferred_until: None,
                expires_at: None,
            };
            if table.push(route).is_err() {
                println!("  routes          : table full, {dst}/{len} via {via} left out");
            }
        }
        for &(dst, len, via) in routes6 {
            let route = Route {
                cidr: IpCidr::Ipv6(Ipv6Cidr::new(dst, len)),
                via_router: IpAddress::Ipv6(via),
                preferred_until: None,
                expires_at: None,
            };
            if table.push(route).is_err() {
                println!("  routes          : table full, {dst}/{len} via {via} left out");
            }
        }
    });
}

/// One line per network (boot, and after a change).
pub fn log_networks(nets: &[crate::config::Lan]) {
    for (name, port) in crate::config::missing_networks() {
        println!("  net             : network {name} left out: no port {port} on this machine");
    }
    for n in nets {
        println!(
            "  net {}       : {} {} ({}, zone {})",
            crate::config::PORTS[n.port],
            n.name,
            cidr(n),
            if n.vid == 0 {
                alloc::string::String::from("untagged")
            } else {
                alloc::format!("vlan {}", n.vid)
            },
            n.zone
        );
    }
}

/// Wait forever (the NICs were stopped; the primary task is rebooting).
async fn park() -> ! {
    loop {
        timer::sleep(Duration::from_secs(3600)).await;
    }
}

/// Primary only: link state and counters of every port, once a second.
fn poll_links(ports: &[Port], sh: &Shared) {
    for (port, sp) in ports.iter().zip(&sh.ports) {
        let mut g = port.dev.lock();
        let Some(dev) = g.as_mut() else { continue };
        let changed = dev.link_changed();
        dev.update_stats();
        let stats = dev.stats();
        drop(g);
        let mut link = port.link.lock();
        if changed.is_some() {
            *link = changed;
        }
        match changed {
            Some((true, speed, fd)) => println!(
                "  net {}       : link up, {speed} Mbit/s {} duplex",
                port.name,
                if fd { "full" } else { "half" }
            ),
            Some((false, ..)) => println!("  net {}       : link down", port.name),
            None => {}
        }
        *sp.snap.lock() = PortSnap { stats, link: *link };
    }
}

/// A datapath direction task: never returns (except into a reboot or a
/// new kernel, from the primary task).
pub async fn run_dir(d: Dir, ports: &'static [Port], sh: &'static Shared, dp: SharedDatapath) {
    let rx_ports: Vec<usize> = d.rx.iter().filter(|&p| p < ports.len()).collect();
    let tx_ports: Vec<usize> = d.tx.iter().filter(|&p| p < ports.len()).collect();
    let mut events: Vec<&'static IrqEvent> = rx_ports.iter().filter_map(|&p| ports[p].irq.map(|i| i.ev)).collect();
    events.extend(tx_ports.iter().map(|&p| sh.tx_kick[p]));
    events.extend(tx_ports.iter().filter_map(|&p| ports[p].tx_irq.map(|i| i.ev)));
    if d.primary {
        events.push(sh.dp_kick);
    }
    let mut batch = Vec::with_capacity(datapath::RX_BUDGET);
    // Per receive port: its interrupt is masked until it is drained.
    let mut masked = alloc::vec![false; rx_ports.len()];
    let mut next_links = 0u64;
    loop {
        for &p in &tx_ports {
            sh.tx_kick[p].take();
            if let Some(t) = ports[p].tx_irq {
                t.ev.take(); // a TX completion: the flush below reaps it
            }
        }
        if d.primary {
            sh.dp_kick.take();
        }
        let mut touched: datapath::Touched = Default::default();
        let mut more = false;
        for (k, &p) in rx_ports.iter().enumerate() {
            let rx = &ports[p];
            // NAPI step 1: IRQ fired → clear device interrupt status. The
            // TX side of this NIC (the other direction) may have completions,
            // unless they have their own interrupt.
            if let Some(i) = rx.irq
                && i.ev.take()
            {
                masked[k] = true;
                if !d.tx.has(p) && rx.tx_irq.is_none() {
                    sh.tx_kick[p].signal();
                }
            }
            // Step 2: take a batch off the NIC (short lock), then forward it.
            let full = {
                let mut g = rx.dev.lock();
                let Some(dev) = g.as_mut() else {
                    drop(g);
                    park().await
                };
                if masked[k] {
                    dev.ack_interrupt();
                }
                while batch.len() < datapath::RX_BUDGET {
                    match dev.receive() {
                        Some(pkt) => batch.push(pkt),
                        None => break,
                    }
                }
                let full = batch.len() == datapath::RX_BUDGET;
                // Step 5 for a self-masking device, while its lock is held:
                // drained, so re-arm (a cause that came in meanwhile fires).
                if masked[k] && !full && rx.irq.is_some_and(|i| i.self_mask) {
                    dev.unmask_irq();
                    masked[k] = false;
                }
                full
            };
            more |= full;
            if !batch.is_empty() {
                dp.rx_batch(p, &mut batch, &mut touched);
            }
        }
        // Step 2b (receiving on the WAN): the ingress stage's shaper
        // releases the download to the egress qdiscs.
        let ingress_wake = if d.rx.has(datapath::WAN_PORT) {
            dp.drain_ingress(&mut touched)
        } else {
            None
        };

        // Step 3 (primary): control messages, housekeeping, status.
        let mut next_hk = u64::MAX;
        if d.primary {
            let (wan, networks, action) = {
                let mut c = sh.control.lock();
                (c.wan.take(), c.networks.take(), c.action.take())
            };
            if let Some(n) = networks {
                dp.apply(n);
            }
            if let Some(action) = action {
                // End the PPPoE session first, so the ISP does not keep
                // (and bill, or refuse a new login for) a stale one.
                if let Some(pkt) = sh.ports.first().and_then(datapath::padt) {
                    if let Some(dev) = ports[0].dev.lock().as_mut() {
                        dev.reap_tx();
                        let _ = dev.transmit(pkt);
                    }
                    timer::sleep(Duration::from_millis(20)).await;
                    println!("  net {}       : PPPoE session ended (PADT)", ports[0].name);
                }
                // Quiesce: dropping the NICs resets them (no more DMA); the
                // other direction then parks.
                for port in ports {
                    drop(port.dev.lock().take());
                }
                match action {
                    Action::Reboot => {
                        crate::watchdog::stop();
                        arch::power::reset()
                    }
                    Action::Exec(staging, prepared, cmdline) => {
                        crate::upgrade::exec(staging, prepared, &cmdline)
                    }
                }
            }
            if let Some(w) = wan {
                dp.set_wan(w.addr, w.gateway, w.mtu);
            }
            dp.housekeeping(&mut touched);
            next_hk = dp.next_housekeeping();
            let now = timer::uptime().as_millis() as u64;
            if now >= next_links {
                next_links = now + 1000;
                poll_links(ports, sh);
            }
        }
        for (p, &t) in touched.iter().enumerate() {
            if t && !d.tx.has(p) && p < sh.tx_kick.len() {
                sh.tx_kick[p].signal();
            }
        }

        // Step 4: this direction's qdiscs → NICs.
        let mut shaper_wake: Option<u64> = None;
        let mut ring_full_backlog = false;
        for &p in &tx_ports {
            let tx = {
                let mut g = ports[p].dev.lock();
                let Some(dev) = g.as_mut() else {
                    drop(g);
                    park().await
                };
                datapath::flush_port(&sh.ports[p], dev)
            };
            shaper_wake = match (shaper_wake, tx.shaper_wake_ns) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            ring_full_backlog |= tx.ring_full_backlog && !tx.tx_armed;
        }

        // Step 5: unmask (a still-pending device re-fires). On aarch64 this
        // also routes the line to this core.
        // A shared INTx line (several NICs) only once every sharer has
        // drained its device (`irq::line_done`).
        for (k, &p) in rx_ports.iter().enumerate() {
            if masked[k] && let Some(i) = ports[p].irq
                && !i.self_mask
            {
                masked[k] = false;
                if irq::line_done(i.intid, i.ev) {
                    arch::irqchip::enable(i.intid, Trigger::Level);
                }
            }
        }

        // Step 6: sleep until an IRQ, a kick or the next deadline.
        if more {
            crate::executor::yield_now().await;
            continue;
        }
        // Primary: next housekeeping / link poll; otherwise only events.
        let now_ms = timer::uptime().as_millis() as u64;
        let due = if d.primary {
            next_hk.min(next_links)
        } else {
            u64::MAX
        };
        let mut delay = Duration::from_millis(due.saturating_sub(now_ms).min(1000));
        for at in [shaper_wake, ingress_wake].into_iter().flatten() {
            delay = delay.min(Duration::from_nanos(at.saturating_sub(datapath::now_ns())));
        }
        // TX completion normally raises an interrupt (handled by the other
        // direction, which kicks us); poll as a fallback while a ring is
        // full with a backlog, and for devices without an IRQ.
        if ring_full_backlog || ports.iter().any(|n| n.irq.is_none()) {
            delay = delay.min(Duration::from_millis(1));
        }
        WaitAny {
            events: &events,
            sleep: timer::sleep(delay),
        }
        .await;
    }
}
