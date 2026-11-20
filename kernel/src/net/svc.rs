//! The services task (`Priority::Service`): the router's own IP stack
//! (smoltcp, one interface per port) and everything on top of it:
//!
//! - WAN: DHCPv4 client (smoltcp socket), or the PPPoE client
//!   (`net::pppoe`, `wan.mode = "pppoe"`); once up, ICMP echo to the
//!   gateway (boot self-test).
//! - LAN: DHCP server and DNS forwarder (`net::services`).
//! - Management web interface (`net::mgmt`).
//!
//! Frames reach smoltcp from the datapath through each port's `local_rx`
//! (`net::shared`, `svc_kick` wakes this task); smoltcp's frames go
//! straight into the port's qdisc, then `dp_kick` wakes the datapath. WAN
//! lease changes and reboot/upgrade requests go to the datapath as
//! `net::shared::Control` messages.

use crate::cli::{Cli, CliAction, Ctx};
use crate::net::datapath;
use crate::net::device::PortDevice;
use crate::net::mgmt::{Mgmt, StoreOp};
use crate::net::pppoe::Pppoe;
use crate::net::services::LanServices;
use proto_dhcp::v4::persist;
use crate::net::shared::{Shared, WanChange};
use crate::net::stack::{self, WaitAny};
use crate::{println, timer};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{dhcpv4, icmp};
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address};

/// Set once the WAN has an address: a DHCP lease or a PPPoE link (read by
/// the boot self-test).
pub static DHCP_OK: AtomicBool = AtomicBool::new(false);
/// Set once the gateway answered a ping.
pub static PING_OK: AtomicBool = AtomicBool::new(false);

const PING_IDENT: u16 = 0x22b;
const PING_COUNT: u16 = 3;
const PING_INTERVAL: Duration = Duration::from_millis(200);

/// The services' half of a port: the router stack's interface and sockets.
pub struct HostIf {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    /// IPv6 neighbors recently made known to smoltcp (`net::device`).
    pub nd: crate::net::device::NdHints,
}

struct Pinger {
    socket: SocketHandle,
    target: Option<Ipv4Address>,
    seq: u16,
    sent_at: [Option<timer::Instant>; PING_COUNT as usize],
    next_send: timer::Instant,
    replies: u16,
}

impl Pinger {
    fn new(sockets: &mut SocketSet<'static>) -> Self {
        let rx = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]);
        let tx = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 512]);
        let mut sock = icmp::Socket::new(rx, tx);
        sock.bind(icmp::Endpoint::Ident(PING_IDENT))
            .expect("icmp bind");
        Self {
            socket: sockets.add(sock),
            target: None,
            seq: 0,
            sent_at: [None; PING_COUNT as usize],
            next_send: timer::Instant::now(),
            replies: 0,
        }
    }

    /// A new WAN gateway (`None` = none): ping it again from seq 0, so
    /// every WAN (re)start shows whether the gateway answers.
    fn retarget(&mut self, target: Option<Ipv4Address>) {
        if target != self.target {
            self.target = target;
            self.seq = 0;
            self.sent_at = [None; PING_COUNT as usize];
            self.next_send = timer::Instant::now();
        }
    }

    fn step(&mut self, sockets: &mut SocketSet<'static>) {
        let Some(target) = self.target else { return };
        let sock = sockets.get_mut::<icmp::Socket>(self.socket);
        let caps = ChecksumCapabilities::default();

        if self.seq < PING_COUNT && sock.can_send() && timer::Instant::now() >= self.next_send {
            let repr = Icmpv4Repr::EchoRequest {
                ident: PING_IDENT,
                seq_no: self.seq,
                data: b"leatos",
            };
            if let Ok(buf) = sock.send(repr.buffer_len(), IpAddress::Ipv4(target)) {
                repr.emit(&mut Icmpv4Packet::new_unchecked(buf), &caps);
                self.sent_at[self.seq as usize] = Some(timer::Instant::now());
                self.seq += 1;
                self.next_send = timer::Instant::now().checked_add(PING_INTERVAL).unwrap();
            }
        }

        while let Ok((payload, from)) = sock.recv() {
            let Ok(pkt) = Icmpv4Packet::new_checked(payload) else {
                continue;
            };
            if let Ok(Icmpv4Repr::EchoReply {
                ident: PING_IDENT,
                seq_no,
                ..
            }) = Icmpv4Repr::parse(&pkt, &caps)
                && let Some(Some(t0)) = self.sent_at.get(seq_no as usize)
            {
                println!(
                    "  net ping        : {from} seq={seq_no} rtt={} us",
                    t0.elapsed().as_micros()
                );
                self.replies += 1;
                PING_OK.store(true, Ordering::Release);
            }
        }
    }

    fn deadline(&self) -> Option<timer::Instant> {
        (self.target.is_some() && self.seq < PING_COUNT).then_some(self.next_send)
    }
}

/// A WAN lease change: (address/prefix, gateway, DNS servers); `None` fields = lost.
pub struct LeaseChange {
    pub addr: Option<(Ipv4Address, u8)>,
    pub gateway: Option<Ipv4Address>,
    pub dns: Vec<Ipv4Address>,
    /// Largest IP packet on the WAN.
    pub mtu: u16,
    /// How the address came (PPPoE session) for the status output; `None` = DHCP.
    pub via: Option<String>,
}

impl LeaseChange {
    pub fn lost() -> Self {
        LeaseChange {
            addr: None,
            gateway: None,
            dns: Vec::new(),
            mtu: fwd::forwarder::DEFAULT_MTU,
            via: None,
        }
    }
}

fn handle_dhcp(name: &str, host: &mut HostIf, pinger: &mut Pinger) -> Option<LeaseChange> {
    let (handle, _) = host
        .sockets
        .iter()
        .find(|(_, s)| matches!(s, smoltcp::socket::Socket::Dhcpv4(_)))?;
    let event = host.sockets.get_mut::<dhcpv4::Socket>(handle).poll();
    match event {
        Some(dhcpv4::Event::Configured(cfg)) => {
            host.iface.update_ip_addrs(|a| {
                a.retain(|c| !matches!(c, IpCidr::Ipv4(_))); // IPv6 stays
                a.push(IpCidr::Ipv4(cfg.address)).expect("wan addr");
            });
            match cfg.router {
                Some(gw) => {
                    host.iface
                        .routes_mut()
                        .add_default_ipv4_route(gw)
                        .expect("route");
                }
                None => {
                    host.iface.routes_mut().remove_default_ipv4_route();
                }
            }
            let dns: Vec<_> = cfg
                .dns_servers
                .iter()
                .map(|d| alloc::format!("{d}"))
                .collect();
            println!(
                "  net {}         : dhcp lease {} gw {} dns [{}]",
                name,
                cfg.address,
                cfg.router
                    .map(|r| alloc::format!("{r}"))
                    .unwrap_or_else(|| "-".into()),
                dns.join(", ")
            );
            warn_overlap(cfg.address);
            DHCP_OK.store(true, Ordering::Release);
            pinger.retarget(cfg.router);
            Some(LeaseChange {
                addr: Some((cfg.address.address(), cfg.address.prefix_len())),
                gateway: cfg.router,
                dns: cfg.dns_servers.iter().copied().collect(),
                mtu: fwd::forwarder::DEFAULT_MTU,
                via: None,
            })
        }
        Some(dhcpv4::Event::Deconfigured) => {
            if DHCP_OK.load(Ordering::Acquire) {
                println!("  net {}         : dhcp lease lost", name);
            }
            host.iface.update_ip_addrs(|a| a.retain(|c| !matches!(c, IpCidr::Ipv4(_))));
            host.iface.routes_mut().remove_default_ipv4_route();
            DHCP_OK.store(false, Ordering::Release);
            pinger.retarget(None);
            Some(LeaseChange::lost())
        }
        None => None,
    }
}

/// A WAN address inside one of the networks breaks forwarding between them.
fn warn_overlap(wan: smoltcp::wire::Ipv4Cidr) {
    for n in crate::config::networks() {
        let lan = smoltcp::wire::Ipv4Cidr::new(n.addr, n.prefix);
        let shorter = wan.prefix_len().min(lan.prefix_len());
        let net = |a: Ipv4Address| {
            u32::from(a) & (u32::MAX.checked_shl(32 - shorter as u32).unwrap_or(0))
        };
        if net(wan.address()) == net(lan.address()) {
            println!(
                "  net WARNING     : WAN {} overlaps network {} {lan}: forwarding between them breaks; boot with e.g. lan=10.10.0.1/24",
                wan, n.name
            );
        }
    }
}

/// A static WAN (`wan.mode = "static"`): the address and default route on
/// the router-stack interface, reported like a lease that never expires.
fn configure_static(
    name: &str,
    host: &mut HostIf,
    pinger: &mut Pinger,
    s: &crate::config::WanStatic,
) -> LeaseChange {
    let cidr = smoltcp::wire::Ipv4Cidr::new(s.addr, s.prefix);
    host.iface.update_ip_addrs(|a| {
        a.retain(|c| !matches!(c, IpCidr::Ipv4(_))); // IPv6 stays
        a.push(IpCidr::Ipv4(cidr)).expect("wan addr");
    });
    host.iface
        .routes_mut()
        .add_default_ipv4_route(s.gateway)
        .expect("route");
    let dns: Vec<_> = s.dns.iter().map(|d| alloc::format!("{d}")).collect();
    println!(
        "  net {}         : static {} gw {} dns [{}]",
        name,
        cidr,
        s.gateway,
        dns.join(", ")
    );
    warn_overlap(cidr);
    DHCP_OK.store(true, Ordering::Release);
    pinger.retarget(Some(s.gateway));
    LeaseChange {
        addr: Some((s.addr, s.prefix)),
        gateway: Some(s.gateway),
        dns: s.dns.clone(),
        mtu: fwd::forwarder::DEFAULT_MTU,
        via: Some(String::from("static")),
    }
}

fn lease_json(c: &LeaseChange) -> alloc::string::String {
    use proto_http::json_str;
    let Some((addr, prefix)) = c.addr else {
        return "null".into();
    };
    let dns: Vec<_> = c
        .dns
        .iter()
        .map(|d| json_str(&alloc::format!("{d}")))
        .collect();
    alloc::format!(
        "{{\"addr\":{},\"gateway\":{},\"dns\":[{}],\"mtu\":{},\"via\":{}}}",
        json_str(&alloc::format!("{addr}/{prefix}")),
        c.gateway
            .map(|g| json_str(&alloc::format!("{g}")))
            .unwrap_or_else(|| "null".into()),
        dns.join(","),
        c.mtu,
        c.via.as_deref().map(json_str).unwrap_or_else(|| "null".into())
    )
}

fn lease_text(c: &LeaseChange) -> String {
    let Some((addr, prefix)) = c.addr else {
        return String::from("no lease");
    };
    let dns: Vec<_> = c.dns.iter().map(|d| alloc::format!("{d}")).collect();
    alloc::format!(
        "{addr}/{prefix}, gateway {}, dns {}{}",
        c.gateway.map(|g| alloc::format!("{g}")).unwrap_or_else(|| "-".into()),
        if dns.is_empty() { String::from("-") } else { dns.join(", ") },
        c.via
            .as_deref()
            .map(|v| alloc::format!(", {v}, mtu {}", c.mtu))
            .unwrap_or_default()
    )
}

fn dhcp_socket(host: &HostIf) -> Option<SocketHandle> {
    host.sockets
        .iter()
        .find(|(_, s)| matches!(s, smoltcp::socket::Socket::Dhcpv4(_)))
        .map(|(h, _)| h)
}

/// Restart the WAN on new link settings: end a PPPoE session, switch the
/// port and its router-stack interface between Ethernet (DHCP, static)
/// and PPPoE (IP only), and start what `new` needs: the DHCP client, the
/// PPPoE client, or the static address (returned as the new lease).
/// Otherwise returns the lost address, except when DHCP stays: then the
/// DHCP client's `Deconfigured` event reports it.
fn restart_wan(
    sh: &Shared,
    wan: &mut HostIf,
    pppoe: &mut Option<Pppoe>,
    pinger: &mut Pinger,
    new: crate::config::WanLink,
) -> Option<LeaseChange> {
    use crate::config::WanLink;
    let port = &sh.ports[0];
    if let Some(mut p) = pppoe.take()
        && p.stop(port, wan)
    {
        sh.tx_kick[0].signal();
    }
    let dhcp = new == WanLink::Dhcp;
    if dhcp && !port.is_pppoe()
        && let Some(h) = dhcp_socket(wan)
    {
        // The lease belongs to the old link: ask again on the new one.
        wan.sockets.get_mut::<dhcpv4::Socket>(h).reset();
        return None;
    }
    let want_pppoe = matches!(new, WanLink::Pppoe(_));
    if port.is_pppoe() != want_pppoe {
        port.pppoe_mode.store(want_pppoe, Ordering::Relaxed);
        let mtu = match &new {
            WanLink::Pppoe(c) => c.mtu,
            _ => fwd::forwarder::DEFAULT_MTU,
        };
        port.mtu.store(u32::from(mtu), Ordering::Relaxed);
        // Another medium: a new interface (the sockets stay).
        wan.iface = stack::new_iface(port);
    }
    // The DHCP client runs only in DHCP mode.
    match (dhcp, dhcp_socket(wan)) {
        (false, Some(h)) => {
            wan.sockets.remove(h);
        }
        (true, None) => {
            wan.sockets.add(dhcpv4::Socket::new());
        }
        _ => {}
    }
    wan.iface.update_ip_addrs(|a| a.retain(|c| !matches!(c, IpCidr::Ipv4(_))));
    wan.iface.routes_mut().remove_default_ipv4_route();
    DHCP_OK.store(false, Ordering::Release);
    pinger.retarget(None);
    match new {
        WanLink::Pppoe(c) => *pppoe = Some(Pppoe::new(c, port)),
        WanLink::Dhcp => println!("  net {}       : DHCP", port.name),
        WanLink::Static(s) => return Some(configure_static(port.name, wan, pinger, &s)),
    }
    Some(LeaseChange::lost())
}

/// A saved config becomes the running one (no trial): shaping, DHCP,
/// PPPoE and DNS are reconfigured in place. Returns the WAN change when
/// the WAN link was restarted.
fn apply_saved(
    (cfg, source): (crate::config::schema::Config, String),
    sh: &Shared,
    hosts: &mut [HostIf],
    (pppoe, pinger): (&mut Option<Pppoe>, &mut Pinger),
    services: Option<&mut LanServices>,
    mgmt: &mut Mgmt,
    slots: &mut Vec<Option<String>>,
) -> Option<LeaseChange> {
    let old = crate::config::qos();
    let old_tag = crate::config::wan_tci();
    let old_link = crate::config::wan_link();
    let old_nets = crate::config::networks();
    crate::config::apply(cfg, source);
    let tag = crate::config::wan_tci();
    let new_link = crate::config::wan_link();
    let mut change = None;
    if let Some(port) = sh.ports.first()
        && (tag != old_tag || new_link != old_link)
    {
        port.set_vlan(tag);
        println!(
            "  net {}       : now {}, restarting {}",
            port.name,
            tag.map_or(String::from("untagged"), stack::vlan_text),
            new_link.name()
        );
        change = restart_wan(sh, &mut hosts[0], pppoe, pinger, new_link);
    }
    // Also picks up the WAN tag's 4 bytes and PPPoE's 8 of shaper overhead.
    stack::apply_qos(sh, &old, &crate::config::qos());
    reapply_networks(sh, hosts, services, mgmt, slots, Some(&old_nets));
    change
}

/// What prefix delegation depends on: the WAN's mode and `[ipv6]`.
fn wan6_key() -> (crate::config::WanLink, crate::config::schema::Ipv6) {
    (crate::config::wan_link(), crate::config::get_ipv6())
}

/// After a saved config: restart prefix delegation if what it depends on
/// changed (a new WAN mode, IPv6 or PD switched). True when it did (the
/// networks follow: the old prefix is gone).
fn wan6_follow(
    w: &mut Option<crate::net::wan6::Wan6>,
    before: &(crate::config::WanLink, crate::config::schema::Ipv6),
    wan: &mut HostIf,
    sh: &Shared,
) -> bool {
    if wan6_key() == *before {
        return false;
    }
    if let Some(old) = w.take() {
        old.stop(wan);
    }
    *w = crate::net::wan6::Wan6::new(wan, sh, now_ms());
    true
}

/// Milliseconds since boot (the WAN's IPv6 timers).
fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

/// Networks and firewall, live (docs/config-v2.md §7): a network keeps its
/// slot while its name stays; addresses for the router stack, the rest for
/// the datapath; the services follow. After a saved config (`old`: the
/// networks before, for the log) or a new WAN prefix (`net::wan6`).
fn reapply_networks(
    sh: &Shared,
    hosts: &mut [HostIf],
    services: Option<&mut LanServices>,
    mgmt: &mut Mgmt,
    slots: &mut Vec<Option<String>>,
    old: Option<&[crate::config::Lan]>,
) {
    if sh.links.len() > 1 {
        let (placed, links, msg) = stack::place_networks(slots);
        *slots = placed;
        let nets = crate::config::networks();
        stack::set_host_addrs(hosts, &nets, &links, &stack::port_macs(&sh.ports));
        let shape = |v: &[crate::config::Lan]| -> Vec<(String, usize, u16, core::net::Ipv4Addr, u8, u8)> {
            v.iter().map(|n| (n.name.clone(), n.port, n.vid, n.addr, n.prefix, n.zone)).collect()
        };
        if old.is_some_and(|o| shape(o) != shape(&nets)) {
            stack::log_networks(&nets);
        }
        sh.post_networks(msg);
        if let Some(svc) = services {
            svc.reconfigure(hosts, &links);
        }
        mgmt.add_sockets(hosts, &links);
    } else if let Some(svc) = services {
        svc.reconfigure(hosts, &[]);
    }
}

/// Tell everyone who depends on the WAN address about a change.
fn publish_wan(
    change: &LeaseChange,
    sh: &Shared,
    mgmt: &mut Mgmt,
    cli: &mut Cli,
    services: Option<&mut LanServices>,
) {
    sh.post_wan(WanChange {
        addr: change.addr,
        gateway: change.gateway,
        mtu: change.mtu,
    });
    mgmt.set_wan_lease(lease_json(change));
    cli.set_wan(lease_text(change));
    if let Some(svc) = services {
        svc.set_upstreams(&change.dns);
        svc.set_wan_up(change.addr.is_some());
    }
}

/// Poll every router-stack interface (one per link); wake the TX task of
/// each port that got frames in its qdisc.
fn poll_stacks(hosts: &mut [HostIf], sh: &Shared) {
    let t = stack::now();
    let now_ns = datapath::now_ns();
    for (host, link) in hosts.iter_mut().zip(&sh.links) {
        let i = link.port();
        let port = &sh.ports[i];
        let mut queued = 0;
        let mut dev = PortDevice {
            link,
            port,
            now_ns,
            queued: &mut queued,
            nd: Some(&mut host.nd),
        };
        host.iface.poll(t, &mut dev, &mut host.sockets);
        if queued > 0 {
            sh.tx_kick[i].signal();
        }
    }
}

/// Carry out a management request on the store (`config` area, or
/// `images` for a kernel). Returns
/// a detail for the answer and, for a save, where the config now comes
/// from (`config::source`).
async fn store_op(
    st: &mut crate::store::Store,
    op: &StoreOp,
) -> Result<(String, Option<String>), String> {
    use crate::config::schema;
    let e = |e: crate::store::Error| alloc::format!("{e}");
    match op {
        StoreOp::Save { toml, flags, .. } => {
            // The header names the schema version: an older kernel skips a
            // newer record and keeps the one before it.
            let (slot, h) = st
                .write_record(
                    "config",
                    schema::VERSION,
                    schema::VERSION,
                    toml.as_bytes(),
                    *flags,
                )
                .await
                .map_err(e)?;
            let slot = crate::store::slot_name(slot);
            Ok((
                alloc::format!("slot {slot}, seq {}, {} bytes", h.seq, h.len),
                Some(alloc::format!("stored (slot {slot}, seq {})", h.seq)),
            ))
        }
        StoreOp::SaveImage(image) => {
            use crate::upgrade::{AREA, IMAGE_FORMAT};
            let (slot, h) = st
                .write_record(AREA, IMAGE_FORMAT, IMAGE_FORMAT, image, config_store::FLAG_TRIAL)
                .await
                .map_err(e)?;
            Ok((
                alloc::format!(
                    "slot {}, seq {}, {} bytes",
                    crate::store::slot_name(slot),
                    h.seq,
                    h.len
                ),
                None,
            ))
        }
        StoreOp::Confirm(area, slot, h) => st
            .rewrite_header(area, *slot, *h)
            .await
            .map(|()| (String::from("confirmed"), None))
            .map_err(e),
        StoreOp::Revert(area, slot) => st
            .erase(area, *slot)
            .await
            .map(|()| (String::from("erased"), None))
            .map_err(e),
    }
}

/// How often the bound DHCP leases are compared with the stored ones.
const LEASE_CHECK: Duration = Duration::from_secs(60);
const LEASE_AREA: &str = "leases";

/// DHCP leases in the store's `leases` area (docs/config-and-storage.md,
/// format in `proto_dhcp::v4::persist`): read at boot, written when the
/// set of bound leases changed (checked every [`LEASE_CHECK`], so
/// renewals alone never write the SD card) and before a reboot or an
/// upgrade.
struct LeaseStore {
    /// Off without a store, without a `leases` area or without networks.
    enabled: bool,
    /// What the store holds (or, after a restore, what was kept of it).
    saved: Vec<persist::Network>,
    next_check: timer::Instant,
}

impl LeaseStore {
    async fn load(st: Option<&mut crate::store::Store>, svc: Option<&mut LanServices>) -> Self {
        let mut me = LeaseStore {
            enabled: false,
            saved: Vec::new(),
            next_check: timer::Instant::now().checked_add(LEASE_CHECK).unwrap_or(timer::Instant::now()),
        };
        let (Some(st), Some(svc)) = (st, svc) else {
            return me;
        };
        match st.read_current(LEASE_AREA, persist::FORMAT).await {
            Err(e) => {
                println!("  leases          : not kept ({e})");
                return me;
            }
            Ok((None, _)) => println!("  leases          : none stored"),
            Ok((Some(rec), _)) => match persist::decode(&rec.payload) {
                Ok(nets) => {
                    let (kept, saved) = svc.restore_leases(&nets);
                    println!(
                        "  leases          : restored {kept} of {saved} (slot {}, seq {})",
                        crate::store::slot_name(rec.slot),
                        rec.header.seq
                    );
                }
                Err(e) => println!("  leases          : stored record unreadable ({e}), starting empty"),
            },
        }
        me.enabled = true;
        me.saved = svc.lease_snapshot();
        me
    }

    fn wake_at(&self) -> Option<timer::Instant> {
        self.enabled.then_some(self.next_check)
    }

    fn due(&self) -> bool {
        self.enabled && timer::Instant::now() >= self.next_check
    }

    /// Write the bound leases if they differ from the stored ones.
    async fn save(&mut self, st: Option<&mut crate::store::Store>, svc: Option<&LanServices>) {
        self.next_check = timer::Instant::now().checked_add(LEASE_CHECK).unwrap_or(timer::Instant::now());
        let (true, Some(st), Some(svc)) = (self.enabled, st, svc) else {
            return;
        };
        let snap = svc.lease_snapshot();
        if snap == self.saved {
            return;
        }
        let data = persist::encode(&snap);
        match st.write_record(LEASE_AREA, persist::FORMAT, persist::FORMAT, &data, 0).await {
            Ok((slot, h)) => {
                println!(
                    "  leases          : saved {} (slot {}, seq {}, {} bytes)",
                    snap.iter().map(|n| n.leases.len()).sum::<usize>(),
                    crate::store::slot_name(slot),
                    h.seq,
                    h.len
                );
                self.saved = snap;
            }
            // Tried again at the next check.
            Err(e) => println!("  leases          : save failed: {e}"),
        }
    }
}

/// The services task: never returns.
pub async fn run(
    mut hosts: Vec<HostIf>,
    sh: &'static Shared,
    mut store: Option<crate::store::Store>,
) {
    let mut pinger = Pinger::new(&mut hosts[0].sockets);
    // Network slots as bring_up placed them (`stack::place_networks`).
    let (mut slots, links, _) = stack::place_networks(&[]);
    let links = if sh.links.len() > 1 { links } else { Vec::new() };
    let mut services = LanServices::new(&mut hosts, &links);
    let mut leases = LeaseStore::load(store.as_mut(), services.as_mut()).await;
    let mut mgmt = Mgmt::new(&mut hosts, &links, store.is_some());
    let mut cli = Cli::new(store.is_some());
    let mut pppoe = crate::config::pppoe().map(|c| Pppoe::new(c, &sh.ports[0]));
    // The WAN's IPv6 by prefix delegation (docs/ipv6.md step 3).
    let mut wan6 = crate::net::wan6::Wan6::new(&mut hosts[0], sh, now_ms());
    // PPPoE: IPv6CP's state the loop last acted on (step 4).
    let mut ppp6 = crate::net::wan6::ppp_link();
    if let crate::config::WanLink::Static(s) = crate::config::wan_link() {
        let c = configure_static(sh.ports[0].name, &mut hosts[0], &mut pinger, &s);
        publish_wan(&c, sh, &mut mgmt, &mut cli, services.as_mut());
    }
    // Serial input wakes the task too (the CLI).
    let rx = crate::console::rx_event();
    let events: Vec<&'static crate::irq::IrqEvent> =
        [Some(sh.svc_kick), rx].into_iter().flatten().collect();

    loop {
        sh.svc_kick.take();
        if let Some(rx) = rx {
            rx.take();
        }
        poll_stacks(&mut hosts, sh);
        let change = match pppoe.as_mut() {
            Some(p) => {
                let (change, queued) = p.step(&sh.ports[0], &mut hosts[0]);
                if queued {
                    sh.tx_kick[0].signal();
                }
                if let Some(c) = &change {
                    DHCP_OK.store(c.addr.is_some(), Ordering::Release);
                    pinger.retarget(c.gateway);
                }
                if p.status_changed() || change.is_some() {
                    mgmt.set_wan_pppoe(Some(p.status_json()));
                    if change.is_none() && !DHCP_OK.load(Ordering::Acquire) {
                        cli.set_wan(p.status_text());
                    }
                }
                change
            }
            None => {
                mgmt.set_wan_pppoe(None);
                handle_dhcp(sh.ports[0].name, &mut hosts[0], &mut pinger)
            }
        };
        if let Some(change) = change {
            publish_wan(&change, sh, &mut mgmt, &mut cli, services.as_mut());
        }
        let now6 = crate::net::wan6::ppp_link();
        if now6 != ppp6 {
            // IPv6CP came or went: prefix delegation over the session
            // starts or stops, the WAN's addresses and route follow.
            ppp6 = now6;
            if let Some(old) = wan6.take() {
                old.stop(&mut hosts[0]);
            }
            wan6 = crate::net::wan6::Wan6::new(&mut hosts[0], sh, now_ms());
            reapply_networks(sh, &mut hosts, services.as_mut(), &mut mgmt, &mut slots, None);
        }
        pinger.step(&mut hosts[0].sockets);
        if let Some(w) = wan6.as_mut()
            && w.step(&mut hosts[0], sh, now_ms())
        {
            // A router or prefix came, changed or went: the networks follow.
            reapply_networks(sh, &mut hosts, services.as_mut(), &mut mgmt, &mut slots, None);
        }
        if let Some(svc) = services.as_mut() {
            svc.step(&mut hosts, sh);
        }
        let action = mgmt.step(&mut hosts, sh, services.as_ref());
        if let Some((conn, op)) = mgmt.take_op()
            && let Some(st) = store.as_mut()
        {
            // Yields while the disk works: the datapath keeps running.
            let r = store_op(st, &op).await;
            if let (
                Ok((_, Some(source))),
                StoreOp::Save {
                    flags: 0,
                    reboot: false,
                    cfg,
                    ..
                },
            ) = (&r, &op)
            {
                // Saved without a trial: run it now, no reboot.
                let cfg = (**cfg).clone();
                let svc = services.as_mut();
                let wan6_before = wan6_key();
                if let Some(c) = apply_saved((cfg, source.clone()), sh, &mut hosts, (&mut pppoe, &mut pinger), svc, &mut mgmt, &mut slots) {
                    publish_wan(&c, sh, &mut mgmt, &mut cli, services.as_mut());
                }
                if wan6_follow(&mut wan6, &wan6_before, &mut hosts[0], sh) {
                    reapply_networks(sh, &mut hosts, services.as_mut(), &mut mgmt, &mut slots, None);
                }
            }
            mgmt.op_done(conn, &op, r.map(|(detail, _)| detail));
        }
        if leases.due() {
            leases.save(store.as_mut(), services.as_ref()).await;
        }
        let cli_action = cli.step(&Ctx {
            hosts: &hosts,
            sh,
            services: services.as_ref(),
        });
        let mut action = action;
        match cli_action {
            Some(CliAction::Reboot) => action = Some(crate::net::mgmt::Action::Reboot),
            Some(CliAction::Save(_)) if mgmt.image_trial_pending() => cli.save_done(
                Err(String::from(
                    "a trial kernel is running: confirm it first (POST /api/upgrade/confirm)",
                )),
                false,
            ),
            Some(CliAction::Save(cfg)) => match store.as_mut() {
                Some(st) => {
                    let mut cfg = cfg;
                    // A new password in clear is stored as a hash only.
                    crate::entropy::with(|p| cfg.hash_new_password(p));
                    let base = crate::config::base();
                    let reboot = cfg.needs_trial(&base) || cfg.needs_reboot(&base);
                    let op = StoreOp::Save {
                        toml: cfg.to_toml(),
                        flags: 0,
                        reboot,
                        cfg,
                    };
                    let r = store_op(st, &op).await;
                    match (r, op) {
                        (Ok((detail, source)), StoreOp::Save { cfg, .. }) => {
                            println!("  cli             : config saved ({detail})");
                            if reboot {
                                action = Some(crate::net::mgmt::Action::Reboot);
                            } else if let Some(source) = source {
                                let svc = services.as_mut();
                                let wan6_before = wan6_key();
                                if let Some(c) = apply_saved((*cfg, source), sh, &mut hosts, (&mut pppoe, &mut pinger), svc, &mut mgmt, &mut slots) {
                                    publish_wan(&c, sh, &mut mgmt, &mut cli, services.as_mut());
                                }
                                if wan6_follow(&mut wan6, &wan6_before, &mut hosts[0], sh) {
                                    reapply_networks(sh, &mut hosts, services.as_mut(), &mut mgmt, &mut slots, None);
                                }
                            }
                            cli.save_done(Ok(detail), reboot);
                        }
                        (Err(e), _) => cli.save_done(Err(e), false),
                        (Ok(_), _) => unreachable!("a save stays a save"),
                    }
                }
                None => cli.save_done(Err(String::from("no store")), false),
            },
            None => {}
        }
        if let Some(action) = action {
            // Leases first, so the next boot (or kernel) gets them back.
            leases.save(store.as_mut(), services.as_ref()).await;
            // The datapath stops the NICs and acts; nothing left to do here.
            sh.post_action(action);
            loop {
                timer::sleep(Duration::from_secs(3600)).await;
            }
        }
        poll_stacks(&mut hosts, sh);

        // More frames arrived while we worked: go round again, after
        // letting the datapath run.
        if cli.more() || sh.links.iter().any(|l| !l.local_rx.lock().is_empty()) {
            crate::executor::yield_now().await;
            continue;
        }
        let t = stack::now();
        let mut delay = hosts
            .iter_mut()
            .filter_map(|h| h.iface.poll_delay(t, &h.sockets))
            .map(|d| Duration::from_micros(d.total_micros()))
            .min()
            .unwrap_or(Duration::from_secs(1));
        if let Some(svc) = &services {
            delay = delay.min(
                svc.next_deadline()
                    .saturating_duration_since(timer::Instant::now()),
            );
        }
        if let Some(at) = leases.wake_at() {
            delay = delay.min(at.saturating_duration_since(timer::Instant::now()));
        }
        if let Some(at) = pinger.deadline() {
            delay = delay.min(at.saturating_duration_since(timer::Instant::now()));
        }
        if let Some(w) = &wan6 {
            delay = delay.min(Duration::from_millis(w.next_deadline().saturating_sub(now_ms())));
        }
        if let Some(at) = pppoe.as_ref().and_then(Pppoe::wake_at) {
            delay = delay.min(at.saturating_duration_since(timer::Instant::now()));
        }
        delay = delay.min(cli.wake_at().saturating_duration_since(timer::Instant::now()));
        if let Some(at) = mgmt.wake_at() {
            delay = delay.min(at.saturating_duration_since(timer::Instant::now()));
        }
        if mgmt.busy() {
            delay = delay.min(Duration::from_millis(10));
        }
        WaitAny {
            events: &events,
            sleep: timer::sleep(delay),
        }
        .await;
    }
}
