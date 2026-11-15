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

    fn step(&mut self, sockets: &mut SocketSet<'static>) {
        let Some(target) = self.target else { return };
        let sock = sockets.get_mut::<icmp::Socket>(self.socket);
        let caps = ChecksumCapabilities::default();

        if self.seq < PING_COUNT && sock.can_send() && timer::Instant::now() >= self.next_send {
            let repr = Icmpv4Repr::EchoRequest {
                ident: PING_IDENT,
                seq_no: self.seq,
                data: b"rrouter",
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
                a.clear();
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
            for n in crate::config::networks() {
                let lan = smoltcp::wire::Ipv4Cidr::new(n.addr, n.prefix);
                let shorter = cfg.address.prefix_len().min(lan.prefix_len());
                let net = |a: Ipv4Address| {
                    u32::from(a) & (u32::MAX.checked_shl(32 - shorter as u32).unwrap_or(0))
                };
                if net(cfg.address.address()) == net(lan.address()) {
                    println!(
                        "  net WARNING     : WAN {} overlaps network {} {lan}: forwarding between them breaks; boot with e.g. lan=10.10.0.1/24",
                        cfg.address, n.name
                    );
                }
            }
            DHCP_OK.store(true, Ordering::Release);
            pinger.target = cfg.router;
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
            host.iface.update_ip_addrs(|a| a.clear());
            host.iface.routes_mut().remove_default_ipv4_route();
            DHCP_OK.store(false, Ordering::Release);
            pinger.target = None;
            Some(LeaseChange::lost())
        }
        None => None,
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
/// port and its router-stack interface between DHCP (Ethernet) and PPPoE
/// (IP only), and start the client for `new` (`None` = DHCP). Returns the
/// lost address, except when DHCP stays: then the DHCP client's
/// `Deconfigured` event reports it.
fn restart_wan(
    sh: &Shared,
    wan: &mut HostIf,
    pppoe: &mut Option<Pppoe>,
    new: Option<proto_pppoe::Config>,
) -> Option<LeaseChange> {
    let port = &sh.ports[0];
    if let Some(mut p) = pppoe.take()
        && p.stop(port, wan)
    {
        sh.tx_kick[0].signal();
    }
    let want = new.is_some();
    if !want && !port.is_pppoe() {
        // The lease belongs to the old link: ask again on the new one.
        if let Some(h) = dhcp_socket(wan) {
            wan.sockets.get_mut::<dhcpv4::Socket>(h).reset();
        }
        return None;
    }
    if port.is_pppoe() != want {
        port.pppoe_mode.store(want, Ordering::Relaxed);
        let mtu = new.as_ref().map_or(fwd::forwarder::DEFAULT_MTU, |c| c.mtu);
        port.mtu.store(u32::from(mtu), Ordering::Relaxed);
        // Another medium: a new interface (the sockets stay).
        wan.iface = stack::new_iface(port);
        match (want, dhcp_socket(wan)) {
            (true, Some(h)) => {
                wan.sockets.remove(h);
            }
            (false, None) => {
                wan.sockets.add(dhcpv4::Socket::new());
            }
            _ => {}
        }
    }
    wan.iface.update_ip_addrs(|a| a.clear());
    wan.iface.routes_mut().remove_default_ipv4_route();
    DHCP_OK.store(false, Ordering::Release);
    *pppoe = new.map(|c| Pppoe::new(c, port));
    if pppoe.is_none() {
        println!("  net {}       : DHCP", port.name);
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
    pppoe: &mut Option<Pppoe>,
    services: Option<&mut LanServices>,
    mgmt: &mut Mgmt,
    slots: &mut Vec<Option<String>>,
) -> Option<LeaseChange> {
    let old = crate::config::qos();
    let old_tag = crate::config::wan_tci();
    let old_pppoe = crate::config::pppoe();
    let old_nets = crate::config::networks();
    crate::config::apply(cfg, source);
    let tag = crate::config::wan_tci();
    let new_pppoe = crate::config::pppoe();
    let mut change = None;
    if let Some(port) = sh.ports.first()
        && (tag != old_tag || new_pppoe != old_pppoe)
    {
        port.set_vlan(tag);
        println!(
            "  net {}       : now {}, restarting {}",
            port.name,
            tag.map_or(String::from("untagged"), stack::vlan_text),
            if new_pppoe.is_some() { "PPPoE" } else { "DHCP" }
        );
        change = restart_wan(sh, &mut hosts[0], pppoe, new_pppoe);
    }
    // Also picks up the WAN tag's 4 bytes and PPPoE's 8 of shaper overhead.
    stack::apply_qos(sh, &old, &crate::config::qos());
    // Networks and firewall, live (docs/config-v2.md §7): a network keeps
    // its slot while its name stays; addresses for the router stack, the
    // rest for the datapath.
    if sh.links.len() > 1 {
        let (placed, links, msg) = stack::place_networks(slots);
        *slots = placed;
        let nets = crate::config::networks();
        stack::set_host_addrs(hosts, &nets, &links);
        let shape = |v: &[crate::config::Lan]| -> Vec<(String, u16, core::net::Ipv4Addr, u8, u8)> {
            v.iter().map(|n| (n.name.clone(), n.vid, n.addr, n.prefix, n.zone)).collect()
        };
        if shape(&old_nets) != shape(&nets) {
            stack::log_networks(sh.ports[1].name, &nets);
        }
        sh.post_networks(msg);
        if let Some(svc) = services {
            svc.reconfigure(hosts, &links);
        }
        mgmt.add_sockets(hosts, &links);
    } else if let Some(svc) = services {
        svc.reconfigure(hosts, &[]);
    }
    change
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
        let i = link.port;
        let port = &sh.ports[i];
        let mut queued = 0;
        let mut dev = PortDevice {
            link,
            port,
            now_ns,
            queued: &mut queued,
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
        StoreOp::Save { toml, flags, cfg, .. } => {
            // The header names the document's version (1 while the config
            // fits it): an older kernel skips a version 2 record and keeps
            // the one before it.
            let (slot, h) = st
                .write_record(
                    "config",
                    cfg.doc_version(),
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
    let mut mgmt = Mgmt::new(&mut hosts, &links, store.is_some());
    let mut cli = Cli::new(store.is_some());
    let mut pppoe = crate::config::pppoe().map(|c| Pppoe::new(c, &sh.ports[0]));
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
                    pinger.target = c.gateway;
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
        pinger.step(&mut hosts[0].sockets);
        if let Some(svc) = services.as_mut() {
            svc.step(&mut hosts, &sh.links);
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
                if let Some(c) = apply_saved((cfg, source.clone()), sh, &mut hosts, &mut pppoe, svc, &mut mgmt, &mut slots) {
                    publish_wan(&c, sh, &mut mgmt, &mut cli, services.as_mut());
                }
            }
            mgmt.op_done(conn, &op, r.map(|(detail, _)| detail));
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
                                if let Some(c) = apply_saved((*cfg, source), sh, &mut hosts, &mut pppoe, svc, &mut mgmt, &mut slots) {
                                    publish_wan(&c, sh, &mut mgmt, &mut cli, services.as_mut());
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
        if let Some(at) = pinger.deadline() {
            delay = delay.min(at.saturating_duration_since(timer::Instant::now()));
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
