//! The services task (`Priority::Service`): the router's own IP stack
//! (per link: its addresses and routes, `net::local` for UDP and ICMP, a
//! `proto_tcp::Tcp` for TCP; docs/own-tcp.md) and everything on top of it:
//!
//! - WAN: DHCPv4 client (`net::wan4`), or the PPPoE client
//!   (`net::pppoe`, `wan.mode = "pppoe"`); once up, ICMP echo to the
//!   gateway (boot self-test).
//! - LAN: DHCP server and DNS forwarder (`net::services`).
//! - Management web interface (`net::mgmt`).
//!
//! Frames reach the router stack from the datapath through each link's
//! `local_rx` (`net::shared`, `svc_kick` wakes this task); its frames go
//! through `Datapath::send_local` or, on PPPoE, into the port's qdisc,
//! then `dp_kick` wakes the datapath. WAN
//! lease changes and reboot/upgrade requests go to the datapath as
//! `net::shared::Control` messages.

use crate::cli::{Cli, CliAction, Ctx};
use crate::net::mgmt::{Mgmt, StoreOp};
use crate::net::pppoe::Pppoe;
use crate::net::services::LanServices;
use proto_dhcp::v4::persist;
use crate::net::shared::{Shared, WanChange};
use crate::net::stack::{self, WaitAny};
use crate::{println, timer};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use core::net::{IpAddr, Ipv4Addr as Ipv4Address, Ipv6Addr};

/// Set once the WAN has an address: a DHCP lease or a PPPoE link (read by
/// the boot self-test).
pub static DHCP_OK: AtomicBool = AtomicBool::new(false);
/// Set once the gateway answered a ping.
pub static PING_OK: AtomicBool = AtomicBool::new(false);

const PING_IDENT: u16 = 0x22b;
const PING_COUNT: u16 = 3;
const PING_INTERVAL: Duration = Duration::from_millis(200);

/// The services' half of a link: the router stack's addresses and routes
/// there, and its TCP.
pub struct HostIf {
    /// The link's addresses and routes (the WAN's from its lease, PPPoE
    /// or static config; a network's from `stack::local_links`): the
    /// datapath gets the same view (`stack::set_wan_local_link`,
    /// `set_local_links`).
    pub link: fwd::local::LocalLink,
    /// The router's TCP on this link (docs/own-tcp.md).
    pub tcp: proto_tcp::Tcp,
    /// The link's frames the services look at first (`net::device`).
    pub tap: crate::net::device::RxTap,
    /// The link's MAC (its port's).
    pub mac: [u8; 6],
    /// The datapath does the link's link layer (every LAN link, a DHCP or
    /// static WAN: `config::wan_ip_only`; set when made, =
    /// [`crate::net::shared::LinkShared::ip_only`]); else PPPoE.
    pub ip_only: bool,
}

impl HostIf {
    pub fn new(mac: [u8; 6], ip_only: bool, mtu: u16) -> Self {
        let mut secret = [0u8; 16];
        secret[..8].copy_from_slice(&crate::entropy::u64().to_le_bytes());
        secret[8..].copy_from_slice(&crate::entropy::u64().to_le_bytes());
        let mut tcp = proto_tcp::Tcp::new(secret);
        tcp.set_mtu(mtu);
        tcp.set_rst_closed(crate::config::tcp_rst());
        Self { link: Default::default(), tcp, tap: Default::default(), mac, ip_only }
    }

    /// The link's IPv4 address (IPv6 stays).
    pub fn set_addr4(&mut self, a: Option<(Ipv4Address, u8)>) {
        self.link.v4 = a;
    }

    /// The IPv4 default route (`None`: none).
    pub fn set_default4(&mut self, gw: Option<Ipv4Address>) {
        self.link.routes4.retain(|r| r.1 != 0);
        if let Some(gw) = gw {
            self.link.routes4.push((Ipv4Address::UNSPECIFIED, 0, gw));
        }
    }

    /// The IPv6 default route.
    pub fn set_default6(&mut self, gw: Option<Ipv6Addr>) {
        self.link.routes6.retain(|r| r.1 != 0);
        if let Some(gw) = gw {
            self.link.routes6.push((Ipv6Addr::UNSPECIFIED, 0, gw));
        }
    }

    /// The link's addresses, for status output (`10.0.0.1/24`, ...).
    pub fn addrs_text(&self) -> Vec<String> {
        let v4 = self.link.v4.map(|(a, l)| alloc::format!("{a}/{l}"));
        v4.into_iter().chain(self.link.v6.iter().map(|(a, l)| alloc::format!("{a}/{l}"))).collect()
    }

    /// One of the router's unicast addresses on this link.
    fn is_ours(&self, a: IpAddr) -> bool {
        match a {
            IpAddr::V4(a) => self.link.v4.is_some_and(|(x, _)| x == a),
            IpAddr::V6(a) => self.link.v6.iter().any(|&(x, _)| x == a),
        }
    }
}

/// The WAN gateway check: three echo requests (`net::local`) after each
/// new gateway; `PING_OK` once one is answered.
struct Pinger {
    target: Option<Ipv4Address>,
    seq: u16,
    sent_at: [Option<timer::Instant>; PING_COUNT as usize],
    next_send: timer::Instant,
    replies: u16,
}

impl Pinger {
    fn new() -> Self {
        crate::net::local::ping_bind(PING_IDENT);
        Self {
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

    fn step(&mut self, sh: &Shared) {
        use crate::net::{datapath::WAN, local};
        let Some(target) = self.target else { return };
        let dst = core::net::IpAddr::V4(target);
        if self.seq < PING_COUNT
            && timer::Instant::now() >= self.next_send
            && let Some(src) = local::source(WAN, dst)
            && local::send_echo(sh, WAN, src, dst, PING_IDENT, self.seq, b"leatos")
        {
            self.sent_at[self.seq as usize] = Some(timer::Instant::now());
            self.seq += 1;
            self.next_send = timer::Instant::now().checked_add(PING_INTERVAL).unwrap();
        }
        while let Some((from, seq_no)) = local::ping_recv(PING_IDENT) {
            if from != dst {
                continue;
            }
            if let Some(Some(t0)) = self.sent_at.get(seq_no as usize) {
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

/// The WAN's DHCP client (`net::wan4`): its events applied in order; the
/// last change (`None`: nothing happened).
fn handle_wan4(name: &str, host: &mut HostIf, pinger: &mut Pinger, events: Vec<proto_dhcp::v4::client::Event>) -> Option<LeaseChange> {
    use proto_dhcp::v4::client::Event;
    let mut change = None;
    for e in events {
        change = Some(match e {
            Event::Bound(l) => lease_bound(name, host, pinger, (l.address, l.prefix_len), l.router, l.dns),
            Event::Lost => lease_lost(name, host, pinger),
        });
    }
    change
}

/// A DHCP lease: the address and default route on the
/// router stack's WAN interface, logged, the gateway pinger aimed.
fn lease_bound(
    name: &str,
    host: &mut HostIf,
    pinger: &mut Pinger,
    address: (Ipv4Address, u8),
    router: Option<Ipv4Address>,
    dns_servers: Vec<Ipv4Address>,
) -> LeaseChange {
    host.set_addr4(Some(address));
    host.set_default4(router);
    let dns: Vec<_> = dns_servers.iter().map(|d| alloc::format!("{d}")).collect();
    println!(
        "  net {}         : dhcp lease {}/{} gw {} dns [{}]",
        name,
        address.0,
        address.1,
        router
            .map(|r| alloc::format!("{r}"))
            .unwrap_or_else(|| "-".into()),
        dns.join(", ")
    );
    warn_overlap(address);
    DHCP_OK.store(true, Ordering::Release);
    pinger.retarget(router);
    LeaseChange {
        addr: Some(address),
        gateway: router,
        dns: dns_servers,
        mtu: fwd::forwarder::DEFAULT_MTU,
        via: None,
    }
}

/// The DHCP lease is gone.
fn lease_lost(name: &str, host: &mut HostIf, pinger: &mut Pinger) -> LeaseChange {
    if DHCP_OK.load(Ordering::Acquire) {
        println!("  net {}         : dhcp lease lost", name);
    }
    host.set_addr4(None);
    host.set_default4(None);
    DHCP_OK.store(false, Ordering::Release);
    pinger.retarget(None);
    LeaseChange::lost()
}

/// A WAN address inside one of the networks breaks forwarding between them.
fn warn_overlap(wan: (Ipv4Address, u8)) {
    for n in crate::config::networks() {
        let shorter = wan.1.min(n.prefix);
        let net = |a: Ipv4Address| {
            u32::from(a) & (u32::MAX.checked_shl(32 - shorter as u32).unwrap_or(0))
        };
        if net(wan.0) == net(n.addr) {
            println!(
                "  net WARNING     : WAN {}/{} overlaps network {} {}/{}: forwarding between them breaks; boot with e.g. lan=10.10.0.1/24",
                wan.0, wan.1, n.name, n.addr, n.prefix
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
    let cidr = (s.addr, s.prefix);
    host.set_addr4(Some(cidr));
    host.set_default4(Some(s.gateway));
    let dns: Vec<_> = s.dns.iter().map(|d| alloc::format!("{d}")).collect();
    println!(
        "  net {}         : static {}/{} gw {} dns [{}]",
        name,
        cidr.0,
        cidr.1,
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

/// The WAN's clients a mode change starts and stops: PPPoE, the gateway
/// pinger, the DHCP client.
type WanClients<'a> = (&'a mut Option<Pppoe>, &'a mut Pinger, &'a mut Option<crate::net::wan4::Wan4>);

/// Restart the WAN on new link settings: end a PPPoE session, switch the
/// port and its router-stack interface between Ethernet (DHCP, static)
/// and PPPoE (IP only), and start what `new` needs: the DHCP client, the
/// PPPoE client, or the static address (returned as the new lease).
/// Otherwise returns the lost address, except when DHCP stays: then the
/// DHCP client's `Deconfigured` event reports it.
fn restart_wan(
    sh: &Shared,
    wan: &mut HostIf,
    (pppoe, pinger, wan4): WanClients<'_>,
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
    let ip_only = crate::config::wan_ip_only(&new);
    // The lease belongs to the old link: ask again on the new one (the
    // client's Lost reports the address gone).
    if dhcp && !port.is_pppoe()
        && let Some(w) = wan4.as_mut()
    {
        w.reset(now_ms());
        return None;
    }
    let want_pppoe = matches!(new, WanLink::Pppoe(_));
    if port.is_pppoe() != want_pppoe || wan.ip_only != ip_only {
        port.pppoe_mode.store(want_pppoe, Ordering::Relaxed);
        let mtu = match &new {
            WanLink::Pppoe(c) => c.mtu,
            _ => fwd::forwarder::DEFAULT_MTU,
        };
        port.mtu.store(u32::from(mtu), Ordering::Relaxed);
        // Another medium (the sockets stay; new connections take the
        // MTU's MSS); with `ip_only` the datapath does the WAN's ARP / ND
        // from now on.
        wan.ip_only = ip_only;
        sh.links[0].set_ip_only(ip_only);
        wan.tcp.set_mtu(mtu);
    }
    // The DHCP client (`net::wan4`) only in DHCP mode.
    match (dhcp, wan4.is_some()) {
        (false, true) => {
            if let Some(w) = wan4.take() {
                w.stop();
            }
        }
        (true, false) => *wan4 = Some(crate::net::wan4::Wan4::new(port.mac, now_ms())),
        _ => {}
    }
    wan.set_addr4(None);
    wan.set_default4(None);
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
    clients: WanClients<'_>,
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
        change = restart_wan(sh, &mut hosts[0], clients, new_link);
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
    *w = crate::net::wan6::Wan6::new(sh, now_ms());
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
        if let Some(dp) = stack::datapath() {
            stack::set_local_links(dp, sh, &nets, &links);
            stack::set_wan_local_link(dp, &mut hosts[0]);
        }
        let shape = |v: &[crate::config::Lan]| -> Vec<(String, usize, u16, core::net::Ipv4Addr, u8, u8)> {
            v.iter().map(|n| (n.name.clone(), n.port, n.vid, n.addr, n.prefix, n.zone)).collect()
        };
        if old.is_some_and(|o| shape(o) != shape(&nets)) {
            stack::log_networks(&nets);
        }
        sh.post_networks(msg);
        if let Some(svc) = services {
            svc.set_dns6(&crate::net::wan6::dns());
            svc.reconfigure(hosts, &links);
        }
        mgmt.add_sockets(hosts, &links);
    } else if let Some(svc) = services {
        svc.set_dns6(&crate::net::wan6::dns());
        svc.reconfigure(hosts, &[]);
    }
}

/// Tell everyone who depends on the WAN address about a change.
fn publish_wan(
    change: &LeaseChange,
    wan: &mut HostIf,
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
    if let Some(dp) = stack::datapath() {
        stack::set_wan_local_link(dp, wan);
    }
    mgmt.set_wan_lease(lease_json(change));
    cli.set_wan(lease_text(change));
    if let Some(svc) = services {
        svc.set_upstreams(&change.dns);
        svc.set_wan_up(change.addr.is_some());
    }
}

/// The router stack's receive and send for every link: frames from the
/// datapath (`local_rx`) to `net::local` (UDP, ICMP echo, IGMP / MLD
/// queries) or the link's TCP; anything else for the router is dropped
/// and counted (`local.other_dropped`). Then the TCP segments due, out
/// through `net::local::send_frame`; the TX task of each port that got
/// frames in its qdisc is woken.
fn poll_stacks(hosts: &mut [HostIf], sh: &Shared) {
    use crate::net::{device, local};
    let now = now_ms();
    for (ifx, (host, link)) in hosts.iter_mut().zip(&sh.links).enumerate() {
        let ifx = ifx as fwd::IfIndex;
        loop {
            let Some(pkt) = link.local_rx.lock().pop_front() else { break };
            let f = pkt.data();
            let ip = matches!(fwd::wire::ethertype(f), Some(fwd::wire::ETHERTYPE_IPV4 | fwd::wire::ETHERTYPE_IPV6));
            if !ip {
                continue; // ARP / ND were the datapath's
            }
            device::tap(&mut host.tap, link, f);
            if local::take(ifx, f) {
                continue;
            }
            match fwd::tcp::parse(f) {
                Some(seg) if host.is_ours(seg.dst) => host.tcp.receive(now, seg.src, seg.dst, &f[seg.l4.0..seg.l4.1]),
                _ => local::other(sh, ifx, f),
            }
        }
        host.tcp.poll(now, |e| {
            let off = fwd::tcp::offset(e.src.is_ipv6());
            let Some(mut pkt) = crate::net::packet::PacketBuf::alloc() else {
                device::count_tx_drop();
                return true; // lost: the retransmission timer covers it
            };
            if off + e.len() > crate::net::packet::RX_AREA {
                device::count_tx_drop();
                return true;
            }
            pkt.set_len(off + e.len());
            let d = pkt.data_mut();
            let Some(n) = e.write(&mut d[off..]).and_then(|n| fwd::tcp::frame(d, e.src.ip(), e.dst.ip(), fwd::tcp::TTL, n)) else {
                device::count_tx_drop();
                return true;
            };
            pkt.set_len(n);
            if !local::send_frame(sh, ifx, pkt) {
                device::count_tx_drop();
            }
            true
        });
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
    /// The WAN's last delegated IPv6 prefix as stored (`net::wan6::last`).
    saved_prefix: Option<(core::net::Ipv6Addr, u8)>,
    next_check: timer::Instant,
}

impl LeaseStore {
    async fn load(st: Option<&mut crate::store::Store>, svc: Option<&mut LanServices>) -> Self {
        let mut me = LeaseStore {
            enabled: false,
            saved: Vec::new(),
            saved_prefix: None,
            next_check: timer::Instant::now().checked_add(LEASE_CHECK).unwrap_or(timer::Instant::now()),
        };
        let (Some(st), Some(svc)) = (st, svc) else {
            return me;
        };
        match st.read_current(LEASE_AREA, persist::FORMAT_V2).await {
            Err(e) => {
                println!("  leases          : not kept ({e})");
                return me;
            }
            Ok((None, _)) => println!("  leases          : none stored"),
            Ok((Some(rec), _)) => match persist::decode_version(rec.header.version, &rec.payload) {
                Ok((nets, prefix)) => {
                    let (kept, saved) = svc.restore_leases(&nets);
                    println!(
                        "  leases          : restored {kept} of {saved} (slot {}, seq {}){}",
                        crate::store::slot_name(rec.slot),
                        rec.header.seq,
                        prefix.map_or(String::new(), |(p, l)| alloc::format!(", last IPv6 prefix {p}/{l}"))
                    );
                    crate::net::wan6::set_last(prefix);
                    me.saved_prefix = prefix;
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
        let prefix = crate::net::wan6::last();
        if snap == self.saved && prefix == self.saved_prefix {
            return;
        }
        let data = persist::encode_v2(&snap, prefix);
        match st.write_record(LEASE_AREA, persist::FORMAT_V2, persist::FORMAT_V2, &data, 0).await {
            Ok((slot, h)) => {
                println!(
                    "  leases          : saved {} (slot {}, seq {}, {} bytes)",
                    snap.iter().map(|n| n.leases.len()).sum::<usize>(),
                    crate::store::slot_name(slot),
                    h.seq,
                    h.len
                );
                self.saved = snap;
                self.saved_prefix = prefix;
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
    let mut pinger = Pinger::new();
    // Network slots as bring_up placed them (`stack::place_networks`).
    let (mut slots, links, _) = stack::place_networks(&[]);
    let links = if sh.links.len() > 1 { links } else { Vec::new() };
    let mut services = LanServices::new(&mut hosts, &links);
    let mut leases = LeaseStore::load(store.as_mut(), services.as_mut()).await;
    let mut mgmt = Mgmt::new(&mut hosts, &links, store.is_some());
    let mut cli = Cli::new(store.is_some());
    let mut pppoe = crate::config::pppoe().map(|c| Pppoe::new(c, &sh.ports[0]));
    // The router's multicast memberships per link (IGMP / MLD reports,
    // docs/local-stack.md step 4): recomputed when the links' addresses
    // or mDNS's memberships change.
    let mut groups = crate::net::groups::Groups::new();
    let mut groups_seen = (u64::MAX, u64::MAX);
    // The WAN's DHCP client over the router's own UDP (`net::local`,
    // docs/local-stack.md step 2b).
    let mut wan4 = (crate::config::wan_link() == crate::config::WanLink::Dhcp)
        .then(|| crate::net::wan4::Wan4::new(sh.ports[0].mac, now_ms()));
    // The WAN's IPv6 by prefix delegation (docs/ipv6.md step 3).
    let mut wan6 = crate::net::wan6::Wan6::new(sh, now_ms());
    // PPPoE: IPv6CP's state the loop last acted on (step 4).
    let mut ppp6 = crate::net::wan6::ppp_link();
    // The datapath's view of an IP-only WAN from the start: its link-local
    // address is answered before any lease (prefix delegation runs from
    // it at once).
    if let Some(dp) = stack::datapath() {
        stack::set_wan_local_link(dp, &mut hosts[0]);
    }
    if let crate::config::WanLink::Static(s) = crate::config::wan_link() {
        let c = configure_static(sh.ports[0].name, &mut hosts[0], &mut pinger, &s);
        publish_wan(&c, &mut hosts[0], sh, &mut mgmt, &mut cli, services.as_mut());
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
                let events = wan4.as_mut().map(|w| w.step(sh, now_ms())).unwrap_or_default();
                handle_wan4(sh.ports[0].name, &mut hosts[0], &mut pinger, events)
            }
        };
        if let Some(change) = change {
            publish_wan(&change, &mut hosts[0], sh, &mut mgmt, &mut cli, services.as_mut());
        }
        let now6 = crate::net::wan6::ppp_link();
        if now6 != ppp6 {
            // IPv6CP came or went: prefix delegation over the session
            // starts or stops, the WAN's addresses and route follow.
            ppp6 = now6;
            if let Some(old) = wan6.take() {
                old.stop(&mut hosts[0]);
            }
            wan6 = crate::net::wan6::Wan6::new(sh, now_ms());
            reapply_networks(sh, &mut hosts, services.as_mut(), &mut mgmt, &mut slots, None);
        }
        pinger.step(sh);
        if let Some(w) = wan6.as_mut()
            && w.step(&mut hosts[0], sh, now_ms())
        {
            // A router or prefix came, changed or went: the networks follow.
            reapply_networks(sh, &mut hosts, services.as_mut(), &mut mgmt, &mut slots, None);
        }
        if let Some(svc) = services.as_mut() {
            svc.step(&mut hosts, sh);
        }
        if let Some(dp) = stack::datapath() {
            let key = (dp.local_gen(), services.as_ref().map_or(0, LanServices::mdns_generation));
            if key != groups_seen {
                groups_seen = key;
                let mdns = services.as_ref().map(LanServices::mdns_members).unwrap_or_default();
                for ifx in 0..sh.links.len() {
                    groups.set(sh, ifx, crate::net::groups::wanted(sh, ifx, &mdns), now_ms());
                }
            }
        }
        while let Some((ifx, q)) = crate::net::local::take_query() {
            groups.query(ifx as usize, q, now_ms());
        }
        groups.step(sh, now_ms());
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
                if let Some(c) = apply_saved((cfg, source.clone()), sh, &mut hosts, (&mut pppoe, &mut pinger, &mut wan4), svc, &mut mgmt, &mut slots) {
                    publish_wan(&c, &mut hosts[0], sh, &mut mgmt, &mut cli, services.as_mut());
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
                                if let Some(c) = apply_saved((*cfg, source), sh, &mut hosts, (&mut pppoe, &mut pinger, &mut wan4), svc, &mut mgmt, &mut slots) {
                                    publish_wan(&c, &mut hosts[0], sh, &mut mgmt, &mut cli, services.as_mut());
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
        if cli.more() || crate::net::local::pending() || sh.links.iter().any(|l| !l.local_rx.lock().is_empty()) {
            crate::executor::yield_now().await;
            continue;
        }
        let t = now_ms();
        let mut delay = hosts
            .iter()
            .filter_map(|h| h.tcp.next_deadline(t))
            .map(|d| Duration::from_millis(d.saturating_sub(t)))
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
        if let Some(w) = &wan4 {
            delay = delay.min(Duration::from_millis(w.next_deadline().saturating_sub(now_ms())));
        }
        delay = delay.min(Duration::from_millis(groups.next_deadline().saturating_sub(now_ms())));
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
        WaitAny::new(&events, timer::sleep(delay)).await;
    }
}
