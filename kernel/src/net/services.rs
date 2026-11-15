//! LAN services: DHCPv4 server and DNS forwarder, plus the SNTP client
//! (`net::ntp`), which resolves its server names through the forwarder.
//!
//! Thin glue between smoltcp UDP sockets and the sans-IO crates
//! (`proto_dhcp::v4::server`, `proto_dns::resolver`): receive datagrams, feed
//! them in with the current time, and send what comes out. DHCP lease events
//! update the DNS zone (`host.lan`). WAN DHCP supplies the DNS upstreams.
//!
//! Per network (`config::networks`): `0.0.0.0:67` (DHCP, unless switched
//! off) and `:53` (DNS from clients) on its interface; one resolver and
//! local zone for all of them. WAN `:<random high port>` (queries to
//! upstream servers). `:5353` on networks taking part in mDNS reflection
//! (`net::mdns`).

use crate::config;
use crate::net::mdns::Mdns;
use crate::net::ntp::{self, Ntp};
use crate::net::svc::HostIf;
use crate::{println, timer};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use proto_dhcp::v4::packet::{CLIENT_PORT, SERVER_PORT};
use proto_dhcp::v4::server::{self as dhcp, Event as DhcpEvent};
use proto_dns::resolver::{self, Action, Resolver};
use proto_dns::zone::{Source, Zone};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;

const DNS_PORT: u16 = 53;
/// How often leases are checked for expiry.
const EXPIRE_EVERY_SECS: u64 = 10;
/// How soon to look again while an mDNS group join waits for the datapath.
const MDNS_RECHECK_MS: u64 = 20;

/// One network's services: its DHCP server (if enabled) and the DNS
/// socket on its address.
struct Net {
    cfg: config::Lan,
    /// Index into the services' `HostIf`s (the network's link).
    host: usize,
    dhcp: Option<(dhcp::Server, SocketHandle)>,
    dns_sock: SocketHandle,
}

pub struct LanServices {
    nets: Vec<Net>,
    /// One forwarder and cache for all networks; one local zone.
    dns: Resolver,
    upstream_sock: Option<SocketHandle>,
    next_expire: u64,
    /// SNTP over the WAN (none without a WAN).
    ntp: Option<Ntp>,
    /// mDNS across networks.
    mdns: Mdns,
}
fn udp_socket(datagrams: usize, bytes: usize) -> udp::Socket<'static> {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; datagrams], vec![0; bytes]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; datagrams], vec![0; bytes]);
    udp::Socket::new(rx, tx)
}

fn dhcp_config(cfg: &config::Lan) -> dhcp::Config {
    dhcp::Config {
        server_ip: cfg.addr,
        netmask: cfg.netmask(),
        router: Some(cfg.addr),
        dns: vec![cfg.addr],
        domain: Some(cfg.domain.clone()),
        range: cfg.dhcp_range,
        lease_secs: cfg.lease_secs,
        statics: cfg.statics.clone(),
    }
}

fn resolver_config(d: &config::Dns) -> resolver::Config {
    resolver::Config {
        cache_entries: d.cache_entries,
        rebind_protection: d.rebind_protection,
        ..Default::default()
    }
}

/// The local zone: the router (its first network's address), reservations
/// with a hostname, and bound DHCP leases with a hostname, of every
/// network; reverse lookups for all their subnets.
fn build_zone<'a>(nets: &[config::Lan], leases: impl Iterator<Item = &'a dhcp::Lease>) -> Zone {
    let first = &nets[0];
    let mut zone = Zone::new(&first.domain, first.addr, (first.addr, first.prefix));
    for n in &nets[1..] {
        zone.add_subnet((n.addr, n.prefix));
    }
    for s in nets.iter().flat_map(|n| &n.statics) {
        if let Some(h) = &s.hostname {
            zone.add(h, s.ip, Source::Static);
        }
    }
    for l in leases.filter(|l| l.state == dhcp::LeaseState::Bound) {
        if let Some(h) = &l.hostname {
            zone.add(h, l.ip, Source::Dhcp);
        }
    }
    zone
}

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

fn now_secs() -> u64 {
    timer::uptime().as_secs()
}

/// A network's services on its link's interface: DHCP (if on) and DNS.
fn open_net(cfg: config::Lan, host: usize, hosts: &mut [HostIf]) -> Net {
    let sockets = &mut hosts[host].sockets;
    let dhcp = cfg.dhcp.then(|| open_dhcp(&cfg, sockets));
    let mut s = udp_socket(32, 32 * 1024);
    s.bind(DNS_PORT).expect("bind :53");
    let dns_sock = sockets.add(s);
    log_net(&cfg);
    Net {
        cfg,
        host,
        dhcp,
        dns_sock,
    }
}

fn open_dhcp(cfg: &config::Lan, sockets: &mut SocketSet<'static>) -> (dhcp::Server, SocketHandle) {
    let mut s = udp_socket(8, 8 * 600);
    s.bind(SERVER_PORT).expect("bind :67");
    (dhcp::Server::new(dhcp_config(cfg)), sockets.add(s))
}

fn log_net(cfg: &config::Lan) {
    println!(
        "  lan services    : {}: {}, dns {}:53 (.{})",
        cfg.name,
        if cfg.dhcp {
            alloc::format!(
                "dhcp {}..{} ({} static)",
                cfg.dhcp_range.0,
                cfg.dhcp_range.1,
                cfg.statics.len()
            )
        } else {
            alloc::string::String::from("no dhcp")
        },
        cfg.addr,
        cfg.domain,
    );
}

impl LanServices {
    /// `hosts[0]` is the WAN; network `k` of `config::networks` is on
    /// `hosts[links[k]]`. `None` without networks.
    pub fn new(hosts: &mut [HostIf], links: &[usize]) -> Option<Self> {
        let cfgs = config::networks();
        if cfgs.is_empty() || links.len() != cfgs.len() {
            return None;
        }
        let dns_cfg = config::dns();
        let zone = build_zone(&cfgs, core::iter::empty());
        let dns = Resolver::new(resolver_config(&dns_cfg), zone, timer::ticks() as u32);
        let nets = cfgs
            .into_iter()
            .zip(links)
            .map(|(cfg, &link)| open_net(cfg, link, hosts))
            .collect();
        let wan = &mut hosts[0];
        // 65000–65535: router-local (fwd::forwarder::ROUTER_CLIENT_PORTS),
        // apart from SNTP's 60000–64999; never a NAT or forwarded port.
        let port = 65_000 + (timer::ticks() % 536) as u16;
        let mut s = udp_socket(32, 32 * 4096);
        s.bind(port).expect("bind upstream port");
        let upstream_sock = Some(wan.sockets.add(s));
        let ntp = Some(Ntp::new(wan));
        println!("  lan services    : dns cache {}", dns_cfg.cache_entries);
        let mdns = Mdns::new(hosts, links);
        Some(Self {
            nets,
            dns,
            upstream_sock,
            next_expire: 0,
            ntp,
            mdns,
        })
    }

    /// Apply the current config (`config::apply`) without a restart: a
    /// network that kept its name and link keeps its DHCP server (leases
    /// still valid under the new pool and reservations stay), new networks
    /// get services, removed ones lose them; DHCP is switched on or off;
    /// the DNS zone is rebuilt from the reservations and the bound leases,
    /// the cache keeps what fits.
    pub fn reconfigure(&mut self, hosts: &mut [HostIf], links: &[usize]) {
        let cfgs = config::networks();
        let dns_cfg = config::dns();
        let mut dropped = 0;
        let mut old = core::mem::take(&mut self.nets);
        for (cfg, &link) in cfgs.iter().zip(links) {
            let Some(pos) = old.iter().position(|n| n.host == link && n.cfg.name == cfg.name) else {
                self.nets.push(open_net(cfg.clone(), link, hosts));
                continue;
            };
            let mut net = old.remove(pos);
            let sockets = &mut hosts[net.host].sockets;
            match (net.dhcp.take(), cfg.dhcp) {
                (Some((mut server, sock)), true) => {
                    dropped += server
                        .reconfigure(now_secs(), dhcp_config(cfg))
                        .iter()
                        .filter(|e| matches!(e, DhcpEvent::Released { .. }))
                        .count();
                    net.dhcp = Some((server, sock));
                }
                (Some((server, sock)), false) => {
                    dropped += server.leases().count();
                    sockets.remove(sock);
                }
                (None, true) => net.dhcp = Some(open_dhcp(cfg, sockets)),
                (None, false) => {}
            }
            net.cfg = cfg.clone();
            self.nets.push(net);
        }
        // Networks that went away (or moved): their sockets go too.
        for net in old {
            let sockets = &mut hosts[net.host].sockets;
            if let Some((server, sock)) = net.dhcp {
                dropped += server.leases().count();
                sockets.remove(sock);
            }
            sockets.remove(net.dns_sock);
            println!("  lan services    : {}: removed", net.cfg.name);
        }
        *self.dns.zone_mut() = build_zone(&cfgs, self.leases());
        self.dns.reconfigure(resolver_config(&dns_cfg));
        if let Some(n) = self.ntp.as_mut() {
            n.reconfigure();
        }
        self.mdns.reconfigure(hosts, links);
        let first = &cfgs[0];
        println!(
            "  lan services    : reconfigured: dhcp {}..{} ({} static, {} lease(s) dropped), domain .{}, cache {}",
            first.dhcp_range.0,
            first.dhcp_range.1,
            cfgs.iter().map(|n| n.statics.len()).sum::<usize>(),
            dropped,
            first.domain,
            dns_cfg.cache_entries
        );
    }

    /// Current DHCP leases of all networks (status page).
    pub fn leases(&self) -> impl Iterator<Item = &dhcp::Lease> {
        self.leases_by_network().map(|(_, l)| l)
    }

    /// Current DHCP leases with their network's name.
    pub fn leases_by_network(&self) -> impl Iterator<Item = (&str, &dhcp::Lease)> {
        self.nets.iter().flat_map(|n| {
            n.dhcp
                .iter()
                .flat_map(move |(s, _)| s.leases().map(move |l| (n.cfg.name.as_str(), l)))
        })
    }

    /// The WAN lease changed: new upstream DNS servers.
    pub fn set_upstreams(&mut self, servers: &[Ipv4Addr]) {
        self.dns.set_upstreams(servers);
    }

    /// The WAN got or lost its lease: SNTP starts or stops (IPv4 literals
    /// work without DNS upstreams; names wait for them).
    pub fn set_wan_up(&mut self, up: bool) {
        if let Some(n) = self.ntp.as_mut() {
            n.set_wan(up);
        }
    }

    /// SNTP state (status page).
    pub fn ntp_status(&self) -> Option<ntp::Status> {
        self.ntp.as_ref().map(Ntp::status)
    }

    /// mDNS reflector counters per network taking part.
    pub fn mdns_status(&self) -> Vec<(&str, proto_mdns::Stats)> {
        self.mdns.status()
    }

    fn apply_dhcp_events(dns: &mut Resolver, net: &str, domain: &str, events: Vec<DhcpEvent>) {
        for ev in events {
            match ev {
                DhcpEvent::Bound { mac, ip, hostname } => {
                    println!(
                        "  dhcp            : {} -> {ip} ({}.{domain}, {net})",
                        smoltcp::wire::EthernetAddress(mac),
                        hostname.as_deref().unwrap_or("-")
                    );
                    if let Some(h) = hostname {
                        dns.zone_mut().add(&h, ip, Source::Dhcp);
                    }
                }
                DhcpEvent::Released { ip, hostname, .. } => {
                    if let Some(h) = hostname {
                        dns.zone_mut().remove_dhcp(&h, ip);
                    }
                }
            }
        }
    }

    /// Send resolver output: answers to clients go out on the socket of
    /// the network the client is on.
    fn send_dns(&mut self, hosts: &mut [HostIf], actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Reply { to, data } if to == ntp::SELF_CLIENT => {
                    if let Some(n) = self.ntp.as_mut() {
                        n.dns_answer(&data, now_ms());
                    }
                }
                Action::Reply { to, data } => {
                    let IpAddr::V4(ip) = to.ip() else { continue };
                    let Some(net) = self.nets.iter().find(|n| n.cfg.contains(ip)) else {
                        continue;
                    };
                    let ep = IpEndpoint::new(to.ip().into(), to.port());
                    let _ = hosts[net.host]
                        .sockets
                        .get_mut::<udp::Socket>(net.dns_sock)
                        .send_slice(&data, ep);
                }
                Action::Upstream { server, data } => {
                    if let Some(h) = self.upstream_sock {
                        let ep = IpEndpoint::new(IpAddr::V4(server).into(), DNS_PORT);
                        let _ = hosts[0].sockets.get_mut::<udp::Socket>(h).send_slice(&data, ep);
                    }
                }
            }
        }
    }

    /// Process received datagrams and timers. Called by the services task
    /// after polling the interfaces (`hosts` as in [`Self::new`];
    /// `links[i]` is `hosts[i]`'s link).
    pub fn step(&mut self, hosts: &mut [HostIf], links: &[crate::net::shared::LinkShared]) {
        // DHCP servers.
        let mut buf = [0u8; 1500];
        let expire = now_secs() >= self.next_expire;
        if expire {
            self.next_expire = now_secs() + EXPIRE_EVERY_SECS;
        }
        for net in &mut self.nets {
            let Some((server, sock)) = net.dhcp.as_mut() else {
                continue;
            };
            let sockets = &mut hosts[net.host].sockets;
            while let Ok((n, _meta)) = sockets.get_mut::<udp::Socket>(*sock).recv_slice(&mut buf) {
                let out = server.handle(now_secs(), &buf[..n]);
                if let Some(reply) = out.reply {
                    let ep = IpEndpoint::new(IpAddr::V4(Ipv4Addr::BROADCAST).into(), CLIENT_PORT);
                    let _ = sockets.get_mut::<udp::Socket>(*sock).send_slice(&reply, ep);
                }
                Self::apply_dhcp_events(&mut self.dns, &net.cfg.name, &net.cfg.domain, out.events);
            }
            if expire {
                let ev = server.expire(now_secs());
                Self::apply_dhcp_events(&mut self.dns, &net.cfg.name, &net.cfg.domain, ev);
            }
        }

        // DNS: client queries, on every network.
        let mut qbuf = [0u8; 1500];
        for i in 0..self.nets.len() {
            let (host, sock) = (self.nets[i].host, self.nets[i].dns_sock);
            loop {
                let s = hosts[host].sockets.get_mut::<udp::Socket>(sock);
                let Ok((n, meta)) = s.recv_slice(&mut qbuf) else {
                    break;
                };
                let client = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                let actions = self.dns.handle_query(now_ms(), client, &qbuf[..n]);
                self.send_dns(hosts, actions);
            }
        }
        // DNS: upstream responses.
        if let Some(h) = self.upstream_sock {
            let mut rbuf = [0u8; 4096]; // EDNS responses may exceed 1500 B
            while let Ok((n, meta)) = hosts[0].sockets.get_mut::<udp::Socket>(h).recv_slice(&mut rbuf) {
                let from = match IpAddr::from(meta.endpoint.addr) {
                    IpAddr::V4(a) if meta.endpoint.port == DNS_PORT => a,
                    _ => continue,
                };
                let actions = self.dns.handle_upstream(now_ms(), from, &rbuf[..n]);
                self.send_dns(hosts, actions);
            }
        }
        // SNTP: our own name lookups, then the protocol.
        let queries = self.ntp.as_mut().map(|n| n.lookups(now_ms())).unwrap_or_default();
        for q in queries {
            let actions = self.dns.handle_query(now_ms(), ntp::SELF_CLIENT, &q);
            self.send_dns(hosts, actions);
        }
        if let Some(n) = self.ntp.as_mut() {
            n.step(&mut hosts[0].sockets);
        }

        // DNS: retries / timeouts.
        let actions = self.dns.poll(now_ms());
        self.send_dns(hosts, actions);

        self.mdns.step(hosts, links);
    }

    /// When `step` must run again even without traffic.
    pub fn next_deadline(&self) -> timer::Instant {
        let ms_now = now_ms();
        let dns_in = self.dns.next_deadline().map(|d| d.saturating_sub(ms_now));
        let expire_in = self.next_expire.saturating_sub(now_secs()) * 1000;
        let mut wait_ms = dns_in.map_or(expire_in, |d| d.min(expire_in));
        if let Some(at) = self.ntp.as_ref().and_then(Ntp::next_deadline_ms) {
            wait_ms = wait_ms.min(at.saturating_sub(ms_now));
        }
        if self.mdns.wants_soon() {
            wait_ms = wait_ms.min(MDNS_RECHECK_MS);
        }
        timer::Instant::now()
            .checked_add(core::time::Duration::from_millis(wait_ms))
            .expect("deadline overflow")
    }
}
