//! LAN services: DHCPv4 server and DNS forwarder, plus the SNTP client
//! (`net::ntp`), which resolves its server names through the forwarder.
//!
//! Thin glue between smoltcp UDP sockets and the sans-IO crates
//! (`proto_dhcp::v4::server`, `proto_dns::resolver`): receive datagrams, feed
//! them in with the current time, and send what comes out. DHCP lease events
//! update the DNS zone (`host.lan`). The DNS upstreams are `dns.upstreams`
//! if set, else the WAN lease's (DHCP or PPPoE); with `dns.tls` they are
//! asked over TLS only (`net::dot`), never in plain text.
//!
//! Per network (`config::networks`): `0.0.0.0:67` (DHCP, unless switched
//! off) and `:53` (DNS from clients) on its interface; one resolver and
//! local zone for all of them. WAN `:<random high port>` (queries to
//! upstream servers over UDP), or TCP connections to port 853 for DNS
//! over TLS. `:5353` on networks taking part in mDNS reflection
//! (`net::mdns`).

use crate::config;
use crate::config::schema::{HostName, LocalHost, NameVisibility};
use crate::net::dot::Dot;
use crate::net::mdns::Mdns;
use crate::net::ntp::{self, Ntp};
use crate::net::svc::HostIf;
use crate::{println, timer};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use proto_dhcp::v4::packet::{CLIENT_PORT, SERVER_PORT};
use proto_dhcp::v4::persist;
use proto_dhcp::v4::server::{self as dhcp, Event as DhcpEvent};
use proto_dns::resolver::{self, Action, Resolver};
use proto_dns::zone::{Source, View, Zone};
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
    /// One forwarder and cache for all networks; one local zone, answered
    /// per network (docs/dns-views.md).
    dns: Resolver,
    /// Who resolves which addresses' names (`dns.views`): new leases.
    names: NameVisibility,
    upstream_sock: Option<SocketHandle>,
    /// The WAN lease's DNS servers (used without `dns.upstreams`).
    lease_dns: Vec<Ipv4Addr>,
    /// UDP port per configured upstream (53 unless given).
    udp_ports: Vec<(Ipv4Addr, u16)>,
    /// `dns.tls`: upstream queries only through `dot`; if that is `None`
    /// (trust anchors failed to load), none at all.
    tls: bool,
    dot: Option<Dot>,
    /// The WAN address changed: DNS-over-TLS connections start over.
    wan_changed: bool,
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
        prefetch: d.prefetch,
        max_stale_secs: d.stale_secs,
        // Over TLS the first query after a while also waits for TCP and
        // the TLS handshake (two more round trips).
        timeout_ms: if d.tls { 3000 } else { 1500 },
        ..Default::default()
    }
}

/// Who gets a name of `ip` (docs/dns-views.md): the networks
/// `dns.views` lets see it, and the router itself.
fn seen_by(names: &NameVisibility, ip: Ipv4Addr) -> View {
    View(names.seen_by(ip)).union(View::ROUTER)
}

/// The local zone: every network's domain with `router.<domain>` (the
/// address of the first network using that domain), reservations with a
/// hostname, and bound DHCP leases with a hostname, each in its network's
/// domain, then `[[dns.host]]` (taking names over for their networks);
/// reverse lookups for all their subnets. Each record is answered to the
/// networks that see its address (`dns.views`), or to a host's own
/// `networks`.
fn build_zone<'a>(
    nets: &[config::Lan],
    names: &NameVisibility,
    hosts: &[LocalHost],
    leases: impl Iterator<Item = (&'a str, &'a dhcp::Lease)>,
) -> Zone {
    let first = &nets[0];
    let mut zone = Zone::new(&first.domain, first.addr, (first.addr, first.prefix));
    for n in &nets[1..] {
        zone.add_domain(&n.domain, n.addr);
        zone.add_subnet((n.addr, n.prefix));
    }
    for n in nets {
        for s in &n.statics {
            if let Some(h) = &s.hostname {
                zone.add_in(&n.domain, h, s.ip, Source::Static, seen_by(names, s.ip));
            }
        }
    }
    for (net, l) in leases.filter(|(_, l)| l.state == dhcp::LeaseState::Bound) {
        let (Some(h), Some(n)) = (&l.hostname, nets.iter().find(|n| n.name == net)) else {
            continue;
        };
        zone.add_in(&n.domain, h, l.ip, Source::Dhcp, seen_by(names, l.ip));
    }
    for h in hosts {
        let view = match h.networks {
            Some(mask) => View(mask).union(View::ROUTER),
            None => seen_by(names, h.ip),
        };
        match &h.name {
            HostName::Local { domain, label } => zone.add_in(domain, label, h.ip, Source::Static, view),
            HostName::Override(name) => zone.add_override(name, h.ip, view),
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
        let (names, local_hosts) = config::dns_names();
        let zone = build_zone(&cfgs, &names, &local_hosts, core::iter::empty());
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
        let mut me = Self {
            nets,
            dns,
            names,
            upstream_sock,
            lease_dns: Vec::new(),
            udp_ports: Vec::new(),
            tls: false,
            dot: None,
            wan_changed: false,
            next_expire: 0,
            ntp,
            mdns,
        };
        me.apply_upstreams(hosts);
        Some(me)
    }

    /// The resolver's upstreams from the config (`dns.upstreams`,
    /// `dns.tls`) or the WAN lease; DNS-over-TLS connections to match.
    fn apply_upstreams(&mut self, hosts: &mut [HostIf]) {
        let d = config::dns();
        let own = !d.upstreams.is_empty() || d.tls;
        let ips: Vec<Ipv4Addr> = if own { d.upstreams.iter().map(|u| u.ip).collect() } else { self.lease_dns.clone() };
        self.dns.set_upstreams(&ips);
        self.udp_ports = d.upstreams.iter().map(|u| (u.ip, u.port(false))).collect();
        self.tls = d.tls;
        match (d.tls, self.dot.as_mut()) {
            (true, Some(dot)) => dot.reconfigure(&mut hosts[0], &d.upstreams, d.tls_ca.as_deref()),
            (true, None) => self.dot = Dot::new(&d.upstreams, d.tls_ca.as_deref()),
            (false, Some(dot)) => {
                dot.shutdown(&mut hosts[0]);
                self.dot = None;
            }
            (false, None) => {}
        }
        if d.tls && d.upstreams.is_empty() {
            println!("  dns upstreams   : DNS over TLS without servers: every query fails (strict)");
        } else if own && !d.tls {
            let list: Vec<String> = d.upstreams.iter().map(|u| alloc::format!("{u}")).collect();
            println!("  dns upstreams   : {} (plain DNS)", list.join(", "));
        }
    }

    /// Where the upstreams come from (status page, CLI).
    pub fn upstream_source(&self) -> &'static str {
        match (self.tls, self.udp_ports.is_empty()) {
            (true, _) => "dns.upstreams, DNS over TLS (strict)",
            (false, false) => "dns.upstreams",
            (false, true) => "WAN lease",
        }
    }

    /// The upstreams the resolver asks.
    pub fn upstreams(&self) -> &[Ipv4Addr] {
        self.dns.upstreams()
    }

    /// Resolver counters and the number of cached answers.
    pub fn dns_stats(&self) -> (resolver::Stats, usize) {
        (self.dns.stats, self.dns.cache_len())
    }

    /// DNS-over-TLS connections (`/api/status` `dns.tls`), if on.
    pub fn dot_status_json(&self) -> Option<String> {
        self.dot.as_ref().map(Dot::status_json)
    }

    /// DNS-over-TLS connections, one line each (CLI `status`).
    pub fn dot_status_lines(&self) -> Vec<String> {
        self.dot.as_ref().map(Dot::status_lines).unwrap_or_default()
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
        let (names, local_hosts) = config::dns_names();
        *self.dns.zone_mut() = build_zone(&cfgs, &names, &local_hosts, self.leases_by_network());
        self.names = names;
        self.dns.reconfigure(resolver_config(&dns_cfg));
        self.apply_upstreams(hosts);
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

    /// The bound leases of every network with DHCP, for the store
    /// (`persist`); compared by `svc` to decide whether to write.
    pub fn lease_snapshot(&self) -> Vec<persist::Network> {
        self.nets
            .iter()
            .filter_map(|n| {
                n.dhcp.as_ref().map(|(s, _)| persist::Network {
                    name: n.cfg.name.clone(),
                    leases: s.snapshot(),
                })
            })
            .collect()
    }

    /// Leases from the store after a restart: each network's (by name)
    /// go to its DHCP server, which keeps what the config still allows,
    /// and into the DNS zone. Returns (restored, saved).
    pub fn restore_leases(&mut self, saved: &[persist::Network]) -> (usize, usize) {
        let mut restored = 0;
        for net in &mut self.nets {
            let (Some((server, _)), Some(s)) = (net.dhcp.as_mut(), saved.iter().find(|s| s.name == net.cfg.name)) else {
                continue;
            };
            for ev in server.restore(now_secs(), &s.leases) {
                if let DhcpEvent::Bound { ip, hostname: Some(h), .. } = ev {
                    let view = seen_by(&self.names, ip);
                    self.dns.zone_mut().add_in(&net.cfg.domain, &h, ip, Source::Dhcp, view);
                }
                restored += 1;
            }
        }
        (restored, saved.iter().map(|s| s.leases.len()).sum())
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

    /// The WAN lease changed: its DNS servers, used unless the config
    /// names its own (`dns.upstreams`, `dns.tls`).
    pub fn set_upstreams(&mut self, servers: &[Ipv4Addr]) {
        self.lease_dns = servers.to_vec();
        if !self.tls && self.udp_ports.is_empty() {
            self.dns.set_upstreams(servers);
        }
    }

    /// The WAN got or lost its lease: SNTP starts or stops (IPv4 literals
    /// work without DNS upstreams; names wait for them); DNS-over-TLS
    /// connections start over.
    pub fn set_wan_up(&mut self, up: bool) {
        if let Some(n) = self.ntp.as_mut() {
            n.set_wan(up);
        }
        self.wan_changed = true;
    }

    /// SNTP state (status page).
    pub fn ntp_status(&self) -> Option<ntp::Status> {
        self.ntp.as_ref().map(Ntp::status)
    }

    /// mDNS reflector counters per network taking part.
    pub fn mdns_status(&self) -> Vec<(&str, proto_mdns::Stats)> {
        self.mdns.status()
    }

    fn apply_dhcp_events(dns: &mut Resolver, names: &NameVisibility, net: &str, domain: &str, events: Vec<DhcpEvent>) {
        for ev in events {
            match ev {
                DhcpEvent::Bound { mac, ip, hostname } => {
                    println!(
                        "  dhcp            : {} -> {ip} ({}.{domain}, {net})",
                        smoltcp::wire::EthernetAddress(mac),
                        hostname.as_deref().unwrap_or("-")
                    );
                    if let Some(h) = hostname {
                        dns.zone_mut().add_in(domain, &h, ip, Source::Dhcp, seen_by(names, ip));
                    }
                }
                DhcpEvent::Released { ip, hostname, .. } => {
                    if let Some(h) = hostname {
                        dns.zone_mut().remove_dhcp_in(domain, &h, ip);
                    }
                }
            }
        }
    }

    /// The UDP port of an upstream: as configured, else 53.
    fn udp_port(&self, server: Ipv4Addr) -> u16 {
        self.udp_ports.iter().find(|(ip, _)| *ip == server).map_or(DNS_PORT, |&(_, p)| p)
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
                // Strict: with `dns.tls` never UDP, also when TLS is unavailable.
                Action::Upstream { server, data } if self.tls => {
                    if let Some(dot) = self.dot.as_mut() {
                        dot.send(&mut hosts[0], server, &data);
                    }
                }
                Action::Upstream { server, data } => {
                    if let Some(h) = self.upstream_sock {
                        let ep = IpEndpoint::new(IpAddr::V4(server).into(), self.udp_port(server));
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
                Self::apply_dhcp_events(&mut self.dns, &self.names, &net.cfg.name, &net.cfg.domain, out.events);
            }
            if expire {
                let ev = server.expire(now_secs());
                Self::apply_dhcp_events(&mut self.dns, &self.names, &net.cfg.name, &net.cfg.domain, ev);
            }
        }

        // DNS: client queries, on every network, answered as that network
        // (the socket it came in on, not the source address: views).
        let mut qbuf = [0u8; 1500];
        for i in 0..self.nets.len() {
            let (host, sock) = (self.nets[i].host, self.nets[i].dns_sock);
            loop {
                let s = hosts[host].sockets.get_mut::<udp::Socket>(sock);
                let Ok((n, meta)) = s.recv_slice(&mut qbuf) else {
                    break;
                };
                let client = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                let actions = self.dns.handle_query_in(now_ms(), client, View::network(i), &qbuf[..n]);
                self.send_dns(hosts, actions);
            }
        }
        // DNS: upstream responses. Over TLS only from the TLS connections:
        // a UDP datagram is never an answer then (no query went out by UDP,
        // so one with a pending ID is spoofed).
        if let Some(h) = self.upstream_sock {
            let mut rbuf = [0u8; 4096]; // EDNS responses may exceed 1500 B
            while let Ok((n, meta)) = hosts[0].sockets.get_mut::<udp::Socket>(h).recv_slice(&mut rbuf) {
                let from = match IpAddr::from(meta.endpoint.addr) {
                    IpAddr::V4(a) if !self.tls && meta.endpoint.port == self.udp_port(a) => a,
                    _ => continue,
                };
                let actions = self.dns.handle_upstream(now_ms(), from, &rbuf[..n]);
                self.send_dns(hosts, actions);
            }
        }
        if let Some(dot) = self.dot.as_mut() {
            if core::mem::take(&mut self.wan_changed) {
                dot.wan_changed(&mut hosts[0]);
            }
            for (from, answer) in dot.step(&mut hosts[0]) {
                let actions = self.dns.handle_upstream(now_ms(), from, &answer);
                self.send_dns(hosts, actions);
            }
        }
        self.wan_changed = false;
        // SNTP: our own name lookups, then the protocol.
        let queries = self.ntp.as_mut().map(|n| n.lookups(now_ms())).unwrap_or_default();
        for q in queries {
            let actions = self.dns.handle_query_in(now_ms(), ntp::SELF_CLIENT, View::ROUTER, &q);
            self.send_dns(hosts, actions);
        }
        if let Some(n) = self.ntp.as_mut() {
            n.step(&mut hosts[0].sockets);
        }

        // DNS: retries / timeouts.
        let actions = self.dns.poll(now_ms());
        self.send_dns(hosts, actions);
        // Queries queued above go out with the next poll of the WAN.
        if let Some(dot) = self.dot.as_mut() {
            dot.flush(&mut hosts[0]);
        }

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
        if let Some(at) = self.dot.as_ref().and_then(Dot::next_deadline) {
            wait_ms = wait_ms.min(at.saturating_duration_since(timer::Instant::now()).as_millis() as u64);
        }
        timer::Instant::now()
            .checked_add(core::time::Duration::from_millis(wait_ms))
            .expect("deadline overflow")
    }
}
