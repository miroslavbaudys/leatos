//! LAN services: DHCPv4 server and DNS forwarder, plus the SNTP client
//! (`net::ntp`), which resolves its server names through the forwarder.
//!
//! Thin glue between smoltcp UDP sockets and the sans-IO crates
//! (`proto_dhcp::v4::server`, `proto_dns::resolver`): receive datagrams, feed
//! them in with the current time, and send what comes out. DHCP lease events
//! update the DNS zone (`host.home.arpa`). The DNS upstreams are `dns.upstreams`
//! if set, else the WAN lease's (DHCP or PPPoE); with `dns.tls` they are
//! asked over TLS only (`net::dot`), never in plain text.
//!
//! Per network (`config::networks`): `0.0.0.0:67` (DHCP, unless switched
//! off) and `:53` (DNS from clients, UDP and TCP: `net::dns_tcp`) on its
//! interface; one resolver and
//! local zone for all of them. WAN `:<random high port>` (queries to
//! upstream servers over UDP), or TCP connections to port 853 for DNS
//! over TLS. `:5353` on networks taking part in mDNS reflection
//! (`net::mdns`). With IPv6 on, a Router Advertisement sender per network
//! (`proto_dhcp::v6::ra`): its ULA /64 for SLAAC and the router's ULA as
//! the DNS server; frames go straight into the port's qdisc, the way the
//! router stack's own do (docs/ipv6.md step 1).

use crate::config;
use crate::config::schema::{HostName, LocalHost, NameVisibility};
use crate::net::dns_tcp;
use crate::net::dot::Dot;
use crate::net::mdns::Mdns;
use crate::net::ntp::{self, Ntp};
use crate::net::shared::CLIENT_PORTS;
use crate::net::shared::Shared;
use crate::net::svc::HostIf;
use crate::{println, timer};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use proto_dhcp::v4::packet::{CLIENT_PORT, SERVER_PORT};
use proto_dhcp::v4::persist;
use proto_dhcp::v4::server::{self as dhcp, Event as DhcpEvent};
use proto_dhcp::v6::ra::{Advertiser, RaConfig};
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
    /// TCP :53 (none with `dns_tcp=0`).
    dns_tcp: Option<dns_tcp::Listener>,
    /// Router Advertisements (IPv6 on: `cfg.ula`).
    ra: Option<Advertiser>,
}

pub struct LanServices {
    nets: Vec<Net>,
    /// One forwarder and cache for all networks; one local zone, answered
    /// per network (docs/dns-views.md).
    dns: Resolver,
    /// Who resolves which addresses' names (`dns.views`): new leases.
    names: NameVisibility,
    /// The `[[dns.host]]` entries in the zone (their hits follow them
    /// through config changes).
    local_hosts: Vec<LocalHost>,
    upstream: Option<Upstream>,
    /// The WAN lease's DNS servers (used without `dns.upstreams`).
    lease_dns: Vec<Ipv4Addr>,
    /// The ISP's IPv6 DNS servers (DHCPv6, `net::wan6`): after the lease's,
    /// while the WAN has a global address to ask them from.
    lease_dns6: Vec<Ipv6Addr>,
    /// UDP port per configured upstream (53 unless given).
    udp_ports: Vec<(IpAddr, u16)>,
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
    /// Advertisers sending their last RA (network or IPv6 gone): (link,
    /// advertiser).
    retiring: Vec<(usize, Advertiser)>,
    /// The clients' IPv6 names in the zone: (domain, host, address, view),
    /// from the datapath's neighbors (`LinkShared::neigh6`) joined with
    /// leases and reservations by MAC; refreshed every [`AAAA_EVERY_MS`].
    aaaa: Vec<(String, String, Ipv6Addr, View)>,
    next_aaaa: u64,
}

/// How often the clients' AAAA records are compared with the neighbors.
const AAAA_EVERY_MS: u64 = 5_000;
/// A neighbor not seen for this long loses its AAAA record.
const AAAA_FORGET_MS: u64 = 30 * 60_000;

/// A network's RA settings: its ULA /64 (and global /64), the router's
/// ULA as DNS server, its domain to search, the MAC of its link's
/// interface; a default router only with an IPv6 default route.
fn ra_config(cfg: &config::Lan, host: &HostIf) -> Option<RaConfig> {
    let ula = cfg.ula?;
    let mac = host.mac;
    // A default router only while the WAN has an IPv6 default route and
    // the network a global prefix (RFC 7084 G-4: with a ULA alone there
    // is no source address to go out with).
    let default = config::wan6().is_some() && cfg.gua.is_some();
    Some(RaConfig {
        mac,
        prefixes: [Some(ula), cfg.gua].into_iter().flatten().collect(),
        router_lifetime: if default { proto_dhcp::v6::ra::ROUTER_SECS } else { 0 },
        mtu: 1500,
        rdnss: vec![ula],
        dnssl: vec![cfg.domain.clone()],
    })
}

/// A frame of the router's own (an RA, a router solicitation) into the
/// qdisc of `link`'s port (with its VLAN tag).
pub fn send_frame(sh: &Shared, link: usize, frame: &[u8]) {
    let l = &sh.links[link];
    let port = l.port();
    let Some(mut pkt) = crate::net::packet::PacketBuf::alloc() else {
        return; // pool empty: the next RA is a few minutes away at most
    };
    pkt.set_len(frame.len());
    pkt.data_mut().copy_from_slice(frame);
    if let Some(tci) = l.tci() {
        pkt.push_vlan(tci);
    }
    let now = crate::net::datapath::now_ns();
    pkt.meta.wire_len = pkt.len() as u32;
    pkt.meta.enqueue_ts = now;
    if qdisc::Qdisc::enqueue(&mut *sh.ports[port].qdisc.lock(), pkt, now).is_ok() {
        sh.tx_kick[port].signal();
    }
}
/// Upstream DNS over UDP (docs/security-audit.md §5 item 7): each query
/// leaves from a socket bound to a fresh random port in
/// [`UPSTREAM_PORTS`] (RFC 5452 §9.2: port and ID to guess, not the ID
/// alone), freed by an answer from the server it went to or after
/// [`UPSTREAM_SLOT_MS`]; all [`UPSTREAM_SLOTS`] busy: the oldest goes (its
/// query is retried by the resolver). The forwarder passes UDP only to
/// ports bound here or by SNTP (`shared::CLIENT_PORTS`), so the others
/// stay silent. `dns_port_random=0`: one port for the whole boot.
const UPSTREAM_SLOTS: usize = 64;
const UPSTREAM_SLOT_MS: u64 = 3_000;
const UPSTREAM_PORTS: (u16, u16) = (61_000, 65_535);

struct Slot {
    handle: SocketHandle,
    /// 0: unbound.
    port: u16,
    /// Where its query went: the only source of its answer.
    server: Option<IpEndpoint>,
    sent_ms: u64,
}

struct Upstream {
    slots: Vec<Slot>,
    /// `dns_port_random=0`: slot 0 only, bound for good.
    fixed: bool,
}

impl Upstream {
    fn new(wan: &mut HostIf) -> Self {
        let fixed = !config::dns_port_random();
        let n = if fixed { 1 } else { UPSTREAM_SLOTS };
        let slots = (0..n)
            .map(|_| {
                // One query, one answer (EDNS: up to 4096 B); the fixed
                // port carries every query.
                let s = if fixed { udp_socket(32, 32 * 4096) } else { udp_socket(2, 2 * 4096) };
                Slot { handle: wan.sockets.add(s), port: 0, server: None, sent_ms: 0 }
            })
            .collect();
        let mut up = Upstream { slots, fixed };
        if fixed {
            up.bind(wan, 0);
        }
        up
    }

    /// Bind slot `i` to a random free port of the range.
    fn bind(&mut self, wan: &mut HostIf, i: usize) {
        let (lo, hi) = UPSTREAM_PORTS;
        let span = u64::from(hi - lo) + 1;
        let port = loop {
            let p = lo + (crate::entropy::u64() % span) as u16;
            if !CLIENT_PORTS.is_open(p) {
                break p;
            }
        };
        if wan.sockets.get_mut::<udp::Socket>(self.slots[i].handle).bind(port).is_ok() {
            CLIENT_PORTS.open(port);
            self.slots[i].port = port;
        }
    }

    fn free(&mut self, wan: &mut HostIf, i: usize) {
        let sl = &mut self.slots[i];
        if sl.port != 0 {
            wan.sockets.get_mut::<udp::Socket>(sl.handle).close();
            CLIENT_PORTS.close(sl.port);
        }
        sl.port = 0;
        sl.server = None;
    }

    fn send(&mut self, wan: &mut HostIf, to: IpEndpoint, data: &[u8], now: u64) {
        let i = if self.fixed {
            0
        } else {
            self.expire(wan, now);
            let i = (0..self.slots.len())
                .find(|&i| self.slots[i].port == 0)
                .or_else(|| (0..self.slots.len()).min_by_key(|&i| self.slots[i].sent_ms))
                .unwrap_or(0);
            self.free(wan, i);
            self.bind(wan, i);
            i
        };
        let sl = &mut self.slots[i];
        sl.server = Some(to);
        sl.sent_ms = now;
        let _ = wan.sockets.get_mut::<udp::Socket>(sl.handle).send_slice(data, to);
    }

    fn expire(&mut self, wan: &mut HostIf, now: u64) {
        for i in 0..self.slots.len() {
            if self.slots[i].port != 0 && now.saturating_sub(self.slots[i].sent_ms) > UPSTREAM_SLOT_MS {
                self.free(wan, i);
            }
        }
    }

    /// Datagrams received: (from, data). A random-port slot takes one
    /// answer, from the server its query went to, and is freed.
    fn recv(&mut self, wan: &mut HostIf, now: u64) -> Vec<(IpEndpoint, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rbuf = [0u8; 4096]; // EDNS responses may exceed 1500 B
        for i in 0..self.slots.len() {
            if self.slots[i].port == 0 {
                continue;
            }
            let sock = wan.sockets.get_mut::<udp::Socket>(self.slots[i].handle);
            let mut answered = false;
            while let Ok((n, meta)) = sock.recv_slice(&mut rbuf) {
                if self.fixed || Some(meta.endpoint) == self.slots[i].server {
                    out.push((meta.endpoint, rbuf[..n].to_vec()));
                    answered = !self.fixed;
                }
            }
            if answered {
                self.free(wan, i);
            }
        }
        if !self.fixed {
            self.expire(wan, now);
        }
        out
    }
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
        routes: cfg.routes.clone(),
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
        if let Some(ula) = n.ula {
            zone.add_router6(&n.domain, ula);
        }
        if let Some(gua) = n.gua {
            zone.add_subnet6(gua);
        }
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
    for (i, h) in hosts.iter().enumerate() {
        let view = match h.networks {
            Some(mask) => View(mask).union(View::ROUTER),
            None => seen_by(names, h.ip),
        };
        // Tagged with the entry's index: its hits (`/api/status` dns.hosts).
        let i = i as u16;
        match &h.name {
            HostName::Local { domain, label } => zone.add_host_in(domain, label, h.ip, view, i),
            HostName::Override(name) => zone.add_host_override(name, h.ip, view, i),
        }
    }
    zone
}

/// The IPv6 neighbors the datapath saw on `net`'s link
/// (`LinkShared::neigh6`) in the last [`AAAA_FORGET_MS`], in one of the
/// network's /64s: global before unique local, newest first.
fn neighbors6(net: &Net, sh: &Shared, now_ms: u64) -> Vec<(Ipv6Addr, [u8; 6])> {
    let prefixes: Vec<u128> = [net.cfg.ula, net.cfg.gua].into_iter().flatten().map(|a| u128::from(a) >> 64).collect();
    if prefixes.is_empty() {
        return Vec::new();
    }
    let mut seen: Vec<(Ipv6Addr, [u8; 6], u64)> = sh.links[net.host]
        .neigh6
        .lock()
        .iter()
        .filter(|e| now_ms.saturating_sub(e.2) <= AAAA_FORGET_MS && prefixes.contains(&(u128::from(e.0) >> 64)))
        .copied()
        .collect();
    let ula = |a: &Ipv6Addr| a.segments()[0] & 0xfe00 == 0xfc00;
    seen.sort_by(|a, b| ula(&a.0).cmp(&ula(&b.0)).then(b.2.cmp(&a.2)));
    seen.into_iter().map(|(ip, mac, _)| (ip, mac)).collect()
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
    let dns_tcp = config::dns_tcp().then(|| dns_tcp::Listener::open(sockets));
    log_net(&cfg);
    let ra = ra_config(&cfg, &hosts[host]).map(|c| {
        println!("  lan services    : {}: ipv6 {}/64, router advertisements", cfg.name, c.prefixes[0]);
        Advertiser::new(c, now_ms(), timer::ticks() ^ host as u64)
    });
    Net {
        cfg,
        host,
        dhcp,
        dns_sock,
        dns_tcp,
        ra,
    }
}

fn open_dhcp(cfg: &config::Lan, sockets: &mut SocketSet<'static>) -> (dhcp::Server, SocketHandle) {
    let mut s = udp_socket(8, 8 * 600);
    s.bind(SERVER_PORT).expect("bind :67");
    (dhcp::Server::new(dhcp_config(cfg)), sockets.add(s))
}

fn log_net(cfg: &config::Lan) {
    println!(
        "  lan services    : {}: {}, dns {}:53 {} (.{})",
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
        if config::dns_tcp() { "udp+tcp" } else { "udp" },
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
        let dns = Resolver::new(resolver_config(&dns_cfg), zone, crate::entropy::u64() as u32);
        let nets = cfgs
            .into_iter()
            .zip(links)
            .map(|(cfg, &link)| open_net(cfg, link, hosts))
            .collect();
        let wan = &mut hosts[0];
        // 61000–65535: router-local (fwd::forwarder::ROUTER_CLIENT_PORTS),
        // apart from SNTP's 60000–60999; never a NAT or forwarded port.
        let upstream = Some(Upstream::new(wan));
        let ntp = Some(Ntp::new(wan));
        println!("  lan services    : dns cache {}", dns_cfg.cache_entries);
        let mdns = Mdns::new(hosts, links);
        let mut me = Self {
            nets,
            dns,
            names,
            local_hosts,
            upstream,
            lease_dns: Vec::new(),
            lease_dns6: Vec::new(),
            udp_ports: Vec::new(),
            tls: false,
            dot: None,
            wan_changed: false,
            next_expire: 0,
            ntp,
            mdns,
            retiring: Vec::new(),
            aaaa: Vec::new(),
            next_aaaa: 0,
        };
        me.apply_upstreams(hosts);
        Some(me)
    }

    /// The resolver's upstreams from the config (`dns.upstreams`,
    /// `dns.tls`) or the WAN lease; DNS-over-TLS connections to match.
    fn apply_upstreams(&mut self, hosts: &mut [HostIf]) {
        let d = config::dns();
        let own = !d.upstreams.is_empty() || d.tls;
        let ips: Vec<IpAddr> = if own { d.upstreams.iter().map(|u| u.ip).collect() } else { self.lease_upstreams() };
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
    pub fn upstreams(&self) -> &[IpAddr] {
        self.dns.upstreams()
    }

    /// Queries answered per `[[dns.host]]` entry (config order).
    pub fn dns_host_hits(&self) -> &[u64] {
        &self.dns.host_hits
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
            match (net.ra.take(), ra_config(cfg, &hosts[net.host])) {
                (Some(mut ra), Some(c)) => {
                    ra.set_config(c, now_ms());
                    net.ra = Some(ra);
                }
                (Some(mut ra), None) => {
                    ra.retire(now_ms());
                    self.retiring.push((net.host, ra));
                }
                (None, Some(c)) => {
                    println!("  lan services    : {}: ipv6 {}/64, router advertisements", cfg.name, c.prefixes[0]);
                    net.ra = Some(Advertiser::new(c, now_ms(), timer::ticks() ^ net.host as u64));
                }
                (None, None) => {}
            }
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
            if let Some(l) = net.dns_tcp {
                l.close(sockets);
            }
            if let Some(mut ra) = net.ra {
                ra.retire(now_ms());
                self.retiring.push((net.host, ra));
            }
            println!("  lan services    : {}: removed", net.cfg.name);
        }
        let (names, local_hosts) = config::dns_names();
        *self.dns.zone_mut() = build_zone(&cfgs, &names, &local_hosts, self.leases_by_network());
        // The clients' IPv6 names again (refreshed at the next step).
        for (d, h, a, v) in &self.aaaa {
            self.dns.zone_mut().add_host6_in(d, h, *a, *v);
        }
        self.next_aaaa = 0;
        // Hit counters follow their entries (same name and address) to
        // their new places; new entries start at 0.
        let old_hits = core::mem::take(&mut self.dns.host_hits);
        self.dns.host_hits = local_hosts
            .iter()
            .map(|h| {
                let same = |o: &LocalHost| o.name == h.name && o.ip == h.ip;
                self.local_hosts.iter().position(same).and_then(|k| old_hits.get(k).copied()).unwrap_or(0)
            })
            .collect();
        self.local_hosts = local_hosts;
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

    /// The DHCP server's refusals and reclaimed offers on network `name`
    /// (`None`: no DHCP there).
    pub fn dhcp_stats(&self, name: &str) -> Option<dhcp::Stats> {
        self.nets.iter().find(|n| n.cfg.name == name)?.dhcp.as_ref().map(|(s, _)| s.stats())
    }

    /// Current DHCP leases with their network's name.
    pub fn leases_by_network(&self) -> impl Iterator<Item = (&str, &dhcp::Lease)> {
        self.nets.iter().flat_map(|n| {
            n.dhcp
                .iter()
                .flat_map(move |(s, _)| s.leases().map(move |l| (n.cfg.name.as_str(), l)))
        })
    }

    /// Each lease with its network and the IPv6 addresses its MAC was
    /// seen at on that network ([`neighbors6`]: global before unique
    /// local, newest first). For the Clients page and the CLI.
    pub fn leases_with_ipv6(&self, sh: &Shared, now_ms: u64) -> Vec<(&str, &dhcp::Lease, Vec<Ipv6Addr>)> {
        let mut out = Vec::new();
        for n in &self.nets {
            let Some((s, _)) = &n.dhcp else { continue };
            let seen = neighbors6(n, sh, now_ms);
            for l in s.leases() {
                let v6 = seen.iter().filter(|e| e.1 == l.mac).map(|e| e.0).collect();
                out.push((n.cfg.name.as_str(), l, v6));
            }
        }
        out
    }

    /// The clients' IPv6 addresses as AAAA names: each neighbor seen in
    /// the last [`AAAA_FORGET_MS`] on a network, in one of its /64s, whose
    /// MAC holds a bound lease or a reservation with a host name, gets
    /// that name with the A record's view. The zone changes only when the
    /// set does.
    fn refresh_aaaa(&mut self, sh: &Shared, now: u64) {
        let mut want: Vec<(String, String, Ipv6Addr, View)> = Vec::new();
        if config::dns_aaaa() {
            for net in &self.nets {
                for (ip, mac) in neighbors6(net, sh, now) {
                    let lease = net.dhcp.as_ref().and_then(|(s, _)| {
                        s.leases()
                            .find(|l| l.mac == mac && l.state == dhcp::LeaseState::Bound && l.hostname.is_some())
                            .map(|l| (l.hostname.clone().unwrap_or_default(), l.ip))
                    });
                    let named = lease.or_else(|| {
                        net.cfg.statics.iter().find(|s| s.mac == mac).and_then(|s| s.hostname.clone().map(|h| (h, s.ip)))
                    });
                    if let Some((host, v4)) = named {
                        want.push((net.cfg.domain.clone(), host, ip, seen_by(&self.names, v4)));
                    }
                }
            }
            want.sort_by(|a, b| (&a.0, &a.1, a.2).cmp(&(&b.0, &b.1, b.2)));
        }
        if want != self.aaaa {
            let z = self.dns.zone_mut();
            z.clear_hosts6();
            for (d, h, a, v) in &want {
                z.add_host6_in(d, h, *a, *v);
            }
            self.aaaa = want;
        }
    }

    /// The WAN lease changed: its DNS servers, used unless the config
    /// names its own (`dns.upstreams`, `dns.tls`).
    pub fn set_upstreams(&mut self, servers: &[Ipv4Addr]) {
        self.lease_dns = servers.to_vec();
        self.refresh_lease_upstreams();
    }

    /// The ISP's IPv6 DNS servers (`net::wan6`), or the WAN's IPv6 address
    /// came or went: the resolver's list follows.
    pub fn set_dns6(&mut self, servers: &[Ipv6Addr]) {
        self.lease_dns6 = servers.to_vec();
        self.refresh_lease_upstreams();
    }

    /// The WAN's servers: the lease's IPv4 ones, then the IPv6 ones once
    /// the WAN has a global IPv6 address (the source to ask them from).
    fn lease_upstreams(&self) -> Vec<IpAddr> {
        let v6 = config::wan6().is_some_and(|w| w.addr.is_some());
        let mut v: Vec<IpAddr> = self.lease_dns.iter().map(|&a| IpAddr::V4(a)).collect();
        if v6 {
            v.extend(self.lease_dns6.iter().map(|&a| IpAddr::V6(a)));
        }
        v
    }

    fn refresh_lease_upstreams(&mut self) {
        let ups = self.lease_upstreams();
        if !self.tls && self.udp_ports.is_empty() && self.dns.upstreams() != ups.as_slice() {
            self.dns.set_upstreams(&ups);
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
                        crate::net::shared::mac_text(&mac),
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
    fn udp_port(&self, server: IpAddr) -> u16 {
        self.udp_ports.iter().find(|(ip, _)| *ip == server).map_or(DNS_PORT, |&(_, p)| p)
    }

    /// Send resolver output: answers to clients go out on the socket of
    /// the network the client is on.
    fn send_dns(&mut self, hosts: &mut [HostIf], actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Reply { to, data, .. } if to == ntp::SELF_CLIENT => {
                    if let Some(n) = self.ntp.as_mut() {
                        n.dns_answer(&data, now_ms());
                    }
                }
                Action::Reply { to, data, tcp: true } => {
                    // The connection's network (the one its query came in on).
                    for net in &mut self.nets {
                        let sockets = &mut hosts[net.host].sockets;
                        if net.dns_tcp.as_mut().is_some_and(|l| l.send(sockets, to, &data, now_ms())) {
                            break;
                        }
                    }
                }
                Action::Reply { to, data, tcp: false } => {
                    // The client's network: its IPv4 subnet, or its IPv6
                    // address in the network's ULA /64 (a client asking the
                    // router's ULA asks from its own ULA, RFC 6724); else
                    // the network whose `[[route]]` leads to it (a host
                    // behind a router there).
                    let ula64 = |n: &Net, ip: Ipv6Addr| n.cfg.ula.is_some_and(|u| u128::from(u) >> 64 == u128::from(ip) >> 64);
                    let mine = |n: &&Net| match to.ip() {
                        IpAddr::V4(ip) => n.cfg.reaches(ip),
                        IpAddr::V6(ip) => ula64(n, ip),
                    };
                    let net = self.nets.iter().find(mine).or_else(|| {
                        let IpAddr::V6(ip) = to.ip() else {
                            return None;
                        };
                        let via = crate::config::static_routes6().into_iter().find(|&(dst, len, _)| {
                            let m = if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len.min(128))) };
                            u128::from(ip) & m == u128::from(dst) & m
                        })?;
                        self.nets.iter().find(|n| ula64(n, via.2))
                    });
                    let Some(net) = net else {
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
                    let ep = IpEndpoint::new(server.into(), self.udp_port(server));
                    if let Some(up) = self.upstream.as_mut() {
                        up.send(&mut hosts[0], ep, &data, now_ms());
                    }
                }
            }
        }
    }

    /// Process received datagrams and timers. Called by the services task
    /// after polling the interfaces (`hosts` as in [`Self::new`];
    /// `links[i]` is `hosts[i]`'s link).
    pub fn step(&mut self, hosts: &mut [HostIf], sh: &Shared) {
        let links = &sh.links;
        let now_aaaa = now_ms();
        if now_aaaa >= self.next_aaaa {
            self.next_aaaa = now_aaaa + AAAA_EVERY_MS;
            self.refresh_aaaa(sh, now_aaaa);
        }
        // Router Advertisements: solicited, periodic, last ones.
        let now = now_ms();
        for net in &mut self.nets {
            let Some(ra) = net.ra.as_mut() else { continue };
            if links[net.host].rs_seen.swap(false, core::sync::atomic::Ordering::Relaxed) {
                ra.solicited(now);
            }
            if let Some(f) = ra.poll(now) {
                send_frame(sh, net.host, &f);
            }
        }
        for (link, ra) in &mut self.retiring {
            if let Some(f) = ra.poll(now) {
                send_frame(sh, *link, &f);
            }
        }
        self.retiring.retain(|(_, ra)| !ra.is_done());

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
            let host = &mut hosts[host];
            let queries = match self.nets[i].dns_tcp.as_mut() {
                Some(l) => l.recv(&mut host.sockets, now_ms()),
                None => Vec::new(),
            };
            for (client, q) in queries {
                let actions = self.dns.handle_query_tcp(now_ms(), client, View::network(i), &q);
                self.send_dns(hosts, actions);
            }
        }
        // DNS: upstream responses. Over TLS only from the TLS connections:
        // a UDP datagram is never an answer then (no query went out by UDP,
        // so one with a pending ID is spoofed).
        let answers = self.upstream.as_mut().map(|up| up.recv(&mut hosts[0], now_ms())).unwrap_or_default();
        for (ep, data) in answers {
            let from = IpAddr::from(ep.addr);
            if self.tls || ep.port != self.udp_port(from) {
                continue;
            }
            let actions = self.dns.handle_upstream(now_ms(), from, &data);
            self.send_dns(hosts, actions);
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

        for net in &mut self.nets {
            if let Some(l) = net.dns_tcp.as_mut() {
                l.step(&mut hosts[net.host].sockets, now_ms());
            }
        }

        self.mdns.step(hosts, links);
    }

    /// IPv6 per network: (name, router ULA, RAs sent, solicitations seen).
    pub fn ipv6_status(&self) -> Vec<(&str, Option<core::net::Ipv6Addr>, u64, u64)> {
        self.nets
            .iter()
            .map(|n| (n.cfg.name.as_str(), n.cfg.ula, n.ra.as_ref().map_or(0, |r| r.sent), n.ra.as_ref().map_or(0, |r| r.solicits)))
            .collect()
    }

    /// DNS over TCP: connections accepted since boot, open now.
    pub fn dns_tcp_status(&self) -> (u64, usize) {
        let open = self.nets.iter().filter_map(|n| n.dns_tcp.as_ref()).map(dns_tcp::Listener::open_conns).sum();
        (dns_tcp::accepted(), open)
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
        if let Some(at) = self.nets.iter().filter_map(|n| n.dns_tcp.as_ref()?.next_deadline()).min() {
            wait_ms = wait_ms.min(at.saturating_sub(ms_now));
        }
        if self.mdns.wants_soon() {
            wait_ms = wait_ms.min(MDNS_RECHECK_MS);
        }
        if let Some(at) = self.dot.as_ref().and_then(Dot::next_deadline) {
            wait_ms = wait_ms.min(at.saturating_duration_since(timer::Instant::now()).as_millis() as u64);
        }
        let ras = self.nets.iter().filter_map(|n| n.ra.as_ref()).chain(self.retiring.iter().map(|(_, ra)| ra));
        if let Some(at) = ras.filter_map(Advertiser::next_deadline).min() {
            wait_ms = wait_ms.min(at.saturating_sub(ms_now));
        }
        timer::Instant::now()
            .checked_add(core::time::Duration::from_millis(wait_ms))
            .expect("deadline overflow")
    }
}
