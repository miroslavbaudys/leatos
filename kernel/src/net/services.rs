//! LAN services: DHCPv4 server and DNS forwarder, plus the SNTP client
//! (`net::ntp`), which resolves its server names through the forwarder.
//!
//! Thin glue between smoltcp UDP sockets and the sans-IO crates
//! (`proto_dhcp::v4::server`, `proto_dns::resolver`): receive datagrams, feed
//! them in with the current time, and send what comes out. DHCP lease events
//! update the DNS zone (`host.lan`). WAN DHCP supplies the DNS upstreams.
//!
//! Sockets: LAN `0.0.0.0:67` (DHCP), LAN `:53` (DNS from clients), WAN
//! `:<random high port>` (queries to upstream servers).

use crate::config;
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

pub struct LanServices {
    dhcp: dhcp::Server,
    dhcp_sock: SocketHandle,
    dns: Resolver,
    dns_sock: SocketHandle,
    upstream_sock: Option<SocketHandle>,
    next_expire: u64,
    /// SNTP over the WAN (none without a WAN).
    ntp: Option<Ntp>,
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

/// The local zone: the router, reservations with a hostname, and bound
/// DHCP leases with a hostname.
fn build_zone<'a>(cfg: &config::Lan, leases: impl Iterator<Item = &'a dhcp::Lease>) -> Zone {
    let mut zone = Zone::new(&cfg.domain, cfg.addr, (cfg.addr, cfg.prefix));
    for s in &cfg.statics {
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

impl LanServices {
    pub fn new(lan: &mut HostIf, wan: Option<&mut HostIf>) -> Self {
        let cfg = config::lan();
        let dns_cfg = config::dns();

        let dhcp_cfg = dhcp_config(&cfg);
        let zone = build_zone(&cfg, core::iter::empty());
        let dns = Resolver::new(resolver_config(&dns_cfg), zone, timer::ticks() as u32);

        let mut s = udp_socket(8, 8 * 600);
        s.bind(SERVER_PORT).expect("bind :67");
        let dhcp_sock = lan.sockets.add(s);
        let mut s = udp_socket(32, 32 * 1024);
        s.bind(DNS_PORT).expect("bind :53");
        let dns_sock = lan.sockets.add(s);
        let mut wan = wan;
        let upstream_sock = wan.as_deref_mut().map(|wan| {
            let port = 40_000 + (timer::ticks() % 20_000) as u16;
            let mut s = udp_socket(32, 32 * 4096);
            s.bind(port).expect("bind upstream port");
            wan.sockets.add(s)
        });
        let ntp = wan.map(Ntp::new);

        println!(
            "  lan services    : dhcp {}..{} ({} static), dns {}:53 (.{}), cache {}",
            cfg.dhcp_range.0,
            cfg.dhcp_range.1,
            cfg.statics.len(),
            cfg.addr,
            cfg.domain,
            dns_cfg.cache_entries
        );
        Self {
            dhcp: dhcp::Server::new(dhcp_cfg),
            dhcp_sock,
            dns,
            dns_sock,
            upstream_sock,
            next_expire: 0,
            ntp,
        }
    }

    /// Apply the current config (`config::apply`) without a restart:
    /// DHCP keeps the leases that are still valid, the DNS zone is rebuilt
    /// from the reservations and the bound leases, the cache keeps what
    /// fits. The LAN address itself never changes here (that is a trial
    /// and reboots).
    pub fn reconfigure(&mut self) {
        let cfg = config::lan();
        let dns_cfg = config::dns();
        let dropped = self
            .dhcp
            .reconfigure(now_secs(), dhcp_config(&cfg))
            .iter()
            .filter(|e| matches!(e, DhcpEvent::Released { .. }))
            .count();
        *self.dns.zone_mut() = build_zone(&cfg, self.dhcp.leases());
        self.dns.reconfigure(resolver_config(&dns_cfg));
        if let Some(n) = self.ntp.as_mut() {
            n.reconfigure();
        }
        println!(
            "  lan services    : reconfigured: dhcp {}..{} ({} static, {} lease(s) dropped), domain .{}, cache {}",
            cfg.dhcp_range.0,
            cfg.dhcp_range.1,
            cfg.statics.len(),
            dropped,
            cfg.domain,
            dns_cfg.cache_entries
        );
    }

    /// Current DHCP leases (status page).
    pub fn leases(&self) -> impl Iterator<Item = &dhcp::Lease> {
        self.dhcp.leases()
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

    fn apply_dhcp_events(&mut self, events: Vec<DhcpEvent>) {
        let domain = config::lan().domain;
        for ev in events {
            match ev {
                DhcpEvent::Bound { mac, ip, hostname } => {
                    println!(
                        "  dhcp            : {} -> {ip} ({}.{domain})",
                        smoltcp::wire::EthernetAddress(mac),
                        hostname.as_deref().unwrap_or("-")
                    );
                    if let Some(h) = hostname {
                        self.dns.zone_mut().add(&h, ip, Source::Dhcp);
                    }
                }
                DhcpEvent::Released { ip, hostname, .. } => {
                    if let Some(h) = hostname {
                        self.dns.zone_mut().remove_dhcp(&h, ip);
                    }
                }
            }
        }
    }

    fn send_dns(
        &mut self,
        lan: &mut SocketSet<'static>,
        wan: Option<&mut SocketSet<'static>>,
        actions: Vec<Action>,
    ) {
        let mut wan = wan;
        for a in actions {
            match a {
                Action::Reply { to, data } if to == ntp::SELF_CLIENT => {
                    if let Some(n) = self.ntp.as_mut() {
                        n.dns_answer(&data, now_ms());
                    }
                }
                Action::Reply { to, data } => {
                    let ep = IpEndpoint::new(to.ip().into(), to.port());
                    let _ = lan
                        .get_mut::<udp::Socket>(self.dns_sock)
                        .send_slice(&data, ep);
                }
                Action::Upstream { server, data } => {
                    if let (Some(h), Some(w)) = (self.upstream_sock, wan.as_deref_mut()) {
                        let ep = IpEndpoint::new(IpAddr::V4(server).into(), DNS_PORT);
                        let _ = w.get_mut::<udp::Socket>(h).send_slice(&data, ep);
                    }
                }
            }
        }
    }

    /// Process received datagrams and timers. Called by the network task
    /// after polling the interfaces.
    pub fn step(&mut self, lan: &mut SocketSet<'static>, mut wan: Option<&mut SocketSet<'static>>) {
        // DHCP server.
        let mut buf = [0u8; 1500];
        loop {
            let sock = lan.get_mut::<udp::Socket>(self.dhcp_sock);
            let Ok((n, _meta)) = sock.recv_slice(&mut buf) else {
                break;
            };
            let out = self.dhcp.handle(now_secs(), &buf[..n]);
            if let Some(reply) = out.reply {
                let ep = IpEndpoint::new(IpAddr::V4(Ipv4Addr::BROADCAST).into(), CLIENT_PORT);
                let _ = lan
                    .get_mut::<udp::Socket>(self.dhcp_sock)
                    .send_slice(&reply, ep);
            }
            self.apply_dhcp_events(out.events);
        }
        if now_secs() >= self.next_expire {
            self.next_expire = now_secs() + EXPIRE_EVERY_SECS;
            let ev = self.dhcp.expire(now_secs());
            self.apply_dhcp_events(ev);
        }

        // DNS: client queries.
        let mut qbuf = [0u8; 1500];
        loop {
            let sock = lan.get_mut::<udp::Socket>(self.dns_sock);
            let Ok((n, meta)) = sock.recv_slice(&mut qbuf) else {
                break;
            };
            let client = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
            let actions = self.dns.handle_query(now_ms(), client, &qbuf[..n]);
            self.send_dns(lan, wan.as_deref_mut(), actions);
        }
        // DNS: upstream responses.
        if let (Some(h), Some(w)) = (self.upstream_sock, wan.as_deref_mut()) {
            let mut rbuf = [0u8; 4096]; // EDNS responses may exceed 1500 B
            while let Ok((n, meta)) = w.get_mut::<udp::Socket>(h).recv_slice(&mut rbuf) {
                let from = match IpAddr::from(meta.endpoint.addr) {
                    IpAddr::V4(a) if meta.endpoint.port == DNS_PORT => a,
                    _ => continue,
                };
                let actions = self.dns.handle_upstream(now_ms(), from, &rbuf[..n]);
                self.send_dns(lan, None, actions);
            }
        }
        // SNTP: our own name lookups, then the protocol.
        let queries = self.ntp.as_mut().map(|n| n.lookups(now_ms())).unwrap_or_default();
        for q in queries {
            let actions = self.dns.handle_query(now_ms(), ntp::SELF_CLIENT, &q);
            self.send_dns(lan, wan.as_deref_mut(), actions);
        }
        if let (Some(n), Some(w)) = (self.ntp.as_mut(), wan.as_deref_mut()) {
            n.step(w);
        }

        // DNS: retries / timeouts.
        let actions = self.dns.poll(now_ms());
        self.send_dns(lan, wan, actions);
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
        timer::Instant::now()
            .checked_add(core::time::Duration::from_millis(wait_ms))
            .expect("deadline overflow")
    }
}
