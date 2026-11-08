//! LAN services: DHCPv4 server and DNS forwarder.
//!
//! Thin glue between smoltcp UDP sockets and the sans-IO crates
//! (`proto_dhcp::v4::server`, `proto_dns::resolver`): receive datagrams, feed
//! them in with the current time, and send what comes out. DHCP lease events
//! update the DNS zone (`host.lan`). WAN DHCP supplies the DNS upstreams.
//!
//! Sockets: LAN `0.0.0.0:67` (DHCP), LAN `:53` (DNS from clients), WAN
//! `:<random high port>` (queries to upstream servers).

use crate::config;
use crate::net::stack::NetIf;
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
}

fn udp_socket(datagrams: usize, bytes: usize) -> udp::Socket<'static> {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; datagrams], vec![0; bytes]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; datagrams], vec![0; bytes]);
    udp::Socket::new(rx, tx)
}

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

fn now_secs() -> u64 {
    timer::uptime().as_secs()
}

impl LanServices {
    pub fn new(lan: &mut NetIf, wan: Option<&mut NetIf>) -> Self {
        let cfg = config::lan();
        let dns_cfg = config::dns();

        let dhcp_cfg = dhcp::Config {
            server_ip: cfg.addr,
            netmask: cfg.netmask(),
            router: Some(cfg.addr),
            dns: vec![cfg.addr],
            domain: Some(cfg.domain.into()),
            range: cfg.dhcp_range,
            lease_secs: cfg.lease_secs,
            statics: cfg.statics.clone(),
        };
        let mut zone = Zone::new(cfg.domain, cfg.addr, (cfg.addr, cfg.prefix));
        for s in &cfg.statics {
            if let Some(h) = &s.hostname {
                zone.add(h, s.ip, Source::Static);
            }
        }
        let dns = Resolver::new(
            resolver::Config {
                cache_entries: dns_cfg.cache_entries,
                rebind_protection: dns_cfg.rebind_protection,
                ..Default::default()
            },
            zone,
            timer::ticks() as u32,
        );

        let mut s = udp_socket(8, 8 * 600);
        s.bind(SERVER_PORT).expect("bind :67");
        let dhcp_sock = lan.sockets.add(s);
        let mut s = udp_socket(32, 32 * 1024);
        s.bind(DNS_PORT).expect("bind :53");
        let dns_sock = lan.sockets.add(s);
        let upstream_sock = wan.map(|wan| {
            let port = 40_000 + (timer::ticks() % 20_000) as u16;
            let mut s = udp_socket(32, 32 * 4096);
            s.bind(port).expect("bind upstream port");
            wan.sockets.add(s)
        });

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
        }
    }

    /// The WAN lease changed: new upstream DNS servers.
    pub fn set_upstreams(&mut self, servers: &[Ipv4Addr]) {
        self.dns.set_upstreams(servers);
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
        // DNS: retries / timeouts.
        let actions = self.dns.poll(now_ms());
        self.send_dns(lan, wan, actions);
    }

    /// When `step` must run again even without traffic.
    pub fn next_deadline(&self) -> timer::Instant {
        let ms_now = now_ms();
        let dns_in = self.dns.next_deadline().map(|d| d.saturating_sub(ms_now));
        let expire_in = self.next_expire.saturating_sub(now_secs()) * 1000;
        let wait_ms = dns_in.map_or(expire_in, |d| d.min(expire_in));
        timer::Instant::now()
            .checked_add(core::time::Duration::from_millis(wait_ms))
            .expect("deadline overflow")
    }
}
