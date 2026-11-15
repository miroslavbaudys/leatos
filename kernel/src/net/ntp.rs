//! SNTP client glue (`proto_sntp`): sets `crate::wallclock`.
//!
//! - Servers: `time.ntp_servers` (boot argument `ntp=a,b`). Names are
//!   resolved through the router's own DNS forwarder (`LanServices`
//!   hands our queries to its resolver as if from a client, with the
//!   [`SELF_CLIENT`] address, and routes the answers back here), so they
//!   share its cache, upstreams and port rules. IPv4 literals need no
//!   lookup.
//! - Transport: one UDP socket on the WAN interface, bound at a port
//!   ≥ 60000 (router-local, never mistaken for NAT or a port forward).
//! - Starts once the WAN has a lease (DNS upstreams known).

use crate::net::svc::HostIf;
use crate::{config, println, timer, wallclock};
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use proto_dns::wire;
use proto_sntp::packet::{LEN, PORT};
use proto_sntp::{Client, Sample};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;

/// The "client" address our own DNS lookups carry inside the resolver.
pub const SELF_CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
/// Retry an unresolved name after this long; re-resolve resolved ones
/// after [`RESOLVE_EVERY_MS`] (pool names rotate).
const RETRY_RESOLVE_MS: u64 = 30_000;
const RESOLVE_EVERY_MS: u64 = 3_600_000;
/// Steps the log reports after the first sync.
const LOG_STEP_NS: u64 = 100_000_000;

struct Server {
    name: String,
    addr: Option<Ipv4Addr>,
    /// The id of our lookup in flight, if any.
    lookup: Option<u16>,
    next_lookup_ms: u64,
}

pub struct Ntp {
    servers: Vec<Server>,
    client: Client<Ipv4Addr>,
    sock: SocketHandle,
    wan_up: bool,
    next_id: u16,
    synced_once: bool,
}

/// What the status page shows.
pub struct Status {
    pub servers: Vec<String>,
    pub server: Option<Ipv4Addr>,
    pub synced: Option<Sample>,
    pub interval_s: u64,
}

fn now_ns() -> u64 {
    timer::uptime().as_nanos() as u64
}

fn servers_from_config() -> Vec<Server> {
    config::ntp_servers()
        .into_iter()
        .map(|name| Server {
            addr: name.parse().ok(),
            name,
            lookup: None,
            next_lookup_ms: 0,
        })
        .collect()
}

impl Ntp {
    pub fn new(wan: &mut HostIf) -> Self {
        let rx = udp::PacketBuffer::new(vec_meta(4), alloc::vec![0; 4 * 64]);
        let tx = udp::PacketBuffer::new(vec_meta(4), alloc::vec![0; 4 * 64]);
        let mut s = udp::Socket::new(rx, tx);
        // 60000–64999: router-local, apart from the DNS upstream port.
        let port = 60_000 + (timer::ticks() % 5_000) as u16;
        s.bind(port).expect("bind ntp port");
        let servers = servers_from_config();
        if servers.is_empty() {
            println!("  ntp             : off (no servers)");
        }
        Ntp {
            servers,
            client: Client::new(timer::ticks()),
            sock: wan.sockets.add(s),
            wan_up: false,
            next_id: (timer::ticks() as u16) | 1,
            synced_once: false,
        }
    }

    /// The config changed: new server list, start over (the clock keeps
    /// its value until the next sync).
    pub fn reconfigure(&mut self) {
        let names: Vec<String> = config::ntp_servers();
        if names.iter().eq(self.servers.iter().map(|s| &s.name)) {
            return;
        }
        self.servers = servers_from_config();
        self.client.set_servers(&[]);
        self.client.restart(now_ns());
        println!("  ntp             : servers [{}]", names.join(", "));
    }

    /// The WAN lease came or went.
    pub fn set_wan(&mut self, up: bool) {
        if up && !self.wan_up {
            println!(
                "  ntp             : asking [{}]",
                self.servers
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        self.wan_up = up;
        if !up {
            self.client.set_servers(&[]);
        }
    }

    /// DNS queries to hand to the resolver now (as from [`SELF_CLIENT`]).
    pub fn lookups(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if !self.wan_up {
            return out;
        }
        for i in 0..self.servers.len() {
            let s = &self.servers[i];
            // A lookup still in flight at its deadline is given up on and
            // replaced (the reply would be ignored: unknown id).
            if now_ms < s.next_lookup_ms || s.name.parse::<Ipv4Addr>().is_ok() {
                continue;
            }
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let s = &mut self.servers[i];
            s.lookup = Some(id);
            s.next_lookup_ms = now_ms + RETRY_RESOLVE_MS;
            out.push(wire::build_query(id, &s.name, wire::TYPE_A));
        }
        out
    }

    /// The resolver's answer to one of our lookups.
    pub fn dns_answer(&mut self, data: &[u8], now_ms: u64) {
        let Ok(h) = wire::Header::parse(data) else { return };
        let Some(s) = self.servers.iter_mut().find(|s| s.lookup == Some(h.id)) else {
            return;
        };
        s.lookup = None;
        let recs = wire::records(data).unwrap_or_default();
        let addr = wire::answer_ipv4s(data, &recs).first().copied();
        if h.rcode() == wire::RCODE_NOERROR && addr.is_some() {
            if s.addr != addr {
                println!("  ntp             : {} is {}", s.name, addr.unwrap_or(Ipv4Addr::UNSPECIFIED));
            }
            s.addr = addr;
            s.next_lookup_ms = now_ms + RESOLVE_EVERY_MS;
        } else if s.addr.is_none() {
            println!("  ntp             : cannot resolve {} (rcode {})", s.name, h.rcode());
        }
    }

    /// Receive replies, send due requests, apply new estimates.
    pub fn step(&mut self, wan: &mut SocketSet<'static>) {
        if !self.wan_up {
            return;
        }
        let addrs: Vec<Ipv4Addr> = self.servers.iter().filter_map(|s| s.addr).collect();
        self.client.set_servers(&addrs);
        let sock = wan.get_mut::<udp::Socket>(self.sock);
        let mut buf = [0u8; 128];
        while let Ok((n, meta)) = sock.recv_slice(&mut buf) {
            if let (IpAddr::V4(from), PORT) = (IpAddr::from(meta.endpoint.addr), meta.endpoint.port) {
                self.client.handle(from, &buf[..n], now_ns());
            }
        }
        while let Some(req) = self.client.poll(now_ns()) {
            let ep = IpEndpoint::new(IpAddr::V4(req.server).into(), PORT);
            let _ = sock.send_slice(&req.data[..LEN], ep);
        }
        if let Some(s) = self.client.take_update() {
            let step = wallclock::now().map(|t| t.0 - s.offset - now_ns() as i64);
            wallclock::set(s.offset);
            let shown = !self.synced_once || step.is_some_and(|d| d.unsigned_abs() > LOG_STEP_NS);
            if shown {
                println!(
                    "  ntp             : synced to {} stratum {}, delay {} ms{}: {}",
                    self.client.status().server.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    s.stratum,
                    s.delay / 1_000_000,
                    step.map(|d| alloc::format!(", stepped {} ms", -d / 1_000_000))
                        .unwrap_or_default(),
                    wallclock::now().map(|t| alloc::format!("{t}")).unwrap_or_default()
                );
            }
            self.synced_once = true;
        }
    }

    /// When [`Self::step`] or [`Self::lookups`] must run next (ms of uptime).
    pub fn next_deadline_ms(&self) -> Option<u64> {
        if !self.wan_up {
            return None;
        }
        let client = self.client.next_deadline().map(|ns| ns.div_ceil(1_000_000));
        let lookup = self
            .servers
            .iter()
            .filter(|s| s.name.parse::<Ipv4Addr>().is_err())
            .map(|s| s.next_lookup_ms)
            .min();
        match (client, lookup) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn status(&self) -> Status {
        let st = self.client.status();
        Status {
            servers: self.servers.iter().map(|s| s.name.clone()).collect(),
            server: st.server,
            synced: st.synced,
            interval_s: st.interval / 1_000_000_000,
        }
    }
}

fn vec_meta(n: usize) -> Vec<udp::PacketMetadata> {
    alloc::vec![udp::PacketMetadata::EMPTY; n]
}
