//! The DNS forwarder (`crates/proto-dns`): queries from LAN clients (UDP
//! and TCP, per view) and answers from upstream servers, which the
//! internet controls. Upstream answers are built for the resolver's own
//! last upstream query (so they match its pending state: cache, prefetch,
//! serve-stale, rebind protection, truncation), damaged copies of them, or
//! raw bytes. Also every `wire` helper on raw input. Checks: replies go to
//! the client that asked; a reply to a UDP query fits 65535 bytes.
#![no_main]

use arbitrary::Arbitrary;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use libfuzzer_sys::fuzz_target;
use proto_dns::resolver::{Action, Config, Resolver};
use proto_dns::wire::{self, Rdata};
use proto_dns::zone::{Source, View, Zone};
use leatos_fuzz::{Addr, damage};

const UP: [Ipv4Addr; 2] = [Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)];
const NAMES: &[&str] = &[
    "example.com",
    "www.example.com",
    "nas.lan",
    "router.lan",
    "x.guest.lan",
    "10.1.168.192.in-addr.arpa",
    "1.0.0.10.in-addr.arpa",
    "lan",
    "",
    "a.b.c.d.e.f.g.h.example",
];

/// An AAAA address: one rebind protection must refuse or let through, or any.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Addr6 {
    Pick(u8),
    Any(u128),
}

const ADDRS6: &[&str] = &["::1", "::", "fe80::1", "fd00::53", "::ffff:192.168.1.10", "::ffff:8.8.8.8", "2001:db8::1", "fec0::1"];

impl Addr6 {
    fn get(self) -> Ipv6Addr {
        match self {
            Addr6::Pick(i) => ADDRS6[i as usize % ADDRS6.len()].parse().unwrap(),
            Addr6::Any(v) => Ipv6Addr::from(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    Query { client: u8, view: u8, tcp: bool, id: u16, name: u8, qtype: u16, edns: bool, noise: Option<Vec<u8>> },
    RawQuery { client: u8, tcp: bool, data: Vec<u8> },
    /// Answer the resolver's last upstream query.
    Answer { rcode: u8, answers: Vec<(Addr, u32)>, aaaa: Vec<(Addr6, u32)>, ptr: Option<u8>, wrong_server: bool, truncated: bool, noise: Option<Vec<u8>> },
    RawUpstream { server: bool, data: Vec<u8> },
    Tick(u16),
    WireHelpers(Vec<u8>),
}

fn client(n: u8) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100 + n % 4), 40000 + u16::from(n)))
}

fn wire_helpers(b: &[u8]) {
    let _ = wire::parse_query(b);
    if let Ok(recs) = wire::records(b) {
        let _ = wire::answer_ipv4s(b, &recs);
        let _ = wire::answer_ipv6s(b, &recs);
    }
    let _ = wire::error_response(b, wire::RCODE_FORMERR);
    let _ = wire::udp_limit(b, 1232);
    let _ = (wire::dnssec_ok(b), wire::has_edns(b), wire::ede_codes(b), wire::is_truncated(b));
    let _ = wire::add_ede(&mut b.to_vec(), 22, "fuzz", false);
    let _ = wire::with_edns_size(b);
    let mut s = b.to_vec();
    if wire::strip_opt(&mut s) {
        assert!(!wire::has_edns(&s), "OPT left after strip_opt");
    }
    let _ = wire::read_name(b, 12);
}

fuzz_target!(|ops: Vec<Op>| {
    let mut z = Zone::new("lan", Ipv4Addr::new(192, 168, 1, 1), (Ipv4Addr::new(192, 168, 1, 0), 24));
    z.add("nas", Ipv4Addr::new(192, 168, 1, 10), Source::Static);
    z.add_in("guest.lan", "x", Ipv4Addr::new(192, 168, 20, 5), Source::Dhcp, View(0b10));
    z.add_override("files.example.com", Ipv4Addr::new(192, 168, 1, 10), View(0b01));
    let cfg = Config { cache_entries: 32, max_pending: 8, max_stale_secs: 600, ..Config::default() };
    let mut r = Resolver::new(cfg, z, 0x5eed);
    r.set_upstreams(&UP);
    let mut now = 1_000u64;
    let mut last_up: Option<(core::net::IpAddr, Vec<u8>)> = None;
    let mut asked: Vec<SocketAddr> = Vec::new();
    for op in ops.into_iter().take(150) {
        let actions = match op {
            Op::Query { client: c, view, tcp, id, name, qtype, edns, noise } => {
                let name = NAMES[name as usize % NAMES.len()];
                let qtype = [wire::TYPE_A, wire::TYPE_AAAA, wire::TYPE_PTR, wire::TYPE_SOA, qtype][qtype as usize % 5];
                let mut q = wire::build_query(id, name, qtype);
                if edns {
                    q = wire::with_edns_size(&q);
                }
                if let Some(n) = &noise {
                    damage(&mut q, n);
                }
                asked.push(client(c));
                let view = View(1 << (view % 3));
                if tcp {
                    r.handle_query_tcp(now, client(c), view, &q)
                } else {
                    r.handle_query_in(now, client(c), view, &q)
                }
            }
            Op::RawQuery { client: c, tcp, data } => {
                asked.push(client(c));
                if tcp {
                    r.handle_query_tcp(now, client(c), View(1), &data)
                } else {
                    r.handle_query(now, client(c), &data)
                }
            }
            Op::Answer { rcode, answers, aaaa, ptr, wrong_server, truncated, noise } => {
                let Some((server, q)) = &last_up else { continue };
                let Ok((_, _, end)) = wire::parse_query(q) else { continue };
                let mut recs: Vec<(Rdata, u32)> = answers.iter().take(20).map(|(a, ttl)| (Rdata::A(a.get()), *ttl % 100_000)).collect();
                recs.extend(aaaa.iter().take(20).map(|(a, ttl)| (Rdata::Aaaa(a.get()), *ttl % 100_000)));
                if let Some(p) = ptr {
                    recs.push((Rdata::Ptr(NAMES[p as usize % NAMES.len()].into()), 60));
                }
                let mut resp = wire::build_response(q, end, rcode % 6, &recs, false);
                if truncated {
                    resp[2] |= 0x02;
                }
                if let Some(n) = &noise {
                    damage(&mut resp, n);
                }
                let from = if wrong_server { core::net::IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6)) } else { *server };
                r.handle_upstream(now, from, &resp)
            }
            Op::RawUpstream { server, data } => r.handle_upstream(now, UP[usize::from(server)], &data),
            Op::Tick(ms) => {
                now += u64::from(ms) * 10;
                r.poll(now)
            }
            Op::WireHelpers(b) => {
                wire_helpers(&b);
                continue;
            }
        };
        for a in actions {
            match a {
                Action::Upstream { server, data } => {
                    assert!(matches!(server, core::net::IpAddr::V4(a) if UP.contains(&a)), "query to a server that is not an upstream: {server}");
                    last_up = Some((server, data));
                }
                Action::Reply { to, data, tcp } => {
                    assert!(asked.contains(&to), "reply to {to}, who never asked");
                    assert!(tcp || data.len() <= 65_535);
                }
            }
        }
    }
});
