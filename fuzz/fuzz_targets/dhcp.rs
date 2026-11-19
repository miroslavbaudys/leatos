//! The DHCPv4 server (`crates/proto-dhcp`): datagrams from any LAN client.
//! Messages built from fields (types, a few MACs, requested addresses,
//! hostnames, client ids), damaged ones, raw bytes; lease expiry, a
//! reconfiguration and a snapshot/restore round trip through the persist
//! format. Checks: no two leases share an address; dynamic leases stay in
//! the pool; persist decodes what it encoded.
#![no_main]

use arbitrary::Arbitrary;
use core::net::Ipv4Addr;
use libfuzzer_sys::fuzz_target;
use proto_dhcp::v4::packet::{Message, Options};
use proto_dhcp::v4::persist;
use proto_dhcp::v4::server::{Config, Server, StaticLease};
use leatos_fuzz::{Addr, damage};

#[derive(Arbitrary, Debug)]
enum Op {
    Msg {
        kind: u8,
        mac: u8,
        requested: Option<Addr>,
        server_id: Option<Addr>,
        ciaddr: Option<Addr>,
        hostname: Option<String>,
        client_id: Option<Vec<u8>>,
        params: Vec<u8>,
        noise: Option<Vec<u8>>,
    },
    Raw(Vec<u8>),
    Tick(u32),
    Reconfigure { small_pool: bool },
    Persist,
}

fn config(small: bool) -> Config {
    let last = if small { 103 } else { 199 };
    Config {
        server_ip: Ipv4Addr::new(192, 168, 1, 1),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain: Some("lan".into()),
        range: (Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, last)),
        lease_secs: 3600,
        statics: vec![StaticLease { mac: [2, 0, 0, 0, 0, 10], ip: Ipv4Addr::new(192, 168, 1, 10), hostname: Some("nas".into()) }],
        routes: vec![(Ipv4Addr::new(10, 30, 0, 0), 24, Ipv4Addr::new(192, 168, 1, 100))],
    }
}

fn check(s: &Server) {
    let mut ips: Vec<Ipv4Addr> = s.leases().map(|l| l.ip).collect();
    let n = ips.len();
    ips.sort();
    ips.dedup();
    assert_eq!(ips.len(), n, "two leases share an address");
    let (lo, hi) = s.config().range;
    for l in s.leases() {
        let is_static = s.config().statics.iter().any(|st| st.mac == l.mac && st.ip == l.ip);
        assert!(is_static || (lo..=hi).contains(&l.ip), "lease {} outside the pool", l.ip);
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut s = Server::new(config(false));
    let mut now = 1_000u64;
    for op in ops.into_iter().take(150) {
        match op {
            Op::Msg { kind, mac, requested, server_id, ciaddr, hostname, client_id, params, noise } => {
                let mut opts = Options::default();
                let mut b = Message {
                    op: 1,
                    xid: u32::from(mac) * 7,
                    secs: 0,
                    flags: 0,
                    ciaddr: ciaddr.map_or(Ipv4Addr::UNSPECIFIED, Addr::get),
                    yiaddr: Ipv4Addr::UNSPECIFIED,
                    siaddr: Ipv4Addr::UNSPECIFIED,
                    giaddr: Ipv4Addr::UNSPECIFIED,
                    chaddr: [2, 0, 0, 0, 0, mac % 16],
                    options: Options::default(),
                };
                opts.requested_ip = requested.map(Addr::get);
                opts.server_id = server_id.map(Addr::get);
                opts.hostname = hostname;
                opts.client_id = client_id;
                opts.param_request = params;
                b.options = opts;
                // The type: emit with Discover, then patch the option value.
                let mut d = b.emit();
                if let Some(i) = d.windows(3).position(|w| w[0] == 53 && w[1] == 1) {
                    d[i + 2] = kind % 9;
                }
                if let Some(n) = &noise {
                    damage(&mut d, n);
                }
                let _ = s.handle(now, &d);
            }
            Op::Raw(d) => {
                if let Ok(m) = Message::parse(&d) {
                    let _ = Message::parse(&m.emit()).expect("emit of a parsed message parses");
                }
                let _ = s.handle(now, &d);
            }
            Op::Tick(secs) => {
                now += u64::from(secs % 100_000);
                let _ = s.expire(now);
            }
            Op::Reconfigure { small_pool } => {
                let _ = s.reconfigure(now, config(small_pool));
            }
            Op::Persist => {
                let saved = s.snapshot();
                let nets = vec![persist::Network { name: "lan".into(), leases: saved.clone() }];
                let enc = persist::encode(&nets);
                let dec = persist::decode(&enc).expect("persist decodes what it encoded");
                assert_eq!(dec, nets);
                let mut t = Server::new(s.config().clone());
                let _ = t.restore(now, &saved);
                check(&t);
            }
        }
        check(&s);
    }
});
