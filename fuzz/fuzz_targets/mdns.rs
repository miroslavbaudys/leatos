//! mDNS (`crates/proto-mdns`): multicast from any host on any network the
//! reflector serves. Raw messages through the parser (a parsed message
//! rebuilds and parses to the same message) and the reflector with rules
//! between three networks. Checks: the reflector only sends to networks a
//! rule allows from the source network, never back to the source, in the
//! family the message came in on.
#![no_main]

use arbitrary::Arbitrary;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use libfuzzer_sys::fuzz_target;
use proto_mdns::{Config, Net, Reflector, Rule, ServiceType};
use proto_mdns::wire::Message;

#[derive(Arbitrary, Debug)]
struct Pkt {
    from: u8,
    src: u8,
    port: bool,
    /// Over IPv6: link-local (0), a network's ULA /64, or elsewhere.
    v6: Option<u8>,
    tick: u16,
    msg: Vec<u8>,
}

fn config() -> Config {
    let net = |a, b| {
        let mut n = Net::v4(Ipv4Addr::new(192, 168, a, b), 24);
        n.addrs6 = [Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(a))), Some(Ipv6Addr::new(0xfd00, 0, 0, u16::from(a), 0, 0, 0, 1)), None];
        Some(n)
    };
    Config {
        nets: vec![net(1, 1), net(20, 1), net(30, 1)],
        rules: vec![
            Rule { from: 1, to: vec![0], services: vec![ServiceType::parse("_ipp._tcp").unwrap()] },
            Rule { from: 0, to: vec![1, 2], services: vec![ServiceType::parse("_airplay._tcp").unwrap(), ServiceType::parse("_raop._tcp").unwrap()] },
        ],
    }
}

fuzz_target!(|pkts: Vec<Pkt>| {
    let mut r = Reflector::new(config());
    let rules = config().rules;
    let mut now = 0u64;
    for p in pkts.into_iter().take(50) {
        if let Ok(m) = Message::parse(&p.msg) {
            if let Ok(b) = m.to_bytes() {
                let again = Message::parse(&b).expect("a rebuilt message parses");
                assert_eq!(again, m, "rebuild changed the message");
            }
        }
        now += u64::from(p.tick);
        let from = usize::from(p.from % 4);
        let third = [1, 20, 30, 40][from];
        let port = if p.port { 5353 } else { 40000 };
        let src: SocketAddr = match p.v6 {
            None => SocketAddrV4::new(Ipv4Addr::new(192, 168, third, p.src), port).into(),
            Some(k) => {
                let a = match k % 3 {
                    0 => Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(p.src)),
                    1 => Ipv6Addr::new(0xfd00, 0, 0, u16::from(third), 0, 0, 0, u16::from(p.src)),
                    _ => Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(p.src)),
                };
                SocketAddr::new(a.into(), port)
            }
        };
        for out in r.handle(now, from, src, &p.msg) {
            assert_eq!(out.v6, src.is_ipv6(), "another family");
            assert_ne!(out.net, from, "reflected back to its own network");
            assert!(rules.iter().any(|ru| ru.from == from && ru.to.contains(&out.net)), "no rule {from} -> {}", out.net);
            assert!(out.msg.len() <= 9000);
        }
    }
});
