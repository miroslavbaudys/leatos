//! mDNS (`crates/proto-mdns`): multicast from any host on any network the
//! reflector serves. Raw messages through the parser (a parsed message
//! rebuilds and parses to the same message) and the reflector with rules
//! between three networks. Checks: the reflector only sends to networks a
//! rule allows from the source network, never back to the source.
#![no_main]

use arbitrary::Arbitrary;
use core::net::{Ipv4Addr, SocketAddrV4};
use libfuzzer_sys::fuzz_target;
use proto_mdns::{Config, Net, Reflector, Rule, ServiceType};
use proto_mdns::wire::Message;

#[derive(Arbitrary, Debug)]
struct Pkt {
    from: u8,
    src: u8,
    port: bool,
    tick: u16,
    msg: Vec<u8>,
}

fn config() -> Config {
    let net = |a, b| Some(Net { addr: Ipv4Addr::new(192, 168, a, b), prefix_len: 24 });
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
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, third, p.src), if p.port { 5353 } else { 40000 });
        for out in r.handle(now, from, src, &p.msg) {
            assert_ne!(out.net, from, "reflected back to its own network");
            assert!(rules.iter().any(|ru| ru.from == from && ru.to.contains(&out.net)), "no rule {from} -> {}", out.net);
            assert!(out.msg.len() <= 9000);
        }
    }
});
