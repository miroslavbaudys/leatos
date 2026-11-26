//! The DHCPv4 client (`proto_dhcp::v4::client`): what the ISP side (or
//! anyone on the WAN segment) controls. Structured: replies to the client's
//! last message (its xid and MAC, so they reach the state machine) with
//! fuzzed kinds, addresses, masks, routers, DNS, lease times, T1/T2 and
//! server identifiers, damaged copies, raw bytes, link resets and time
//! passing. Checks: never a panic; every message is a well-formed request
//! from our MAC, from 0.0.0.0 to broadcast unless renewing / rebinding
//! (then from the leased address); a held lease is a host address with a
//! contiguous mask, at most 4 DNS servers and no router equal to itself;
//! `Lost` only after `Bound`; the next deadline is never in the past.
#![no_main]

use arbitrary::Arbitrary;
use core::net::Ipv4Addr;
use leatos_fuzz::damage;
use libfuzzer_sys::fuzz_target;
use proto_dhcp::v4::client::{Client, Config, Event, State};
use proto_dhcp::v4::packet::{Message, MessageType, OP_REPLY, OP_REQUEST, Options};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

#[derive(Arbitrary, Debug)]
enum Op {
    /// Answer the last message: kind (OFFER, ACK, NAK, other), yiaddr,
    /// mask, router, DNS, lease, T1, T2, server id, MTU.
    Answer {
        kind: u8,
        yiaddr: u32,
        mask_len: Option<u8>,
        routers: Vec<u32>,
        dns: Vec<u32>,
        lease: Option<u32>,
        t1: Option<u32>,
        t2: Option<u32>,
        server: Option<u8>,
        mtu: Option<u16>,
        noise: Option<Vec<u8>>,
    },
    Raw(Vec<u8>),
    Reset,
    Tick(u32),
}

fn addr(a: u32) -> Ipv4Addr {
    // Mostly the ISP's /24, sometimes anything.
    if a & 0x8000_0000 == 0 { Ipv4Addr::new(203, 0, 113, a as u8) } else { Ipv4Addr::from(a) }
}

fuzz_target!(|input: (bool, Vec<Op>)| {
    let (reboot, ops) = input;
    let last = reboot.then_some(Ipv4Addr::new(203, 0, 113, 50));
    let cfg = Config { mac: MAC, hostname: None, last, broadcast: false };
    let mut c = Client::new(cfg, 0, 0x5eed);
    let mut now = 0u64;
    let mut last_xid: Option<u32> = None;
    let mut bound = false;
    for op in ops.into_iter().take(100) {
        match op {
            Op::Answer { kind, yiaddr, mask_len, routers, dns, lease, t1, t2, server, mtu, noise } => {
                let Some(xid) = last_xid else { continue };
                let msg_type = match kind % 4 {
                    0 => Some(MessageType::Offer),
                    1 => Some(MessageType::Ack),
                    2 => Some(MessageType::Nak),
                    _ => None,
                };
                let mask = mask_len.map(|l| Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(l % 33)).unwrap_or(0)));
                let m = Message {
                    op: OP_REPLY,
                    xid,
                    secs: 0,
                    flags: 0,
                    ciaddr: Ipv4Addr::UNSPECIFIED,
                    yiaddr: addr(yiaddr),
                    siaddr: Ipv4Addr::UNSPECIFIED,
                    giaddr: Ipv4Addr::UNSPECIFIED,
                    chaddr: MAC,
                    options: Options {
                        msg_type,
                        server_id: server.map(|s| Ipv4Addr::new(203, 0, 113, s % 4)),
                        subnet_mask: mask,
                        routers: routers.into_iter().take(8).map(addr).collect(),
                        dns: dns.into_iter().take(16).map(addr).collect(),
                        lease_time: lease,
                        renewal_t1: t1,
                        rebinding_t2: t2,
                        mtu,
                        ..Default::default()
                    },
                };
                let mut b = m.emit();
                if let Some(n) = &noise {
                    damage(&mut b, n);
                }
                c.handle(now, &b);
            }
            Op::Raw(data) => c.handle(now, &data),
            Op::Reset => c.reset(now),
            Op::Tick(ms) => now += u64::from(ms % 8_000_000),
        }
        if let Some(t) = c.poll(now) {
            let m = Message::parse(&t.payload).expect("the client's message parses");
            assert_eq!((m.op, m.chaddr), (OP_REQUEST, MAC));
            assert!(matches!(m.options.msg_type, Some(MessageType::Discover | MessageType::Request)));
            match c.state() {
                State::Renewing | State::Rebinding => {
                    let l = c.lease().expect("renewing without a lease");
                    assert_eq!((t.src, m.ciaddr), (l.address, l.address));
                    assert!(t.dst == l.server || t.dst == Ipv4Addr::BROADCAST);
                }
                State::Bound => panic!("sent while bound"),
                _ => assert_eq!((t.src, t.dst, m.ciaddr), (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, Ipv4Addr::UNSPECIFIED)),
            }
            last_xid = Some(m.xid);
            assert!(c.poll(now).is_none(), "two messages at one instant");
        }
        assert!(c.next_deadline() > now, "deadline {} at {now}", c.next_deadline());
        while let Some(e) = c.poll_event() {
            match e {
                Event::Bound(_) => bound = true,
                Event::Lost => {
                    assert!(bound, "Lost without a lease");
                    bound = false;
                }
            }
        }
        assert_eq!(bound, c.lease().is_some(), "events and the held lease agree");
        if let Some(l) = c.lease() {
            assert!((1..=32).contains(&l.prefix_len));
            let o = l.address.octets();
            assert!(o[0] != 0 && o[0] != 127 && o[0] < 224, "{}", l.address);
            assert!(l.dns.len() <= 4 && l.router != Some(l.address));
            assert!(l.mtu.is_none_or(|m| m >= 576));
        }
    }
});
