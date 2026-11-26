use super::*;
use crate::v4::server::{self, Server, StaticLease};
use alloc::string::ToString;
use alloc::vec;

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const ISP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const ISP2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const ONE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 100);

fn cfg() -> Config {
    Config { mac: MAC, hostname: Some("leatos".to_string()), last: None, broadcast: false }
}

fn server_cfg(ip: Ipv4Addr, lease_secs: u32) -> server::Config {
    server::Config {
        server_ip: ip,
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        router: Some(ISP),
        dns: vec![ISP, Ipv4Addr::new(198, 51, 100, 53)],
        domain: Some("isp.example".to_string()),
        range: (ONE, Ipv4Addr::new(203, 0, 113, 150)),
        lease_secs,
        statics: Vec::<StaticLease>::new(),
        routes: Vec::new(),
    }
}

/// The client's message at `now` (ms), parsed.
fn sent(c: &mut Client, now: u64) -> Option<(Transmit, Message)> {
    c.poll(now).map(|t| {
        let m = Message::parse(&t.payload).unwrap();
        (t, m)
    })
}

fn sent_next(c: &mut Client) -> Option<(Transmit, Message)> {
    let t = c.next_deadline();
    sent(c, t)
}

/// One client message to the server (its clock in seconds) and the reply
/// back; whether there was a reply.
fn step(c: &mut Client, s: &mut Server, now: u64) -> bool {
    let Some(t) = c.poll(now) else { return false };
    match s.handle(now / 1000, &t.payload).reply {
        Some(r) => {
            c.handle(now, &r);
            true
        }
        None => false,
    }
}

fn events(c: &mut Client) -> Vec<Event> {
    core::iter::from_fn(|| c.poll_event()).collect()
}

/// Client and server until bound; returns the time.
fn bind(c: &mut Client, s: &mut Server, mut now: u64) -> u64 {
    for _ in 0..10 {
        now = now.max(c.next_deadline());
        step(c, s, now);
        if c.state() == State::Bound {
            return now;
        }
    }
    panic!("not bound: {:?}", c.state());
}

#[test]
fn dora_against_the_server() {
    let mut c = Client::new(cfg(), 0, 1);
    let mut s = Server::new(server_cfg(ISP, 3600));
    assert!(c.next_deadline() <= START_DELAY_MS, "starts within a second");

    let (t, d) = sent_next(&mut c).unwrap();
    assert_eq!((t.src, t.dst), (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    assert_eq!(d.options.msg_type, Some(MessageType::Discover));
    assert_eq!(d.chaddr, MAC);
    assert_eq!(d.options.client_id.as_deref(), Some(&[1, 0x52, 0x54, 0, 0x12, 0x34, 0x56][..]));
    assert_eq!(d.options.hostname.as_deref(), Some("leatos"));
    assert_eq!(d.flags, 0, "unicast replies are fine unless configured");
    assert_eq!(d.options.requested_ip, None);
    assert!(d.options.param_request.contains(&26), "asks for the MTU");

    let offer = s.handle(0, &t.payload).reply.unwrap();
    c.handle(0, &offer);
    assert_eq!(c.state(), State::Requesting);
    let (t, r) = sent(&mut c, 0).unwrap();
    assert_eq!(r.options.msg_type, Some(MessageType::Request));
    assert_eq!(r.options.server_id, Some(ISP));
    assert_eq!(r.options.requested_ip, Some(ONE));
    assert_eq!(r.ciaddr, Ipv4Addr::UNSPECIFIED);
    let ack = s.handle(0, &t.payload).reply.unwrap();
    c.handle(0, &ack);

    assert_eq!(c.state(), State::Bound);
    let lease = Lease {
        address: ONE,
        prefix_len: 24,
        router: Some(ISP),
        dns: vec![ISP, Ipv4Addr::new(198, 51, 100, 53)],
        domain: Some("isp.example".to_string()),
        mtu: None,
        server: ISP,
        lease_secs: 3600,
    };
    assert_eq!(events(&mut c), [Event::Bound(lease.clone())]);
    assert_eq!(c.lease(), Some(&lease));
    assert_eq!(c.next_deadline(), 1_800_000, "T1 from the server");
    assert!(c.poll(1_799_999).is_none());
    assert_eq!(c.stats(), Stats { sent: 2, received: 2, naks: 0, ignored: 0 });
}

#[test]
fn renews_unicast_at_t1_and_reports_only_changes() {
    let mut c = Client::new(cfg(), 0, 2);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let b = bind(&mut c, &mut s, 0);
    events(&mut c);

    let (t, r) = sent(&mut c, b + 1_800_000).unwrap();
    assert_eq!(c.state(), State::Renewing);
    assert_eq!((t.src, t.dst), (ONE, ISP), "unicast from the address to the server");
    assert_eq!(r.ciaddr, ONE);
    assert_eq!((r.options.server_id, r.options.requested_ip), (None, None), "§4.3.2");
    assert_eq!(r.flags, 0);
    c.handle(b + 1_800_000, &s.handle((b + 1_800_000) / 1000, &t.payload).reply.unwrap());
    assert_eq!(c.state(), State::Bound);
    assert!(events(&mut c).is_empty(), "same settings: no event");
    assert_eq!(c.next_deadline(), b + 3_600_000, "T1 counted from the renewal");

    // The server's DNS changed: the renewal reports it.
    let mut sc = server_cfg(ISP, 3600);
    sc.dns = vec![Ipv4Addr::new(198, 51, 100, 54)];
    s.reconfigure((b + 3_600_000) / 1000, sc);
    assert!(step(&mut c, &mut s, b + 3_600_000));
    match &events(&mut c)[..] {
        [Event::Bound(l)] => assert_eq!(l.dns, [Ipv4Addr::new(198, 51, 100, 54)]),
        e => panic!("{e:?}"),
    }
}

#[test]
fn rebinds_by_broadcast_when_the_server_is_gone() {
    let mut c = Client::new(cfg(), 0, 3);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let b = bind(&mut c, &mut s, 0);
    events(&mut c);
    // T1 = 1800 s, T2 = 3150 s: renewals unanswered, half the time left
    // each, at least 60 s.
    let mut now = b + 1_800_000;
    let mut renews = Vec::new();
    while now < b + 3_150_000 {
        if c.poll(now).is_some() {
            renews.push(now);
        }
        now = c.next_deadline();
    }
    assert_eq!(c.state(), State::Renewing);
    assert_eq!(&renews[..3], &[b + 1_800_000, b + 2_475_000, b + 2_812_500][..], "{renews:?}");
    for w in renews.windows(2) {
        assert!(w[1] - w[0] >= MIN_RENEW_RT_MS, "{renews:?}");
    }
    assert_eq!(now, b + 3_150_000, "T2 is a deadline");

    let (t, r) = sent(&mut c, now).unwrap();
    assert_eq!(c.state(), State::Rebinding);
    assert_eq!((t.src, t.dst), (ONE, Ipv4Addr::BROADCAST));
    assert_eq!(r.ciaddr, ONE);
    assert_eq!(r.options.server_id, None);
    // Another server of the ISP (same pool) answers.
    let mut s2 = Server::new(server_cfg(ISP2, 3600));
    c.handle(now, &s2.handle(now / 1000, &t.payload).reply.unwrap());
    assert_eq!(c.state(), State::Bound);
    assert_eq!(c.lease().unwrap().server, ISP2, "the new server from now on");
    assert!(events(&mut c).is_empty(), "same address, router and DNS");
    let (t, _) = sent_next(&mut c).unwrap();
    assert_eq!(t.dst, ISP2, "renews with the server that answered");
}

#[test]
fn lease_lost_at_its_end_then_asks_for_it_again() {
    let mut c = Client::new(cfg(), 0, 4);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let b = bind(&mut c, &mut s, 0);
    events(&mut c);
    let mut now = b;
    while now < b + 3_600_000 {
        c.poll(now);
        now = c.next_deadline();
    }
    assert_eq!(now, b + 3_600_000, "the end is a deadline");
    assert!(events(&mut c).is_empty());
    let (t, d) = sent(&mut c, now).unwrap();
    assert_eq!(events(&mut c), [Event::Lost]);
    assert!(c.lease().is_none());
    assert_eq!(c.state(), State::Selecting);
    assert_eq!((t.src, t.dst), (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    assert_eq!(d.options.requested_ip, Some(ONE), "asks for the old address");
    assert_eq!(d.ciaddr, Ipv4Addr::UNSPECIFIED);
}

#[test]
fn nak_while_renewing_starts_over() {
    let mut c = Client::new(cfg(), 0, 5);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let b = bind(&mut c, &mut s, 0);
    events(&mut c);
    // The ISP renumbered: the old address is outside its subnet now.
    let mut sc = server_cfg(ISP, 3600);
    sc.server_ip = Ipv4Addr::new(198, 51, 100, 1);
    sc.range = (Ipv4Addr::new(198, 51, 100, 100), Ipv4Addr::new(198, 51, 100, 150));
    sc.router = Some(sc.server_ip);
    let mut s = Server::new(sc);
    let (t, _) = sent(&mut c, b + 1_800_000).unwrap();
    let nak = s.handle((b + 1_800_000) / 1000, &t.payload).reply.unwrap();
    assert_eq!(Message::parse(&nak).unwrap().options.msg_type, Some(MessageType::Nak));
    // From the server we hold (renewing): a NAK from another one is
    // ignored. Our server here has a new identifier, so first as is:
    c.handle(b + 1_800_000, &nak);
    assert_eq!(c.state(), State::Renewing, "NAK from a server we did not ask");
    let mut m = Message::parse(&nak).unwrap();
    m.options.server_id = Some(ISP);
    c.handle(b + 1_800_000, &m.emit());
    assert_eq!(events(&mut c), [Event::Lost]);
    assert_eq!(c.state(), State::Selecting);
    assert_eq!(c.stats().naks, 1);
    let (_, d) = sent(&mut c, b + 1_800_000).unwrap();
    assert_eq!(d.options.requested_ip, None, "not the refused address");
    let now = bind(&mut c, &mut s, b + 1_800_000);
    assert_eq!(c.lease().unwrap().address, Ipv4Addr::new(198, 51, 100, 100));
    assert!(now < b + 1_800_000 + 10_000);
}

#[test]
fn init_reboot_with_the_stored_address() {
    // The server still has the binding (or the address is free): ACK.
    let mut s = Server::new(server_cfg(ISP, 3600));
    let mut c = Client::new(Config { last: Some(Ipv4Addr::new(203, 0, 113, 120)), ..cfg() }, 0, 6);
    assert_eq!(c.state(), State::Rebooting);
    let (t, r) = sent_next(&mut c).unwrap();
    assert_eq!(r.options.msg_type, Some(MessageType::Request));
    assert_eq!(r.options.requested_ip, Some(Ipv4Addr::new(203, 0, 113, 120)));
    assert_eq!(r.options.server_id, None, "§3.2 INIT-REBOOT");
    assert_eq!(r.ciaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!((t.src, t.dst), (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    c.handle(0, &s.handle(0, &t.payload).reply.unwrap());
    assert_eq!(c.state(), State::Bound);
    assert_eq!(c.lease().unwrap().address, Ipv4Addr::new(203, 0, 113, 120));

    // Another network now: NAK, then DISCOVER without the hint.
    let mut sc = server_cfg(ISP, 3600);
    sc.server_ip = Ipv4Addr::new(198, 51, 100, 1);
    sc.range = (Ipv4Addr::new(198, 51, 100, 100), Ipv4Addr::new(198, 51, 100, 150));
    let mut s = Server::new(sc);
    let mut c = Client::new(Config { last: Some(Ipv4Addr::new(203, 0, 113, 120)), ..cfg() }, 0, 6);
    assert!({ let t = c.next_deadline(); step(&mut c, &mut s, t) });
    assert_eq!(c.state(), State::Selecting);
    assert!(events(&mut c).is_empty(), "nothing was held");
    let now = bind(&mut c, &mut s, 0);
    assert_eq!(c.lease().unwrap().address, Ipv4Addr::new(198, 51, 100, 100));
    assert!(now < 2_000);
}

#[test]
fn init_reboot_unanswered_falls_back_to_discover_for_the_same_address() {
    let last = Ipv4Addr::new(203, 0, 113, 120);
    let mut c = Client::new(Config { last: Some(last), ..cfg() }, 0, 7);
    let mut now = c.next_deadline();
    for _ in 0..REBOOT_TRIES {
        let (_, r) = sent(&mut c, now).unwrap();
        assert_eq!(r.options.msg_type, Some(MessageType::Request));
        now = c.next_deadline();
    }
    let (_, d) = sent(&mut c, now).unwrap();
    assert_eq!(d.options.msg_type, Some(MessageType::Discover));
    assert_eq!(d.options.requested_ip, Some(last));
    assert!(now < 16_000, "{now}");
    // A zero or broadcast `last` is no address: plain DISCOVER.
    let c = Client::new(Config { last: Some(Ipv4Addr::UNSPECIFIED), ..cfg() }, 0, 7);
    assert_eq!(c.state(), State::Selecting);
}

#[test]
fn retransmission_backs_off_with_jitter() {
    let mut c = Client::new(cfg(), 0, 8);
    let mut now = c.next_deadline();
    let mut times = Vec::new();
    let mut xids = Vec::new();
    for _ in 0..8 {
        let (_, d) = sent(&mut c, now).unwrap();
        assert!(c.poll(now).is_none(), "one per timeout");
        xids.push(d.xid);
        times.push(now);
        now = c.next_deadline();
    }
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    for (g, want) in gaps.iter().zip([4_000, 8_000, 16_000, 32_000, 64_000, 64_000, 64_000]) {
        assert!(g.abs_diff(want) <= JITTER_MS, "{gaps:?}");
    }
    assert!(xids.iter().all(|&x| x == xids[0]), "retransmissions keep the xid");
    assert_eq!(c.stats().sent, 8);
}

#[test]
fn unanswered_requests_start_over() {
    let mut c = Client::new(cfg(), 0, 9);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let t = c.poll(c.next_deadline()).unwrap();
    c.handle(0, &s.handle(0, &t.payload).reply.unwrap());
    let mut now = 0;
    for _ in 0..REQUEST_TRIES {
        let (_, r) = sent(&mut c, now).unwrap();
        assert_eq!(r.options.msg_type, Some(MessageType::Request));
        now = c.next_deadline();
    }
    let (_, d) = sent(&mut c, now).unwrap();
    assert_eq!(d.options.msg_type, Some(MessageType::Discover));
    assert_eq!(c.state(), State::Selecting);
}

#[test]
fn repeated_naks_are_spaced_out() {
    let mut c = Client::new(cfg(), 0, 10);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let mut now = c.next_deadline();
    let mut starts = Vec::new();
    for _ in 0..6 {
        // DISCOVER → OFFER, REQUEST → NAK (a server that refuses).
        let t = c.poll(now).unwrap();
        c.handle(now, &s.handle(now / 1000, &t.payload).reply.unwrap());
        let (t, _) = sent(&mut c, now).unwrap();
        let mut m = Message::parse(&s.handle(now / 1000, &t.payload).reply.unwrap()).unwrap();
        m.options.msg_type = Some(MessageType::Nak);
        c.handle(now, &m.emit());
        assert_eq!(c.state(), State::Selecting);
        now = c.next_deadline();
        starts.push(now);
    }
    let gaps: Vec<u64> = starts.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(gaps, [2_000, 4_000, 8_000, 16_000, 32_000], "{starts:?}");
    // A lease resets it.
    bind(&mut c, &mut s, now);
    assert_eq!(c.stats().naks, 6);
}

#[test]
fn ignores_what_is_not_an_answer() {
    let mut c = Client::new(cfg(), 0, 11);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let t = c.poll(c.next_deadline()).unwrap();
    let offer = s.handle(0, &t.payload).reply.unwrap();
    let base = Message::parse(&offer).unwrap();
    let mut bad = Vec::new();
    let mut m = base.clone();
    m.xid ^= 1;
    bad.push(("xid", m));
    let mut m = base.clone();
    m.chaddr[5] ^= 1;
    bad.push(("chaddr", m));
    let mut m = base.clone();
    m.op = OP_REQUEST;
    bad.push(("op", m));
    let mut m = base.clone();
    m.options.server_id = None;
    bad.push(("no server id", m));
    for a in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::LOCALHOST] {
        let mut m = base.clone();
        m.yiaddr = a;
        bad.push(("yiaddr", m));
    }
    let mut m = base.clone();
    m.options.msg_type = Some(MessageType::Ack);
    bad.push(("ACK while selecting", m));
    for (why, m) in &bad {
        c.handle(0, &m.emit());
        assert_eq!(c.state(), State::Selecting, "{why}");
    }
    c.handle(0, &[0; 3]);
    assert_eq!(c.stats().ignored, bad.len() as u64 + 1);
    assert_eq!(c.stats().received, 0);

    let before = c.stats().ignored;
    c.handle(0, &offer);
    let (t, _) = sent(&mut c, 0).unwrap();
    let ack = Message::parse(&s.handle(0, &t.payload).reply.unwrap()).unwrap();
    let mut bad = Vec::new();
    let mut m = ack.clone();
    m.options.server_id = Some(ISP2);
    bad.push(("another server's ACK", m));
    let mut m = ack.clone();
    m.options.subnet_mask = None;
    bad.push(("no mask", m));
    let mut m = ack.clone();
    m.options.subnet_mask = Some(Ipv4Addr::new(255, 0, 255, 0));
    bad.push(("mask with holes", m));
    let mut m = ack.clone();
    m.options.subnet_mask = Some(Ipv4Addr::UNSPECIFIED);
    bad.push(("/0", m));
    for a in [Ipv4Addr::new(203, 0, 113, 0), Ipv4Addr::new(203, 0, 113, 255)] {
        let mut m = ack.clone();
        m.yiaddr = a;
        bad.push(("network / broadcast address", m));
    }
    let mut m = ack.clone();
    m.options.msg_type = Some(MessageType::Offer);
    bad.push(("OFFER while requesting", m));
    for (why, m) in &bad {
        c.handle(0, &m.emit());
        assert_eq!(c.state(), State::Requesting, "{why}");
    }
    // Another server's NAK is no answer to our choice either.
    let mut m = ack.clone();
    m.options.msg_type = Some(MessageType::Nak);
    m.options.server_id = Some(ISP2);
    c.handle(0, &m.emit());
    assert_eq!(c.state(), State::Requesting);

    c.handle(0, &ack.emit());
    assert_eq!(c.state(), State::Bound);
    c.handle(0, &ack.emit());
    assert_eq!(c.stats().ignored, before + bad.len() as u64 + 2, "a duplicate ACK while bound");
}

#[test]
fn lease_checks_drop_bad_routers_and_dns() {
    let mut o = Options {
        subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 255)),
        routers: vec![Ipv4Addr::UNSPECIFIED, ONE, ISP],
        dns: vec![Ipv4Addr::BROADCAST, ISP, ISP, Ipv4Addr::new(239, 1, 1, 1), ISP2],
        domain: Some(String::new()),
        mtu: Some(500),
        ..Default::default()
    };
    // A /32 (point-to-point style): no network / broadcast check.
    let l = lease_of(&ONE, &o, ISP).unwrap();
    assert_eq!((l.prefix_len, l.router), (32, Some(ISP)), "first usable router that is not us");
    assert_eq!(l.dns, [ISP, ISP2], "deduplicated, unicast only");
    assert_eq!((l.domain, l.mtu), (None, None), "empty domain, MTU below 576");
    assert_eq!(l.lease_secs, DEFAULT_LEASE_SECS, "no option 51");
    o.dns = (1..=10).map(|i| Ipv4Addr::new(198, 51, 100, i)).collect();
    o.mtu = Some(1492);
    let l = lease_of(&ONE, &o, ISP).unwrap();
    assert_eq!(l.dns.len(), MAX_DNS);
    assert_eq!(l.mtu, Some(1492));
    // /31 (RFC 3021): both addresses are hosts.
    o.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 254));
    assert!(lease_of(&Ipv4Addr::new(203, 0, 113, 100), &o, ISP).is_some());
    assert!(lease_of(&Ipv4Addr::new(203, 0, 113, 101), &o, ISP).is_some());
}

/// A reply built byte by byte the way busybox udhcpd (the lab ISP) writes
/// one: siaddr set, the broadcast flag echoed, options in its order with
/// no T1 / T2, padding and an option we do not know. Not a capture: the
/// home line is PPPoE, so no real DHCPv4 replies are recorded.
fn udhcpd_reply(kind: u8, xid: u32, yiaddr: Ipv4Addr, extra: &[u8]) -> Vec<u8> {
    let mut b = vec![2, 1, 6, 0];
    b.extend_from_slice(&xid.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0x80, 0]); // secs, flags: broadcast
    b.extend_from_slice(&[0; 4]); // ciaddr
    b.extend_from_slice(&yiaddr.octets());
    b.extend_from_slice(&ISP.octets()); // siaddr: udhcpd fills it
    b.extend_from_slice(&[0; 4]); // giaddr
    b.extend_from_slice(&MAC);
    b.resize(236, 0);
    b.extend_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(&[53, 1, kind]);
    b.extend_from_slice(&[54, 4, 203, 0, 113, 1]);
    b.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10]); // 3600 s
    b.extend_from_slice(&[0, 0]); // pad
    b.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
    b.extend_from_slice(&[3, 4, 203, 0, 113, 1]);
    b.extend_from_slice(&[6, 8, 203, 0, 113, 1, 8, 8, 8, 8]);
    b.extend_from_slice(&[15, 11]);
    b.extend_from_slice(b"isp.example");
    b.extend_from_slice(&[43, 3, 1, 2, 3]); // vendor specific: skipped
    b.extend_from_slice(extra);
    b.push(255);
    b.resize(548, 0);
    b
}

#[test]
fn takes_replies_in_other_servers_formats() {
    let mut c = Client::new(cfg(), 0, 12);
    let (_, d) = sent_next(&mut c).unwrap();
    c.handle(0, &udhcpd_reply(2, d.xid, ONE, &[]));
    let (_, r) = sent(&mut c, 0).unwrap();
    assert_eq!((r.options.server_id, r.options.requested_ip), (Some(ISP), Some(ONE)));
    c.handle(0, &udhcpd_reply(5, r.xid, ONE, &[]));
    assert_eq!(c.state(), State::Bound);
    let l = c.lease().unwrap().clone();
    assert_eq!((l.address, l.prefix_len, l.router), (ONE, 24, Some(ISP)));
    assert_eq!(l.dns, [ISP, Ipv4Addr::new(8, 8, 8, 8)]);
    assert_eq!(l.domain.as_deref(), Some("isp.example"));
    // No T1/T2: 0.5 and 0.875 of the lease (§4.4.5).
    assert_eq!(c.next_deadline(), 1_800_000);
    let t = c.poll(1_800_000).unwrap();
    assert_eq!(t.dst, ISP);
    let mut now = 1_800_000;
    while c.state() == State::Renewing {
        now = c.next_deadline();
        c.poll(now);
    }
    assert_eq!(now, 3_150_000);

    // T1/T2 and the MTU (as dnsmasq or Kea may send them), T2 past the
    // lease ignored.
    let mut c = Client::new(cfg(), 0, 13);
    let (_, d) = sent_next(&mut c).unwrap();
    c.handle(0, &udhcpd_reply(2, d.xid, ONE, &[]));
    let (_, r) = sent(&mut c, 0).unwrap();
    let extra = [58, 4, 0, 0, 0x03, 0x84, 59, 4, 0, 1, 0, 0, 26, 2, 0x05, 0xd4];
    c.handle(0, &udhcpd_reply(5, r.xid, ONE, &extra));
    assert_eq!(c.lease().unwrap().mtu, Some(1492));
    assert_eq!(c.next_deadline(), 900_000, "T1 = 900 s");
    c.poll(900_000);
    let mut now = 900_000;
    while c.state() == State::Renewing {
        now = c.next_deadline();
        c.poll(now);
    }
    assert_eq!(now, 3_150_000, "T2 0x10000 s > lease: 0.875 instead");
}

#[test]
fn infinite_and_tiny_leases() {
    let mut c = Client::new(cfg(), 0, 14);
    let mut s = Server::new(server_cfg(ISP, u32::MAX));
    bind(&mut c, &mut s, 0);
    assert_eq!(c.next_deadline(), u64::MAX, "never renews");
    assert_eq!(c.lease_end(), Some(u64::MAX));
    assert!(c.poll(u64::MAX - 1).is_none());

    let mut c = Client::new(cfg(), 0, 15);
    let mut s = Server::new(server_cfg(ISP, 1));
    // The server's T1/T2 (0 and 0) are dropped as invalid.
    let now = bind(&mut c, &mut s, 0);
    assert_eq!(c.lease().unwrap().lease_secs, 1);
    assert_eq!(c.next_deadline(), now + 30_000, "lease taken as 60 s");
    assert_eq!(c.lease_end(), Some(now + 60_000));
}

#[test]
fn reset_drops_the_lease_and_asks_again() {
    let mut c = Client::new(cfg(), 0, 16);
    let mut s = Server::new(server_cfg(ISP, 3600));
    bind(&mut c, &mut s, 0);
    events(&mut c);
    c.reset(5_000);
    assert_eq!(events(&mut c), [Event::Lost]);
    let (t, d) = sent(&mut c, 5_000).unwrap();
    assert_eq!(d.options.msg_type, Some(MessageType::Discover));
    assert_eq!(d.options.requested_ip, Some(ONE));
    assert_eq!(t.src, Ipv4Addr::UNSPECIFIED);
    c.reset(6_000);
    assert!(events(&mut c).is_empty(), "nothing held: no second Lost");
}

#[test]
fn broadcast_flag_only_without_an_address() {
    let mut c = Client::new(Config { broadcast: true, ..cfg() }, 0, 17);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let (t, d) = sent_next(&mut c).unwrap();
    assert_eq!(d.flags, FLAG_BROADCAST);
    c.handle(0, &s.handle(0, &t.payload).reply.unwrap());
    let (t, r) = sent(&mut c, 0).unwrap();
    assert_eq!(r.flags, FLAG_BROADCAST);
    c.handle(0, &s.handle(0, &t.payload).reply.unwrap());
    let (_, r) = sent_next(&mut c).unwrap();
    assert_eq!(r.flags, 0, "renewing: the address is ours");
}

#[test]
fn secs_counts_from_the_exchange_start() {
    let mut c = Client::new(cfg(), 0, 18);
    let first = c.next_deadline();
    let (_, d) = sent(&mut c, first).unwrap();
    assert_eq!(d.secs, 0);
    let (_, d) = sent_next(&mut c).unwrap();
    assert!((3..=5).contains(&d.secs), "{}", d.secs);
}

#[test]
fn random_bytes_never_panic() {
    let mut c = Client::new(cfg(), 0, 19);
    let mut s = Server::new(server_cfg(ISP, 3600));
    let t = c.poll(c.next_deadline()).unwrap();
    let base = s.handle(0, &t.payload).reply.unwrap();
    let mut seed = 0x9e37_79b9_u32;
    for i in 0..20_000u64 {
        let mut b = base.clone();
        for _ in 0..6 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let k = (seed as usize) % b.len();
            b[k] = (seed >> 8) as u8;
        }
        b.truncate((seed as usize >> 4) % (b.len() + 1));
        c.handle(i, &b);
        c.poll(i);
    }
}

/// Fuzz find (`dhcp_client`): with T1 = T2 the client sent a RENEW and a
/// REBIND at the same instant; now it goes straight to REBINDING.
#[test]
fn t1_equal_to_t2_sends_one_rebind() {
    let mut c = Client::new(cfg(), 0, 20);
    let (_, d) = sent_next(&mut c).unwrap();
    c.handle(0, &udhcpd_reply(2, d.xid, ONE, &[]));
    let (_, r) = sent(&mut c, 0).unwrap();
    let t = [58, 4, 0, 0, 0x07, 0x08, 59, 4, 0, 0, 0x07, 0x08]; // 1800 s both
    c.handle(0, &udhcpd_reply(5, r.xid, ONE, &t));
    let (t, r) = sent(&mut c, 1_800_000).unwrap();
    assert_eq!(c.state(), State::Rebinding);
    assert_eq!((t.dst, r.ciaddr), (Ipv4Addr::BROADCAST, ONE));
    assert!(c.poll(1_800_000).is_none());
}
