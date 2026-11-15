use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};

use crate::wire::*;
use crate::*;

const LAN: NetId = 0;
const IOT: NetId = 1;
const GUEST: NetId = 2;
const PHONE: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 50);
const SPEAKER: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 20);
const GUEST_HOST: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 77);

fn n(s: &str) -> Name {
    Name::from_dotted(s).unwrap()
}

fn svc(s: &str) -> ServiceType {
    ServiceType::parse(s).unwrap()
}

fn config() -> Config {
    let net = |a: [u8; 4]| Some(Net { addr: Ipv4Addr::from(a), prefix_len: 24 });
    Config {
        nets: vec![net([10, 10, 0, 1]), net([10, 30, 0, 1]), net([10, 20, 0, 1])],
        rules: vec![Rule { from: IOT, to: vec![LAN], services: vec![svc("_airplay._tcp"), svc("_ipp._tcp")] }],
    }
}

fn from(ip: Ipv4Addr) -> SocketAddrV4 {
    SocketAddrV4::new(ip, PORT)
}

fn q(name: &str, qtype: u16) -> Question {
    Question { name: n(name), qtype, qclass: CLASS_IN }
}

fn qu(name: &str, qtype: u16) -> Question {
    Question { name: n(name), qtype, qclass: CLASS_IN | CLASS_TOP_BIT }
}

fn rr(name: &str, rtype: u16, ttl: u32, rdata: Rdata) -> Record {
    Record { name: n(name), rtype, rclass: CLASS_IN | CLASS_TOP_BIT, ttl, rdata }
}

fn ptr(name: &str, target: &str) -> Record {
    Record { rclass: CLASS_IN, ..rr(name, TYPE_PTR, 4500, Rdata { pre: vec![], name: Some(n(target)), post: vec![] }) }
}

fn srv(name: &str, ttl: u32, target: &str) -> Record {
    rr(name, TYPE_SRV, ttl, Rdata { pre: vec![0, 0, 0, 0, 0x1b, 0x58], name: Some(n(target)), post: vec![] })
}

fn txt(name: &str) -> Record {
    rr(name, TYPE_TXT, 4500, Rdata::raw(b"\x05ver=1"))
}

fn a(name: &str, ip: Ipv4Addr) -> Record {
    rr(name, TYPE_A, 120, Rdata::raw(&ip.octets()))
}

fn aaaa(name: &str, b: [u8; 16]) -> Record {
    rr(name, TYPE_AAAA, 120, Rdata::raw(&b))
}

fn query(questions: Vec<Question>) -> Message {
    Message { questions, ..Default::default() }
}

fn response(answers: Vec<Record>, additional: Vec<Record>) -> Message {
    Message { flags: FLAG_QR | FLAG_AA, answers, additional, ..Default::default() }
}

fn bytes(m: &Message) -> Vec<u8> {
    m.to_bytes().unwrap()
}

fn one(out: &[Output]) -> (NetId, Message) {
    assert_eq!(out.len(), 1, "{out:?}");
    (out[0].net, Message::parse(&out[0].msg).unwrap())
}

/// The speaker's full announcement: two allowed services, one not, its
/// host's addresses (one link-local each).
fn announcement() -> Message {
    let inst = "Living Room._airplay._tcp.local";
    response(
        vec![
            ptr("_airplay._tcp.local", inst),
            srv(inst, 120, "speaker.local"),
            txt(inst),
            ptr("_ipp._tcp.local", "Living Room._ipp._tcp.local"),
            srv("Living Room._ipp._tcp.local", 120, "speaker.local"),
            ptr("_ssh._tcp.local", "speaker._ssh._tcp.local"),
            srv("speaker._ssh._tcp.local", 120, "speaker.local"),
            a("speaker.local", SPEAKER),
            a("speaker.local", Ipv4Addr::new(169, 254, 3, 4)),
            aaaa("speaker.local", [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]),
            aaaa("speaker.local", [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            a("other.local", Ipv4Addr::new(10, 30, 0, 21)),
        ],
        vec![],
    )
}

// ---- wire ----

#[test]
fn compressed_names_parse() {
    // PTR _ipp._tcp.local → "Pr.nter" (a dot inside a label) + pointer.
    let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    b.extend_from_slice(b"\x04_ipp\x04_tcp\x05local\x00");
    b.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 9]);
    b.extend_from_slice(b"\x06Pr.nte\xc0\x0c");
    let m = Message::parse(&b).unwrap();
    assert!(m.is_response());
    let r = &m.answers[0];
    assert_eq!(r.name, n("_ipp._tcp.local"));
    assert_eq!((r.rtype, r.ttl), (TYPE_PTR, 4500));
    let target = r.rdata.name.as_ref().unwrap();
    assert_eq!(target.labels()[0], b"Pr.nte");
    assert!(target.ends_with_ignore_case(&[b"_IPP", b"_tcp", b"LOCAL"]));
    // Written back compressed, it parses to the same message.
    let again = bytes(&m);
    assert!(again.len() <= b.len());
    assert_eq!(Message::parse(&again).unwrap(), m);
}

#[test]
fn bad_pointers_are_refused() {
    let head = [0u8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    // A name pointing at itself.
    let mut b = head.to_vec();
    b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::BadName));
    // Pointing forwards.
    let mut b = head.to_vec();
    b.extend_from_slice(&[0xc0, 14, 0, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::BadName));
    // Into the middle of its own labels.
    let mut b = head.to_vec();
    b.extend_from_slice(b"\x01a\xc0\x0c\x00\x01\x00\x01");
    assert_eq!(Message::parse(&b), Err(Error::BadName));
    // Reserved label type.
    let mut b = head.to_vec();
    b.extend_from_slice(&[0x40, 0, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&b), Err(Error::BadName));
}

#[test]
fn rdata_name_stays_inside_rdata() {
    // A PTR whose rdata length (2) ends inside its target name.
    let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    b.extend_from_slice(b"\x01x\x00");
    b.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 1, 0, 2]);
    b.extend_from_slice(b"\x03abc\x00");
    assert!(Message::parse(&b).is_err());
}

#[test]
fn absurd_counts_and_sizes() {
    let b = [0u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0];
    assert_eq!(Message::parse(&b), Err(Error::Truncated));
    assert_eq!(Message::parse(&[0; 11]), Err(Error::Truncated));
    assert_eq!(Message::parse(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLarge));
    assert_eq!(Name::new(vec![vec![b'a'; 64]]), Err(Error::BadName));
    assert_eq!(Name::new(vec![vec![b'a'; 63]; 4]), Err(Error::BadName), "256 bytes on the wire");
}

#[test]
fn roundtrip_and_compression() {
    let m = announcement();
    let b = bytes(&m);
    assert_eq!(Message::parse(&b).unwrap(), m);
    let plain: usize = m.answers.iter().map(|r| r.name.wire_len() + 10 + r.rdata.pre.len() + r.rdata.name.as_ref().map_or(0, |x| x.wire_len())).sum();
    assert!(b.len() < plain * 3 / 5, "compressed {} vs {}", b.len(), plain);
}

#[test]
fn nsec_name_not_compressed() {
    let r = rr("speaker.local", TYPE_NSEC, 120, Rdata { pre: vec![], name: Some(n("speaker.local")), post: vec![0, 4, 0x40, 0, 0, 8] });
    let b = bytes(&response(vec![a("speaker.local", SPEAKER), r], vec![]));
    assert!(b.windows(16).any(|w| w == b"\x07speaker\x05local\x00\x00"), "NSEC next name written in full");
    assert_eq!(Message::parse(&b).unwrap().answers[1].rdata.post, [0, 4, 0x40, 0, 0, 8]);
}

#[test]
fn mutated_input_never_panics() {
    let good = bytes(&announcement());
    let mut r = Reflector::new(config());
    for len in 0..good.len() {
        let _ = Message::parse(&good[..len]);
        let _ = r.handle(len as u64 * 1000, IOT, from(SPEAKER), &good[..len]);
    }
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..5000 {
        let mut b = good.clone();
        for _ in 0..1 + rnd() % 8 {
            let at = (rnd() as usize) % b.len();
            b[at] = rnd() as u8;
        }
        if let Ok(m) = Message::parse(&b) {
            // Whatever parses writes back and parses to the same.
            if let Ok(w) = m.to_bytes() {
                assert_eq!(Message::parse(&w).unwrap(), m);
            }
        }
        let net = if i % 2 == 0 { IOT } else { LAN };
        let _ = r.handle(i * 1000, net, from(if net == IOT { SPEAKER } else { PHONE }), &b);
    }
}

// ---- service types ----

#[test]
fn service_type_parse() {
    for ok in ["_ipp._tcp", "_airplay._TCP", "_googlecast._tcp", "_sleep-proxy._udp", "_a._udp", "_x1._tcp"] {
        assert!(ServiceType::parse(ok).is_some(), "{ok}");
    }
    for bad in ["ipp._tcp", "_ipp", "_ipp._sctp", "_._tcp", "_-ipp._tcp", "_ipp-._tcp", "_123._tcp", "_a.b._tcp", "_abcdefghijklmnop._tcp", "_ipp._tcp.local", "_i p._tcp"] {
        assert!(ServiceType::parse(bad).is_none(), "{bad}");
    }
    assert_eq!(svc("_AirPlay._Tcp").to_string(), "_airplay._tcp");
}

// ---- reflector ----

#[test]
fn browse_query_goes_to_the_service_network() {
    let mut r = Reflector::new(config());
    let out = r.handle(0, LAN, from(PHONE), &bytes(&query(vec![qu("_airplay._tcp.local", TYPE_PTR)])));
    let (net, m) = one(&out);
    assert_eq!(net, IOT);
    assert_eq!(m.questions, [q("_airplay._tcp.local", TYPE_PTR)], "QU bit cleared");
    assert_eq!((r.stats(LAN).received, r.stats(IOT).sent), (1, 1));
}

#[test]
fn queries_filtered_by_rule_and_direction() {
    let mut r = Reflector::new(config());
    // Not an allowed type.
    assert!(r.handle(0, LAN, from(PHONE), &bytes(&query(vec![q("_ssh._tcp.local", TYPE_PTR)]))).is_empty());
    // The meta-query would list everything: not reflected.
    assert!(r.handle(1, LAN, from(PHONE), &bytes(&query(vec![q("_services._dns-sd._udp.local", TYPE_PTR)]))).is_empty());
    // Wrong direction: the rule shows IoT's services on the LAN, not back.
    assert!(r.handle(2, IOT, from(SPEAKER), &bytes(&query(vec![q("_airplay._tcp.local", TYPE_PTR)]))).is_empty());
    // A network without a rule.
    assert!(r.handle(3, GUEST, from(GUEST_HOST), &bytes(&query(vec![q("_airplay._tcp.local", TYPE_PTR)]))).is_empty());
    assert_eq!(r.stats(LAN).filtered, 2);
    assert_eq!(r.stats(IOT).sent, 0);
    // Mixed: only the allowed question goes.
    let out = r.handle(4, LAN, from(PHONE), &bytes(&query(vec![q("_ssh._tcp.local", TYPE_PTR), q("Office._ipp._tcp.local", TYPE_SRV)])));
    assert_eq!(one(&out).1.questions, [q("Office._ipp._tcp.local", TYPE_SRV)]);
}

#[test]
fn announcement_rebuilt_with_allowed_parts_only() {
    let mut r = Reflector::new(config());
    let out = r.handle(0, IOT, from(SPEAKER), &bytes(&announcement()));
    let (net, m) = one(&out);
    assert_eq!(net, LAN);
    let inst = "Living Room._airplay._tcp.local";
    assert_eq!(
        m.answers,
        [
            ptr("_airplay._tcp.local", inst),
            srv(inst, 120, "speaker.local"),
            txt(inst),
            ptr("_ipp._tcp.local", "Living Room._ipp._tcp.local"),
            srv("Living Room._ipp._tcp.local", 120, "speaker.local"),
            a("speaker.local", SPEAKER),
            aaaa("speaker.local", [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ],
        "no _ssh, no link-local addresses, no unrelated host"
    );
    assert!(m.is_response());
    // Guest has no rule: nothing went there.
    assert_eq!(r.stats(GUEST).sent, 0);
}

#[test]
fn additional_records_follow_the_same_filter() {
    let mut r = Reflector::new(config());
    let inst = "Office._ipp._tcp.local";
    let m = response(
        vec![ptr("_ipp._tcp.local", inst)],
        vec![srv(inst, 120, "printer.local"), a("printer.local", Ipv4Addr::new(10, 30, 0, 9)), a("nas.local", Ipv4Addr::new(10, 30, 0, 10))],
    );
    let (_, out) = one(&r.handle(0, IOT, from(SPEAKER), &bytes(&m)));
    assert_eq!(out.additional, [srv(inst, 120, "printer.local"), a("printer.local", Ipv4Addr::new(10, 30, 0, 9))]);
    // Only additional records allowed, no answer: nothing to send.
    let m = response(vec![ptr("_ssh._tcp.local", "x._ssh._tcp.local")], vec![a("printer.local", Ipv4Addr::new(10, 30, 0, 9))]);
    assert!(r.handle(1, IOT, from(SPEAKER), &bytes(&m)).is_empty());
}

#[test]
fn hosts_learned_from_srv_records() {
    let mut r = Reflector::new(config());
    let host_q = || bytes(&query(vec![q("speaker.local", TYPE_A)]));
    let host_a = || bytes(&response(vec![a("speaker.local", SPEAKER)], vec![]));
    // Unknown host: not reflected either way.
    assert!(r.handle(0, LAN, from(PHONE), &host_q()).is_empty());
    assert!(r.handle(1, IOT, from(SPEAKER), &host_a()).is_empty());
    // An _ssh SRV teaches nothing (not allowed), a goodbye SRV neither.
    r.handle(2, IOT, from(SPEAKER), &bytes(&response(vec![srv("s._ssh._tcp.local", 120, "speaker.local")], vec![])));
    r.handle(3, IOT, from(SPEAKER), &bytes(&response(vec![srv("s._ipp._tcp.local", 0, "speaker.local")], vec![])));
    assert!(r.handle(4, LAN, from(PHONE), &host_q()).is_empty());
    // An allowed SRV does, for its TTL.
    r.handle(5, IOT, from(SPEAKER), &bytes(&response(vec![srv("s._ipp._tcp.local", 10, "Speaker.local")], vec![])));
    assert_eq!(one(&r.handle(1000, LAN, from(PHONE), &host_q())).0, IOT);
    assert_eq!(one(&r.handle(2000, IOT, from(SPEAKER), &host_a())).0, LAN);
    // Only on the network it was learned on.
    let guest_host = bytes(&response(vec![a("speaker.local", GUEST_HOST)], vec![]));
    assert!(r.handle(3000, GUEST, from(GUEST_HOST), &guest_host).is_empty());
    // Expired.
    assert!(r.handle(10_006, LAN, from(PHONE), &host_q()).is_empty());
}

#[test]
fn learned_hosts_are_bounded() {
    let mut r = Reflector::new(config());
    for i in 0..MAX_HOSTS as u64 + 10 {
        let host = alloc::format!("h{i}.local");
        let m = response(vec![srv(&alloc::format!("i{i}._ipp._tcp.local"), 100 + i as u32, &host)], vec![]);
        // 10 s apart, so the rate limit never bites.
        r.handle(i * 10_000, IOT, from(SPEAKER), &bytes(&m));
    }
    let now = (MAX_HOSTS as u64 + 10) * 10_000;
    // The first ones were evicted (they expire first), the last are kept.
    let ask = |r: &mut Reflector, t: u64, i: u64| r.handle(now + t, LAN, from(PHONE), &bytes(&query(vec![q(&alloc::format!("h{i}.local"), TYPE_A)])));
    assert!(ask(&mut r, 0, 0).is_empty());
    assert!(!ask(&mut r, 10, MAX_HOSTS as u64 + 9).is_empty());
}

#[test]
fn probes_lose_authority_and_known_answers_are_filtered() {
    let mut r = Reflector::new(config());
    let inst = "Living Room._airplay._tcp.local";
    let probe = Message {
        questions: vec![qu(inst, TYPE_ANY)],
        authority: vec![srv(inst, 120, "phone.local")],
        additional: vec![a("phone.local", PHONE)],
        ..Default::default()
    };
    let (_, m) = one(&r.handle(0, LAN, from(PHONE), &bytes(&probe)));
    assert_eq!(m.questions, [q(inst, TYPE_ANY)]);
    assert!(m.authority.is_empty() && m.additional.is_empty());
    // Known answers: kept for allowed names, dropped otherwise.
    let ka = Message {
        questions: vec![q("_airplay._tcp.local", TYPE_PTR)],
        answers: vec![ptr("_airplay._tcp.local", inst), ptr("_ssh._tcp.local", "x._ssh._tcp.local")],
        ..Default::default()
    };
    let (_, m) = one(&r.handle(1000, LAN, from(PHONE), &bytes(&ka)));
    assert_eq!(m.answers, [ptr("_airplay._tcp.local", inst)]);
}

#[test]
fn foreign_sources_are_ignored() {
    let mut r = Reflector::new(config());
    let msg = bytes(&query(vec![q("_ipp._tcp.local", TYPE_PTR)]));
    // Legacy unicast query (source port not 5353).
    assert!(r.handle(0, LAN, SocketAddrV4::new(PHONE, 40000), &msg).is_empty());
    // Outside the network's subnet.
    assert!(r.handle(1, LAN, from(SPEAKER), &msg).is_empty());
    // The router itself, on this network or another.
    assert!(r.handle(2, LAN, from(Ipv4Addr::new(10, 10, 0, 1)), &msg).is_empty());
    assert_eq!(r.stats(LAN).foreign, 3);
    // A network not taking part.
    let mut cfg = config();
    cfg.nets[LAN] = None;
    let mut r = Reflector::new(cfg);
    assert!(r.handle(3, LAN, from(PHONE), &msg).is_empty());
    assert_eq!(r.stats(LAN).received, 0);
}

#[test]
fn echoes_of_sent_messages_are_dropped() {
    let mut r = Reflector::new(config());
    let out = r.handle(0, IOT, from(SPEAKER), &bytes(&announcement()));
    let sent = out[0].msg.clone();
    // Another reflector on the LAN sends our copy back.
    let other = Ipv4Addr::new(10, 10, 0, 2);
    assert!(r.handle(500, LAN, from(other), &sent).is_empty());
    assert_eq!(r.stats(LAN).duplicate, 1);
    // Outside the window it is a new message (a response: no rule from the
    // LAN, so filtered, not duplicate).
    assert!(r.handle(500 + DUP_WINDOW_MS + 1, LAN, from(other), &sent).is_empty());
    assert_eq!((r.stats(LAN).duplicate, r.stats(LAN).filtered), (1, 1));
}

#[test]
fn rate_limit_per_network() {
    let mut r = Reflector::new(config());
    let msg = bytes(&query(vec![q("_ipp._tcp.local", TYPE_PTR)]));
    // Distinct messages (the id differs) so duplicates do not interfere.
    let ask = |r: &mut Reflector, t: u64, id: u16| {
        let mut b = msg.clone();
        b[..2].copy_from_slice(&id.to_be_bytes());
        !r.handle(t, LAN, from(PHONE), &b).is_empty()
    };
    let passed = (0..BURST as u16 + 20).filter(|&i| ask(&mut r, 0, i)).count();
    assert_eq!(passed as u64, BURST);
    assert_eq!(r.stats(LAN).rate_limited, 20);
    // Refills at RATE_PER_SEC.
    let later = (0..RATE_PER_SEC as u16 + 5).filter(|&i| ask(&mut r, 1000, 1000 + i)).count();
    assert_eq!(later as u64, RATE_PER_SEC);
    // Another network has its own bucket.
    let m = bytes(&response(vec![ptr("_ipp._tcp.local", "x._ipp._tcp.local")], vec![]));
    assert!(!r.handle(1000, IOT, from(SPEAKER), &m).is_empty());
}

#[test]
fn oversize_copies_are_dropped() {
    let mut r = Reflector::new(config());
    // 40 printers with distinct hosts: under MAX_MESSAGE, over MAX_OUTPUT.
    let mut answers = Vec::new();
    for i in 0..40 {
        let inst = alloc::format!("A printer with a long name number {i}._ipp._tcp.local");
        answers.push(ptr("_ipp._tcp.local", &inst));
        answers.push(srv(&inst, 120, &alloc::format!("printer-{i}.local")));
    }
    let b = bytes(&response(answers, vec![]));
    assert!(b.len() > MAX_OUTPUT && b.len() <= MAX_MESSAGE);
    assert!(r.handle(0, IOT, from(SPEAKER), &b).is_empty());
    assert_eq!(r.stats(IOT).oversize, 1);
}

#[test]
fn several_rules_and_targets() {
    let mut cfg = config();
    // Printers on IoT are visible to the guests too; guests' casts to the LAN.
    cfg.rules.push(Rule { from: IOT, to: vec![GUEST], services: vec![svc("_ipp._tcp")] });
    cfg.rules.push(Rule { from: GUEST, to: vec![LAN], services: vec![svc("_googlecast._tcp")] });
    let mut r = Reflector::new(cfg);
    assert!(r.takes_part(GUEST) && r.takes_part(LAN));
    let out = r.handle(0, IOT, from(SPEAKER), &bytes(&announcement()));
    assert_eq!(out.iter().map(|o| o.net).collect::<Vec<_>>(), [LAN, GUEST]);
    let guest = Message::parse(&out[1].msg).unwrap();
    assert!(guest.answers.iter().all(|r| !r.name.ends_with_ignore_case(&[b"_airplay", b"_tcp", b"local"])), "guests see printers only");
    assert!(guest.answers.iter().any(|r| r.rtype == TYPE_A), "the printer's host");
    // A LAN query for casts goes to the guests only, for printers to IoT only.
    let out = r.handle(1, LAN, from(PHONE), &bytes(&query(vec![q("_googlecast._tcp.local", TYPE_PTR)])));
    assert_eq!(one(&out).0, GUEST);
    // The guest asking for printers: to IoT.
    let out = r.handle(2, GUEST, from(GUEST_HOST), &bytes(&query(vec![q("_ipp._tcp.local", TYPE_PTR), q("_airplay._tcp.local", TYPE_PTR)])));
    let (net, m) = one(&out);
    assert_eq!((net, m.questions.len()), (IOT, 1));
}

#[test]
fn bad_opcode_or_rcode_is_malformed() {
    let mut r = Reflector::new(config());
    let mut m = query(vec![q("_ipp._tcp.local", TYPE_PTR)]);
    m.flags = 0x2800; // opcode 5 (update)
    assert!(r.handle(0, LAN, from(PHONE), &bytes(&m)).is_empty());
    m.flags = FLAG_QR | 3;
    assert!(r.handle(1, LAN, from(PHONE), &bytes(&m)).is_empty());
    assert_eq!(r.stats(LAN).malformed, 2);
}

#[test]
fn reconfigure_keeps_counters_forgets_hosts() {
    let mut r = Reflector::new(config());
    r.handle(0, IOT, from(SPEAKER), &bytes(&announcement()));
    assert_eq!(r.stats(LAN).sent, 1);
    r.reconfigure(config());
    assert_eq!(r.stats(LAN).sent, 1);
    assert!(r.handle(1, LAN, from(PHONE), &bytes(&query(vec![q("speaker.local", TYPE_A)]))).is_empty());
    // No rules: nothing reflected, no network takes part.
    r.reconfigure(Config { rules: vec![], ..config() });
    assert!(!r.takes_part(LAN));
    assert!(r.handle(2, LAN, from(PHONE), &bytes(&query(vec![q("_ipp._tcp.local", TYPE_PTR)]))).is_empty());
}
