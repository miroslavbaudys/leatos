use super::*;
use alloc::vec;

const MAC: [u8; 6] = [0x52, 0x54, 0, 0, 0, 1];
const SRV: &[u8] = &[0, 3, 0, 1, 2, 0, 0, 0, 0, 0x99];

fn cfg() -> PdConfig {
    PdConfig { mac: MAC, iaid: 1, hint_len: 56, last: None }
}

#[test]
fn solicit_asks_for_the_last_prefix_again() {
    let last: Ipv6Addr = "2001:db8:910::".parse().unwrap();
    let mut c = Client::new(PdConfig { last: Some((last, 60)), ..cfg() }, 0, 42);
    let t = c.next_deadline();
    let sol = c.poll(t).unwrap();
    let (_, _, opts) = sent(&sol);
    let ia = has(&opts, OPT_IA_PD).unwrap();
    let (code, iap) = options(&ia[12..]).next().unwrap();
    assert_eq!((code, iap[8]), (OPT_IAPREFIX, 60));
    assert_eq!(&iap[9..25], &last.octets());
}

fn pfx() -> Ipv6Addr {
    "2001:db8:100::".parse().unwrap()
}

type Opts = Vec<(u16, Vec<u8>)>;

/// What the client sent: (type, xid, options by code).
fn sent(m: &[u8]) -> (u8, [u8; 3], Opts) {
    (m[0], [m[1], m[2], m[3]], options(&m[4..]).map(|(c, d)| (c, d.to_vec())).collect())
}

fn has(opts: &[(u16, Vec<u8>)], code: u16) -> Option<&Vec<u8>> {
    opts.iter().find(|o| o.0 == code).map(|o| &o.1)
}

/// A server message answering `to` (its xid and client id).
fn answer(kind: u8, to: &[u8], prefix: Option<(Ipv6Addr, u8, u32, u32)>, t: (u32, u32), status: Option<u16>) -> Vec<u8> {
    let (_, xid, opts) = sent(to);
    let mut b = vec![kind, xid[0], xid[1], xid[2]];
    opt(&mut b, OPT_CLIENTID, has(&opts, OPT_CLIENTID).unwrap());
    opt(&mut b, OPT_SERVERID, SRV);
    let mut ia = Vec::new();
    ia.extend_from_slice(&1u32.to_be_bytes());
    ia.extend_from_slice(&t.0.to_be_bytes());
    ia.extend_from_slice(&t.1.to_be_bytes());
    if let Some((p, len, pref, valid)) = prefix {
        let mut x = Vec::new();
        x.extend_from_slice(&pref.to_be_bytes());
        x.extend_from_slice(&valid.to_be_bytes());
        x.push(len);
        x.extend_from_slice(&p.octets());
        opt(&mut ia, OPT_IAPREFIX, &x);
    }
    if let Some(code) = status {
        opt(&mut ia, OPT_STATUS, &code.to_be_bytes());
    }
    opt(&mut b, OPT_IA_PD, &ia);
    opt(&mut b, OPT_DNS, &"2001:db8:ffff::53".parse::<Ipv6Addr>().unwrap().octets());
    b
}

/// Bound at t≈2 s with T1 1000 s, T2 1600 s, valid 4000 s.
fn bound() -> (Client, u64) {
    let mut c = Client::new(cfg(), 0, 42);
    let t = c.next_deadline();
    let sol = c.poll(t).unwrap();
    c.handle(t + 5, &answer(ADVERTISE, &sol, Some((pfx(), 56, 3000, 4000)), (1000, 1600), None));
    let req = c.poll(t + 5).unwrap();
    c.handle(t + 10, &answer(REPLY, &req, Some((pfx(), 56, 3000, 4000)), (1000, 1600), None));
    assert_eq!(c.state(), State::Bound);
    (c, t + 10)
}

#[test]
fn solicit_advertise_request_reply() {
    let mut c = Client::new(cfg(), 0, 42);
    let t = c.next_deadline();
    assert!(t <= SOL_MAX_DELAY_MS, "first Solicit within the delay");
    let sol = c.poll(t).unwrap();
    let (kind, _, opts) = sent(&sol);
    assert_eq!(kind, SOLICIT);
    assert_eq!(has(&opts, OPT_CLIENTID).unwrap(), &vec![0, 3, 0, 1, 0x52, 0x54, 0, 0, 0, 1], "DUID-LL");
    assert!(has(&opts, OPT_SERVERID).is_none());
    assert_eq!(has(&opts, OPT_ORO).unwrap(), &OPT_DNS.to_be_bytes().to_vec());
    let ia = has(&opts, OPT_IA_PD).unwrap();
    assert_eq!(&ia[..4], &1u32.to_be_bytes());
    let (c26, iap) = options(&ia[12..]).next().unwrap();
    assert_eq!((c26, iap[8]), (OPT_IAPREFIX, 56), "hint ::/56");
    c.handle(t + 5, &answer(ADVERTISE, &sol, Some((pfx(), 56, 3000, 4000)), (1000, 1600), None));
    assert_eq!(c.state(), State::Request);
    let req = c.poll(t + 5).unwrap();
    let (kind, _, opts) = sent(&req);
    assert_eq!(kind, REQUEST);
    assert_eq!(has(&opts, OPT_SERVERID).unwrap(), &SRV.to_vec());
    let iap = options(&has(&opts, OPT_IA_PD).unwrap()[12..]).next().unwrap().1.to_vec();
    assert_eq!(&iap[9..25], &pfx().octets(), "asks for the offered prefix");
    c.handle(t + 10, &answer(REPLY, &req, Some((pfx(), 56, 3000, 4000)), (1000, 1600), None));
    let Some(Event::Bound(d)) = c.poll_event() else { panic!("not bound") };
    assert_eq!((d.prefix, d.len, d.preferred_secs, d.valid_secs), (pfx(), 56, 3000, 4000));
    assert_eq!(d.dns, vec!["2001:db8:ffff::53".parse::<Ipv6Addr>().unwrap()]);
    assert_eq!(c.next_deadline(), t + 10 + 1_000_000, "T1");
    assert!(c.poll(t + 20).is_none(), "quiet while bound");
}

#[test]
fn renew_then_rebind_then_lost() {
    let (mut c, t0) = bound();
    let t1 = t0 + 1_000_000;
    let ren = c.poll(t1).unwrap();
    let (kind, _, opts) = sent(&ren);
    assert_eq!((kind, c.state()), (RENEW, State::Renew));
    assert!(has(&opts, OPT_SERVERID).is_some());
    // No answer: Rebind at T2, without the server id.
    let reb = c.poll(t0 + 1_600_000).unwrap();
    let (kind, _, opts) = sent(&reb);
    assert_eq!((kind, c.state()), (REBIND, State::Rebind));
    assert!(has(&opts, OPT_SERVERID).is_none());
    // Still nothing: lost at the valid lifetime, soliciting again.
    let end = t0 + 4_000_000;
    let _ = c.poll(end - 1);
    while c.poll_event().is_some() {}
    let _ = c.poll(end);
    assert_eq!(c.poll_event(), Some(Event::Lost));
    assert_eq!((c.state(), c.delegation()), (State::Solicit, None));
}

#[test]
fn renewal_answered_keeps_or_changes_the_prefix() {
    let (mut c, t0) = bound();
    while c.poll_event().is_some() {}
    let ren = c.poll(t0 + 1_000_000).unwrap();
    let other: Ipv6Addr = "2001:db8:200::".parse().unwrap();
    c.handle(t0 + 1_000_010, &answer(REPLY, &ren, Some((other, 56, 3000, 4000)), (1000, 1600), None));
    assert!(matches!(c.poll_event(), Some(Event::Bound(d)) if d.prefix == other));
    assert_eq!(c.state(), State::Bound);
}

#[test]
fn no_binding_goes_back_to_solicit() {
    let (mut c, t0) = bound();
    while c.poll_event().is_some() {}
    let ren = c.poll(t0 + 1_000_000).unwrap();
    c.handle(t0 + 1_000_010, &answer(REPLY, &ren, None, (0, 0), Some(NO_BINDING)));
    assert_eq!(c.poll_event(), Some(Event::Lost));
    assert_eq!(c.state(), State::Solicit);
    // An Advertise without a prefix (NoPrefixAvail) is not taken.
    let sol = c.poll(c.next_deadline()).unwrap();
    c.handle(t0 + 1_000_020, &answer(ADVERTISE, &sol, None, (0, 0), Some(NO_PREFIX_AVAIL)));
    assert_eq!(c.state(), State::Solicit);
}

#[test]
fn foreign_and_malformed_messages_are_ignored() {
    let mut c = Client::new(cfg(), 0, 42);
    let t = c.next_deadline();
    let sol = c.poll(t).unwrap();
    let mut wrong_xid = answer(ADVERTISE, &sol, Some((pfx(), 56, 3000, 4000)), (0, 0), None);
    wrong_xid[1] ^= 1;
    c.handle(t + 1, &wrong_xid);
    let mut other_client = answer(ADVERTISE, &sol, Some((pfx(), 56, 3000, 4000)), (0, 0), None);
    other_client[4 + 4 + 9] ^= 1; // last byte of our DUID
    c.handle(t + 1, &other_client);
    c.handle(t + 1, &[2, 0, 0]);
    c.handle(t + 1, &answer(ADVERTISE, &sol, Some((pfx(), 80, 3000, 4000)), (0, 0), None)); // /80: not a delegation
    c.handle(t + 1, &answer(ADVERTISE, &sol, Some((pfx(), 56, 5000, 4000)), (0, 0), None)); // preferred > valid
    c.handle(t + 1, &answer(REPLY, &sol, Some((pfx(), 56, 3000, 4000)), (0, 0), None)); // a Reply to a Solicit
    assert_eq!((c.state(), c.received), (State::Solicit, 0));
}

#[test]
fn retransmission_backs_off_with_jitter() {
    let mut c = Client::new(cfg(), 0, 7);
    let mut t = c.next_deadline();
    let mut gaps = Vec::new();
    for _ in 0..16 {
        c.poll(t).unwrap();
        let n = c.next_deadline();
        gaps.push(n - t);
        t = n;
    }
    assert!(gaps[0] > SOL.0 && gaps[0] <= SOL.0 * 11 / 10, "first above IRT: {gaps:?}");
    assert!(gaps[1] >= gaps[0] * 18 / 10 && gaps[1] <= gaps[0] * 22 / 10, "doubling: {gaps:?}");
    assert!(gaps.iter().all(|&g| g <= SOL.1 * 11 / 10), "capped at SOL_MAX_RT: {gaps:?}");
    assert!(*gaps.last().unwrap() >= SOL.1 * 9 / 10);
    // Request gives up after REQ_MAX_RC tries and solicits again.
    let mut c = Client::new(cfg(), 0, 7);
    let t = c.next_deadline();
    let sol = c.poll(t).unwrap();
    c.handle(t, &answer(ADVERTISE, &sol, Some((pfx(), 56, 3000, 4000)), (0, 0), None));
    let mut now = t;
    let mut requests = 0;
    loop {
        match c.poll(now) {
            Some(m) if m[0] == REQUEST => requests += 1,
            Some(m) => {
                assert_eq!(m[0], SOLICIT);
                break;
            }
            None => {}
        }
        now = c.next_deadline();
    }
    assert_eq!(requests, REQ.2);
}

#[test]
fn t1_t2_zero_follow_the_preferred_lifetime() {
    let mut c = Client::new(cfg(), 0, 42);
    let t = c.next_deadline();
    let sol = c.poll(t).unwrap();
    c.handle(t, &answer(ADVERTISE, &sol, Some((pfx(), 56, 1000, 2000)), (0, 0), None));
    let req = c.poll(t).unwrap();
    c.handle(t, &answer(REPLY, &req, Some((pfx(), 56, 1000, 2000)), (0, 0), None));
    assert_eq!(c.next_deadline(), t + 500_000, "T1 = preferred / 2");
}

#[test]
fn a_renewal_listing_the_old_prefix_at_zero_takes_the_new_one() {
    let (mut c, t0) = bound();
    while c.poll_event().is_some() {}
    let ren = c.poll(t0 + 1_000_000).unwrap();
    let mut reply = answer(REPLY, &ren, Some((pfx(), 56, 0, 0)), (1000, 1600), None);
    // Append a second IAPREFIX (the new one) inside the IA_PD: rebuild it.
    let new: Ipv6Addr = "2001:db8:200::".parse().unwrap();
    let (_, xid, opts) = sent(&ren);
    let mut b = vec![REPLY, xid[0], xid[1], xid[2]];
    opt(&mut b, OPT_CLIENTID, has(&opts, OPT_CLIENTID).unwrap());
    opt(&mut b, OPT_SERVERID, SRV);
    let mut ia = Vec::new();
    ia.extend_from_slice(&1u32.to_be_bytes());
    ia.extend_from_slice(&1000u32.to_be_bytes());
    ia.extend_from_slice(&1600u32.to_be_bytes());
    for (p, pref, valid) in [(pfx(), 0u32, 0u32), (new, 3000, 4000)] {
        let mut x = Vec::new();
        x.extend_from_slice(&pref.to_be_bytes());
        x.extend_from_slice(&valid.to_be_bytes());
        x.push(56);
        x.extend_from_slice(&p.octets());
        opt(&mut ia, OPT_IAPREFIX, &x);
    }
    opt(&mut b, OPT_IA_PD, &ia);
    reply.clear();
    reply.extend_from_slice(&b);
    c.handle(t0 + 1_000_010, &reply);
    assert!(matches!(c.poll_event(), Some(Event::Bound(d)) if d.prefix == new), "straight to the new prefix");
    assert_eq!(c.state(), State::Bound);
}
