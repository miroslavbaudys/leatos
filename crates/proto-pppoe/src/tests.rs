//! The client against a simulated access concentrator (enough of
//! pppoe-server + pppd to exercise every phase).

use super::*;
use alloc::vec;

const CLIENT: Mac = [2, 0, 0, 0, 0, 1];
const AC_MAC: Mac = [2, 0, 0, 0, 0, 0xac];
const AC2_MAC: Mac = [2, 0, 0, 0, 0, 0xad];
const LOCAL: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 23);
const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const DNS1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 53);
const DNS2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 54);

#[derive(Clone, Copy, PartialEq)]
enum SimAuth {
    None,
    Pap,
    Chap,
    /// Asks for EAP first, then accepts CHAP when naked.
    EapThenChap,
}

struct Ac {
    mac: Mac,
    name: &'static str,
    session: u16,
    auth: SimAuth,
    user: &'static str,
    pass: &'static str,
    answer_echo: bool,
    reject_dns: bool,
    offer_ipv6cp: bool,
    /// Second DNS server handed out (pppd with one `ms-dns` repeats it).
    dns2: Ipv4Addr,
    /// Send no PADS (lost).
    drop_padr: bool,
    /// RFC 4638: echo PPP-Max-Payload in the PADO and PADS, and offer
    /// that MRU in LCP.
    rfc4638: bool,
    /// The PADR's PPP-Max-Payload (the session's, when echoed).
    padr_max: Option<u16>,
    /// Largest PPP payload the path (modem, NICs) carries either way;
    /// larger frames are lost.
    path_mtu: usize,
    /// Echo replies without the request's data (a short reply).
    echo_short: bool,
    /// The MRU the AC asks for in LCP (default: the session's); the real
    /// AC asks 1492 even after agreeing to 1500 in discovery.
    ac_mru: Option<u16>,
    /// Take an MRU the client suggests in a Configure-Nak.
    take_mru_nak: bool,
    lcp_req_id: u8,
    lcp_ours_acked: bool,
    lcp_theirs_acked: bool,
    challenge_sent: bool,
    authed: bool,
    ipcp_sent: bool,
    ipcp_up: bool,
    use_chap: bool,
    /// Every frame the client sent us.
    got: Vec<Vec<u8>>,
    proto_rejects: Vec<u16>,
    echo_requests: u32,
    padts: u32,
}

impl Ac {
    fn new(auth: SimAuth) -> Self {
        Ac {
            mac: AC_MAC,
            name: "isp-ac",
            session: 0x1234,
            auth,
            user: "alice@isp",
            pass: "s3cret",
            answer_echo: true,
            reject_dns: false,
            offer_ipv6cp: false,
            dns2: DNS2,
            drop_padr: false,
            rfc4638: false,
            padr_max: None,
            path_mtu: 1500,
            echo_short: false,
            ac_mru: None,
            take_mru_nak: false,
            lcp_req_id: 0,
            lcp_ours_acked: false,
            lcp_theirs_acked: false,
            challenge_sent: false,
            authed: false,
            ipcp_sent: false,
            ipcp_up: false,
            use_chap: auth == SimAuth::Chap,
            got: Vec::new(),
            proto_rejects: Vec::new(),
            echo_requests: 0,
            padts: 0,
        }
    }

    fn ppp(&self, proto: u16, body: &[u8]) -> Vec<u8> {
        session_frame(CLIENT, self.mac, self.session, proto, body)
    }

    fn lcp_request(&mut self) -> Vec<u8> {
        self.lcp_req_id = self.lcp_req_id.wrapping_add(1);
        let mut o = Vec::new();
        put_option(&mut o, LCP_MRU, &self.ac_mru.unwrap_or(self.session_mru()).to_be_bytes());
        match self.auth {
            SimAuth::Pap => put_option(&mut o, LCP_AUTH, &[0xc0, 0x23]),
            SimAuth::Chap => put_option(&mut o, LCP_AUTH, &[0xc2, 0x23, 5]),
            SimAuth::EapThenChap if self.use_chap => put_option(&mut o, LCP_AUTH, &[0xc2, 0x23, 5]),
            SimAuth::EapThenChap => put_option(&mut o, LCP_AUTH, &[0xc2, 0x27]),
            SimAuth::None => {}
        }
        put_option(&mut o, LCP_MAGIC, &0x0bad_cafe_u32.to_be_bytes());
        let b = ctrl(CONF_REQ, self.lcp_req_id, &o);
        self.ppp(PPP_LCP, &b)
    }

    /// MRU of this session: the RFC 4638 one when agreed in discovery.
    fn session_mru(&self) -> u16 {
        self.padr_max.filter(|_| self.rfc4638).unwrap_or(1492)
    }

    fn after_lcp(&mut self, out: &mut Vec<Vec<u8>>) {
        if !(self.lcp_ours_acked && self.lcp_theirs_acked) {
            return;
        }
        match self.auth {
            SimAuth::Pap => {}
            SimAuth::None => self.network(out),
            _ => {
                if !self.challenge_sent {
                    self.challenge_sent = true;
                    let mut d = vec![16];
                    d.extend_from_slice(&[7u8; 16]);
                    d.extend_from_slice(b"isp-ac");
                    out.push(self.ppp(PPP_CHAP, &ctrl(1, 42, &d)));
                }
            }
        }
    }

    fn network(&mut self, out: &mut Vec<Vec<u8>>) {
        self.authed = true;
        if !self.ipcp_sent {
            self.ipcp_sent = true;
            let mut o = Vec::new();
            put_option(&mut o, IPCP_ADDR, &REMOTE.octets());
            out.push(self.ppp(PPP_IPCP, &ctrl(CONF_REQ, 1, &o)));
            if self.offer_ipv6cp {
                let mut o = Vec::new();
                put_option(&mut o, 1, &[0, 0, 0, 0, 0, 0, 0, 1]);
                out.push(self.ppp(PPP_IPV6CP, &ctrl(CONF_REQ, 1, &o)));
            }
        }
    }

    fn input(&mut self, f: &[u8]) -> Vec<Vec<u8>> {
        let p = parse(f).expect("client sent a valid PPPoE frame");
        // Lost on the way (too large for the path).
        if p.ethertype == ETHERTYPE_SESSION && p.payload.len() > self.path_mtu + 2 {
            return Vec::new();
        }
        let mut out = self.answer(f);
        let path = self.path_mtu;
        out.retain(|r| parse(r).is_none_or(|q| q.ethertype != ETHERTYPE_SESSION || q.payload.len() <= path + 2));
        out
    }

    fn answer(&mut self, f: &[u8]) -> Vec<Vec<u8>> {
        self.got.push(f.to_vec());
        let mut out = Vec::new();
        let p = parse(f).expect("client sent a valid PPPoE frame");
        assert_eq!(p.src, CLIENT);
        assert!(f.len() >= MIN_FRAME);
        if p.ethertype == ETHERTYPE_DISCOVERY {
            let uniq = find_tag(p.payload, TAG_HOST_UNIQ).unwrap_or(b"").to_vec();
            match p.code {
                PADI => {
                    assert_eq!(p.dst, BROADCAST);
                    let max = find_tag(p.payload, TAG_PPP_MAX_PAYLOAD).filter(|_| self.rfc4638).map(<[u8]>::to_vec);
                    let mut t: Vec<(u16, &[u8])> = alloc::vec![
                        (TAG_AC_NAME, self.name.as_bytes()),
                        (TAG_SERVICE_NAME, b""),
                        (TAG_SERVICE_NAME, b"internet"),
                        (TAG_HOST_UNIQ, &uniq),
                        (TAG_AC_COOKIE, b"cookie"),
                    ];
                    if let Some(m) = &max {
                        t.push((TAG_PPP_MAX_PAYLOAD, m));
                    }
                    out.push(discovery(CLIENT, self.mac, PADO, 0, &t));
                }
                PADR if p.dst == self.mac => {
                    assert_eq!(find_tag(p.payload, TAG_AC_COOKIE), Some(&b"cookie"[..]));
                    self.padr_max = find_tag(p.payload, TAG_PPP_MAX_PAYLOAD).map(|v| get16(v, 0));
                    // A new session: negotiation starts over.
                    self.lcp_ours_acked = false;
                    self.lcp_theirs_acked = false;
                    self.authed = false;
                    self.ipcp_sent = false;
                    self.ipcp_up = false;
                    self.challenge_sent = false;
                    if self.drop_padr {
                        return out;
                    }
                    let max = self.padr_max.filter(|_| self.rfc4638).map(u16::to_be_bytes);
                    let mut t: Vec<(u16, &[u8])> = alloc::vec![(TAG_SERVICE_NAME, b""), (TAG_HOST_UNIQ, &uniq)];
                    if let Some(m) = &max {
                        t.push((TAG_PPP_MAX_PAYLOAD, m));
                    }
                    out.push(discovery(CLIENT, self.mac, PADS, self.session, &t));
                    out.push(self.lcp_request());
                }
                PADT => self.padts += 1,
                _ => {}
            }
            return out;
        }
        assert_eq!((p.session, p.dst), (self.session, self.mac));
        let proto = get16(p.payload, 0);
        let c = parse_ctrl(&p.payload[2..]).expect("control packet");
        match proto {
            PPP_LCP => match c.code {
                CONF_REQ => {
                    let opts = options(c.data).unwrap();
                    let mru = self.session_mru();
                    assert!(
                        opts.iter()
                            .any(|&(k, v)| k == LCP_MRU && get16(v, 0) <= mru)
                    );
                    out.push(self.ppp(PPP_LCP, &ctrl(CONF_ACK, c.id, c.data)));
                    self.lcp_theirs_acked = true;
                    self.after_lcp(&mut out);
                }
                CONF_ACK if c.id == self.lcp_req_id => {
                    self.lcp_ours_acked = true;
                    self.after_lcp(&mut out);
                }
                CONF_NAK => {
                    let opts = options(c.data).unwrap();
                    for (k, v) in opts {
                        match k {
                            LCP_MRU if self.take_mru_nak => self.ac_mru = Some(get16(v, 0)),
                            LCP_MRU => {}
                            LCP_AUTH => {
                                assert_eq!(v, &[0xc2, 0x23, 5][..]);
                                self.use_chap = true;
                            }
                            _ => panic!("unexpected nak of option {k}"),
                        }
                    }
                    out.push(self.lcp_request());
                }
                ECHO_REQ => {
                    self.echo_requests += 1;
                    if self.answer_echo {
                        let mut d = 0x0bad_cafe_u32.to_be_bytes().to_vec();
                        if !self.echo_short {
                            d.extend_from_slice(&c.data[4..]);
                        }
                        out.push(self.ppp(PPP_LCP, &ctrl(ECHO_REPLY, c.id, &d)));
                    }
                }
                PROTO_REJ => self.proto_rejects.push(get16(c.data, 0)),
                _ => {}
            },
            PPP_PAP => {
                let d = c.data;
                let u = &d[1..1 + d[0] as usize];
                let rest = &d[1 + d[0] as usize..];
                let pw = &rest[1..1 + rest[0] as usize];
                if u == self.user.as_bytes() && pw == self.pass.as_bytes() {
                    out.push(self.ppp(PPP_PAP, &ctrl(2, c.id, b"\x02ok")));
                    self.network(&mut out);
                } else {
                    out.push(self.ppp(PPP_PAP, &ctrl(3, c.id, b"\x0bbad account")));
                }
            }
            PPP_CHAP => {
                assert_eq!((c.code, c.id), (2, 42));
                let n = c.data[0] as usize;
                let digest = &c.data[1..1 + n];
                assert_eq!(&c.data[1 + n..], self.user.as_bytes());
                if digest == chap_md5(42, self.pass.as_bytes(), &[7u8; 16]) {
                    out.push(self.ppp(PPP_CHAP, &ctrl(3, 42, b"Welcome")));
                    self.network(&mut out);
                } else {
                    out.push(self.ppp(PPP_CHAP, &ctrl(4, 42, b"Access denied")));
                }
            }
            PPP_IPCP => match c.code {
                CONF_REQ => {
                    assert!(self.authed, "IPCP before authentication");
                    let opts = options(c.data).unwrap();
                    let want = |k: u8| -> Option<Ipv4Addr> {
                        opts.iter().find(|o| o.0 == k).map(|o| ip(o.1))
                    };
                    let mut nak = Vec::new();
                    let mut rej = Vec::new();
                    if want(IPCP_ADDR) != Some(LOCAL) {
                        put_option(&mut nak, IPCP_ADDR, &LOCAL.octets());
                    }
                    for (k, v) in [(IPCP_DNS1, DNS1), (IPCP_DNS2, self.dns2)] {
                        match want(k) {
                            Some(_) if self.reject_dns => put_option(&mut rej, k, &[0; 4]),
                            Some(d) if d != v => put_option(&mut nak, k, &v.octets()),
                            _ => {}
                        }
                    }
                    let code = if !rej.is_empty() {
                        (CONF_REJ, rej)
                    } else if !nak.is_empty() {
                        (CONF_NAK, nak)
                    } else {
                        self.ipcp_up = true;
                        (CONF_ACK, c.data.to_vec())
                    };
                    out.push(self.ppp(PPP_IPCP, &ctrl(code.0, c.id, &code.1)));
                }
                CONF_ACK => {}
                _ => {}
            },
            _ => {}
        }
        out
    }
}

struct Run {
    c: Client,
    now: u64,
    events: Vec<Event>,
}

impl Run {
    fn new(cfg: Config) -> Self {
        let mut c = Client::new(cfg, CLIENT, 0x5eed);
        c.start(0);
        Run {
            c,
            now: 0,
            events: Vec::new(),
        }
    }

    fn pap() -> Self {
        Run::new(Config {
            username: "alice@isp".into(),
            password: "s3cret".into(),
            ..Config::default()
        })
    }

    /// Exchange frames with the ACs (each sees every client frame) for
    /// `ms`, in 100 ms steps.
    fn run(&mut self, acs: &mut [&mut Ac], ms: u64) {
        let end = self.now + ms;
        loop {
            self.c.poll(self.now);
            // Until quiet: answers can trigger more frames.
            for _ in 0..50 {
                let mut replies = Vec::new();
                while let Some(f) = self.c.poll_transmit() {
                    for ac in acs.iter_mut() {
                        let to_ac =
                            parse(&f).is_some_and(|p| p.dst == ac.mac || p.dst == BROADCAST);
                        if to_ac {
                            replies.extend(ac.input(&f));
                        }
                    }
                }
                if replies.is_empty() {
                    break;
                }
                for r in replies {
                    self.c.handle_frame(self.now, &r);
                }
            }
            while let Some(e) = self.c.poll_event() {
                self.events.push(e);
            }
            if self.now >= end {
                break;
            }
            self.now += 100;
        }
    }

    fn up(&self) -> Option<&Link> {
        self.events.iter().rev().find_map(|e| match e {
            Event::Up(l) => Some(l),
            _ => None,
        })
    }

    fn downs(&self) -> Vec<&Reason> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Down { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    }
}

fn expected_link(mtu: u16) -> Link {
    Link {
        session: Session {
            id: 0x1234,
            peer: AC_MAC,
        },
        local: LOCAL,
        remote: REMOTE,
        dns: vec![DNS1, DNS2],
        mtu,
        ac_name: "isp-ac".into(),
    }
}

#[test]
fn pap_session_comes_up() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(r.up(), Some(&expected_link(1492)));
    assert_eq!(r.c.state(), State::Up);
    assert_eq!(
        r.events.first(),
        Some(&Event::Session(Session {
            id: 0x1234,
            peer: AC_MAC
        }))
    );
    assert!(ac.ipcp_up);
    assert!(r.downs().is_empty());
}

#[test]
fn chap_session_comes_up() {
    let mut ac = Ac::new(SimAuth::Chap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(r.up(), Some(&expected_link(1492)));
}

#[test]
fn no_authentication_required() {
    let mut ac = Ac::new(SimAuth::None);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert!(r.up().is_some());
}

#[test]
fn unsupported_auth_is_naked_to_chap() {
    let mut ac = Ac::new(SimAuth::EapThenChap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert!(ac.use_chap);
    assert_eq!(r.up(), Some(&expected_link(1492)));
}

#[test]
fn smaller_mtu_from_config() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::new(Config {
        username: "alice@isp".into(),
        password: "s3cret".into(),
        mtu: 1480,
        ..Config::default()
    });
    r.run(&mut [&mut ac], 1000);
    assert_eq!(r.up(), Some(&expected_link(1480)));
    // Above what PPPoE carries even with RFC 4638: clamped.
    let c = Client::new(
        Config {
            mtu: 1600,
            ..Config::default()
        },
        CLIENT,
        1,
    );
    assert_eq!(c.config().mtu, MAX_MTU_RFC4638);
}

#[test]
fn wrong_password_fails_and_retries_after_backoff() {
    let mut ac = Ac::new(SimAuth::Pap);
    ac.pass = "other";
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(
        r.downs(),
        vec![&Reason::AuthFailed(String::from("bad account"))]
    );
    assert!(matches!(r.c.state(), State::Waiting(t) if t >= AUTH_FAIL_MIN_MS));
    assert_eq!(ac.padts, 1, "a failed session is torn down with PADT");
    let padis = |ac: &Ac| {
        ac.got
            .iter()
            .filter(|f| f[15] == PADI && get16(f, 12) == ETHERTYPE_DISCOVERY)
            .count()
    };
    let before = padis(&ac);
    r.run(&mut [&mut ac], 5_000);
    assert_eq!(padis(&ac), before, "no retry before the backoff");
    r.run(&mut [&mut ac], 6_000);
    assert!(padis(&ac) > before);
    // Fixed password: the next attempt succeeds.
    ac.pass = "s3cret";
    ac.lcp_ours_acked = false;
    ac.lcp_theirs_acked = false;
    ac.ipcp_sent = false;
    ac.authed = false;
    r.run(&mut [&mut ac], 30_000);
    assert!(r.up().is_some());
}

#[test]
fn chap_wrong_password() {
    let mut ac = Ac::new(SimAuth::Chap);
    ac.pass = "other";
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(
        r.downs(),
        vec![&Reason::AuthFailed(String::from("Access denied"))]
    );
}

#[test]
fn echo_keepalive_detects_a_dead_link() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert!(r.up().is_some());
    // Answered echoes keep it up.
    r.run(&mut [&mut ac], 60_000);
    assert!(ac.echo_requests >= 5);
    assert!(r.downs().is_empty());
    // Peer gone silent: 5 unanswered requests at 10 s, then down.
    ac.answer_echo = false;
    let n = ac.echo_requests;
    r.run(&mut [&mut ac], 45_000);
    assert!(r.downs().is_empty(), "not before 5 intervals");
    r.run(&mut [&mut ac], 20_000);
    assert_eq!(ac.echo_requests - n, 5);
    assert_eq!(r.downs(), vec![&Reason::EchoTimeout]);
    assert!(r.events.contains(&Event::Down {
        reason: Reason::EchoTimeout,
        was_up: true
    }));
    assert_eq!(ac.padts, 1);
}

#[test]
fn late_echo_replies_count_looped_back_ones_do_not() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    ac.answer_echo = false;
    let lcp = |id: u8, magic: [u8; 4]| ac_frame(PPP_LCP, &ctrl(ECHO_REPLY, id, &magic));
    // 4 requests unanswered, then a reply to an older one: still alive.
    r.run(&mut [&mut ac], 40_000);
    r.c.handle_frame(r.now, &lcp(1, [0x0b, 0xad, 0xca, 0xfe]));
    r.run(&mut [&mut ac], 40_000);
    assert!(r.downs().is_empty(), "{:?}", r.downs());
    // Our own magic number coming back is no sign of life.
    let ours = {
        r.c.poll(r.now + 10_000);
        let f = r.c.poll_transmit().expect("echo request");
        let p = parse(&f).unwrap();
        let c = parse_ctrl(&p.payload[2..]).unwrap();
        assert_eq!(c.code, ECHO_REQ);
        [c.data[0], c.data[1], c.data[2], c.data[3]]
    };
    for _ in 0..6 {
        r.c.handle_frame(r.now, &lcp(9, ours));
        r.run(&mut [&mut ac], 10_000);
    }
    assert_eq!(r.downs(), vec![&Reason::EchoTimeout]);
}

fn ac_frame(proto: u16, body: &[u8]) -> Vec<u8> {
    session_frame(CLIENT, AC_MAC, 0x1234, proto, body)
}

#[test]
fn padt_ends_the_session_and_rediscovers() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    let padt = discovery(CLIENT, AC_MAC, PADT, 0x1234, &[]);
    // From another MAC or for another session: ignored.
    r.c.handle_frame(r.now, &discovery(CLIENT, AC2_MAC, PADT, 0x1234, &[]));
    r.c.handle_frame(r.now, &discovery(CLIENT, AC_MAC, PADT, 0x9999, &[]));
    assert_eq!(r.c.state(), State::Up);
    r.c.handle_frame(r.now, &padt);
    r.run(&mut [], 0);
    assert_eq!(
        r.events.last(),
        Some(&Event::Down {
            reason: Reason::Padt,
            was_up: true
        })
    );
    assert_eq!(r.c.session(), None);
    // Backoff was reset by the successful session: 1 s.
    let mut ac = Ac::new(SimAuth::Pap);
    ac.session = 0x2222;
    r.run(&mut [&mut ac], 2_000);
    assert_eq!(r.up().unwrap().session.id, 0x2222);
}

#[test]
fn lcp_terminate_request_from_peer() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    let term = ac.ppp(PPP_LCP, &ctrl(TERM_REQ, 9, b"bye"));
    r.c.handle_frame(r.now, &term);
    let f = r.c.poll_transmit().unwrap();
    let p = parse(&f).unwrap();
    assert_eq!(get16(p.payload, 0), PPP_LCP);
    assert_eq!(parse_ctrl(&p.payload[2..]).unwrap().code, TERM_ACK);
    r.run(&mut [&mut ac], 0);
    assert_eq!(r.downs(), vec![&Reason::Terminated]);
}

#[test]
fn ac_name_filter_picks_the_right_concentrator() {
    let mut a = Ac::new(SimAuth::Pap);
    a.name = "wrong-ac";
    let mut b = Ac::new(SimAuth::Pap);
    b.mac = AC2_MAC;
    b.name = "isp-ac";
    let mut r = Run::new(Config {
        username: "alice@isp".into(),
        password: "s3cret".into(),
        ac_name: "isp-ac".into(),
        ..Config::default()
    });
    r.run(&mut [&mut a, &mut b], 1000);
    let l = r.up().expect("up via the named AC");
    assert_eq!(l.session.peer, AC2_MAC);
    assert!(
        !a.got.iter().any(|f| f[15] == PADR),
        "no PADR to the other AC"
    );
}

#[test]
fn service_name_filter() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::new(Config {
        username: "alice@isp".into(),
        password: "s3cret".into(),
        service: "internet".into(),
        ..Config::default()
    });
    r.run(&mut [&mut ac], 1000);
    assert!(r.up().is_some(), "the PADO lists the service");
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::new(Config {
        username: "alice@isp".into(),
        password: "s3cret".into(),
        service: "iptv".into(),
        ..Config::default()
    });
    r.run(&mut [&mut ac], 3000);
    assert!(r.up().is_none());
    assert!(matches!(r.c.state(), State::Discovery(_)));
}

#[test]
fn foreign_host_uniq_is_ignored() {
    let mut r = Run::pap();
    let pado = discovery(
        CLIENT,
        AC_MAC,
        PADO,
        0,
        &[(TAG_AC_NAME, b"x"), (TAG_HOST_UNIQ, b"someone else")],
    );
    r.c.poll_transmit(); // the PADI
    r.c.handle_frame(0, &pado);
    assert_eq!(r.c.state(), State::Discovery(1));
    assert!(r.c.poll_transmit().is_none());
}

#[test]
fn padi_backs_off_exponentially() {
    let mut r = Run::pap();
    let mut sent = Vec::new();
    for t in (0..=70_000).step_by(100) {
        r.c.poll(t);
        while let Some(f) = r.c.poll_transmit() {
            assert_eq!(f[15], PADI);
            sent.push(t);
        }
    }
    assert_eq!(sent, vec![0, 1_000, 3_000, 7_000, 15_000, 31_000, 63_000]);
}

#[test]
fn lost_pads_falls_back_to_padi() {
    let mut ac = Ac::new(SimAuth::Pap);
    ac.drop_padr = true;
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 6_500);
    let padrs = ac.got.iter().filter(|f| f[15] == PADR).count();
    assert_eq!(padrs, 4, "PADR, 2 retries, then PADI and a new PADR");
    assert_eq!(r.c.state(), State::Requesting);
}

#[test]
fn pads_error_is_refused() {
    let mut r = Run::pap();
    let f = r.c.poll_transmit().unwrap();
    let uniq = find_tag(parse(&f).unwrap().payload, TAG_HOST_UNIQ)
        .unwrap()
        .to_vec();
    r.c.handle_frame(
        0,
        &discovery(
            CLIENT,
            AC_MAC,
            PADO,
            0,
            &[(TAG_AC_NAME, b"a"), (TAG_HOST_UNIQ, &uniq)],
        ),
    );
    assert_eq!(r.c.state(), State::Requesting);
    r.c.handle_frame(
        10,
        &discovery(
            CLIENT,
            AC_MAC,
            PADS,
            0,
            &[
                (TAG_HOST_UNIQ, &uniq),
                (TAG_SERVICE_NAME_ERROR, b"no such service"),
            ],
        ),
    );
    r.run(&mut [], 0);
    assert_eq!(
        r.downs(),
        vec![&Reason::Refused(String::from("no such service"))]
    );
}

#[test]
fn ipv6cp_is_protocol_rejected() {
    let mut ac = Ac::new(SimAuth::Pap);
    ac.offer_ipv6cp = true;
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(ac.proto_rejects, vec![PPP_IPV6CP]);
    assert!(r.up().is_some());
}

#[test]
fn dns_rejected_still_comes_up() {
    let mut ac = Ac::new(SimAuth::Pap);
    ac.reject_dns = true;
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(r.up().unwrap().dns, Vec::<Ipv4Addr>::new());
}

#[test]
fn the_same_dns_server_twice_is_listed_once() {
    // pppd with one ms-dns answers both DNS options with it.
    let mut ac = Ac::new(SimAuth::Pap);
    ac.dns2 = DNS1;
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    assert_eq!(r.up().unwrap().dns, vec![DNS1]);
}

#[test]
fn echo_request_from_peer_is_answered() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    let req = ac.ppp(
        PPP_LCP,
        &ctrl(ECHO_REQ, 77, &[0x0b, 0xad, 0xca, 0xfe, 1, 2]),
    );
    r.c.handle_frame(r.now, &req);
    let f = r.c.poll_transmit().unwrap();
    let p = parse(&f).unwrap();
    let c = parse_ctrl(&p.payload[2..]).unwrap();
    assert_eq!((c.code, c.id), (ECHO_REPLY, 77));
    assert_ne!(&c.data[..4], &[0; 4], "our magic number");
    assert_eq!(&c.data[4..], &[1, 2]);
}

#[test]
fn stop_sends_terminate_and_padt() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    r.c.stop();
    r.run(&mut [&mut ac], 0);
    assert_eq!(ac.padts, 1);
    assert_eq!(r.c.state(), State::Idle);
    assert_eq!(r.c.next_deadline(), None);
    assert_eq!(
        r.events.last(),
        Some(&Event::Down {
            reason: Reason::Stopped,
            was_up: true
        })
    );
}

#[test]
fn session_pack_roundtrip() {
    let s = Session {
        id: 0xbeef,
        peer: [1, 2, 3, 4, 5, 6],
    };
    assert_eq!(Session::unpack(s.pack()), Some(s));
    assert_eq!(Session::unpack(0), None);
}

/// An Ethernet/IPv4 frame with a 20-byte IP header and `extra` bytes.
fn ip_frame(extra: usize) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + extra];
    f[0..6].copy_from_slice(&AC_MAC);
    f[6..12].copy_from_slice(&CLIENT);
    f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f[14] = 0x45;
    for (i, b) in f[34..].iter_mut().enumerate() {
        *b = i as u8;
    }
    f
}

#[test]
fn encap_decap_roundtrip() {
    let s = Session {
        id: 7,
        peer: AC_MAC,
    };
    let plain = ip_frame(30);
    let mut buf = vec![0u8; SESSION_OVERHEAD];
    buf.extend_from_slice(&plain);
    encap_ipv4(&mut buf, s, CLIENT);
    let p = parse(&buf).unwrap();
    assert_eq!(
        (p.ethertype, p.session, p.dst, p.src),
        (ETHERTYPE_SESSION, 7, AC_MAC, CLIENT)
    );
    assert_eq!(p.payload.len(), 2 + 50);
    assert_eq!(&p.payload[2..], &plain[14..]);
    // Received with Ethernet padding: the length field wins.
    let mut rx = buf.clone();
    rx.extend_from_slice(&[0xee; 10]);
    // (sent by CLIENT here, so CLIENT is the peer for this check)
    let from = Session {
        id: 7,
        peer: CLIENT,
    };
    let SessionRx::Ipv4 { len } = classify_session(&rx, Some(from)) else {
        panic!()
    };
    assert_eq!(len, 50);
    decap_ipv4(&mut rx);
    let out = &rx[SESSION_OVERHEAD..SESSION_OVERHEAD + ETH_HDR + len];
    assert_eq!(&out[12..], &plain[12..]);
    assert_eq!(&out[..6], &AC_MAC); // dst/src as received (rewritten by the caller)
}

#[test]
fn classify_rejects_other_sessions_and_protocols() {
    let s = Session {
        id: 7,
        peer: AC_MAC,
    };
    let ipv4 = session_frame(CLIENT, AC_MAC, 7, PPP_IPV4, &[0x45; 20]);
    assert_eq!(
        classify_session(&ipv4, Some(s)),
        SessionRx::Ipv4 { len: 20 }
    );
    assert_eq!(classify_session(&ipv4, None), SessionRx::Control);
    let other = Session { id: 8, ..s };
    assert_eq!(classify_session(&ipv4, Some(other)), SessionRx::Control);
    let spoofed = session_frame(CLIENT, AC2_MAC, 7, PPP_IPV4, &[0x45; 20]);
    assert_eq!(classify_session(&spoofed, Some(s)), SessionRx::Control);
    let lcp = session_frame(CLIENT, AC_MAC, 7, PPP_LCP, &[1, 1, 0, 4]);
    assert_eq!(classify_session(&lcp, Some(s)), SessionRx::Control);
    let mut short = ipv4.clone();
    short[18..20].copy_from_slice(&500u16.to_be_bytes()); // length past the end
    assert_eq!(classify_session(&short, Some(s)), SessionRx::Control);
}

#[test]
fn padt_frame_for_shutdown() {
    let s = Session {
        id: 0x4242,
        peer: AC_MAC,
    };
    let mut buf = [0xffu8; 64];
    let n = write_padt(&mut buf, s, CLIENT);
    let p = parse(&buf[..n]).unwrap();
    assert_eq!((p.code, p.session, p.dst), (PADT, 0x4242, AC_MAC));
    assert!(p.payload.is_empty());
}

#[test]
fn chap_md5_known_answer() {
    // MD5(0x01 ‖ "secret" ‖ 16 zero bytes), from Python's hashlib.
    let d = chap_md5(1, b"secret", &[0; 16]);
    let hex: String = d.iter().map(|b| alloc::format!("{b:02x}")).collect();
    assert_eq!(hex, "7570c653cdf4755ccffcaa80f29268d1");
}

/// Random and mutated frames in every phase: no panic, bounded output.
#[test]
fn fuzz_frames() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    // Valid frames to mutate: a full PAP session's worth.
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = Run::pap();
    r.run(&mut [&mut ac], 1000);
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    {
        let mut ac2 = Ac::new(SimAuth::Chap);
        let mut c = Client::new(Run::pap().c.config().clone(), CLIENT, 3);
        c.start(0);
        for _ in 0..20 {
            while let Some(f) = c.poll_transmit() {
                for reply in ac2.input(&f) {
                    corpus.push(reply.clone());
                    c.handle_frame(0, &reply);
                }
            }
        }
    }
    assert!(corpus.len() > 4);
    for round in 0..20_000u64 {
        let mut f = if round % 3 == 0 {
            let n = (rnd() % 80) as usize;
            let mut f: Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
            if f.len() >= 14 {
                f[0..6].copy_from_slice(&CLIENT);
                f[12] = 0x88;
                f[13] = if rnd() & 1 == 0 { 0x63 } else { 0x64 };
            }
            f
        } else {
            corpus[(rnd() as usize) % corpus.len()].clone()
        };
        let flips = rnd() % 4;
        for _ in 0..flips {
            if !f.is_empty() {
                let i = (rnd() as usize) % f.len();
                f[i] = rnd() as u8;
            }
        }
        if rnd() % 5 == 0 {
            let cut = (rnd() as usize) % (f.len() + 1);
            f.truncate(cut);
        }
        r.c.handle_frame(r.now, &f);
        r.c.poll(r.now);
        r.now += rnd() % 500;
        let mut n = 0;
        while r.c.poll_transmit().is_some() {
            n += 1;
        }
        assert!(n <= TX_QUEUE_MAX);
        while r.c.poll_event().is_some() {}
        let _ = classify_session(
            &f,
            Some(Session {
                id: 0x1234,
                peer: AC_MAC,
            }),
        );
    }
}

// ---- RFC 4638: MTU 1500 over PPPoE --------------------------------------

fn jumbo() -> Run {
    Run::new(Config {
        username: "alice@isp".into(),
        password: "s3cret".into(),
        mtu: 1500,
        ..Config::default()
    })
}

fn tag_of(f: &[u8]) -> Option<u16> {
    find_tag(parse(f).unwrap().payload, TAG_PPP_MAX_PAYLOAD).map(|v| get16(v, 0))
}

fn first(ac: &Ac, code: u8) -> Vec<u8> {
    ac.got
        .iter()
        .find(|f| get16(f, 12) == ETHERTYPE_DISCOVERY && f[15] == code)
        .unwrap()
        .clone()
}

/// The full-size echo requests the client sent (LCP length = 1500).
fn jumbo_echoes(ac: &Ac) -> usize {
    ac.got
        .iter()
        .filter(|f| {
            let p = parse(f).unwrap();
            p.ethertype == ETHERTYPE_SESSION
                && get16(p.payload, 0) == PPP_LCP
                && p.payload[2] == ECHO_REQ
                && p.payload.len() == 2 + 1500
        })
        .count()
}

#[test]
fn rfc4638_session_at_1500() {
    let mut ac = Ac::new(SimAuth::Pap);
    ac.rfc4638 = true;
    let mut r = jumbo();
    r.run(&mut [&mut ac], 2000);
    assert_eq!(r.up(), Some(&expected_link(1500)));
    assert_eq!(tag_of(&first(&ac, PADI)), Some(1500));
    assert_eq!(tag_of(&first(&ac, PADR)), Some(1500));
    assert_eq!(jumbo_echoes(&ac), 1, "the path was checked once");
    assert!(!r.c.jumbo_failed());
}

#[test]
fn rfc4638_without_ac_support_is_1492() {
    let mut ac = Ac::new(SimAuth::Pap);
    let mut r = jumbo();
    r.run(&mut [&mut ac], 2000);
    assert_eq!(r.up(), Some(&expected_link(1492)));
    assert_eq!(tag_of(&first(&ac, PADI)), Some(1500), "asked");
    assert_eq!(tag_of(&first(&ac, PADR)), None, "not echoed: not asked again");
    assert_eq!(jumbo_echoes(&ac), 0);
}

/// The AC agrees, but the path loses large frames, or its echo comes back
/// short: the session ends and the next one is a plain 1492 one.
#[test]
fn rfc4638_falls_back_when_the_path_does_not_carry_it() {
    for (path, short) in [(1492, false), (1500, true)] {
        let mut ac = Ac::new(SimAuth::Pap);
        ac.rfc4638 = true;
        ac.path_mtu = path;
        ac.echo_short = short;
        let mut r = jumbo();
        r.run(&mut [&mut ac], 10_000);
        assert!(
            r.events.contains(&Event::Down { reason: Reason::JumboFailed, was_up: false }),
            "{:?}",
            r.events
        );
        assert!(r.c.jumbo_failed());
        assert_eq!(r.up(), Some(&expected_link(1492)), "path {path}, short {short}");
        assert_eq!(ac.padts, 1, "the jumbo session was ended");
        // The second PADI asks no more.
        let padis: Vec<_> = ac
            .got
            .iter()
            .filter(|f| get16(f, 12) == ETHERTYPE_DISCOVERY && f[15] == PADI)
            .collect();
        assert_eq!(tag_of(padis.last().unwrap()), None);
        // Before the fallback, no Up was reported at 1500.
        assert!(!r.events.iter().any(|e| matches!(e, Event::Up(l) if l.mtu == 1500)));
    }
}

/// The real AC's way: 1500 agreed in discovery, MRU 1492 asked in LCP.
#[test]
fn rfc4638_ac_asking_1492_is_asked_for_1500() {
    // It takes the suggestion: 1500 both ways.
    let mut ac = Ac::new(SimAuth::Pap);
    ac.rfc4638 = true;
    ac.ac_mru = Some(1492);
    ac.take_mru_nak = true;
    let mut r = jumbo();
    r.run(&mut [&mut ac], 2000);
    assert_eq!(r.up(), Some(&expected_link(1500)));
    // It insists: we send 1492, it may send us 1500 (checked on the path).
    let mut ac = Ac::new(SimAuth::Pap);
    ac.rfc4638 = true;
    ac.ac_mru = Some(1492);
    let mut r = jumbo();
    r.run(&mut [&mut ac], 2000);
    assert_eq!(r.up(), Some(&expected_link(1492)));
    assert_eq!(jumbo_echoes(&ac), 1, "the receive direction was checked");
    assert!(!r.c.jumbo_failed());
    let t = r.c.rfc4638_trace().unwrap();
    assert_eq!((t.pado, t.pads, t.our_mru, t.peer_mru), (Some(1500), Some(1500), Some(1500), Some(1492)));
    // It insists and the path loses large frames: back to 1492 both ways.
    let mut ac = Ac::new(SimAuth::Pap);
    ac.rfc4638 = true;
    ac.ac_mru = Some(1492);
    ac.path_mtu = 1492;
    let mut r = jumbo();
    r.run(&mut [&mut ac], 10_000);
    assert!(r.c.jumbo_failed());
    assert_eq!(r.up(), Some(&expected_link(1492)));
    assert_eq!(r.c.rfc4638_trace().unwrap().our_mru, Some(1492));
}
