//! The PPPoE client (`crates/proto-pppoe`): frames from the WAN, before and
//! after a session exists. A reactive access concentrator answers what the
//! client last sent (PADO/PADS echoing Host-Uniq and the cookie, ACKs of
//! its configure requests, PAP/CHAP, IPCP), so sequences reach LCP, the
//! authentication and IPCP; any frame may be damaged or replaced by raw
//! bytes. Checks: everything the client sends parses as PPPoE from its own
//! MAC; its transmit queue stays bounded.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use proto_pppoe::wire::{self, *};
use proto_pppoe::{Client, Config};
use rrouter_fuzz::damage;

const CLIENT: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AC: [u8; 6] = [2, 0xac, 0, 0, 0, 1];
const PROTOS: [u16; 6] = [PPP_LCP, PPP_PAP, PPP_CHAP, PPP_IPCP, PPP_IPV6CP, PPP_IPV4];

#[derive(Arbitrary, Debug)]
enum Op {
    Pado { cookie: Vec<u8>, ac_name: Vec<u8>, max_payload: Option<u16>, error_tag: bool, keep_uniq: bool },
    Pads { session: u16, max_payload: Option<u16> },
    Padt,
    /// ACK (or NAK/REJ) the client's last configure request of a protocol.
    Answer { proto: u8, code: u8 },
    /// A control packet of our own in the session.
    Ctrl { proto: u8, code: u8, id: Option<u8>, data: Vec<u8> },
    /// PPP payload of any protocol number.
    Payload { proto: u16, body: Vec<u8> },
    Raw(Vec<u8>),
    Tick(u16),
    Damage(Vec<u8>),
}

#[derive(Default)]
struct Ac {
    session: u16,
    /// Last discovery payload from the client (Host-Uniq source).
    discovery: Vec<u8>,
    /// Last control packet per protocol from the client: (id, data).
    last_ctrl: Vec<(u16, u8, Vec<u8>)>,
}

impl Ac {
    fn observe(&mut self, f: &[u8]) {
        let p = wire::parse(f).expect("client sent a frame that is not PPPoE");
        assert_eq!(p.src, CLIENT, "client sent from another MAC");
        if p.ethertype == ETHERTYPE_DISCOVERY {
            self.discovery = p.payload.to_vec();
        } else if p.payload.len() >= 2 {
            let proto = get16(p.payload, 0);
            if let Some(c) = parse_ctrl(&p.payload[2..]) {
                self.last_ctrl.retain(|(pr, ..)| *pr != proto);
                self.last_ctrl.push((proto, c.id, c.data.to_vec()));
            }
        }
    }
}

fuzz_target!(|input: (u64, bool, Vec<Op>)| {
    let (seed, auth, ops) = input;
    let cfg = Config {
        username: if auth { "user".into() } else { String::new() },
        password: "secret".into(),
        mtu: 1500,
        ..Config::default()
    };
    let mut c = Client::new(cfg, CLIENT, seed);
    let mut ac = Ac::default();
    let mut now = 0u64;
    c.start(now);
    let mut pending_damage: Option<Vec<u8>> = None;
    for op in ops.into_iter().take(150) {
        while let Some(f) = c.poll_transmit() {
            ac.observe(&f);
        }
        while c.poll_event().is_some() {}
        let uniq = find_tag(&ac.discovery, TAG_HOST_UNIQ).unwrap_or(b"").to_vec();
        let mut frame = match op {
            Op::Pado { cookie, ac_name, max_payload, error_tag, keep_uniq } => {
                let mp = max_payload.map(u16::to_be_bytes);
                let mut t: Vec<(u16, &[u8])> = vec![(TAG_AC_NAME, &ac_name), (TAG_SERVICE_NAME, b""), (TAG_AC_COOKIE, &cookie)];
                if keep_uniq {
                    t.push((TAG_HOST_UNIQ, &uniq));
                }
                if let Some(m) = &mp {
                    t.push((TAG_PPP_MAX_PAYLOAD, m));
                }
                if error_tag {
                    t.push((TAG_AC_SYSTEM_ERROR, b"busy"));
                }
                discovery(CLIENT, AC, PADO, 0, &t)
            }
            Op::Pads { session, max_payload } => {
                ac.session = session;
                let mp = max_payload.map(u16::to_be_bytes);
                let mut t: Vec<(u16, &[u8])> = vec![(TAG_SERVICE_NAME, b""), (TAG_HOST_UNIQ, &uniq)];
                if let Some(m) = &mp {
                    t.push((TAG_PPP_MAX_PAYLOAD, m));
                }
                discovery(CLIENT, AC, PADS, session, &t)
            }
            Op::Padt => discovery(CLIENT, AC, PADT, ac.session, &[]),
            Op::Answer { proto, code } => {
                let proto = PROTOS[proto as usize % 4];
                let Some((_, id, data)) = ac.last_ctrl.iter().find(|(p, ..)| *p == proto).cloned() else { continue };
                let code = [CONF_ACK, CONF_ACK, CONF_NAK, CONF_REJ, ECHO_REQ + 1][code as usize % 5];
                let body = match proto {
                    // PAP: Authenticate-Ack / Nak; CHAP: a Challenge.
                    PPP_PAP => ctrl(2 + code % 2, id, b"\x00"),
                    PPP_CHAP => ctrl(1, id.wrapping_add(1), b"\x10abcdefghijklmnopAC"),
                    _ => ctrl(code, id, &data),
                };
                session_frame(CLIENT, AC, ac.session, proto, &body)
            }
            Op::Ctrl { proto, code, id, data } => {
                let proto = PROTOS[proto as usize % PROTOS.len()];
                let id = id.unwrap_or_else(|| ac.last_ctrl.iter().find(|(p, ..)| *p == proto).map_or(1, |x| x.1));
                session_frame(CLIENT, AC, ac.session, proto, &ctrl(code % 16, id, &data))
            }
            Op::Payload { proto, body } => session_frame(CLIENT, AC, ac.session, proto, &body),
            Op::Raw(mut f) => {
                f.truncate(1600);
                f
            }
            Op::Tick(ms) => {
                now += u64::from(ms) * 20;
                c.poll(now);
                continue;
            }
            Op::Damage(noise) => {
                pending_damage = Some(noise);
                continue;
            }
        };
        if let Some(noise) = pending_damage.take() {
            damage(&mut frame, &noise);
        }
        // What the datapath does with it first.
        let _ = classify_session(&frame, c.session());
        c.handle_frame(now, &frame);
        let mut n = 0;
        while let Some(f) = c.poll_transmit() {
            ac.observe(&f);
            n += 1;
            assert!(n <= 64, "transmit queue grows without bound");
        }
    }
});
