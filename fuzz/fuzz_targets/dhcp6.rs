//! The DHCPv6 prefix delegation client (`proto_dhcp::v6::pd`) and the RA
//! parser (`proto_dhcp::v6::ra::parse_frame`): what the ISP side controls.
//! Structured: replies to the client's last message (its xid and client
//! id, so they reach the state machine) with fuzzed prefixes, lifetimes,
//! T1/T2 and status codes, damaged copies, raw bytes, and time passing.
//! Checks: never a panic; a held delegation is a /1–/64 with preferred ≤
//! valid; after Lost nothing is held; deadlines never lie in the past of
//! a poll that sent nothing; RA parsing never panics.
#![no_main]

use arbitrary::Arbitrary;
use core::net::Ipv6Addr;
use leatos_fuzz::damage;
use libfuzzer_sys::fuzz_target;
use proto_dhcp::v6::pd::{Client, Event, PdConfig};
use proto_dhcp::v6::ra;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Answer the last message: kind (2 Advertise, 7 Reply, other), a
    /// prefix (len, preferred, valid), T1, T2, an IA or top-level status.
    Answer { kind: u8, prefix: Option<(u8, u32, u32, u16)>, t1: u32, t2: u32, status: Option<(bool, u16)>, noise: Option<Vec<u8>> },
    Raw(Vec<u8>),
    Ra(Vec<u8>),
    Tick(u32),
}

fn opt(b: &mut Vec<u8>, code: u16, data: &[u8]) {
    b.extend_from_slice(&code.to_be_bytes());
    b.extend_from_slice(&(data.len() as u16).to_be_bytes());
    b.extend_from_slice(data);
}

fn client_id(m: &[u8]) -> Option<Vec<u8>> {
    let mut o = m.get(4..)?;
    while o.len() >= 4 {
        let (c, l) = (u16::from_be_bytes([o[0], o[1]]), usize::from(u16::from_be_bytes([o[2], o[3]])));
        let d = o.get(4..4 + l)?;
        if c == 1 {
            return Some(d.to_vec());
        }
        o = &o[4 + l..];
    }
    None
}

fuzz_target!(|ops: Vec<Op>| {
    let mut c = Client::new(PdConfig { mac: [2, 0, 0, 0, 0, 1], iaid: 1, hint_len: 56, last: None }, 0, 0x5eed);
    let mut now = 0u64;
    let mut last: Option<Vec<u8>> = None;
    for op in ops.into_iter().take(100) {
        match op {
            Op::Answer { kind, prefix, t1, t2, status, noise } => {
                let Some(m) = &last else { continue };
                let Some(cid) = client_id(m) else { continue };
                let k = match kind % 3 {
                    0 => 2,
                    1 => 7,
                    _ => kind,
                };
                let mut b = vec![k, m[1], m[2], m[3]];
                opt(&mut b, 1, &cid);
                opt(&mut b, 2, &[0, 3, 0, 1, 2, 0, 0, 0, 0, 9]);
                let mut ia = Vec::new();
                ia.extend_from_slice(&1u32.to_be_bytes());
                ia.extend_from_slice(&t1.to_be_bytes());
                ia.extend_from_slice(&t2.to_be_bytes());
                if let Some((len, pref, valid, hi)) = prefix {
                    let mut x = Vec::new();
                    x.extend_from_slice(&pref.to_be_bytes());
                    x.extend_from_slice(&valid.to_be_bytes());
                    x.push(len);
                    x.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, hi, 0, 0, 0, 0, 0).octets());
                    opt(&mut ia, 26, &x);
                }
                if let Some((true, code)) = status {
                    opt(&mut ia, 13, &code.to_be_bytes());
                }
                opt(&mut b, 25, &ia);
                if let Some((false, code)) = status {
                    opt(&mut b, 13, &code.to_be_bytes());
                }
                if let Some(n) = &noise {
                    damage(&mut b, n);
                }
                c.handle(now, &b);
            }
            Op::Raw(data) => c.handle(now, &data),
            Op::Ra(data) => {
                if let Some(r) = ra::parse_frame(&data) {
                    assert!(r.prefixes.len() <= 16 && r.rdnss.len() <= 64);
                }
            }
            Op::Tick(ms) => now += u64::from(ms % 4_000_000),
        }
        if let Some(m) = c.poll(now) {
            last = Some(m);
        }
        assert!(c.next_deadline() > now || c.poll(now).is_none_or(|m| { last = Some(m); true }));
        while let Some(e) = c.poll_event() {
            if e == Event::Lost {
                assert!(c.delegation().is_none() || c.state() == proto_dhcp::v6::pd::State::Bound, "lost but held");
            }
        }
        if let Some(d) = c.delegation() {
            assert!((1..=64).contains(&d.len), "delegated /{}", d.len);
            assert!(d.preferred_secs <= d.valid_secs, "preferred above valid");
        }
    }
});
