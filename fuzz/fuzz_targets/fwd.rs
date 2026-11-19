//! The forwarder (`crates/fwd`): every forwarded packet, internet-facing.
//! Structured: packets built from fields over address/port sets the router
//! knows (valid checksums, so they reach NAT, conntrack and the firewall),
//! replies and ICMP errors to what it forwarded (the NAT reverse path),
//! later fragments, policy changes, expiry and raw damaged frames.
//! Checks: forwarded frames stay inside the buffer, and a frame that came
//! in with valid checksums leaves with valid checksums (NAT rewrites them
//! incrementally).
#![no_main]

use arbitrary::Arbitrary;
use core::net::Ipv4Addr;
use fwd::conntrack::Budget;
use fwd::forwarder::{
    Action, Forwarder, Interface, Policy, PortForward, Redirect, Role, Rule, RuleTo, Verdict, proto, svc,
};
use fwd::wire::{self, ETH_HDR, PROTO_ICMP, PROTO_TCP, PROTO_UDP, SplitPlan};
use libfuzzer_sys::fuzz_target;
use rrouter_fuzz::{Addr, Ipv4Pkt, checksums_ok, damage};

const WAN: u8 = 0;
const MACS: [[u8; 6]; 3] = [[2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 3]];
const PEER: [u8; 6] = [2, 0xaa, 0, 0, 0, 9];
const TAIL: usize = 64;

#[derive(Arbitrary, Debug)]
enum Op {
    /// A packet arriving on interface `ifx % 3` (to the router's MAC, or
    /// broadcast / another MAC).
    Packet { ifx: u8, to_other_mac: Option<u8>, pkt: Ipv4Pkt, noise: Option<Vec<u8>> },
    /// The far end answers the last forwarded packet (addresses and ports
    /// swapped), optionally with other TCP flags.
    Reply { flags: Option<u8>, noise: Option<Vec<u8>> },
    /// An ICMP error about the last forwarded packet, from `from`.
    IcmpError { from: Addr, kind: u8, code: u8 },
    /// Arbitrary bytes on an interface.
    Raw { ifx: u8, data: Vec<u8> },
    Tick(u16),
    Expire(u8),
    SetPolicy(bool),
    SetMtu(u16),
    SetWanAddr(Option<Addr>),
}

fn policy() -> Policy {
    let nas = Ipv4Addr::new(192, 168, 1, 10);
    Policy {
        // Zones: 0 = wan, 1 = lan, 2 = guest. lan → wan, guest; guest → wan.
        forward: vec![0, 0b101, 0b001],
        input: vec![Some(0), None, Some(svc::DHCP | svc::DNS | svc::PING)],
        reject_input: vec![false, false, true],
        rules: vec![
            Rule {
                from: Some(2),
                to: RuleTo::Zone(1),
                protos: proto::ICMP,
                src: None,
                dst: Some((nas, 32)),
                dport: None,
                action: Action::Accept,
            },
            Rule {
                from: Some(2),
                to: RuleTo::Zone(0),
                protos: proto::TCP,
                src: None,
                dst: None,
                dport: Some((80, 80)),
                action: Action::Reject,
            },
            Rule { from: None, to: RuleTo::Router, protos: proto::ANY, src: Some((Ipv4Addr::new(10, 0, 0, 0), 8)), dst: None, dport: None, action: Action::Drop },
        ],
        forwards: vec![
            PortForward { protos: proto::TCP | proto::UDP, lo: 8080, hi: 8081, to: nas, to_port: Some(80), src: None, hairpin: true },
            PortForward { protos: proto::TCP, lo: 8443, hi: 8443, to: nas, to_port: None, src: Some((Ipv4Addr::new(198, 51, 100, 0), 24)), hairpin: false },
        ],
        redirects: vec![Redirect { from: None, protos: proto::UDP, lo: 123, hi: 123, to: Ipv4Addr::new(192, 168, 1, 101), to_port: None }],
        router_tcp_peers: vec![(Ipv4Addr::new(8, 8, 8, 8), 853)],
    }
}

fn router() -> Forwarder {
    let mut fw = Forwarder::new(64, 0x1234);
    // A small table with a host limit: early drop and limits are reached.
    fw.set_conn_budget(Budget::with_host_limit(64, 16, 0x1234));
    let addrs = [
        ((Ipv4Addr::new(203, 0, 113, 10), 24), Role::Wan, 0),
        ((Ipv4Addr::new(192, 168, 1, 1), 24), Role::Lan, 1),
        ((Ipv4Addr::new(192, 168, 20, 1), 24), Role::Lan, 2),
    ];
    for (i, (addr, role, zone)) in addrs.into_iter().enumerate() {
        fw.add_interface(Interface { mac: MACS[i], addr: Some(addr), role, zone });
    }
    fw.set_default_route(Some((WAN, Ipv4Addr::new(203, 0, 113, 1))));
    fw.set_static_routes(&[(Ipv4Addr::new(10, 30, 0, 0), 24, Ipv4Addr::new(192, 168, 1, 100))]);
    fw.set_policy(Some(policy()));
    fw
}

/// What the forwarder last sent: (egress, frame).
struct Last {
    egress: u8,
    frame: Vec<u8>,
}

fn check_forward(v: &Verdict, buf: &[u8], clean: bool) -> Option<(u8, usize)> {
    let Verdict::Forward { egress, len, split, .. } = *v else { return None };
    assert!(len <= buf.len(), "forward len {len} beyond the buffer {}", buf.len());
    assert!(egress < 3);
    let f = &buf[..len];
    if clean && wire::Ipv4View::parse(f, ETH_HDR).is_some_and(|v| !v.is_fragment) {
        assert!(checksums_ok(f), "valid checksums in, broken out: {f:02x?}");
    }
    if split != 0 {
        if let Some(plan) = SplitPlan::new(f, split) {
            let mut out = vec![0u8; 2048];
            for i in 0..plan.pieces() {
                let n = plan.write_piece(f, i, &mut out);
                assert!(n <= out.len());
            }
        }
    }
    Some((egress, len))
}

fuzz_target!(|ops: Vec<Op>| {
    let mut fw = router();
    let mut now = 1_000u64;
    let mut last: Option<Last> = None;
    let mut frag = None;
    for op in ops.into_iter().take(200) {
        let (ifx, mut buf, clean) = match op {
            Op::Packet { ifx, to_other_mac, pkt, noise } => {
                let ifx = ifx % 3;
                let dst = match to_other_mac {
                    None => MACS[ifx as usize],
                    Some(0) => [0xff; 6],
                    Some(n) => [2, 0xbb, 0, 0, 0, n],
                };
                let mut f = pkt.frame(dst, PEER, TAIL);
                let n = f.len() - TAIL;
                if let Some(noise) = &noise {
                    damage(&mut f[..n], noise);
                }
                let clean = noise.is_none() && !pkt.is_fragment();
                // A later fragment goes the way of its first one.
                if pkt.frag_offset() != 0 {
                    if let Some(d) = frag {
                        let v = fw.forward_fragment(now, ifx, &mut f, n, &d);
                        if let Some((egress, len)) = check_forward(&v, &f, false) {
                            last = Some(Last { egress, frame: f[..len].to_vec() });
                        }
                        continue;
                    }
                }
                (ifx, f, clean)
            }
            Op::Reply { flags, noise } => {
                let Some(l) = &last else { continue };
                let mut f = l.frame.clone();
                let Some(v) = wire::Ipv4View::parse(&f, ETH_HDR) else { continue };
                if v.is_fragment {
                    continue;
                }
                let (src, dst) = (v.src(&f), v.dst(&f));
                wire::put_ip(&mut f, v.ip + 12, dst);
                wire::put_ip(&mut f, v.ip + 16, src);
                f[v.ip + 8] = 64;
                let seg = v.l4;
                match v.proto {
                    PROTO_TCP | PROTO_UDP if v.l4_len >= 8 => {
                        let (sp, dp) = (wire::get16(&f, seg), wire::get16(&f, seg + 2));
                        wire::put16(&mut f, seg, dp);
                        wire::put16(&mut f, seg + 2, sp);
                        if v.proto == PROTO_TCP && v.l4_len >= 20 {
                            f[seg + 13] = flags.unwrap_or(0x12);
                        }
                    }
                    PROTO_ICMP if v.l4_len >= 4 => f[seg] = 0, // echo reply
                    _ => {}
                }
                // Checksums from scratch.
                wire::put16(&mut f, v.ip + 10, 0);
                let c = wire::checksum(&f[v.ip..v.l4]);
                wire::put16(&mut f, v.ip + 10, c);
                let end = v.l4 + v.l4_len;
                match v.proto {
                    PROTO_TCP if v.l4_len >= 20 => {
                        wire::put16(&mut f, seg + 16, 0);
                        let c = wire::l4_checksum(dst, src, PROTO_TCP, &f[seg..end]);
                        wire::put16(&mut f, seg + 16, c);
                    }
                    PROTO_UDP if v.l4_len >= 8 => {
                        wire::put16(&mut f, seg + 6, 0);
                        let c = wire::l4_checksum(dst, src, PROTO_UDP, &f[seg..end]);
                        wire::put16(&mut f, seg + 6, if c == 0 { 0xffff } else { c });
                    }
                    PROTO_ICMP if v.l4_len >= 4 => {
                        wire::put16(&mut f, seg + 2, 0);
                        let c = wire::checksum(&f[seg..end]);
                        wire::put16(&mut f, seg + 2, c);
                    }
                    _ => {}
                }
                f[0..6].copy_from_slice(&MACS[l.egress as usize]);
                f[6..12].copy_from_slice(&PEER);
                if let Some(noise) = &noise {
                    damage(&mut f, noise);
                }
                f.resize(f.len() + TAIL, 0);
                (l.egress, f, noise.is_none())
            }
            Op::IcmpError { from, kind, code } => {
                let Some(l) = &last else { continue };
                let Some(v) = wire::Ipv4View::parse(&l.frame, ETH_HDR) else { continue };
                let quoted = &l.frame[v.ip..(v.l4 + 8).min(l.frame.len())];
                let mut body = vec![[3u8, 11, 12][kind as usize % 3], code % 16, 0, 0, 0, 0, 0, 0];
                body.extend_from_slice(quoted);
                let c = wire::checksum(&body);
                wire::put16(&mut body, 2, c);
                let pkt = Ipv4Pkt {
                    src: from,
                    dst: Addr::Any(u32::from(v.src(&l.frame))),
                    sport: rrouter_fuzz::Port::Any(0),
                    dport: rrouter_fuzz::Port::Any(0),
                    l4: rrouter_fuzz::L4Kind::Other(PROTO_ICMP),
                    ttl: 64,
                    tos: 0,
                    id: 1,
                    df: false,
                    more_frags: false,
                    frag_offset: None,
                    ip_options: None,
                    payload: body,
                };
                (l.egress, pkt.frame(MACS[l.egress as usize], PEER, TAIL), false)
            }
            Op::Raw { ifx, data } => {
                let mut f = data;
                f.truncate(1600);
                let n = f.len();
                f.resize(n + TAIL, 0);
                let ifx = ifx % 3;
                let v = fw.process(now, ifx, &mut f, n);
                check_forward(&v, &f, false);
                continue;
            }
            Op::Tick(ms) => {
                now += u64::from(ms) * 50;
                continue;
            }
            Op::Expire(max) => {
                fw.expire_some(now, max as usize);
                continue;
            }
            Op::SetPolicy(on) => {
                fw.set_policy(on.then(policy));
                fw.recheck();
                continue;
            }
            Op::SetMtu(mtu) => {
                fw.set_mtu(WAN, 68 + mtu % 1500);
                continue;
            }
            Op::SetWanAddr(a) => {
                fw.set_addr(WAN, a.map(|a| (a.get(), 24)));
                continue;
            }
        };
        let n = buf.len() - TAIL;
        let v = fw.process(now, ifx, &mut buf, n);
        if let Some(d) = fw.take_fragment() {
            frag = Some(d);
        }
        if let Some((egress, len)) = check_forward(&v, &buf, clean) {
            last = Some(Last { egress, frame: buf[..len].to_vec() });
        }
    }
});
