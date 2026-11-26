//! The forwarder (`crates/fwd`): every forwarded packet, internet-facing.
//! Structured: packets built from fields over address/port sets the router
//! knows (valid checksums, so they reach NAT, conntrack and the firewall),
//! replies and ICMP errors to what it forwarded (the NAT reverse path),
//! later fragments, policy changes, expiry and raw damaged frames.
//! IPv6 to and through the router (extension headers, ND, the zone input
//! filter, forwarding with conntrack, ICMPv6 errors, replies).
//! Checks: forwarded frames stay inside the buffer, a frame that came
//! in with valid checksums leaves with valid checksums (NAT rewrites them
//! incrementally; IPv6 is not translated, the MSS clamp updates), and a
//! forwarded IPv6 packet has one hop less.
#![no_main]

use arbitrary::Arbitrary;
use core::net::{Ipv4Addr, Ipv6Addr};
use fwd::conntrack::Budget;
use fwd::forwarder::{
    Action, Forwarder, Interface, Policy, PortForward, Redirect, Role, Rule, Rule6, RuleTo, Verdict, proto, svc,
};
use fwd::wire::{self, ETH_HDR, PROTO_ICMP, PROTO_TCP, PROTO_UDP, SplitPlan};
use libfuzzer_sys::fuzz_target;
use leatos_fuzz::{Addr, Ipv4Pkt, checksums_ok, damage};

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
    /// An IPv6 packet on interface `ifx % 3` to one of the router's
    /// addresses or groups (or another host), behind extension headers
    /// (`ext`: kinds from Hop-by-Hop, Destination Options, Routing,
    /// Fragment), with `proto` and a port or ICMPv6 type.
    Packet6 { ifx: u8, src: u8, dst: u8, hop: u8, ext: Vec<(u8, u8)>, proto: u8, port: u16, flags: u8, noise: Option<Vec<u8>> },
    /// The far end answers the last forwarded IPv6 packet.
    Reply6 { flags: Option<u8> },
    /// Arbitrary bytes on an interface.
    Raw { ifx: u8, data: Vec<u8> },
    /// ARP or neighbor discovery on interface `ifx % 3` for the router's
    /// link layer (`fwd::nd`): built valid (checksum), then `edit`ed.
    Nd { ifx: u8, kind: u8, target: u8, src: u8, mac: u8, hop: u8, edit: Option<(u8, u8)> },
    SetIpv6(bool),
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
                v6: Rule6::default(),
            },
            Rule {
                from: Some(2),
                to: RuleTo::Zone(0),
                protos: proto::TCP,
                src: None,
                dst: None,
                dport: Some((80, 80)),
                action: Action::Reject,
                v6: Rule6::default(),
            },
            Rule { from: None, to: RuleTo::Router, protos: proto::ANY, src: Some((Ipv4Addr::new(10, 0, 0, 0), 8)), dst: None, dport: None, action: Action::Drop, v6: Rule6::default() },
            // An IPv6 pinhole by interface identifier (wan -> lan TCP 8087).
            Rule {
                from: Some(0),
                to: RuleTo::Zone(1),
                protos: proto::TCP,
                src: None,
                dst: None,
                dport: Some((8087, 8087)),
                action: Action::Accept,
                v6: Rule6 { dst_iid: Some(0x10), ..Rule6::default() },
            },
        ],
        forwards: vec![
            PortForward { protos: proto::TCP | proto::UDP, lo: 8080, hi: 8081, to: nas, to_port: Some(80), src: None, hairpin: true },
            PortForward { protos: proto::TCP, lo: 8443, hi: 8443, to: nas, to_port: None, src: Some((Ipv4Addr::new(198, 51, 100, 0), 24)), hairpin: false },
        ],
        redirects: vec![Redirect { from: None, protos: proto::UDP, lo: 123, hi: 123, to: Ipv4Addr::new(192, 168, 1, 101), to_port: None }],
        router_tcp_peers: vec![(Ipv4Addr::new(8, 8, 8, 8), 853)],
        router_tcp_peers6: vec![],
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
    fw.ipv6 = true;
    fw.set_ula6(1, Some(ULA[1]));
    fw.set_ula6(2, Some(ULA[2]));
    fw.set_gua6(0, Some((Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 2), 64)));
    fw.set_default_route6(Some((0, Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1))));
    fw.set_gua6(1, Some((GUA[1], 64)));
    fw.set_gua6(2, Some((GUA[2], 64)));
    fw
}

/// The networks' global /64s (router ::1).
const GUA: [Ipv6Addr; 3] = [
    Ipv6Addr::UNSPECIFIED,
    Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0x2001, 0xdb8, 0x100, 1, 0, 0, 0, 1),
];

/// A host address in network `i`'s /64 (`ula`: its ULA one).
fn host6(i: usize, ula: bool, n: u16) -> Ipv6Addr {
    let p = if ula { ULA[i] } else { GUA[i] };
    let s = p.segments();
    Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0x100 + n % 4)
}

/// Fill in the L4 checksum of an IPv6 frame (no extension headers).
fn fix_l4_checksum6(f: &mut [u8]) {
    let Some(v) = wire::Ipv6View::parse(f, ETH_HDR) else { return };
    let (src, dst) = (v.src(f), v.dst(f));
    let end = v.l4 + v.l4_len;
    let at = match v.proto {
        PROTO_TCP if v.l4_len >= 20 => v.l4 + 16,
        PROTO_UDP if v.l4_len >= 8 => v.l4 + 6,
        wire::PROTO_ICMPV6 if v.l4_len >= 4 => v.l4 + 2,
        _ => return,
    };
    wire::put16(f, at, 0);
    let c = match v.proto {
        wire::PROTO_ICMPV6 => wire::icmpv6_checksum(src, dst, &f[v.l4..end]),
        p => wire::l4_checksum6(src, dst, p, &f[v.l4..end]),
    };
    wire::put16(f, at, c);
}

/// The L4 checksum of an IPv6 frame is valid (`None`: not checkable).
fn l4_ok6(f: &[u8]) -> Option<bool> {
    let v = wire::Ipv6View::parse(f, ETH_HDR)?;
    if v.l4 != ETH_HDR + 40 || !v.has_l4() {
        return None;
    }
    let seg = &f[v.l4..v.l4 + v.l4_len];
    Some(match v.proto {
        wire::PROTO_ICMPV6 => wire::icmpv6_checksum(v.src(f), v.dst(f), seg) == 0,
        p @ (PROTO_TCP | PROTO_UDP) => wire::l4_checksum6(v.src(f), v.dst(f), p, seg) == 0,
        _ => return None,
    })
}

/// A forwarded IPv6 frame: inside the buffer; one hop less, checksums kept
/// when they were valid; or an ICMPv6 error of the router's own, valid.
fn check_forward6(v: &Verdict, inp: &[u8], buf: &[u8]) -> Option<(u8, usize)> {
    let Verdict::Forward6 { egress, len, .. } = *v else { return None };
    assert!(len <= buf.len() && egress < 3, "forward6 {len} / {}", buf.len());
    let out = &buf[..len];
    let ov = wire::Ipv6View::parse(out, ETH_HDR).expect("forwarded IPv6 parses");
    let own_error = ov.proto == wire::PROTO_ICMPV6 && ov.l4_len > 0 && out[ov.l4] < 128 && ov.hop_limit(out) == 64
        && wire::ETH_HDR + 48 <= len;
    if own_error && l4_ok6(out) == Some(true) {
        return Some((egress, len));
    }
    let iv = wire::Ipv6View::parse(inp, ETH_HDR).expect("input was IPv6");
    assert_eq!(ov.hop_limit(out) + 1, iv.hop_limit(inp), "one hop less");
    if l4_ok6(inp) == Some(true) {
        assert_eq!(l4_ok6(out), Some(true), "valid checksum in, broken out");
    }
    Some((egress, len))
}

const ULA: [Ipv6Addr; 3] = [
    Ipv6Addr::UNSPECIFIED,
    Ipv6Addr::new(0xfd00, 1, 2, 0, 0, 0, 0, 1),
    Ipv6Addr::new(0xfd00, 1, 2, 1, 0, 0, 0, 1),
];

/// An Ethernet + IPv6 frame (see [`Op::Packet6`]).
#[allow(clippy::too_many_arguments)]
fn ipv6_frame(ifx: u8, src: u8, dst: u8, hop: u8, ext: &[(u8, u8)], proto: u8, port: u16, flags: u8) -> Vec<u8> {
    let i = ifx as usize;
    let server = Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1 + src as u16 % 3);
    let srcs = [
        if i == 0 { server } else { host6(i, false, src as u16) },
        if i == 0 { server } else { host6(i, true, src as u16) },
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9),
        host6((i + 1) % 3, false, 1), // spoofed
        Ipv6Addr::new(0x2001, 0xdb8, 0x77, 0, 0, 0, 0, src as u16),
    ];
    let src = srcs[src as usize % srcs.len()];
    let dsts = [
        host6(1, false, dst as u16),
        host6(2, false, dst as u16),
        host6(1, true, dst as u16),
        Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1 + dst as u16 % 3),
        GUA[i],
        wire::link_local(MACS[ifx as usize]),
        ULA[ifx as usize],
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 1),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        ULA[(ifx as usize + 1) % 3],
    ];
    let dst = dsts[dst as usize % dsts.len()];
    let protos = [wire::PROTO_ICMPV6, PROTO_UDP, PROTO_TCP, 59, proto];
    let proto = protos[proto as usize % protos.len()];
    let kinds = [0u8, 60, 43, 44];
    let mut hdrs: Vec<(u8, Vec<u8>)> = Vec::new();
    for &(k, arg) in ext.iter().take(10) {
        let kind = kinds[k as usize % 4];
        let h = match kind {
            44 => vec![0, 0, (arg >> 4) as u16 as u8, arg & 0x9, 0, 0, 0, 1], // offset / M from arg
            43 => vec![0, 0, arg % 3, 0, 0, 0, 0, 0],
            _ => {
                let len = arg as usize % 3;
                let mut h = vec![0u8; 8 * (len + 1)];
                h[1] = len as u8;
                h
            }
        };
        hdrs.push((kind, h));
    }
    let mut l4 = vec![0u8; 20];
    if proto == wire::PROTO_ICMPV6 {
        l4[0] = [128, 129, 1, 2, 3, (port >> 8) as u8][(port & 7) as usize % 6];
        l4[4..6].copy_from_slice(&(port & 0xff).to_be_bytes());
    } else {
        l4[0..2].copy_from_slice(&40000u16.to_be_bytes());
        l4[2..4].copy_from_slice(&port.to_be_bytes());
        if proto == PROTO_TCP {
            l4[12] = 5 << 4;
            l4[13] = flags;
        } else if proto == PROTO_UDP {
            l4[4..6].copy_from_slice(&20u16.to_be_bytes());
        }
    }
    let mut body = Vec::new();
    for (i, (_, h)) in hdrs.iter().enumerate() {
        let mut h = h.clone();
        h[0] = hdrs.get(i + 1).map_or(proto, |n| n.0);
        body.extend_from_slice(&h);
    }
    body.extend_from_slice(&l4);
    let mac = if dst.is_multicast() { [0x33, 0x33, 0, 0, 0, 1] } else { MACS[ifx as usize] };
    let mut f = Vec::new();
    f.extend_from_slice(&mac);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&wire::ETHERTYPE_IPV6.to_be_bytes());
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&(body.len() as u16).to_be_bytes());
    f.push(hdrs.first().map_or(proto, |h| h.0));
    f.push(hop);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(&body);
    if hdrs.is_empty() {
        fix_l4_checksum6(&mut f);
    }
    f
}

/// The router stack's ND help (`kernel/src/net/device.rs`): a hint is a
/// valid NS with a correct checksum; readdressing a probe keeps a valid
/// checksum valid.
/// `fwd::udp` (the router's own datagrams): a parsed payload lies inside
/// the frame, and building the same datagram again parses back to it.
fn udp_check(f: &[u8]) {
    // ICMP echo (the router's answers, docs/local-stack.md step 4): a
    // reply is a reply, back to the sender, with the request's data.
    if let Some(e) = fwd::echo::parse(f) {
        assert!(e.data.0 <= e.data.1 && e.data.1 <= f.len(), "{e:?}");
        let mut out = vec![0u8; 1600];
        if let Some(n) = fwd::echo::reply(f, &mut out) {
            let r = fwd::echo::parse(&out[..n]).expect("own reply parses");
            assert!(e.request && !r.request && r.src == e.dst && r.dst == e.src && (r.ident, r.seq) == (e.ident, e.seq));
            assert_eq!(&out[r.data.0..r.data.1], &f[e.data.0..e.data.1]);
        }
    }
    let _ = fwd::mcast::parse_query(f);
    if let Some(d) = fwd::udp::parse6(f) {
        assert!(d.payload.0 <= d.payload.1 && d.payload.1 <= f.len(), "{d:?}");
        let payload = &f[d.payload.0..d.payload.1];
        let mut out = vec![0u8; fwd::udp::OVERHEAD6 + payload.len()];
        let n = fwd::udp::build6(&mut out, &d.ends, 64, payload).expect("fits");
        let again = fwd::udp::parse6(&out[..n]).expect("own datagram parses");
        assert_eq!(again.ends, d.ends);
        assert_eq!(&out[again.payload.0..again.payload.1], payload);
    }
    let Some(d) = fwd::udp::parse4(f) else { return };
    assert!(d.payload.0 <= d.payload.1 && d.payload.1 <= f.len(), "{d:?}");
    let payload = &f[d.payload.0..d.payload.1];
    let mut out = vec![0u8; fwd::udp::OVERHEAD + payload.len()];
    let n = fwd::udp::build4(&mut out, &d.ends, 64, payload).expect("fits");
    let again = fwd::udp::parse4(&out[..n]).expect("own datagram parses");
    assert_eq!(again.ends, d.ends);
    assert_eq!(&out[again.payload.0..again.payload.1], payload);
}

/// The router's IPv4 address and prefix on interface `i` (as `router()`).
fn addr4(i: usize) -> (Ipv4Addr, u8) {
    [(Ipv4Addr::new(203, 0, 113, 10), 24), (Ipv4Addr::new(192, 168, 1, 1), 24), (Ipv4Addr::new(192, 168, 20, 1), 24)][i]
}

/// The router's IPv6 addresses on interface `i`: link-local, ULA, global.
fn addrs6(i: usize) -> Vec<Ipv6Addr> {
    let gua = if i == 0 { Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 2) } else { GUA[i] };
    [wire::link_local(MACS[i]), ULA[i], gua].into_iter().filter(|a| !a.is_unspecified()).collect()
}

/// An ARP or ND frame toward interface `ifx`'s router addresses:
/// `kind` % 6 = ARP request, ARP probe, NS to the group, unicast NS, DAD
/// NS, NA; `target` picks one of ours (or another address), `src` the
/// sender, `mac` the sender's MAC (ours, a client's, multicast), `hop`
/// the hop limit (mostly 255), `edit` one byte changed after the
/// checksum.
fn nd_frame(ifx: usize, kind: u8, target: u8, src: u8, mac: u8, hop: u8, edit: Option<(u8, u8)>) -> Vec<u8> {
    let smac = match mac % 4 {
        0 => MACS[ifx],
        1 => [0x01, 0, 0x5e, 0, 0, 1],
        _ => [2, 0xcc, 0, 0, 0, mac],
    };
    let (a4, len) = addr4(ifx);
    let mine6 = addrs6(ifx);
    let t6 = match target % 5 {
        4 => host6(ifx.max(1), true, 7),
        n => mine6[usize::from(n) % mine6.len()],
    };
    let s6 = match src % 4 {
        0 => mine6[0],
        1 => host6(ifx.max(1), src & 4 != 0, u16::from(src)),
        _ => wire::link_local(smac),
    };
    let mut f = match kind % 6 {
        k @ (0 | 1) => {
            let t4 = if target % 4 == 3 { Ipv4Addr::new(192, 168, 1, 77) } else { a4 };
            let s4 = match (k, src % 3) {
                (1, _) => Ipv4Addr::UNSPECIFIED,
                (_, 0) => a4,
                (_, 1) => Ipv4Addr::new(10, 9, 9, 9),
                _ => Ipv4Addr::from(u32::from(a4) & (u32::MAX << (32 - u32::from(len))) | 0x50),
            };
            let mut b = [0u8; 60];
            let n = wire::build_arp_request(&mut b, smac, s4, t4);
            b[..n].to_vec()
        }
        k => {
            let mut b = [0u8; wire::NS_LEN];
            wire::build_ns(&mut b, smac, s6, t6);
            let mut f = b.to_vec();
            let ip = ETH_HDR;
            match k {
                3 => f[ip + 24..ip + 40].copy_from_slice(&t6.octets()),
                4 => {
                    f[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
                    f.truncate(ip + 40 + 24);
                    wire::put16(&mut f, ip + 4, 24);
                }
                5 => {
                    f[ip + 40] = 136;
                    f[ip + 40 + 24] = 2;
                }
                _ => {}
            }
            f[ip + 7] = if hop % 8 == 0 { hop } else { 255 };
            fix_l4_checksum6(&mut f);
            f
        }
    };
    if let Some((at, v)) = edit {
        let at = usize::from(at) % f.len();
        f[at] ^= v;
    }
    f
}

/// The router's ARP / ND answers (`fwd::nd`) for a frame on interface
/// `ifx`: a reply only to an ARP request or NS for one of its addresses,
/// never to its own MAC, and well formed (ARP reply from us to the
/// asker; NA for the target from the target with our MAC, valid
/// checksum, hop limit 255, to the solicitor or all nodes).
fn nd_answer(ifx: usize, f: &[u8]) {
    let mine6 = addrs6(ifx);
    let (a4, len) = addr4(ifx);
    let me = fwd::nd::Link { mac: MACS[ifx], v4: Some((a4, len)), v6: &mine6 };
    let mut out = [0u8; fwd::nd::REPLY_LEN];
    let o = fwd::nd::answer(f, &me, fwd::nd::Config::default(), &mut out);
    if let Some((ip, mac)) = o.conflict {
        assert_ne!(mac, MACS[ifx], "our own MAC is no conflict");
        match ip {
            core::net::IpAddr::V4(ip) => assert_eq!(ip, a4),
            core::net::IpAddr::V6(ip) => assert!(mine6.contains(&ip)),
        }
    }
    let Some(n) = o.reply else { return };
    let r = &out[..n];
    assert_ne!(&f[6..12], &MACS[ifx], "answered ourselves");
    assert_eq!(&r[6..12], &MACS[ifx], "reply from our MAC");
    match wire::ethertype(f) {
        Some(wire::ETHERTYPE_ARP) => {
            let q = wire::parse_arp(f).expect("answered ARP parses");
            assert_eq!((q.op, q.target_ip), (1, a4), "answered only requests for us");
            let a = wire::parse_arp(r).expect("reply parses");
            assert_eq!((a.op, a.sender_mac, a.sender_ip), (2, MACS[ifx], a4));
            assert_eq!(&r[0..6], &q.sender_mac, "to the asker");
            assert!(!wire::is_multicast_mac(&q.sender_mac));
        }
        Some(wire::ETHERTYPE_IPV6) => {
            assert_eq!(f[ETH_HDR + 40], 135, "answered only NS");
            assert_eq!(f[ETH_HDR + 7], 255, "on-link only");
            let target = wire::get_ip6(f, ETH_HDR + 48);
            assert!(mine6.contains(&target), "answered for ours only");
            assert_eq!(wire::parse_nd(r), Some((target, MACS[ifx])), "valid NA (checksum, hop limit, TLLA)");
            let v = wire::Ipv6View::parse(r, ETH_HDR).unwrap();
            assert_eq!(v.src(r), target);
            let src = wire::get_ip6(f, ETH_HDR + 8);
            if src.is_unspecified() {
                assert_eq!(v.dst(r), Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
            } else {
                assert_eq!(v.dst(r), src, "to the solicitor");
                assert!(!wire::is_multicast_mac(&r[0..6].try_into().unwrap()));
            }
        }
        t => panic!("reply to ethertype {t:?}"),
    }
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
    let mut last6: Option<(u8, Vec<u8>)> = None;
    let mut frag6: Option<fwd::frag::Decision> = None;
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
                udp_check(&f[..n]);
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
                    sport: leatos_fuzz::Port::Any(0),
                    dport: leatos_fuzz::Port::Any(0),
                    l4: leatos_fuzz::L4Kind::Other(PROTO_ICMP),
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
            Op::Packet6 { ifx, src, dst, hop, ext, proto, port, flags, noise } => {
                let ifx = ifx % 3;
                let mut f = ipv6_frame(ifx, src, dst, hop, &ext, proto, port, flags);
                if let Some(noise) = &noise {
                    damage(&mut f, noise);
                }
                let n = f.len();
                udp_check(&f);
                let inp = f.clone();
                f.resize(n + TAIL + 1300, 0);
                // A later fragment goes the way of its first one (as the
                // datapath does it: fwd::frag).
                if let (fwd::frag::Kind::Later(_), Some(d)) = (fwd::frag::classify(&inp), frag6) {
                    let v = fw.forward_fragment(now, ifx, &mut f, n, &d);
                    check_forward6(&v, &inp, &f);
                    continue;
                }
                let v = fw.process(now, ifx, &mut f, n);
                assert!(!matches!(v, Verdict::Forward { .. }), "IPv6 as IPv4: {v:?}");
                if let Some(d @ fwd::frag::Decision::V6(_)) = fw.take_fragment() {
                    frag6 = Some(d);
                }
                if let Some((egress, len)) = check_forward6(&v, &inp, &f) {
                    last6 = Some((egress, f[..len].to_vec()));
                }
                continue;
            }
            Op::Reply6 { flags } => {
                let Some((egress, l)) = &last6 else { continue };
                let mut f = l.clone();
                let Some(v) = wire::Ipv6View::parse(&f, ETH_HDR) else { continue };
                if v.l4 != ETH_HDR + 40 {
                    continue;
                }
                let (src, dst) = (v.src(&f), v.dst(&f));
                f[v.ip + 8..v.ip + 24].copy_from_slice(&dst.octets());
                f[v.ip + 24..v.ip + 40].copy_from_slice(&src.octets());
                f[v.ip + 7] = 60;
                match v.proto {
                    PROTO_TCP | PROTO_UDP if v.l4_len >= 8 => {
                        let (sp, dp) = (wire::get16(&f, v.l4), wire::get16(&f, v.l4 + 2));
                        wire::put16(&mut f, v.l4, dp);
                        wire::put16(&mut f, v.l4 + 2, sp);
                        if v.proto == PROTO_TCP && v.l4_len >= 20 {
                            f[v.l4 + 13] = flags.unwrap_or(0x12);
                        }
                    }
                    wire::PROTO_ICMPV6 if v.l4_len >= 8 && f[v.l4] == 128 => f[v.l4] = 129,
                    _ => {}
                }
                fix_l4_checksum6(&mut f);
                f[0..6].copy_from_slice(&MACS[*egress as usize]);
                f[6..12].copy_from_slice(&PEER);
                let n = f.len();
                let inp = f.clone();
                f.resize(n + TAIL + 1300, 0);
                let v = fw.process(now, *egress, &mut f, n);
                check_forward6(&v, &inp, &f);
                continue;
            }
            Op::SetIpv6(on) => {
                fw.ipv6 = on;
                continue;
            }
            Op::Nd { ifx, kind, target, src, mac, hop, edit } => {
                let ifx = usize::from(ifx % 3);
                let f = nd_frame(ifx, kind, target, src, mac, hop, edit);
                nd_answer(ifx, &f);
                continue;
            }
            Op::Raw { ifx, data } => {
                let mut f = data;
                f.truncate(1600);
                udp_check(&f);
                nd_answer(usize::from(ifx % 3), &f);
                let n = f.len();
                f.resize(n + TAIL, 0);
                let ifx = ifx % 3;
                let v = fw.process(now, ifx, &mut f, n);
                if wire::ethertype(&f[..n]) == Some(wire::ETHERTYPE_IPV6) {
                    assert!(!matches!(v, Verdict::Forward { .. }), "IPv6 forwarded: {v:?}");
                }
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
