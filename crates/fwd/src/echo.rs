//! ICMP and ICMPv6 echo for the router itself (docs/local-stack.md step 4):
//! the reply to a ping of one of its addresses, and the requests of its own
//! pinger (the WAN gateway check), without a host stack.
//!
//! Frames are 14 bytes of Ethernet header (addresses zero: the datapath
//! fills them in), the IP header (IPv4 without options, IPv6 without
//! extension headers on send), then the echo message. Parsing checks every
//! length and checksum and refuses fragments.

use crate::wire::{
    ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST, Ipv4View, Ipv6View, PROTO_ICMP,
    PROTO_ICMPV6, checksum, ethertype, get_ip, get_ip6, icmpv6_checksum, put16, put_ip,
};
use core::net::IpAddr;
#[cfg(test)]
use core::net::{Ipv4Addr, Ipv6Addr};

const ECHO_REQUEST4: u8 = 8;
const ECHO_REPLY4: u8 = 0;
const ECHO_HDR: usize = 8;
/// Time to live / hop limit of the router's echo messages.
pub const TTL: u8 = 64;
/// The most echo data a reply carries (a bigger ping gets no answer:
/// replies stay within one buffer and the link MTU without fragments).
pub const MAX_DATA: usize = 1452;

/// An echo message in a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Request (true) or reply.
    pub request: bool,
    pub ident: u16,
    pub seq: u16,
    /// `frame[data.0..data.1]`.
    pub data: (usize, usize),
}

/// The echo request or reply in `frame`, if it is one: IPv4 (valid header
/// checksum, not a fragment) or IPv6 (extension headers walked, not a
/// fragment), code 0, and a valid ICMP checksum.
pub fn parse(frame: &[u8]) -> Option<Echo> {
    let (src, dst, l4, len, request) = match ethertype(frame)? {
        ETHERTYPE_IPV4 => {
            let v = Ipv4View::parse(frame, ETH_HDR)?;
            if v.proto != PROTO_ICMP || v.is_fragment || v.l4_len < ECHO_HDR {
                return None;
            }
            let msg = &frame[v.l4..v.l4 + v.l4_len];
            let request = match msg[0] {
                ECHO_REQUEST4 => true,
                ECHO_REPLY4 => false,
                _ => return None,
            };
            if msg[1] != 0 || checksum(msg) != 0 {
                return None;
            }
            (IpAddr::V4(get_ip(frame, v.ip + 12)), IpAddr::V4(get_ip(frame, v.ip + 16)), v.l4, v.l4_len, request)
        }
        ETHERTYPE_IPV6 => {
            let v = Ipv6View::parse(frame, ETH_HDR)?;
            if v.proto != PROTO_ICMPV6 || v.is_fragment || v.l4_len < ECHO_HDR {
                return None;
            }
            let msg = &frame[v.l4..v.l4 + v.l4_len];
            let request = match msg[0] {
                ICMPV6_ECHO_REQUEST => true,
                ICMPV6_ECHO_REPLY => false,
                _ => return None,
            };
            let (src, dst) = (get_ip6(frame, v.ip + 8), get_ip6(frame, v.ip + 24));
            if msg[1] != 0 || icmpv6_checksum(src, dst, msg) != 0 {
                return None;
            }
            (IpAddr::V6(src), IpAddr::V6(dst), v.l4, v.l4_len, request)
        }
        _ => return None,
    };
    let msg = &frame[l4..l4 + len];
    Some(Echo {
        src,
        dst,
        request,
        ident: u16::from_be_bytes([msg[4], msg[5]]),
        seq: u16::from_be_bytes([msg[6], msg[7]]),
        data: (l4 + ECHO_HDR, l4 + len),
    })
}

/// Write an echo message from `src` to `dst` into `out` (the same family;
/// `request`: a request, else a reply); its length, or `None` if the
/// families differ, `data` is above [`MAX_DATA`] or `out` is too small.
pub fn build(out: &mut [u8], src: IpAddr, dst: IpAddr, request: bool, ident: u16, seq: u16, data: &[u8]) -> Option<usize> {
    if data.len() > MAX_DATA {
        return None;
    }
    let msg_len = ECHO_HDR + data.len();
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = ETH_HDR + 20 + msg_len;
            let f = out.get_mut(..total)?;
            f[..12].fill(0);
            put16(f, 12, ETHERTYPE_IPV4);
            let ip = ETH_HDR;
            f[ip..ip + 20].fill(0);
            f[ip] = 0x45;
            put16(f, ip + 2, (20 + msg_len) as u16);
            f[ip + 8] = TTL;
            f[ip + 9] = PROTO_ICMP;
            put_ip(f, ip + 12, s);
            put_ip(f, ip + 16, d);
            let c = checksum(&f[ip..ip + 20]);
            put16(f, ip + 10, c);
            let m = ip + 20;
            write_msg(&mut f[m..], if request { ECHO_REQUEST4 } else { ECHO_REPLY4 }, ident, seq, data);
            let c = checksum(&f[m..]);
            put16(f, m + 2, c);
            Some(total)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let total = ETH_HDR + 40 + msg_len;
            let f = out.get_mut(..total)?;
            f[..12].fill(0);
            put16(f, 12, ETHERTYPE_IPV6);
            let ip = ETH_HDR;
            f[ip..ip + 4].copy_from_slice(&[0x60, 0, 0, 0]);
            put16(f, ip + 4, msg_len as u16);
            f[ip + 6] = PROTO_ICMPV6;
            f[ip + 7] = TTL;
            f[ip + 8..ip + 24].copy_from_slice(&s.octets());
            f[ip + 24..ip + 40].copy_from_slice(&d.octets());
            let m = ip + 40;
            write_msg(&mut f[m..], if request { ICMPV6_ECHO_REQUEST } else { ICMPV6_ECHO_REPLY }, ident, seq, data);
            let c = icmpv6_checksum(s, d, &f[m..]);
            put16(f, m + 2, c);
            Some(total)
        }
        _ => None,
    }
}

fn write_msg(m: &mut [u8], kind: u8, ident: u16, seq: u16, data: &[u8]) {
    m[0] = kind;
    m[1] = 0;
    put16(m, 2, 0);
    put16(m, 4, ident);
    put16(m, 6, seq);
    m[ECHO_HDR..ECHO_HDR + data.len()].copy_from_slice(data);
}

/// The reply to the echo request in `frame` (from its destination back to
/// its source, same identifier, sequence number and data) into `out`; its
/// length. `None` if it is no valid request, its source is not one a
/// reply may go to (unspecified, multicast, broadcast, loopback), or its
/// data is above [`MAX_DATA`]. The caller checks that the destination is
/// one of the router's unicast addresses.
pub fn reply(frame: &[u8], out: &mut [u8]) -> Option<usize> {
    let e = parse(frame).filter(|e| e.request)?;
    let bad = match e.src {
        IpAddr::V4(a) => a.is_unspecified() || a.is_multicast() || a.is_broadcast() || a.is_loopback() || a.octets()[0] == 0,
        IpAddr::V6(a) => a.is_unspecified() || a.is_multicast() || a.is_loopback(),
    };
    if bad {
        return None;
    }
    build(out, e.dst, e.src, false, e.ident, e.seq, &frame[e.data.0..e.data.1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{EthernetFrame, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, Ipv4Packet, Ipv6Packet};

    const ME4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const CL4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const ME6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1);
    const CL6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0x10);

    fn frame(src: IpAddr, dst: IpAddr, request: bool, data: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = vec![0u8; 1600];
        let n = build(&mut out, src, dst, request, 0x22b, 7, data).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn built_messages_parse_with_smoltcp() {
        let caps = ChecksumCapabilities::default();
        let f = frame(CL4.into(), ME4.into(), true, b"ping data");
        let ip = Ipv4Packet::new_checked(EthernetFrame::new_checked(&f[..]).unwrap().payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!((ip.src_addr(), ip.dst_addr(), ip.hop_limit()), (CL4, ME4, TTL));
        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(
            Icmpv4Repr::parse(&icmp, &caps).unwrap(),
            Icmpv4Repr::EchoRequest { ident: 0x22b, seq_no: 7, data: b"ping data" }
        );
        let f = frame(CL6.into(), ME6.into(), false, b"v6");
        let ip = Ipv6Packet::new_checked(EthernetFrame::new_checked(&f[..]).unwrap().payload()).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr(), ip.hop_limit()), (CL6, ME6, TTL));
        let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(
            Icmpv6Repr::parse(&CL6, &ME6, &icmp, &caps).unwrap(),
            Icmpv6Repr::EchoReply { ident: 0x22b, seq_no: 7, data: b"v6" }
        );
        assert_eq!(build(&mut [0u8; 100], ME4.into(), CL6.into(), true, 1, 1, b""), None, "families differ");
        assert_eq!(build(&mut [0u8; 40], ME4.into(), CL4.into(), true, 1, 1, b""), None, "too small");
    }

    #[test]
    fn replies_go_back_with_the_same_ident_seq_and_data() {
        for (me, cl) in [(IpAddr::V4(ME4), IpAddr::V4(CL4)), (IpAddr::V6(ME6), IpAddr::V6(CL6))] {
            let req = frame(cl, me, true, b"0123456789abcdef");
            let mut out = vec![0u8; 1600];
            let n = reply(&req, &mut out).unwrap();
            let e = parse(&out[..n]).unwrap();
            assert_eq!((e.src, e.dst, e.request, e.ident, e.seq), (me, cl, false, 0x22b, 7));
            assert_eq!(&out[e.data.0..e.data.1], b"0123456789abcdef");
            // A reply is not answered; neither is a request from nowhere.
            assert_eq!(reply(&out[..n], &mut vec![0u8; 1600]), None, "a reply");
        }
        for src in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::LOCALHOST] {
            assert_eq!(reply(&frame(src.into(), ME4.into(), true, b"x"), &mut [0u8; 200]), None, "{src}");
        }
        let mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(reply(&frame(mcast.into(), ME6.into(), true, b"x"), &mut [0u8; 200]), None);
        // Too much data: no answer.
        let big = vec![0u8; MAX_DATA + 1];
        assert_eq!(build(&mut vec![0u8; 2000], CL4.into(), ME4.into(), true, 1, 1, &big), None);
        assert!(build(&mut vec![0u8; 2000], CL4.into(), ME4.into(), true, 1, 1, &big[..MAX_DATA]).is_some());
    }

    #[test]
    fn refuses_what_is_no_valid_echo() {
        let good = frame(CL4.into(), ME4.into(), true, b"payload");
        let m = ETH_HDR + 20;
        type Damage = fn(&mut alloc::vec::Vec<u8>);
        let bad: [(&str, Damage); 6] = [
            ("not an echo", |f| f[ETH_HDR + 20] = 3),
            ("code", |f| f[ETH_HDR + 21] = 1),
            ("icmp checksum", |f| *f.last_mut().unwrap() ^= 1),
            ("ip checksum", |f| f[ETH_HDR + 8] ^= 1),
            ("fragment", |f| f[ETH_HDR + 6] |= 0x20),
            ("truncated", |f| f.truncate(f.len() - 1)),
        ];
        assert!(parse(&good).is_some());
        for (why, damage) in bad {
            let mut f = good.clone();
            damage(&mut f);
            assert_eq!(parse(&f), None, "{why}");
        }
        assert_eq!(parse(&good[..m + 4]), None);
        let good6 = frame(CL6.into(), ME6.into(), true, b"payload");
        let mut f = good6.clone();
        *f.last_mut().unwrap() ^= 1;
        assert_eq!(parse(&f), None, "icmpv6 checksum");
        let mut f = good6.clone();
        f[ETH_HDR + 40] = 1; // destination unreachable
        assert_eq!(parse(&f), None);
    }

    #[test]
    fn random_damage_never_panics() {
        let base = frame(CL4.into(), ME4.into(), true, b"some ping data for the mutation test");
        let base6 = frame(CL6.into(), ME6.into(), true, b"some ping data for the mutation test");
        let mut seed = 0x2468_ace1_u32;
        let mut out = vec![0u8; 1600];
        for i in 0..50_000 {
            let mut f = if i % 2 == 0 { base.clone() } else { base6.clone() };
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let k = (seed as usize) % f.len();
                f[k] = (seed >> 8) as u8;
            }
            f.truncate((seed as usize >> 3) % (f.len() + 1));
            if let Some(e) = parse(&f) {
                assert!(e.data.0 <= e.data.1 && e.data.1 <= f.len());
            }
            if let Some(n) = reply(&f, &mut out) {
                assert!(parse(&out[..n]).is_some_and(|e| !e.request), "own reply parses");
            }
        }
    }
}
