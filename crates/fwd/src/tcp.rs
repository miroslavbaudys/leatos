//! The IP layer of the router's own TCP (docs/own-tcp.md §3.3): the
//! segments `proto_tcp` sends get an IPv4 or IPv6 header (and 14 bytes of
//! Ethernet header with zero addresses, as [`crate::udp`]'s frames, for
//! `Datapath::send_local`), and a frame the datapath delivered to the
//! router is checked down to its TCP segment. The TCP checksum is
//! `proto_tcp`'s (it needs the addresses, which it gets from here).

use crate::wire::{
    ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Ipv6View, PROTO_TCP, checksum, ethertype, get16, get_ip, get_ip6, put16,
    put_ip,
};
use core::net::IpAddr;

const IP_HDR: usize = 20;
const IP6_HDR: usize = 40;
/// Time to live / hop limit of the router's own segments.
pub const TTL: u8 = 64;

/// Where the TCP segment starts in a frame of this family.
pub fn offset(v6: bool) -> usize {
    ETH_HDR + if v6 { IP6_HDR } else { IP_HDR }
}

/// Put the Ethernet and IP headers in front of the `seg_len` bytes of TCP
/// segment already at [`offset`] in `out`, from `src` to `dst`; the
/// frame's length, or `None` if the families differ or it does not fit.
/// IPv4 without options, DF clear (a path with a smaller MTU fragments:
/// the router ignores Packet Too Big, docs/own-tcp.md §7); IPv6 without
/// extension headers.
pub fn frame(out: &mut [u8], src: IpAddr, dst: IpAddr, ttl: u8, seg_len: usize) -> Option<usize> {
    let total = offset(src.is_ipv6()) + seg_len;
    if out.len() < total || seg_len > usize::from(u16::MAX) - IP_HDR {
        return None;
    }
    let f = &mut out[..total];
    f[..12].fill(0);
    let ip = ETH_HDR;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            put16(f, 12, ETHERTYPE_IPV4);
            f[ip] = 0x45;
            f[ip + 1] = 0;
            put16(f, ip + 2, (IP_HDR + seg_len) as u16);
            put16(f, ip + 4, 0);
            put16(f, ip + 6, 0);
            f[ip + 8] = ttl;
            f[ip + 9] = PROTO_TCP;
            put16(f, ip + 10, 0);
            put_ip(f, ip + 12, s);
            put_ip(f, ip + 16, d);
            let c = checksum(&f[ip..ip + IP_HDR]);
            put16(f, ip + 10, c);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            put16(f, 12, ETHERTYPE_IPV6);
            f[ip..ip + 4].copy_from_slice(&[0x60, 0, 0, 0]);
            put16(f, ip + 4, seg_len as u16);
            f[ip + 6] = PROTO_TCP;
            f[ip + 7] = ttl;
            f[ip + 8..ip + 24].copy_from_slice(&s.octets());
            f[ip + 24..ip + 40].copy_from_slice(&d.octets());
        }
        _ => return None,
    }
    Some(total)
}

/// A TCP segment in a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// `frame[l4.0..l4.1]`: header and payload.
    pub l4: (usize, usize),
}

/// A host address: not multicast, broadcast or unspecified.
fn unicast(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => !(a.is_multicast() || a.is_broadcast() || a.is_unspecified()),
        IpAddr::V6(a) => !(a.is_multicast() || a.is_unspecified()),
    }
}

/// The TCP segment in an Ethernet `frame`, if it is one: IPv4 with a valid
/// header checksum (options skipped) or IPv6 (extension headers walked),
/// not a fragment, lengths inside the frame (padding after it allowed),
/// both ends unicast. The TCP checksum is not checked here.
pub fn parse(frame: &[u8]) -> Option<Segment> {
    let (src, dst, l4) = match ethertype(frame)? {
        ETHERTYPE_IPV4 => {
            let ip = ETH_HDR;
            let ihl = usize::from(*frame.get(ip)? & 0x0f) * 4;
            if frame[ip] >> 4 != 4 || ihl < IP_HDR || frame.len() < ip + ihl {
                return None;
            }
            let total = usize::from(get16(frame, ip + 2));
            if total < ihl || frame.len() < ip + total {
                return None;
            }
            if frame[ip + 9] != PROTO_TCP || get16(frame, ip + 6) & 0x3fff != 0 {
                return None;
            }
            if checksum(&frame[ip..ip + ihl]) != 0 {
                return None;
            }
            let (s, d) = (get_ip(frame, ip + 12), get_ip(frame, ip + 16));
            (IpAddr::V4(s), IpAddr::V4(d), (ip + ihl, ip + total))
        }
        ETHERTYPE_IPV6 => {
            let v = Ipv6View::parse(frame, ETH_HDR)?;
            if v.proto != PROTO_TCP || v.is_fragment {
                return None;
            }
            let (s, d) = (get_ip6(frame, v.ip + 8), get_ip6(frame, v.ip + 24));
            (IpAddr::V6(s), IpAddr::V6(d), (v.l4, v.l4 + v.l4_len))
        }
        _ => return None,
    };
    if !unicast(src) || !unicast(dst) {
        return None;
    }
    Some(Segment { src, dst, l4 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use smoltcp::wire::{EthernetFrame, IpProtocol, Ipv4Packet, Ipv6Packet};

    const S4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const D4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    const S6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1));
    const D6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 2));

    fn build(src: IpAddr, dst: IpAddr, seg: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = vec![0xaa; offset(src.is_ipv6()) + seg.len()];
        let o = offset(src.is_ipv6());
        out[o..].copy_from_slice(seg);
        let n = frame(&mut out, src, dst, TTL, seg.len()).unwrap();
        assert_eq!(n, out.len());
        out
    }

    #[test]
    fn ipv4_parses_with_smoltcp_and_back() {
        let seg = [7u8; 33];
        let f = build(S4, D4, &seg);
        let eth = EthernetFrame::new_checked(&f[..]).unwrap();
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.next_header(), IpProtocol::Tcp);
        assert_eq!(ip.hop_limit(), TTL);
        assert_eq!(ip.payload(), &seg[..]);
        let p = parse(&f).unwrap();
        assert_eq!((p.src, p.dst), (S4, D4));
        assert_eq!(&f[p.l4.0..p.l4.1], &seg[..]);
    }

    #[test]
    fn ipv6_parses_with_smoltcp_and_back() {
        let seg = [9u8; 40];
        let f = build(S6, D6, &seg);
        let eth = EthernetFrame::new_checked(&f[..]).unwrap();
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Tcp);
        assert_eq!(ip.payload(), &seg[..]);
        let p = parse(&f).unwrap();
        assert_eq!((p.src, p.dst), (S6, D6));
        assert_eq!(&f[p.l4.0..p.l4.1], &seg[..]);
    }

    #[test]
    fn refused() {
        assert_eq!(frame(&mut [0u8; 100], S4, D6, TTL, 20), None);
        // A fragment.
        let mut f = build(S4, D4, &[1; 20]);
        put16(&mut f, ETH_HDR + 6, 0x2000);
        let c = checksum(&{
            let mut h = f[ETH_HDR..ETH_HDR + 20].to_vec();
            h[10] = 0;
            h[11] = 0;
            h
        });
        put16(&mut f, ETH_HDR + 10, c);
        assert_eq!(parse(&f), None);
        // A bad header checksum.
        let mut f = build(S4, D4, &[1; 20]);
        f[ETH_HDR + 10] ^= 1;
        assert_eq!(parse(&f), None);
        // Truncated.
        let f = build(S4, D4, &[1; 20]);
        assert_eq!(parse(&f[..f.len() - 1]), None);
        // To a broadcast or multicast address, from multicast.
        assert_eq!(parse(&build(S4, IpAddr::V4(Ipv4Addr::BROADCAST), &[1; 20])), None);
        assert_eq!(parse(&build(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)), D6, &[1; 20])), None);
        // Not TCP.
        let mut f = build(S4, D4, &[1; 20]);
        f[ETH_HDR + 9] = 17;
        assert_eq!(parse(&f), None);
    }

    #[test]
    fn padding_allowed() {
        let mut f = build(S4, D4, &[1; 20]);
        f.resize(80, 0);
        let p = parse(&f).unwrap();
        assert_eq!(p.l4.1 - p.l4.0, 20);
    }
}
