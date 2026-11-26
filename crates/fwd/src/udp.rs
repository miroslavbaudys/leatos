//! The router's own UDP over IPv4 without a host stack (docs/local-stack.md
//! §3.1–3.2): build a datagram into a frame for `Datapath::send_local`, and
//! parse one the datapath delivered to the router. First user: the WAN's
//! DHCPv4 client (step 2b), from 0.0.0.0 and to 255.255.255.255 too.
//!
//! Frames are 14 bytes of Ethernet header (addresses zero: the datapath
//! fills them in, `fwd::local` picks the next hop), the IPv4 header without
//! options, then UDP. Parsing checks every length and both checksums, so a
//! service only ever sees a well-formed payload.

use crate::wire::{ETH_HDR, ETHERTYPE_IPV4, PROTO_UDP, checksum, ethertype, get16, get_ip, l4_checksum, put16, put_ip};
use core::net::Ipv4Addr;

const IP_HDR: usize = 20;
const UDP_HDR: usize = 8;
/// Headers in front of the payload.
pub const OVERHEAD: usize = ETH_HDR + IP_HDR + UDP_HDR;
/// Time to live of the router's own datagrams.
pub const TTL: u8 = 64;

/// The two ends of a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ends {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
}

/// A datagram in a frame: its ends and where its payload is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub ends: Ends,
    /// `frame[payload.0..payload.1]`.
    pub payload: (usize, usize),
}

/// Write `payload` from `e.src:e.sport` to `e.dst:e.dport` into `out`;
/// the frame's length, or `None` if `out` is too small or the payload does
/// not fit in one datagram. No fragmentation (DF clear, never needed:
/// the router's payloads fit the link MTU, docs/local-stack.md §3.2).
pub fn build4(out: &mut [u8], e: &Ends, payload: &[u8]) -> Option<usize> {
    let total = OVERHEAD + payload.len();
    if out.len() < total || IP_HDR + UDP_HDR + payload.len() > usize::from(u16::MAX) {
        return None;
    }
    let f = &mut out[..total];
    f[..12].fill(0);
    put16(f, 12, ETHERTYPE_IPV4);
    let ip = ETH_HDR;
    f[ip] = 0x45;
    f[ip + 1] = 0;
    put16(f, ip + 2, (total - ETH_HDR) as u16);
    put16(f, ip + 4, 0); // identification: no fragments
    put16(f, ip + 6, 0);
    f[ip + 8] = TTL;
    f[ip + 9] = PROTO_UDP;
    put16(f, ip + 10, 0);
    put_ip(f, ip + 12, e.src);
    put_ip(f, ip + 16, e.dst);
    let c = checksum(&f[ip..ip + IP_HDR]);
    put16(f, ip + 10, c);
    let u = ip + IP_HDR;
    put16(f, u, e.sport);
    put16(f, u + 2, e.dport);
    put16(f, u + 4, (UDP_HDR + payload.len()) as u16);
    put16(f, u + 6, 0);
    f[u + UDP_HDR..].copy_from_slice(payload);
    let c = l4_checksum(e.src, e.dst, PROTO_UDP, &f[u..]);
    // RFC 768: a computed 0 is sent as all ones (0 means "no checksum").
    put16(f, u + 6, if c == 0 { 0xffff } else { c });
    Some(total)
}

/// The UDP datagram in an Ethernet `frame`, if it is one: IPv4, a valid
/// header checksum, not a fragment, lengths inside the frame (Ethernet
/// padding after the datagram allowed), and a valid UDP checksum (or none,
/// RFC 768). Options in the IPv4 header are skipped.
pub fn parse4(frame: &[u8]) -> Option<Datagram> {
    if ethertype(frame) != Some(ETHERTYPE_IPV4) || frame.len() < ETH_HDR + IP_HDR {
        return None;
    }
    let ip = ETH_HDR;
    let ihl = usize::from(frame[ip] & 0x0f) * 4;
    if frame[ip] >> 4 != 4 || ihl < IP_HDR || frame.len() < ip + ihl {
        return None;
    }
    let total = usize::from(get16(frame, ip + 2));
    if total < ihl + UDP_HDR || frame.len() < ip + total {
        return None;
    }
    if frame[ip + 9] != PROTO_UDP || get16(frame, ip + 6) & 0x3fff != 0 {
        return None; // not UDP, or a fragment (MF or an offset)
    }
    if checksum(&frame[ip..ip + ihl]) != 0 {
        return None;
    }
    let u = ip + ihl;
    let len = usize::from(get16(frame, u + 4));
    if len < UDP_HDR || u + len > ip + total {
        return None;
    }
    let src = get_ip(frame, ip + 12);
    let dst = get_ip(frame, ip + 16);
    if get16(frame, u + 6) != 0 && l4_checksum(src, dst, PROTO_UDP, &frame[u..u + len]) != 0 {
        return None;
    }
    Some(Datagram {
        ends: Ends { src, dst, sport: get16(frame, u), dport: get16(frame, u + 2) },
        payload: (u + UDP_HDR, u + len),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use smoltcp::wire::{EthernetFrame, IpProtocol, Ipv4Packet, UdpPacket};

    const E: Ends = Ends {
        src: Ipv4Addr::UNSPECIFIED,
        dst: Ipv4Addr::BROADCAST,
        sport: 68,
        dport: 67,
    };

    #[test]
    fn build_parses_with_smoltcp_and_back() {
        for (e, payload) in [
            (E, &b"discover, padded to 300 bytes by the DHCP codec"[..]),
            (Ends { src: Ipv4Addr::new(203, 0, 113, 60), dst: Ipv4Addr::new(203, 0, 113, 1), ..E }, b"renew"),
            (Ends { src: Ipv4Addr::new(10, 0, 0, 1), dst: Ipv4Addr::new(10, 0, 0, 2), sport: 61000, dport: 53 }, b""),
        ] {
            let mut out = vec![0xaa; 600];
            let n = build4(&mut out, &e, payload).unwrap();
            assert_eq!(n, OVERHEAD + payload.len());
            let f = &out[..n];
            let eth = EthernetFrame::new_checked(f).unwrap();
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!((ip.src_addr(), ip.dst_addr(), ip.next_header(), ip.hop_limit()), (e.src, e.dst, IpProtocol::Udp, TTL));
            assert!(!ip.dont_frag() && !ip.more_frags() && ip.frag_offset() == 0);
            let udp = UdpPacket::new_checked(ip.payload()).unwrap();
            assert!(udp.verify_checksum(&e.src.into(), &e.dst.into()));
            assert_eq!((udp.src_port(), udp.dst_port(), udp.payload()), (e.sport, e.dport, payload));
            let d = parse4(f).unwrap();
            assert_eq!(d.ends, e);
            assert_eq!(&f[d.payload.0..d.payload.1], payload);
        }
    }

    #[test]
    fn too_small_a_buffer() {
        let mut out = [0u8; OVERHEAD + 3];
        assert_eq!(build4(&mut out, &E, b"four"), None);
        assert_eq!(build4(&mut out, &E, b"abc"), Some(OVERHEAD + 3));
    }

    fn frame(payload: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = vec![0; OVERHEAD + payload.len()];
        let n = build4(&mut out, &E, payload).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn padding_options_and_no_checksum() {
        // Ethernet padding after the datagram.
        let mut f = frame(b"x");
        f.resize(60, 0);
        let d = parse4(&f).unwrap();
        assert_eq!(&f[d.payload.0..d.payload.1], b"x");
        // No UDP checksum (0) is allowed.
        let mut f = frame(b"hello");
        put16(&mut f, ETH_HDR + IP_HDR + 6, 0);
        assert!(parse4(&f).is_some());
        // An IPv4 option (4 bytes of NOPs + EOL): skipped.
        let f0 = frame(b"opt");
        let mut f = f0[..ETH_HDR + IP_HDR].to_vec();
        f.extend_from_slice(&[1, 1, 1, 0]);
        f.extend_from_slice(&f0[ETH_HDR + IP_HDR..]);
        f[ETH_HDR] = 0x46;
        let ip_len = (f.len() - ETH_HDR) as u16;
        put16(&mut f, ETH_HDR + 2, ip_len);
        put16(&mut f, ETH_HDR + 10, 0);
        let c = checksum(&f[ETH_HDR..ETH_HDR + 24]);
        put16(&mut f, ETH_HDR + 10, c);
        let d = parse4(&f).unwrap();
        assert_eq!(d.ends, E);
        assert_eq!(&f[d.payload.0..d.payload.1], b"opt");
    }

    type Damage = fn(&mut alloc::vec::Vec<u8>);

    #[test]
    fn refuses_what_is_not_a_valid_datagram() {
        let good = frame(b"payload");
        let bad: [(&str, Damage); 11] = [
            ("not IPv4", |f| put16(f, 12, 0x86dd)),
            ("version", |f| f[ETH_HDR] = 0x65),
            ("ihl below 5", |f| f[ETH_HDR] = 0x44),
            ("TCP", |f| f[ETH_HDR + 9] = 6),
            ("header checksum", |f| f[ETH_HDR + 8] ^= 1),
            ("more fragments", |f| f[ETH_HDR + 6] |= 0x20),
            ("fragment offset", |f| f[ETH_HDR + 7] = 1),
            ("UDP checksum", |f| *f.last_mut().unwrap() ^= 1),
            ("UDP length past the packet", |f| put16(f, ETH_HDR + IP_HDR + 4, 200)),
            ("UDP length below 8", |f| put16(f, ETH_HDR + IP_HDR + 4, 7)),
            ("truncated", |f| f.truncate(f.len() - 1)),
        ];
        assert!(parse4(&good).is_some());
        for (why, damage) in bad {
            let mut f = good.clone();
            damage(&mut f);
            assert_eq!(parse4(&f), None, "{why}");
        }
        assert_eq!(parse4(&good[..ETH_HDR + 10]), None);
        assert_eq!(parse4(&[]), None);
    }

    #[test]
    fn random_damage_never_panics() {
        let base = frame(b"some payload for the mutation test");
        let mut seed = 0x1234_5678_u32;
        for _ in 0..50_000 {
            let mut f = base.clone();
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let i = (seed as usize) % f.len();
                f[i] = (seed >> 8) as u8;
            }
            f.truncate((seed as usize >> 3) % (f.len() + 1));
            if let Some(d) = parse4(&f) {
                assert!(d.payload.0 <= d.payload.1 && d.payload.1 <= f.len());
            }
        }
    }
}
