//! IGMP and MLD for the router's own multicast groups (docs/local-stack.md
//! step 4): the reports that tell snooping switches to forward a group to
//! the router (mDNS 224.0.0.251 / ff02::fb, the solicited-node groups of
//! its IPv6 addresses, all-routers ff02::2), and the queries it answers.
//!
//! IGMPv2 (RFC 2236) reports and leaves; MLDv2 (RFC 3810) reports, one
//! message for all groups of a link. Both from the link's address (IPv4:
//! its address; IPv6: link-local), TTL / hop limit 1 with Router Alert.
//! Queries of IGMPv1/v2/v3 and MLDv1/v2 are understood (their group and
//! maximum response time). Frames are 14 bytes of Ethernet header
//! (addresses zero: the datapath maps the group to its MAC), then IP.

use crate::wire::{
    ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ICMPV6_MLD2_REPORT, ICMPV6_MLD_QUERY, Ipv4View, Ipv6View, PROTO_ICMPV6,
    checksum, ethertype, get16, get_ip, get_ip6, icmpv6_checksum, put16, put_ip,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PROTO_IGMP: u8 = 2;
const IGMP_QUERY: u8 = 0x11;
const IGMP2_REPORT: u8 = 0x16;
const IGMP2_LEAVE: u8 = 0x17;
/// All routers (IGMPv2 leaves go there).
pub const ALL_ROUTERS4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
/// MLDv2-capable routers (MLDv2 reports go there).
pub const MLDV2_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
/// All routers, a group the router itself is in (RFC 4291 §2.7.1).
pub const ALL_ROUTERS6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// Groups per MLDv2 report (20 bytes each, well inside one frame).
pub const MAX_RECORDS: usize = 32;

/// An MLDv2 multicast address record type (RFC 3810 §5.2.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// MODE_IS_EXCLUDE with no sources: a member (answers to a query).
    IsMember = 2,
    /// CHANGE_TO_INCLUDE_MODE with no sources: left.
    Left = 3,
    /// CHANGE_TO_EXCLUDE_MODE with no sources: joined.
    Joined = 4,
}

/// The Router Alert option (RFC 2113) as an IPv4 option.
const RA4: [u8; 4] = [0x94, 0x04, 0, 0];

/// An IGMPv2 message (`IGMP2_REPORT` to the group, `IGMP2_LEAVE` to
/// all-routers) from `src` about `group`.
fn igmp2(out: &mut [u8], src: Ipv4Addr, group: Ipv4Addr, kind: u8) -> Option<usize> {
    let ihl = 24;
    let total = ETH_HDR + ihl + 8;
    let f = out.get_mut(..total)?;
    f.fill(0);
    put16(f, 12, ETHERTYPE_IPV4);
    let ip = ETH_HDR;
    let dst = if kind == IGMP2_LEAVE { ALL_ROUTERS4 } else { group };
    f[ip] = 0x46;
    put16(f, ip + 2, (ihl + 8) as u16);
    f[ip + 8] = 1; // TTL 1: link-local
    f[ip + 9] = PROTO_IGMP;
    put_ip(f, ip + 12, src);
    put_ip(f, ip + 16, dst);
    f[ip + 20..ip + 24].copy_from_slice(&RA4);
    let c = checksum(&f[ip..ip + ihl]);
    put16(f, ip + 10, c);
    let m = ip + ihl;
    f[m] = kind;
    put_ip(f, m + 4, group);
    let c = checksum(&f[m..m + 8]);
    put16(f, m + 2, c);
    Some(total)
}

/// An IGMPv2 Membership Report for `group` from `src`.
pub fn igmp2_report(out: &mut [u8], src: Ipv4Addr, group: Ipv4Addr) -> Option<usize> {
    igmp2(out, src, group, IGMP2_REPORT)
}

/// An IGMPv2 Leave Group for `group` from `src` (to 224.0.0.2).
pub fn igmp2_leave(out: &mut [u8], src: Ipv4Addr, group: Ipv4Addr) -> Option<usize> {
    igmp2(out, src, group, IGMP2_LEAVE)
}

/// An MLDv2 Report from `src` (the link-local address) to ff02::16 with
/// one record of `kind` per group (at most [`MAX_RECORDS`]).
pub fn mld2_report(out: &mut [u8], src: Ipv6Addr, kind: Record, groups: &[Ipv6Addr]) -> Option<usize> {
    if groups.is_empty() || groups.len() > MAX_RECORDS {
        return None;
    }
    let msg_len = 8 + 20 * groups.len();
    let hbh = 8;
    let total = ETH_HDR + 40 + hbh + msg_len;
    let f = out.get_mut(..total)?;
    f.fill(0);
    put16(f, 12, ETHERTYPE_IPV6);
    let ip = ETH_HDR;
    f[ip] = 0x60;
    put16(f, ip + 4, (hbh + msg_len) as u16);
    f[ip + 6] = 0; // Hop-by-Hop options
    f[ip + 7] = 1; // hop limit 1
    f[ip + 8..ip + 24].copy_from_slice(&src.octets());
    f[ip + 24..ip + 40].copy_from_slice(&MLDV2_ROUTERS.octets());
    // Hop-by-Hop: next header ICMPv6, length 0 (8 bytes): Router Alert
    // (RFC 2711, value 0: MLD), then PadN of 2.
    let h = ip + 40;
    f[h..h + 8].copy_from_slice(&[PROTO_ICMPV6, 0, 5, 2, 0, 0, 1, 0]);
    let m = h + hbh;
    f[m] = ICMPV6_MLD2_REPORT;
    put16(f, m + 6, groups.len() as u16);
    for (k, g) in groups.iter().enumerate() {
        let r = m + 8 + 20 * k;
        f[r] = kind as u8;
        f[r + 4..r + 20].copy_from_slice(&g.octets());
    }
    let c = icmpv6_checksum(src, MLDV2_ROUTERS, &f[m..m + msg_len]);
    put16(f, m + 2, c);
    Some(total)
}

/// A membership query the router heard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    /// The group asked about; `None`: a general query (all groups).
    pub group: Option<IpAddr>,
    /// How long members may wait before answering (ms).
    pub max_resp_ms: u32,
}

/// The IGMP or MLD query in `frame`, if it is one with valid checksums.
pub fn parse_query(frame: &[u8]) -> Option<Query> {
    match ethertype(frame)? {
        ETHERTYPE_IPV4 => {
            let v = Ipv4View::parse(frame, ETH_HDR)?;
            if v.proto != PROTO_IGMP || v.is_fragment || v.l4_len < 8 {
                return None;
            }
            let m = &frame[v.l4..v.l4 + v.l4_len];
            if m[0] != IGMP_QUERY || checksum(m) != 0 {
                return None;
            }
            // v1: code 0 means 10 s; v2: tenths of a second; v3 (12+
            // bytes): an exponential code from 128 (RFC 3376 §4.1.1).
            let code = u32::from(m[1]);
            let tenths = match (m.len() >= 12, code) {
                (_, 0) => 100,
                (true, c) if c >= 128 => ((c & 0x0f) | 0x10) << (((c >> 4) & 0x07) + 3),
                (_, c) => c,
            };
            let g = get_ip(m, 4);
            Some(Query { group: (!g.is_unspecified()).then_some(IpAddr::V4(g)), max_resp_ms: tenths * 100 })
        }
        ETHERTYPE_IPV6 => {
            let v = Ipv6View::parse(frame, ETH_HDR)?;
            if v.proto != PROTO_ICMPV6 || v.is_fragment || v.l4_len < 24 {
                return None;
            }
            let m = &frame[v.l4..v.l4 + v.l4_len];
            let (src, dst) = (get_ip6(frame, v.ip + 8), get_ip6(frame, v.ip + 24));
            if m[0] != ICMPV6_MLD_QUERY || icmpv6_checksum(src, dst, m) != 0 {
                return None;
            }
            // v1: ms; v2 (28+ bytes): an exponential code from 32768
            // (RFC 3810 §5.1.3).
            let code = u32::from(get16(m, 4));
            let ms = if m.len() >= 28 && code >= 32768 { ((code & 0x0fff) | 0x1000) << (((code >> 12) & 0x07) + 3) } else { code };
            let g = get_ip6(m, 8);
            Some(Query { group: (!g.is_unspecified()).then_some(IpAddr::V6(g)), max_resp_ms: ms })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use smoltcp::wire::{EthernetFrame, Ipv4Packet, Ipv6Packet};

    const ME4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const MDNS4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    const LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe00, 1);
    const MDNS6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

    #[test]
    fn igmp2_report_and_leave() {
        let mut out = vec![0u8; 100];
        let n = igmp2_report(&mut out, ME4, MDNS4).unwrap();
        let ip = Ipv4Packet::new_checked(EthernetFrame::new_checked(&out[..n]).unwrap().payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!((ip.src_addr(), ip.dst_addr(), ip.hop_limit(), ip.header_len()), (ME4, MDNS4, 1, 24));
        assert_eq!(&out[ETH_HDR + 20..ETH_HDR + 24], &RA4, "router alert");
        let m = &out[ETH_HDR + 24..n];
        assert_eq!((m[0], checksum(m), get_ip(m, 4)), (IGMP2_REPORT, 0, MDNS4));
        let n = igmp2_leave(&mut out, ME4, MDNS4).unwrap();
        let ip = Ipv4Packet::new_checked(EthernetFrame::new_checked(&out[..n]).unwrap().payload()).unwrap();
        assert_eq!(ip.dst_addr(), ALL_ROUTERS4);
        assert_eq!(out[ETH_HDR + 24], IGMP2_LEAVE);
        assert_eq!(igmp2_report(&mut [0u8; 20], ME4, MDNS4), None, "too small");
    }

    #[test]
    fn mld2_report_with_records() {
        let groups = [MDNS6, ALL_ROUTERS6, crate::wire::solicited_node(LL)];
        let mut out = vec![0u8; 300];
        let n = mld2_report(&mut out, LL, Record::Joined, &groups).unwrap();
        let ip = Ipv6Packet::new_checked(EthernetFrame::new_checked(&out[..n]).unwrap().payload()).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr(), ip.hop_limit()), (LL, MLDV2_ROUTERS, 1));
        let v = Ipv6View::parse(&out[..n], ETH_HDR).unwrap();
        assert_eq!((v.proto, v.l4_len), (PROTO_ICMPV6, 8 + 20 * 3), "behind the Hop-by-Hop header");
        let m = &out[v.l4..n];
        assert_eq!(icmpv6_checksum(LL, MLDV2_ROUTERS, m), 0);
        assert_eq!((m[0], get16(m, 6)), (ICMPV6_MLD2_REPORT, 3));
        for (k, g) in groups.iter().enumerate() {
            let r = &m[8 + 20 * k..28 + 20 * k];
            assert_eq!((r[0], r[1], get16(r, 2), get_ip6(r, 4)), (Record::Joined as u8, 0, 0, *g));
        }
        assert_eq!(mld2_report(&mut out, LL, Record::IsMember, &[]), None);
        assert_eq!(mld2_report(&mut out, LL, Record::IsMember, &[MDNS6; MAX_RECORDS + 1]), None);
    }

    /// An IGMP query (`len` 8 for v2, 12 for v3) to all hosts.
    fn igmp_query(code: u8, group: Ipv4Addr, len: usize) -> alloc::vec::Vec<u8> {
        let mut f = vec![0u8; ETH_HDR + 20 + len];
        put16(&mut f, 12, ETHERTYPE_IPV4);
        let ip = ETH_HDR;
        f[ip] = 0x45;
        put16(&mut f, ip + 2, (20 + len) as u16);
        f[ip + 8] = 1;
        f[ip + 9] = PROTO_IGMP;
        put_ip(&mut f, ip + 12, Ipv4Addr::new(192, 168, 1, 2));
        put_ip(&mut f, ip + 16, Ipv4Addr::new(224, 0, 0, 1));
        let c = checksum(&f[ip..ip + 20]);
        put16(&mut f, ip + 10, c);
        let m = ip + 20;
        f[m] = IGMP_QUERY;
        f[m + 1] = code;
        put_ip(&mut f, m + 4, group);
        let c = checksum(&f[m..]);
        put16(&mut f, m + 2, c);
        f
    }

    #[test]
    fn igmp_queries() {
        let q = parse_query(&igmp_query(100, Ipv4Addr::UNSPECIFIED, 8)).unwrap();
        assert_eq!(q, Query { group: None, max_resp_ms: 10_000 }, "v2 general, 10 s");
        let q = parse_query(&igmp_query(0, Ipv4Addr::UNSPECIFIED, 8)).unwrap();
        assert_eq!(q.max_resp_ms, 10_000, "v1: code 0");
        let q = parse_query(&igmp_query(20, MDNS4, 8)).unwrap();
        assert_eq!(q, Query { group: Some(IpAddr::V4(MDNS4)), max_resp_ms: 2_000 }, "group-specific");
        // v3, code 0x80 (exp 0, mant 0): (0x10) << 3 = 128 tenths.
        let q = parse_query(&igmp_query(0x80, Ipv4Addr::UNSPECIFIED, 12)).unwrap();
        assert_eq!(q.max_resp_ms, 12_800);
        let mut f = igmp_query(100, Ipv4Addr::UNSPECIFIED, 8);
        *f.last_mut().unwrap() ^= 1;
        assert_eq!(parse_query(&f), None, "checksum");
        let mut out = vec![0u8; 100];
        let n = igmp2_report(&mut out, ME4, MDNS4).unwrap();
        assert_eq!(parse_query(&out[..n]), None, "a report is no query");
    }

    #[test]
    fn mld_queries() {
        // An MLDv2 general query behind Hop-by-Hop (Router Alert).
        let mut f = vec![0u8; ETH_HDR + 40 + 8 + 28];
        put16(&mut f, 12, ETHERTYPE_IPV6);
        let ip = ETH_HDR;
        f[ip] = 0x60;
        put16(&mut f, ip + 4, 8 + 28);
        f[ip + 7] = 1;
        let router = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9);
        let all = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        f[ip + 8..ip + 24].copy_from_slice(&router.octets());
        f[ip + 24..ip + 40].copy_from_slice(&all.octets());
        f[ip + 40..ip + 48].copy_from_slice(&[PROTO_ICMPV6, 0, 5, 2, 0, 0, 1, 0]);
        let m = ip + 48;
        f[m] = ICMPV6_MLD_QUERY;
        put16(&mut f, m + 4, 10_000);
        let c = icmpv6_checksum(router, all, &f[m..]);
        put16(&mut f, m + 2, c);
        assert_eq!(parse_query(&f), Some(Query { group: None, max_resp_ms: 10_000 }));
        // The exponential code (0x8000: mant 0, exp 0 -> 0x1000 << 3).
        put16(&mut f, m + 4, 0x8000);
        put16(&mut f, m + 2, 0);
        let c = icmpv6_checksum(router, all, &f[m..]);
        put16(&mut f, m + 2, c);
        assert_eq!(parse_query(&f).unwrap().max_resp_ms, 0x1000 << 3);
        f[m + 8..m + 24].copy_from_slice(&MDNS6.octets());
        put16(&mut f, m + 2, 0);
        let c = icmpv6_checksum(router, all, &f[m..]);
        put16(&mut f, m + 2, c);
        assert_eq!(parse_query(&f).unwrap().group, Some(IpAddr::V6(MDNS6)));
        *f.last_mut().unwrap() ^= 1;
        assert_eq!(parse_query(&f), None, "checksum");
        // Our own report is no query.
        let mut out = vec![0u8; 300];
        let n = mld2_report(&mut out, LL, Record::IsMember, &[MDNS6]).unwrap();
        assert_eq!(parse_query(&out[..n]), None);
    }

    #[test]
    fn random_damage_never_panics() {
        let bases = [igmp_query(100, Ipv4Addr::UNSPECIFIED, 12), {
            let mut out = vec![0u8; 300];
            let n = mld2_report(&mut out, LL, Record::IsMember, &[MDNS6, ALL_ROUTERS6]).unwrap();
            out.truncate(n);
            out[ETH_HDR + 48] = ICMPV6_MLD_QUERY;
            out
        }];
        let mut seed = 0x1357_9bdf_u32;
        for i in 0..50_000 {
            let mut f = bases[i % 2].clone();
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let k = (seed as usize) % f.len();
                f[k] = (seed >> 8) as u8;
            }
            f.truncate((seed as usize >> 3) % (f.len() + 1));
            let _ = parse_query(&f);
        }
    }
}
