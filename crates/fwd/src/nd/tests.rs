use super::*;
use crate::wire::{NS_LEN, build_arp_request, build_ns, link_local};
use alloc::vec::Vec;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv6Packet, Icmpv6Repr,
    IpProtocol, Ipv6Packet, NdiscNeighborFlags, NdiscRepr,
};

const ME: Mac = [0x52, 0x54, 0, 0, 0, 1];
const CLIENT: Mac = [0x52, 0x54, 0, 0, 0, 0x22];
const OTHER: Mac = [0x52, 0x54, 0, 0, 0, 0x33];
const MY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const ULA: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1);
const GUA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
const CLIENT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0x100);

fn v6() -> [Ipv6Addr; 3] {
    [link_local(ME), ULA, GUA]
}

fn run(frame: &[u8], cfg: Config) -> (Outcome, Vec<u8>) {
    let addrs = v6();
    let me = Link {
        mac: ME,
        v4: Some((MY_IP, 24)),
        v6: &addrs,
    };
    let mut out = [0u8; REPLY_LEN];
    let o = answer(frame, &me, cfg, &mut out);
    (o, out[..o.reply.unwrap_or(0)].to_vec())
}

fn arp_request(from: Mac, sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut b = [0u8; 60];
    let n = build_arp_request(&mut b, from, sender, target);
    b[..n].to_vec()
}

/// An ARP frame parsed by smoltcp: (Ethernet destination, its repr).
fn arp_reply_of(frame: &[u8]) -> (EthernetAddress, ArpRepr) {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
    assert_eq!(eth.src_addr(), EthernetAddress(ME));
    let repr = ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).unwrap()).unwrap();
    (eth.dst_addr(), repr)
}

/// Recompute an ICMPv6 message's checksum after a test changed the frame.
fn fix_checksum(f: &mut [u8]) {
    let ip = ETH_HDR;
    let len = usize::from(get16(f, ip + 4));
    let (src, dst) = (get_ip6(f, ip + 8), get_ip6(f, ip + 24));
    put16(f, ip + 42, 0);
    let c = icmpv6_checksum(src, dst, &f[ip + 40..ip + 40 + len]);
    put16(f, ip + 42, c);
}

use crate::wire::{get16, put16};

/// An NS from the client to `target`'s solicited-node group.
fn ns(target: Ipv6Addr) -> Vec<u8> {
    let mut b = [0u8; NS_LEN];
    build_ns(&mut b, CLIENT, CLIENT6, target);
    b.to_vec()
}

/// The same NS sent unicast to `target` (a reachability probe).
fn ns_unicast(target: Ipv6Addr) -> Vec<u8> {
    let mut f = ns(target);
    f[0..6].copy_from_slice(&ME);
    f[ETH_HDR + 24..ETH_HDR + 40].copy_from_slice(&target.octets());
    fix_checksum(&mut f);
    f
}

/// A unicast NS without the source link-layer option (allowed, §7.2.2).
fn ns_unicast_no_slla(target: Ipv6Addr) -> Vec<u8> {
    let mut f = ns_unicast(target);
    f.truncate(ETH_HDR + 40 + 24);
    put16(&mut f, ETH_HDR + 4, 24);
    fix_checksum(&mut f);
    f
}

/// A DAD probe for `target` from `from` (source ::, no SLLA).
fn dad(from: Mac, target: Ipv6Addr) -> Vec<u8> {
    let mut f = ns_unicast_no_slla(target);
    f[6..12].copy_from_slice(&from);
    let group = solicited_node(target);
    f[0..2].copy_from_slice(&[0x33, 0x33]);
    f[2..6].copy_from_slice(&group.octets()[12..16]);
    f[ETH_HDR + 8..ETH_HDR + 24].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
    f[ETH_HDR + 24..ETH_HDR + 40].copy_from_slice(&group.octets());
    fix_checksum(&mut f);
    f
}

/// An NA from `from` advertising `target` at `from`.
fn na(from: Mac, target: Ipv6Addr) -> Vec<u8> {
    let mut out = [0u8; REPLY_LEN];
    build_na(&mut out, from, ME, target, link_local(ME), NA_OVERRIDE);
    // From the other node's own address.
    out[ETH_HDR + 8..ETH_HDR + 24].copy_from_slice(&CLIENT6.octets());
    let mut f = out.to_vec();
    fix_checksum(&mut f);
    f
}

/// An NA parsed by smoltcp (checksum verified): (Ethernet destination,
/// IPv6 source, IPv6 destination, flags, target, lladdr).
fn na_of(frame: &[u8]) -> (EthernetAddress, Ipv6Addr, Ipv6Addr, NdiscNeighborFlags, Ipv6Addr, Option<Vec<u8>>) {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
    assert_eq!(eth.src_addr(), EthernetAddress(ME));
    let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
    assert_eq!(ip.hop_limit(), 255);
    let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
    let repr = Icmpv6Repr::parse(&ip.src_addr(), &ip.dst_addr(), &icmp, &ChecksumCapabilities::default()).unwrap();
    let Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert { flags, target_addr, lladdr }) = repr else {
        panic!("not a neighbor advertisement: {repr:?}");
    };
    (eth.dst_addr(), ip.src_addr(), ip.dst_addr(), flags, target_addr, lladdr.map(|l| l.as_bytes().to_vec()))
}

// ---- ARP ----------------------------------------------------------------------------

#[test]
fn arp_request_for_us_is_answered_to_the_asker() {
    let (o, r) = run(&arp_request(CLIENT, CLIENT_IP, MY_IP), Config::default());
    assert_eq!(o.reply, Some(ARP_REPLY_LEN));
    assert_eq!(o.conflict, None);
    let (dst, repr) = arp_reply_of(&r);
    assert_eq!(dst, EthernetAddress(CLIENT));
    assert_eq!(
        repr,
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: EthernetAddress(ME),
            source_protocol_addr: MY_IP,
            target_hardware_addr: EthernetAddress(CLIENT),
            target_protocol_addr: CLIENT_IP,
        }
    );
}

#[test]
fn arp_request_for_another_address_is_not_answered() {
    let (o, _) = run(&arp_request(CLIENT, CLIENT_IP, Ipv4Addr::new(192, 168, 1, 2)), Config::default());
    assert_eq!(o, Outcome::default());
}

#[test]
fn arp_request_from_outside_the_subnet_is_not_answered() {
    let (o, _) = run(&arp_request(CLIENT, Ipv4Addr::new(10, 0, 0, 5), MY_IP), Config::default());
    assert_eq!(o, Outcome::default());
}

#[test]
fn arp_probe_for_our_address_is_answered_and_a_conflict() {
    let (o, r) = run(&arp_request(OTHER, Ipv4Addr::UNSPECIFIED, MY_IP), Config::default());
    assert_eq!(o.conflict, Some((IpAddr::V4(MY_IP), OTHER)));
    let (dst, repr) = arp_reply_of(&r);
    assert_eq!(dst, EthernetAddress(OTHER));
    let ArpRepr::EthernetIpv4 { source_protocol_addr, target_protocol_addr, .. } = repr else {
        unreachable!()
    };
    assert_eq!((source_protocol_addr, target_protocol_addr), (MY_IP, Ipv4Addr::UNSPECIFIED));
}

#[test]
fn arp_claiming_our_address_is_a_conflict_without_reply() {
    // Gratuitous announcement (sender = target = our address).
    let (o, _) = run(&arp_request(OTHER, MY_IP, MY_IP), Config::default());
    assert_eq!(o, Outcome { reply: None, conflict: Some((IpAddr::V4(MY_IP), OTHER)) });
}

#[test]
fn arp_from_ourselves_or_a_multicast_mac_is_ignored() {
    assert_eq!(run(&arp_request(ME, MY_IP, MY_IP), Config::default()).0, Outcome::default());
    let mut f = arp_request(CLIENT, CLIENT_IP, MY_IP);
    f[ETH_HDR + 8] |= 1; // sender MAC multicast
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
}

/// Found by the `fwd` fuzz target: the ARP sender field was checked, the
/// frame's own source MAC not, so a frame from our MAC (a loop, or forged)
/// carrying a client's MAC inside was answered.
#[test]
fn frames_from_our_own_or_a_multicast_mac_are_ignored() {
    for from in [ME, [0x01, 0, 0x5e, 0, 0, 1]] {
        let mut f = arp_request(CLIENT, CLIENT_IP, MY_IP);
        f[6..12].copy_from_slice(&from);
        assert_eq!(run(&f, Config::default()).0, Outcome::default(), "ARP from {from:x?}");
        let mut f = ns(ULA);
        f[6..12].copy_from_slice(&from);
        assert_eq!(run(&f, Config::default()).0, Outcome::default(), "NS from {from:x?}");
    }
}

#[test]
fn arp_reply_to_us_is_not_answered() {
    let mut f = arp_request(CLIENT, CLIENT_IP, MY_IP);
    put16(&mut f, ETH_HDR + 6, 2);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
}

#[test]
fn no_ipv4_address_no_arp_answer() {
    let me = Link { mac: ME, v4: None, v6: &[] };
    let mut out = [0u8; REPLY_LEN];
    let o = answer(&arp_request(CLIENT, CLIENT_IP, MY_IP), &me, Config::default(), &mut out);
    assert_eq!(o, Outcome::default());
}

#[test]
fn short_or_foreign_frames_are_ignored() {
    for n in 0..60 {
        let f = arp_request(CLIENT, CLIENT_IP, MY_IP);
        let _ = run(&f[..n.min(f.len())], Config::default());
    }
    let f = ns(ULA);
    for n in 0..f.len() {
        assert_eq!(run(&f[..n], Config::default()).0.reply, None, "truncated to {n}");
    }
}

// ---- Neighbor discovery ----------------------------------------------------------------

#[test]
fn ns_to_the_solicited_node_group_is_answered_for_each_address() {
    for target in v6() {
        let (o, r) = run(&ns(target), Config::default());
        assert_eq!(o.reply, Some(NA_LEN), "{target}");
        assert_eq!(o.conflict, None);
        let (edst, src, dst, flags, t, lladdr) = na_of(&r);
        assert_eq!(edst, EthernetAddress(CLIENT));
        assert_eq!((src, dst, t), (target, CLIENT6, target));
        assert_eq!(flags, NdiscNeighborFlags::ROUTER | NdiscNeighborFlags::SOLICITED | NdiscNeighborFlags::OVERRIDE);
        assert_eq!(lladdr, Some(ME.to_vec()));
    }
}

#[test]
fn unicast_ns_is_answered_unless_switched_off() {
    let (o, r) = run(&ns_unicast(ULA), Config::default());
    assert_eq!(o.reply, Some(NA_LEN));
    assert_eq!(na_of(&r).0, EthernetAddress(CLIENT));
    // Negative control: smoltcp 0.14's behaviour (`nd_unicast=0`).
    let off = Config { unicast_ns: false, ..Config::default() };
    assert_eq!(run(&ns_unicast(ULA), off).0, Outcome::default());
    assert_eq!(run(&ns(ULA), off).0.reply, Some(NA_LEN), "multicast still answered");
}

#[test]
fn unicast_ns_without_slla_goes_to_the_frames_source() {
    let (o, r) = run(&ns_unicast_no_slla(GUA), Config::default());
    assert_eq!(o.reply, Some(NA_LEN));
    assert_eq!(na_of(&r).0, EthernetAddress(CLIENT));
}

#[test]
fn router_flag_can_be_cleared() {
    let (_, r) = run(&ns(ULA), Config { router: false, ..Config::default() });
    assert_eq!(na_of(&r).3, NdiscNeighborFlags::SOLICITED | NdiscNeighborFlags::OVERRIDE);
}

#[test]
fn ns_for_another_target_is_not_answered() {
    assert_eq!(run(&ns(CLIENT6), Config::default()).0, Outcome::default());
    // To another address's group.
    let mut f = ns(ULA);
    let g = solicited_node(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0x12, 0x3456));
    f[ETH_HDR + 24..ETH_HDR + 40].copy_from_slice(&g.octets());
    fix_checksum(&mut f);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
}

#[test]
fn invalid_ns_is_not_answered() {
    // RFC 4861 §7.1.1, each check on its own: the unchanged frame passes.
    assert_eq!(run(&ns(ULA), Config::default()).0.reply, Some(NA_LEN));
    let mut hop = ns(ULA);
    hop[ETH_HDR + 7] = 64;
    let mut sum = ns(ULA);
    sum[ETH_HDR + 42] ^= 1;
    let mut code = ns(ULA);
    code[ETH_HDR + 41] = 1;
    fix_checksum(&mut code);
    let mut opt = ns(ULA);
    opt[ETH_HDR + 40 + 25] = 0; // option length 0
    fix_checksum(&mut opt);
    let mut mtarget = ns(ULA);
    mtarget[ETH_HDR + 48..ETH_HDR + 64].copy_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets());
    fix_checksum(&mut mtarget);
    for (what, f) in [("hop limit", hop), ("checksum", sum), ("code", code), ("option", opt), ("target", mtarget)] {
        assert_eq!(run(&f, Config::default()).0, Outcome::default(), "{what}");
    }
}

#[test]
fn ns_from_our_own_mac_or_address_is_ignored() {
    let mut f = ns(ULA);
    f[6..12].copy_from_slice(&ME);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
    let mut f = ns(ULA);
    f[ETH_HDR + 8..ETH_HDR + 24].copy_from_slice(&GUA.octets());
    fix_checksum(&mut f);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
}

#[test]
fn dad_for_our_address_is_defended_to_all_nodes() {
    let (o, r) = run(&dad(OTHER, ULA), Config::default());
    assert_eq!(o.conflict, Some((IpAddr::V6(ULA), OTHER)));
    let (edst, src, dst, flags, t, _) = na_of(&r);
    assert_eq!(edst, EthernetAddress([0x33, 0x33, 0, 0, 0, 1]));
    assert_eq!((src, dst, t), (ULA, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), ULA));
    assert!(!flags.contains(NdiscNeighborFlags::SOLICITED));
}

#[test]
fn invalid_dad_is_ignored() {
    // With a source link-layer option (§7.1.1).
    let mut f = dad(OTHER, ULA);
    f.extend_from_slice(&[OPT_SLLA, 1, 0x52, 0x54, 0, 0, 0, 0x33]);
    put16(&mut f, ETH_HDR + 4, 32);
    fix_checksum(&mut f);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
    // Unicast.
    let mut f = dad(OTHER, ULA);
    f[ETH_HDR + 24..ETH_HDR + 40].copy_from_slice(&ULA.octets());
    fix_checksum(&mut f);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
}

#[test]
fn na_claiming_our_address_is_a_conflict() {
    assert_eq!(run(&na(OTHER, GUA), Config::default()).0, Outcome {
        reply: None,
        conflict: Some((IpAddr::V6(GUA), OTHER)),
    });
    assert_eq!(run(&na(OTHER, CLIENT6), Config::default()).0, Outcome::default(), "not ours");
}

#[test]
fn other_ipv6_is_ignored() {
    // An RS (type 133) and an echo request to us.
    let mut f = ns(ULA);
    f[ETH_HDR + 40] = 133;
    fix_checksum(&mut f);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
    let mut f = ns_unicast(ULA);
    f[ETH_HDR + 40] = 128;
    fix_checksum(&mut f);
    assert_eq!(run(&f, Config::default()).0, Outcome::default());
}
