use super::*;
use alloc::string::ToString;
use alloc::vec;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv6Packet, NdiscPrefixInfoFlags,
    NdiscRepr,
};

const MAC: [u8; 6] = [0x52, 0x54, 0, 0, 0, 2];
const ULA: Ipv6Addr = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0, 0, 0, 0, 1);

fn cfg() -> RaConfig {
    RaConfig {
        mac: MAC,
        prefix: ULA,
        mtu: 1500,
        rdnss: vec![ULA],
        dnssl: vec!["home.arpa".to_string()],
    }
}

/// The RA's options after the 16-byte header: (type, body).
fn options(icmp: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut o = &icmp[16..];
    while o.len() >= 8 {
        let len = o[1] as usize * 8;
        assert!(len >= 8 && len <= o.len(), "option length");
        out.push((o[0], o[2..len].to_vec()));
        o = &o[len..];
    }
    assert!(o.is_empty());
    out
}

/// Parse the frame with smoltcp (checksum verified) and return the RA's
/// ICMPv6 bytes.
fn check(frame: &[u8], retired: bool) -> Vec<u8> {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.dst_addr(), EthernetAddress([0x33, 0x33, 0, 0, 0, 1]));
    assert_eq!(eth.src_addr(), EthernetAddress(MAC));
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
    let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
    assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
    assert_eq!(ip.hop_limit(), 255);
    assert_eq!(ip.src_addr(), "fe80::5054:ff:fe00:2".parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "ff02::1".parse::<Ipv6Addr>().unwrap());
    let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
    let repr = Icmpv6Repr::parse(&ip.src_addr(), &ip.dst_addr(), &icmp, &ChecksumCapabilities::default()).unwrap();
    let Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert { router_lifetime, lladdr, mtu, prefix_info, flags, .. }) = repr else {
        panic!("not a router advertisement: {repr:?}");
    };
    assert_eq!(router_lifetime.total_millis(), 0);
    assert!(flags.is_empty());
    assert_eq!(lladdr.map(|l| l.as_bytes().to_vec()), Some(MAC.to_vec()));
    assert_eq!(mtu, Some(1500));
    let p = prefix_info.unwrap();
    assert_eq!(p.prefix_len, 64);
    assert!(p.flags.contains(NdiscPrefixInfoFlags::ON_LINK | NdiscPrefixInfoFlags::ADDRCONF));
    assert_eq!(p.prefix, "fd12:3456:789a::".parse::<Ipv6Addr>().unwrap());
    let (valid, preferred) = if retired { (RETIRED_VALID_SECS, 0) } else { (VALID_SECS, PREFERRED_SECS) };
    assert_eq!(p.valid_lifetime.secs(), u64::from(valid));
    assert_eq!(p.preferred_lifetime.secs(), u64::from(preferred));
    ip.payload().to_vec()
}

#[test]
fn ra_carries_prefix_mtu_dns_and_search_domain() {
    let mut a = Advertiser::new(cfg(), 0, 7);
    let f = a.poll(0).unwrap();
    let icmp = check(&f, false);
    let opts = options(&icmp);
    let rdnss = opts.iter().find(|o| o.0 == OPT_RDNSS).unwrap();
    assert_eq!(u32::from_be_bytes(rdnss.1[2..6].try_into().unwrap()), DNS_SECS);
    assert_eq!(rdnss.1[6..22], ULA.octets());
    let dnssl = opts.iter().find(|o| o.0 == OPT_DNSSL).unwrap();
    assert_eq!(&dnssl.1[6..17], b"\x04home\x04arpa\x00");
    assert!(dnssl.1[17..].iter().all(|&b| b == 0), "padding");
}

#[test]
fn bad_search_domains_are_left_out() {
    let mut c = cfg();
    c.dnssl = vec!["".to_string(), "a..b".to_string(), "x".repeat(64)];
    c.rdnss.clear();
    let mut a = Advertiser::new(c, 0, 7);
    let icmp = check(&a.poll(0).unwrap(), false);
    let types: Vec<u8> = options(&icmp).iter().map(|o| o.0).collect();
    assert_eq!(types, vec![OPT_SLLA, OPT_MTU, OPT_PREFIX]);
}

#[test]
fn schedule_initial_then_slow() {
    let mut a = Advertiser::new(cfg(), 1_000, 99);
    assert_eq!(a.next_deadline(), Some(1_000));
    assert!(a.poll(999).is_none());
    let mut t = 1_000;
    let mut gaps = Vec::new();
    for _ in 0..6 {
        assert!(a.poll(t).is_some());
        let next = a.next_deadline().unwrap();
        gaps.push(next - t);
        t = next;
    }
    // Three initial RAs at most 16 s apart, then 200–600 s.
    assert!(gaps[..3].iter().all(|&g| g <= MAX_INITIAL_INTERVAL_MS), "{gaps:?}");
    assert!(gaps[3..].iter().all(|&g| (MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&g)), "{gaps:?}");
    assert_eq!(a.sent, 6);
}

#[test]
fn solicitations_are_answered_soon_but_not_more_than_every_3_s() {
    let mut a = Advertiser::new(cfg(), 0, 5);
    for _ in 0..4 {
        a.poll(a.next_deadline().unwrap()).unwrap();
    }
    let t = a.next_deadline().unwrap() - 100_000; // well inside a slow interval
    a.solicited(t);
    let at = a.next_deadline().unwrap();
    assert!((t..=t + MAX_RA_DELAY_MS).contains(&at), "{at} vs {t}");
    a.poll(at).unwrap();
    // A burst of solicitations right after: the next RA waits 3 s.
    for i in 0..10 {
        a.solicited(at + i * 10);
    }
    let next = a.next_deadline().unwrap();
    assert!(next >= at + MIN_DELAY_MS && next <= at + MIN_DELAY_MS + MAX_RA_DELAY_MS, "{next}");
    assert_eq!(a.solicits, 11);
}

#[test]
fn retire_deprecates_and_stops() {
    let mut a = Advertiser::new(cfg(), 0, 5);
    a.poll(0).unwrap();
    a.retire(10);
    let icmp = check(&a.poll(10).unwrap(), true);
    let rdnss = options(&icmp).into_iter().find(|o| o.0 == OPT_RDNSS).unwrap();
    assert_eq!(rdnss.1[2..6], [0, 0, 0, 0], "DNS server withdrawn");
    assert!(a.is_done());
    assert_eq!(a.next_deadline(), None);
    assert!(a.poll(1_000_000).is_none());
    a.solicited(2_000_000);
    assert!(a.poll(3_000_000).is_none());
}

#[test]
fn new_config_is_advertised_soon() {
    let mut a = Advertiser::new(cfg(), 0, 5);
    for _ in 0..5 {
        a.poll(a.next_deadline().unwrap()).unwrap();
    }
    let t = a.next_deadline().unwrap() - 150_000;
    let mut c = cfg();
    c.dnssl = vec!["guest.lan".to_string()];
    a.set_config(c.clone(), t);
    assert_eq!(a.next_deadline(), Some(t));
    a.set_config(c, t + 1); // the same again: nothing new
    assert_eq!(a.next_deadline(), Some(t));
}

#[test]
fn link_local_and_prefix() {
    assert_eq!(link_local([0x52, 0x54, 0, 0x12, 0x34, 0x56]), "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap());
    assert_eq!(prefix64("fd12:3456:789a:1::1".parse().unwrap()), "fd12:3456:789a:1::".parse::<Ipv6Addr>().unwrap());
}
