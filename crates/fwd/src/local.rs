//! Where a packet from the router's own stack goes on a link whose stack
//! has no link layer (the kernel's `net::local`, docs/lan-neighbors.md step
//! 2): a fixed MAC (broadcast, multicast) or a neighbor to resolve through
//! [`crate::neigh`], the destination itself or a `[[route]]`'s gateway on
//! the link. The kernel's `Datapath::send_local` acts on the answer.
//!
//! Sans-IO: a frame (14 bytes of Ethernet header, then the IP packet) and
//! the link's addresses and routes in, a [`NextHop`] out.

use crate::wire::{ETH_HDR, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Mac, BROADCAST_MAC, get_ip, get_ip6};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

/// The router's view of one link for its own packets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalLink {
    /// The link's IPv4 address and prefix length.
    pub v4: Option<(Ipv4Addr, u8)>,
    /// Its IPv6 addresses with their prefix lengths (link-local, ULA,
    /// global: each /64 on the link).
    pub v6: Vec<(Ipv6Addr, u8)>,
    /// `[[route]]`s through a router on this link: (prefix, length, gateway).
    pub routes4: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
    pub routes6: Vec<(Ipv6Addr, u8, Ipv6Addr)>,
}

/// Where a packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextHop {
    /// To this MAC as is (broadcast, multicast).
    Mac(Mac),
    /// Through the neighbor table: this neighbor's MAC.
    Neighbor4(Ipv4Addr),
    Neighbor6(Ipv6Addr),
    /// Not on the link and no route: dropped.
    NoRoute,
}

fn mask4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len.min(32))) }
}

fn in4((a, len): (Ipv4Addr, u8), ip: Ipv4Addr) -> bool {
    u32::from(a) & mask4(len) == u32::from(ip) & mask4(len)
}

fn in6((a, len): (Ipv6Addr, u8), ip: Ipv6Addr) -> bool {
    let m = if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len.min(128))) };
    u128::from(a) & m == u128::from(ip) & m
}

/// The Ethernet multicast address of an IPv4 group (RFC 1112 §6.4).
pub fn multicast_mac4(a: Ipv4Addr) -> Mac {
    let o = a.octets();
    [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]
}

/// The Ethernet multicast address of an IPv6 group (RFC 2464 §7).
pub fn multicast_mac6(a: Ipv6Addr) -> Mac {
    let o = a.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

impl LocalLink {
    /// Where `frame`'s IP packet goes; `NoRoute` for anything else (not
    /// IP, too short, or the unspecified address).
    pub fn next_hop(&self, frame: &[u8]) -> NextHop {
        if frame.len() < ETH_HDR + 1 {
            return NextHop::NoRoute;
        }
        match crate::wire::ethertype(frame) {
            Some(ETHERTYPE_IPV4) if frame.len() >= ETH_HDR + 20 && frame[ETH_HDR] >> 4 == 4 => {
                self.next_hop4(get_ip(frame, ETH_HDR + 16))
            }
            Some(ETHERTYPE_IPV6) if frame.len() >= ETH_HDR + 40 && frame[ETH_HDR] >> 4 == 6 => {
                self.next_hop6(get_ip6(frame, ETH_HDR + 24))
            }
            _ => NextHop::NoRoute,
        }
    }

    /// IPv4: broadcast (limited, or the subnet's directed one), multicast,
    /// on the subnet, or the longest matching route's gateway.
    pub fn next_hop4(&self, dst: Ipv4Addr) -> NextHop {
        if dst.is_broadcast() {
            return NextHop::Mac(BROADCAST_MAC);
        }
        if dst.is_multicast() {
            return NextHop::Mac(multicast_mac4(dst));
        }
        if dst.is_unspecified() {
            return NextHop::NoRoute;
        }
        if let Some(net @ (a, len)) = self.v4 {
            if len < 31 && u32::from(dst) == u32::from(a) | !mask4(len) {
                return NextHop::Mac(BROADCAST_MAC);
            }
            if dst == a {
                return NextHop::NoRoute;
            }
            if in4(net, dst) {
                return NextHop::Neighbor4(dst);
            }
        }
        self.routes4
            .iter()
            .filter(|&&(p, l, _)| in4((p, l), dst))
            .max_by_key(|&&(_, l, _)| l)
            .map_or(NextHop::NoRoute, |&(_, _, gw)| NextHop::Neighbor4(gw))
    }

    /// IPv6: multicast, link-local, one of the link's prefixes, or the
    /// longest matching route's gateway.
    pub fn next_hop6(&self, dst: Ipv6Addr) -> NextHop {
        if dst.is_multicast() {
            return NextHop::Mac(multicast_mac6(dst));
        }
        if dst.is_unspecified() || self.v6.iter().any(|&(a, _)| a == dst) {
            return NextHop::NoRoute;
        }
        if dst.is_unicast_link_local() || self.v6.iter().any(|&net| in6(net, dst)) {
            return NextHop::Neighbor6(dst);
        }
        self.routes6
            .iter()
            .filter(|&&(p, l, _)| in6((p, l), dst))
            .max_by_key(|&&(_, l, _)| l)
            .map_or(NextHop::NoRoute, |&(_, _, gw)| NextHop::Neighbor6(gw))
    }

    /// The router's IPv6 addresses on the link (for [`crate::nd::Link`]).
    pub fn addrs6(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.v6.iter().map(|&(a, _)| a)
    }

    /// The source address for the router's own IPv6 packet to `dst` on
    /// this link (docs/local-stack.md §3.2, an RFC 6724 subset): link-local
    /// for link-local and link-scoped multicast destinations (ff02::/16);
    /// otherwise an address of the same kind (unique local for a unique
    /// local destination, global for the rest) with the longest prefix in
    /// common, else any non-link-local one, else link-local. `None`
    /// without an address that fits.
    pub fn source6(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        let ll = || self.addrs6().find(|a| a.is_unicast_link_local());
        let link_scope = dst.is_unicast_link_local() || (dst.is_multicast() && dst.segments()[0] & 0x000f <= 2);
        if link_scope {
            return ll();
        }
        let ula = |a: &Ipv6Addr| a.segments()[0] & 0xfe00 == 0xfc00;
        let common = |a: &Ipv6Addr| (u128::from(*a) ^ u128::from(dst)).leading_zeros();
        let routable = || self.addrs6().filter(|a| !a.is_unicast_link_local());
        routable()
            .filter(|a| ula(a) == ula(&dst))
            .max_by_key(common)
            .or_else(|| routable().max_by_key(common))
            .or_else(ll)
    }

    /// The source address for the router's own IPv4 packet on this link:
    /// the link's address (`None` without one: then only 0.0.0.0, which a
    /// caller like the DHCP client chooses itself).
    pub fn source4(&self) -> Option<Ipv4Addr> {
        self.v4.map(|(a, _)| a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe00, 1);
    const ULA: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1);
    const GUA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);

    fn link() -> LocalLink {
        LocalLink {
            v4: Some((Ipv4Addr::new(192, 168, 1, 1), 24)),
            v6: vec![(LL, 64), (ULA, 64), (GUA, 64)],
            routes4: vec![
                (Ipv4Addr::new(10, 30, 0, 0), 16, Ipv4Addr::new(192, 168, 1, 100)),
                (Ipv4Addr::new(10, 30, 5, 0), 24, Ipv4Addr::new(192, 168, 1, 101)),
            ],
            routes6: vec![(Ipv6Addr::new(0xfd00, 0x30, 0, 0, 0, 0, 0, 0), 64, Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0x100))],
        }
    }

    fn v4(a: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(a)
    }

    #[test]
    fn ipv4_broadcast_and_multicast_get_fixed_macs() {
        let l = link();
        assert_eq!(l.next_hop4(Ipv4Addr::BROADCAST), NextHop::Mac(BROADCAST_MAC));
        assert_eq!(l.next_hop4(v4([192, 168, 1, 255])), NextHop::Mac(BROADCAST_MAC), "directed");
        assert_eq!(l.next_hop4(v4([224, 0, 0, 251])), NextHop::Mac([1, 0, 0x5e, 0, 0, 0xfb]));
        // The top bit of the second octet is not mapped (RFC 1112).
        assert_eq!(l.next_hop4(v4([239, 129, 2, 3])), NextHop::Mac([1, 0, 0x5e, 1, 2, 3]));
    }

    #[test]
    fn ipv4_on_link_route_or_nothing() {
        let l = link();
        assert_eq!(l.next_hop4(v4([192, 168, 1, 100])), NextHop::Neighbor4(v4([192, 168, 1, 100])));
        assert_eq!(l.next_hop4(v4([10, 30, 0, 5])), NextHop::Neighbor4(v4([192, 168, 1, 100])));
        assert_eq!(l.next_hop4(v4([10, 30, 5, 5])), NextHop::Neighbor4(v4([192, 168, 1, 101])), "longest prefix");
        assert_eq!(l.next_hop4(v4([8, 8, 8, 8])), NextHop::NoRoute, "no default route on a LAN");
        assert_eq!(l.next_hop4(v4([192, 168, 1, 1])), NextHop::NoRoute, "ourselves");
        assert_eq!(l.next_hop4(Ipv4Addr::UNSPECIFIED), NextHop::NoRoute);
    }

    #[test]
    fn ipv4_point_to_point_prefixes_have_no_directed_broadcast() {
        let l = LocalLink { v4: Some((v4([10, 0, 0, 0]), 31)), ..LocalLink::default() };
        assert_eq!(l.next_hop4(v4([10, 0, 0, 1])), NextHop::Neighbor4(v4([10, 0, 0, 1])));
    }

    #[test]
    fn ipv6_multicast_link_local_prefixes_and_routes() {
        let l = link();
        let all = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(l.next_hop6(all), NextHop::Mac([0x33, 0x33, 0, 0, 0, 1]));
        let mdns = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
        assert_eq!(l.next_hop6(mdns), NextHop::Mac([0x33, 0x33, 0, 0, 0, 0xfb]));
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x22);
        assert_eq!(l.next_hop6(ll), NextHop::Neighbor6(ll));
        let c = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x99);
        assert_eq!(l.next_hop6(c), NextHop::Neighbor6(c));
        let behind = Ipv6Addr::new(0xfd00, 0x30, 0, 0, 0, 0, 0, 5);
        assert_eq!(l.next_hop6(behind), NextHop::Neighbor6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0x100)));
        assert_eq!(l.next_hop6(Ipv6Addr::new(0x2001, 0xdb8, 9, 0, 0, 0, 0, 1)), NextHop::NoRoute);
        assert_eq!(l.next_hop6(ULA), NextHop::NoRoute, "ourselves");
    }

    #[test]
    fn frames_are_read_by_version() {
        let l = link();
        let mut f = vec![0u8; ETH_HDR + 40];
        crate::wire::put16(&mut f, 12, ETHERTYPE_IPV4);
        f[ETH_HDR] = 0x45;
        crate::wire::put_ip(&mut f, ETH_HDR + 16, v4([192, 168, 1, 7]));
        assert_eq!(l.next_hop(&f), NextHop::Neighbor4(v4([192, 168, 1, 7])));
        f[ETH_HDR] = 0x65; // wrong version for the EtherType
        assert_eq!(l.next_hop(&f), NextHop::NoRoute);
        let mut f = vec![0u8; ETH_HDR + 40];
        crate::wire::put16(&mut f, 12, ETHERTYPE_IPV6);
        f[ETH_HDR] = 0x60;
        f[ETH_HDR + 24..ETH_HDR + 40].copy_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2).octets());
        assert_eq!(l.next_hop(&f), NextHop::Mac([0x33, 0x33, 0, 0, 0, 2]));
        for n in 0..f.len() {
            let _ = l.next_hop(&f[..n]);
        }
        assert_eq!(l.next_hop(&f[..ETH_HDR + 39]), NextHop::NoRoute);
    }

    #[test]
    fn source_addresses() {
        let l = LocalLink {
            v4: Some((Ipv4Addr::new(192, 168, 1, 1), 24)),
            v6: vec![(LL, 64), (ULA, 64), (GUA, 64)],
            ..Default::default()
        };
        assert_eq!(l.source4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(LocalLink::default().source4(), None);
        let s = |d: Ipv6Addr| l.source6(d);
        // Link scope: link-local.
        assert_eq!(s(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 9)), Some(LL));
        assert_eq!(s(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)), Some(LL), "mDNS group");
        assert_eq!(s(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 9)), Some(LL), "solicited-node");
        // Unique local to unique local, global to global (also off-link).
        assert_eq!(s(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0x10)), Some(ULA));
        assert_eq!(s(Ipv6Addr::new(0xfd99, 1, 2, 3, 0, 0, 0, 1)), Some(ULA), "another ULA prefix");
        assert_eq!(s(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x10)), Some(GUA));
        assert_eq!(s(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)), Some(GUA), "the internet");
        assert_eq!(s(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 2)), Some(GUA), "site-scoped multicast");
        // Longest common prefix among several of a kind.
        let gua2 = Ipv6Addr::new(0x2a03, 0xab00, 0x1000, 0x910, 0, 0, 0, 1);
        let two = LocalLink { v6: vec![(LL, 64), (GUA, 64), (gua2, 64)], ..Default::default() };
        assert_eq!(two.source6(Ipv6Addr::new(0x2a03, 0xab00, 0x10, 0, 0, 0, 0, 0x131)), Some(gua2));
        assert_eq!(two.source6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1)), Some(GUA));
        // Missing a kind: the other routable one, then link-local.
        let ula_only = LocalLink { v6: vec![(LL, 64), (ULA, 64)], ..Default::default() };
        assert_eq!(ula_only.source6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), Some(ULA));
        let ll_only = LocalLink { v6: vec![(LL, 64)], ..Default::default() };
        assert_eq!(ll_only.source6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), Some(LL));
        assert_eq!(LocalLink::default().source6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), None);
    }
}
