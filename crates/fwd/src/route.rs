//! Routing table: longest-prefix match, for IPv4 (the default) or IPv6
//! ([`RouteAddr`]).
//!
//! A sorted list is plenty for a SOHO router (connected subnets + default
//! route). A DIR-24-8 / Poptrie structure can replace it behind the same
//! API if full tables are ever needed.

use crate::IfIndex;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

/// An address family a [`RouteTable`] routes.
pub trait RouteAddr: Copy + Eq {
    /// The first `len` bits of the address, the rest zero.
    fn masked(self, len: u8) -> Self;
}

impl RouteAddr for Ipv4Addr {
    fn masked(self, len: u8) -> Self {
        Ipv4Addr::from(u32::from(self) & mask(len))
    }
}

impl RouteAddr for Ipv6Addr {
    fn masked(self, len: u8) -> Self {
        let m = if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len.min(128))) };
        Ipv6Addr::from(u128::from(self) & m)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route<A = Ipv4Addr> {
    pub prefix: A,
    pub len: u8,
    pub egress: IfIndex,
    /// `None` = directly connected (next hop is the destination itself).
    pub gateway: Option<A>,
    pub kind: RouteKind,
}

/// Where a route comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// An interface's own subnet.
    Connected,
    /// The WAN's gateway (lease, PPPoE peer).
    Default,
    /// Configured (`[[route]]`), through a router on a connected subnet.
    Static,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Default => "default",
            Self::Static => "static",
        }
    }
}

fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    }
}

impl<A: RouteAddr> Route<A> {
    pub fn contains(&self, a: A) -> bool {
        a.masked(self.len) == self.prefix.masked(self.len)
    }
}

pub struct RouteTable<A = Ipv4Addr> {
    /// Sorted by prefix length, longest first.
    routes: Vec<Route<A>>,
}

impl<A> Default for RouteTable<A> {
    fn default() -> Self {
        Self { routes: Vec::new() }
    }
}

impl<A: RouteAddr> RouteTable<A> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace the route for (prefix, len).
    pub fn set(&mut self, r: Route<A>) {
        let r = Route {
            prefix: r.prefix.masked(r.len),
            ..r
        };
        self.routes
            .retain(|x| !(x.prefix == r.prefix && x.len == r.len));
        let pos = self
            .routes
            .iter()
            .position(|x| x.len < r.len)
            .unwrap_or(self.routes.len());
        self.routes.insert(pos, r);
    }

    pub fn remove(&mut self, prefix: A, len: u8) {
        let p = prefix.masked(len);
        self.routes.retain(|x| !(x.prefix == p && x.len == len));
    }

    pub fn lookup(&self, dst: A) -> Option<&Route<A>> {
        self.routes.iter().find(|r| r.contains(dst))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Route<A>> {
        self.routes.iter()
    }

    /// Remove every route of one kind.
    pub fn remove_kind(&mut self, kind: RouteKind) {
        self.routes.retain(|r| r.kind != kind);
    }

    /// The route for exactly (prefix, len).
    pub fn get(&self, prefix: A, len: u8) -> Option<&Route<A>> {
        let p = prefix.masked(len);
        self.routes.iter().find(|x| x.prefix == p && x.len == len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins() {
        let mut t = RouteTable::new();
        t.set(Route {
            prefix: Ipv4Addr::UNSPECIFIED,
            len: 0,
            egress: 0,
            gateway: Some(Ipv4Addr::new(203, 0, 113, 1)),
            kind: RouteKind::Default,
        });
        t.set(Route {
            prefix: Ipv4Addr::new(192, 168, 1, 77),
            len: 24,
            egress: 1,
            gateway: None,
            kind: RouteKind::Connected,
        });
        assert_eq!(t.lookup(Ipv4Addr::new(192, 168, 1, 5)).unwrap().egress, 1);
        assert_eq!(t.lookup(Ipv4Addr::new(8, 8, 8, 8)).unwrap().egress, 0);
        t.remove(Ipv4Addr::UNSPECIFIED, 0);
        assert!(t.lookup(Ipv4Addr::new(8, 8, 8, 8)).is_none());
        assert_eq!(
            t.iter().next().unwrap().prefix,
            Ipv4Addr::new(192, 168, 1, 0),
            "prefix normalised"
        );
    }

    #[test]
    fn ipv6_longest_prefix_wins() {
        let a = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let mut t: RouteTable<Ipv6Addr> = RouteTable::new();
        t.set(Route { prefix: Ipv6Addr::UNSPECIFIED, len: 0, egress: 0, gateway: Some(a("fe80::1")), kind: RouteKind::Default });
        t.set(Route { prefix: a("2001:db8:100:1::1"), len: 64, egress: 2, gateway: None, kind: RouteKind::Connected });
        t.set(Route { prefix: a("2001:db8:100::"), len: 56, egress: 1, gateway: None, kind: RouteKind::Static });
        assert_eq!(t.lookup(a("2001:db8:100:1::99")).unwrap().egress, 2);
        assert_eq!(t.lookup(a("2001:db8:100:7::1")).unwrap().egress, 1);
        assert_eq!(t.lookup(a("2001:db8:999::1")).unwrap().egress, 0);
        assert_eq!(t.get(a("2001:db8:100:1::"), 64).unwrap().prefix, a("2001:db8:100:1::"), "prefix normalised");
        assert_eq!(Ipv6Addr::masked(a("ffff::ffff"), 1), a("8000::"));
        assert_eq!(Ipv6Addr::masked(a("ffff::ffff"), 128), a("ffff::ffff"));
    }
}
