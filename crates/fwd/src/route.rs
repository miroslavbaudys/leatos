//! IPv4 routing table: longest-prefix match.
//!
//! A sorted list is plenty for a SOHO router (connected subnets + default
//! route). A DIR-24-8 / Poptrie structure can replace it behind the same
//! API if full tables are ever needed.

use crate::IfIndex;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub prefix: Ipv4Addr,
    pub len: u8,
    pub egress: IfIndex,
    /// `None` = directly connected (next hop is the destination itself).
    pub gateway: Option<Ipv4Addr>,
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

impl Route {
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        u32::from(a) & mask(self.len) == u32::from(self.prefix) & mask(self.len)
    }
}

#[derive(Default)]
pub struct RouteTable {
    /// Sorted by prefix length, longest first.
    routes: Vec<Route>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace the route for (prefix, len).
    pub fn set(&mut self, r: Route) {
        let r = Route {
            prefix: Ipv4Addr::from(u32::from(r.prefix) & mask(r.len)),
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

    pub fn remove(&mut self, prefix: Ipv4Addr, len: u8) {
        let p = Ipv4Addr::from(u32::from(prefix) & mask(len));
        self.routes.retain(|x| !(x.prefix == p && x.len == len));
    }

    pub fn lookup(&self, dst: Ipv4Addr) -> Option<&Route> {
        self.routes.iter().find(|r| r.contains(dst))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.routes.iter()
    }

    /// Remove every route of one kind.
    pub fn remove_kind(&mut self, kind: RouteKind) {
        self.routes.retain(|r| r.kind != kind);
    }

    /// The route for exactly (prefix, len).
    pub fn get(&self, prefix: Ipv4Addr, len: u8) -> Option<&Route> {
        let p = Ipv4Addr::from(u32::from(prefix) & mask(len));
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
}
