//! Local authoritative zone: `router.<domain>`, static hosts and DHCP
//! hostnames, plus reverse (PTR) records for them.
//!
//! Names under the local domain (and reverse lookups for the LAN subnet)
//! are **never forwarded** upstream: unknown ones get NXDOMAIN.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Static,
    Dhcp,
}

pub struct Zone {
    domain: String,
    /// The router's subnets (address, prefix length): their reverse zones
    /// are local too.
    subnets: Vec<(Ipv4Addr, u8)>,
    /// host label → (address, source)
    hosts: BTreeMap<String, (Ipv4Addr, Source)>,
}

pub enum Lookup {
    /// The name is ours and has addresses / PTR targets.
    A(Vec<Ipv4Addr>),
    Ptr(Vec<String>),
    /// The name is ours but has no record of the requested type.
    NoData,
    /// The name is in our zone but doesn't exist.
    NxDomain,
    /// Not our zone: forward upstream.
    NotLocal,
}

fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

fn parse_reverse(name: &str) -> Option<Ipv4Addr> {
    let rest = name.strip_suffix(".in-addr.arpa")?;
    let mut parts = rest.split('.').map(|p| p.parse::<u8>().ok());
    let (d, c, b, a) = (
        parts.next()??,
        parts.next()??,
        parts.next()??,
        parts.next()??,
    );
    parts.next().is_none().then(|| Ipv4Addr::new(a, b, c, d))
}

impl Zone {
    pub fn new(domain: &str, router_ip: Ipv4Addr, subnet: (Ipv4Addr, u8)) -> Self {
        let mut z = Self {
            domain: domain.trim_matches('.').to_ascii_lowercase(),
            subnets: alloc::vec![subnet],
            hosts: BTreeMap::new(),
        };
        z.add("router", router_ip, Source::Static);
        z
    }

    /// Another subnet whose reverse zone is local (a second network).
    pub fn add_subnet(&mut self, subnet: (Ipv4Addr, u8)) {
        self.subnets.push(subnet);
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Add or replace a host. DHCP entries never override static ones.
    pub fn add(&mut self, host: &str, ip: Ipv4Addr, source: Source) {
        let host = host.to_ascii_lowercase();
        if source == Source::Dhcp
            && self
                .hosts
                .get(&host)
                .is_some_and(|(_, s)| *s == Source::Static)
        {
            return;
        }
        self.hosts.insert(host, (ip, source));
    }

    /// Remove a DHCP host (only if it still points at `ip`).
    pub fn remove_dhcp(&mut self, host: &str, ip: Ipv4Addr) {
        let host = host.to_ascii_lowercase();
        if self.hosts.get(&host) == Some(&(ip, Source::Dhcp)) {
            self.hosts.remove(&host);
        }
    }

    fn in_subnet(&self, ip: Ipv4Addr) -> bool {
        self.subnets.iter().any(|&(net, len)| {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - len as u32)
            };
            u32::from(ip) & mask == u32::from(net) & mask
        })
    }

    /// Resolve `name` (lowercase, no trailing dot) for `qtype`.
    pub fn lookup(&self, name: &str, qtype: u16) -> Lookup {
        use crate::wire::{TYPE_A, TYPE_PTR};
        if let Some(ip) = parse_reverse(name) {
            if !self.in_subnet(ip) {
                return Lookup::NotLocal;
            }
            let names: Vec<String> = self
                .hosts
                .iter()
                .filter(|(_, (a, _))| *a == ip)
                .map(|(h, _)| format!("{h}.{}", self.domain))
                .collect();
            return match (names.is_empty(), qtype == TYPE_PTR) {
                (true, _) => Lookup::NxDomain,
                (false, true) => Lookup::Ptr(names),
                (false, false) => Lookup::NoData,
            };
        }
        let host = if name == self.domain {
            return Lookup::NoData;
        } else if let Some(h) = name
            .strip_suffix(self.domain.as_str())
            .and_then(|h| h.strip_suffix('.'))
        {
            h
        } else {
            return Lookup::NotLocal;
        };
        match self.hosts.get(host) {
            Some((ip, _)) if qtype == TYPE_A => Lookup::A(alloc::vec![*ip]),
            Some(_) => Lookup::NoData,
            None => Lookup::NxDomain,
        }
    }

    pub fn reverse_of(ip: Ipv4Addr) -> String {
        reverse_name(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{TYPE_A, TYPE_AAAA, TYPE_PTR};

    fn zone() -> Zone {
        let mut z = Zone::new(
            "lan",
            Ipv4Addr::new(192, 168, 1, 1),
            (Ipv4Addr::new(192, 168, 1, 0), 24),
        );
        z.add("nas", Ipv4Addr::new(192, 168, 1, 10), Source::Static);
        z
    }

    #[test]
    fn forward_and_reverse() {
        let mut z = zone();
        z.add("laptop", Ipv4Addr::new(192, 168, 1, 100), Source::Dhcp);
        assert!(
            matches!(z.lookup("nas.lan", TYPE_A), Lookup::A(v) if v == [Ipv4Addr::new(192, 168, 1, 10)])
        );
        assert!(matches!(z.lookup("router.lan", TYPE_A), Lookup::A(_)));
        assert!(matches!(z.lookup("nas.lan", TYPE_AAAA), Lookup::NoData));
        assert!(matches!(z.lookup("ghost.lan", TYPE_A), Lookup::NxDomain));
        assert!(matches!(z.lookup("example.com", TYPE_A), Lookup::NotLocal));
        assert!(
            matches!(z.lookup("100.1.168.192.in-addr.arpa", TYPE_PTR), Lookup::Ptr(v) if v == ["laptop.lan"])
        );
        assert!(matches!(
            z.lookup("200.1.168.192.in-addr.arpa", TYPE_PTR),
            Lookup::NxDomain
        ));
        assert!(matches!(
            z.lookup("8.8.8.8.in-addr.arpa", TYPE_PTR),
            Lookup::NotLocal
        ));
        assert_eq!(
            Zone::reverse_of(Ipv4Addr::new(10, 0, 0, 1)),
            "1.0.0.10.in-addr.arpa"
        );
    }

    #[test]
    fn dhcp_cannot_hijack_static_and_removal_is_exact() {
        let mut z = zone();
        z.add("nas", Ipv4Addr::new(192, 168, 1, 150), Source::Dhcp);
        assert!(
            matches!(z.lookup("nas.lan", TYPE_A), Lookup::A(v) if v == [Ipv4Addr::new(192, 168, 1, 10)])
        );
        z.add("pc", Ipv4Addr::new(192, 168, 1, 101), Source::Dhcp);
        z.remove_dhcp("pc", Ipv4Addr::new(192, 168, 1, 199)); // stale removal: ignored
        assert!(matches!(z.lookup("pc.lan", TYPE_A), Lookup::A(_)));
        z.remove_dhcp("pc", Ipv4Addr::new(192, 168, 1, 101));
        assert!(matches!(z.lookup("pc.lan", TYPE_A), Lookup::NxDomain));
    }

    #[test]
    fn reverse_zones_of_every_subnet_are_local() {
        use crate::wire::TYPE_PTR;
        let mut z = Zone::new("lan", Ipv4Addr::new(10, 10, 0, 1), (Ipv4Addr::new(10, 10, 0, 1), 24));
        z.add("tv", Ipv4Addr::new(10, 20, 0, 5), Source::Dhcp);
        let q = Zone::reverse_of(Ipv4Addr::new(10, 20, 0, 5));
        assert!(matches!(z.lookup(&q, TYPE_PTR), Lookup::NotLocal));
        z.add_subnet((Ipv4Addr::new(10, 20, 0, 1), 24));
        assert!(matches!(z.lookup(&q, TYPE_PTR), Lookup::Ptr(_)));
        let other = Zone::reverse_of(Ipv4Addr::new(10, 20, 0, 6));
        assert!(matches!(z.lookup(&other, TYPE_PTR), Lookup::NxDomain));
    }
}
