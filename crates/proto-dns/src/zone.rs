//! Local authoritative zone: one or more local domains (one per network,
//! or shared), each with `router.<domain>`, static hosts and DHCP
//! hostnames, plus reverse (PTR) records for them.
//!
//! Names under a local domain (and reverse lookups for the router's
//! subnets) are **never forwarded** upstream: unknown ones get NXDOMAIN.
//! Domains may nest (`home.arpa` and `iot.home.arpa`): a name belongs to
//! the longest local domain it ends in.

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

/// One local domain and its hosts.
struct Domain {
    name: String,
    /// host label → (address, source)
    hosts: BTreeMap<String, (Ipv4Addr, Source)>,
}

pub struct Zone {
    /// The first is the default domain ([`Zone::add`]).
    domains: Vec<Domain>,
    /// The router's subnets (address, prefix length): their reverse zones
    /// are local too.
    subnets: Vec<(Ipv4Addr, u8)>,
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

fn normalize(domain: &str) -> String {
    domain.trim_matches('.').to_ascii_lowercase()
}

/// `name` is `domain` or ends in `.domain`.
fn under(name: &str, domain: &str) -> bool {
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

impl Zone {
    pub fn new(domain: &str, router_ip: Ipv4Addr, subnet: (Ipv4Addr, u8)) -> Self {
        let mut z = Self {
            domains: Vec::new(),
            subnets: alloc::vec![subnet],
        };
        z.add_domain(domain, router_ip);
        z
    }

    /// Another local domain with `router.<domain>` = `router_ip`. A domain
    /// that is already local keeps its hosts (and its router address).
    pub fn add_domain(&mut self, domain: &str, router_ip: Ipv4Addr) {
        let name = normalize(domain);
        if self.domains.iter().any(|d| d.name == name) {
            return;
        }
        self.domains.push(Domain {
            name: name.clone(),
            hosts: BTreeMap::new(),
        });
        self.add_in(&name, "router", router_ip, Source::Static);
    }

    /// Another subnet whose reverse zone is local (a second network).
    pub fn add_subnet(&mut self, subnet: (Ipv4Addr, u8)) {
        self.subnets.push(subnet);
    }

    /// The default (first) domain.
    pub fn domain(&self) -> &str {
        &self.domains[0].name
    }

    /// `name` (lowercase, no trailing dot) is in a local domain.
    pub fn is_local_name(&self, name: &str) -> bool {
        self.domains.iter().any(|d| under(name, &d.name))
    }

    fn find_mut(&mut self, domain: &str) -> Option<&mut Domain> {
        let name = normalize(domain);
        self.domains.iter_mut().find(|d| d.name == name)
    }

    /// Add or replace a host in the default domain.
    pub fn add(&mut self, host: &str, ip: Ipv4Addr, source: Source) {
        let first = self.domains[0].name.clone();
        self.add_in(&first, host, ip, source);
    }

    /// Add or replace a host in local domain `domain` (ignored if it is not
    /// local). DHCP entries never override static ones.
    pub fn add_in(&mut self, domain: &str, host: &str, ip: Ipv4Addr, source: Source) {
        let Some(d) = self.find_mut(domain) else {
            return;
        };
        let host = host.to_ascii_lowercase();
        if source == Source::Dhcp
            && d.hosts
                .get(&host)
                .is_some_and(|(_, s)| *s == Source::Static)
        {
            return;
        }
        d.hosts.insert(host, (ip, source));
    }

    /// Remove a DHCP host from the default domain (only if it still points
    /// at `ip`).
    pub fn remove_dhcp(&mut self, host: &str, ip: Ipv4Addr) {
        let first = self.domains[0].name.clone();
        self.remove_dhcp_in(&first, host, ip);
    }

    /// Remove a DHCP host from `domain` (only if it still points at `ip`).
    pub fn remove_dhcp_in(&mut self, domain: &str, host: &str, ip: Ipv4Addr) {
        let Some(d) = self.find_mut(domain) else {
            return;
        };
        let host = host.to_ascii_lowercase();
        if d.hosts.get(&host) == Some(&(ip, Source::Dhcp)) {
            d.hosts.remove(&host);
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
                .domains
                .iter()
                .flat_map(|d| {
                    d.hosts
                        .iter()
                        .filter(move |(_, (a, _))| *a == ip)
                        .map(move |(h, _)| format!("{h}.{}", d.name))
                })
                .collect();
            return match (names.is_empty(), qtype == TYPE_PTR) {
                (true, _) => Lookup::NxDomain,
                (false, true) => Lookup::Ptr(names),
                (false, false) => Lookup::NoData,
            };
        }
        // The longest local domain the name is in.
        let Some(d) = self
            .domains
            .iter()
            .filter(|d| under(name, &d.name))
            .max_by_key(|d| d.name.len())
        else {
            return Lookup::NotLocal;
        };
        if name == d.name {
            return Lookup::NoData;
        }
        let host = &name[..name.len() - d.name.len() - 1];
        match d.hosts.get(host) {
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

    #[test]
    fn several_domains_nested() {
        let mut z = Zone::new("home.arpa", Ipv4Addr::new(192, 168, 1, 1), (Ipv4Addr::new(192, 168, 1, 1), 24));
        z.add_domain("IoT.home.arpa.", Ipv4Addr::new(192, 168, 2, 1));
        z.add_subnet((Ipv4Addr::new(192, 168, 2, 1), 24));
        z.add_domain("home.arpa", Ipv4Addr::new(10, 0, 0, 1)); // already local: kept
        z.add("pc", Ipv4Addr::new(192, 168, 1, 100), Source::Dhcp);
        z.add_in("iot.home.arpa", "boiler", Ipv4Addr::new(192, 168, 2, 82), Source::Static);
        z.add_in("other.example", "x", Ipv4Addr::new(192, 168, 2, 9), Source::Static); // not local
        fn a_of(z: &Zone, n: &str) -> Option<Ipv4Addr> {
            match z.lookup(n, TYPE_A) {
                Lookup::A(v) => Some(v[0]),
                _ => None,
            }
        }
        assert_eq!(a_of(&z, "router.home.arpa"), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(a_of(&z, "router.iot.home.arpa"), Some(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(a_of(&z, "boiler.iot.home.arpa"), Some(Ipv4Addr::new(192, 168, 2, 82)));
        assert_eq!(a_of(&z, "pc.home.arpa"), Some(Ipv4Addr::new(192, 168, 1, 100)));
        // Each name in its own domain only.
        assert!(matches!(z.lookup("boiler.home.arpa", TYPE_A), Lookup::NxDomain));
        assert!(matches!(z.lookup("pc.iot.home.arpa", TYPE_A), Lookup::NxDomain));
        assert!(matches!(z.lookup("iot.home.arpa", TYPE_A), Lookup::NoData));
        assert!(matches!(z.lookup("x.other.example", TYPE_A), Lookup::NotLocal));
        assert!(z.is_local_name("a.iot.home.arpa") && z.is_local_name("home.arpa"));
        assert!(!z.is_local_name("xhome.arpa") && !z.is_local_name("example.com"));
        let ptr = Zone::reverse_of(Ipv4Addr::new(192, 168, 2, 82));
        assert!(matches!(z.lookup(&ptr, TYPE_PTR), Lookup::Ptr(v) if v == ["boiler.iot.home.arpa"]));
        // Removal is per domain.
        z.add_in("iot.home.arpa", "pc", Ipv4Addr::new(192, 168, 2, 100), Source::Dhcp);
        z.remove_dhcp("pc", Ipv4Addr::new(192, 168, 2, 100)); // wrong domain: no effect
        assert_eq!(a_of(&z, "pc.iot.home.arpa"), Some(Ipv4Addr::new(192, 168, 2, 100)));
        z.remove_dhcp_in("iot.home.arpa", "pc", Ipv4Addr::new(192, 168, 2, 100));
        assert!(matches!(z.lookup("pc.iot.home.arpa", TYPE_A), Lookup::NxDomain));
        assert_eq!(a_of(&z, "pc.home.arpa"), Some(Ipv4Addr::new(192, 168, 1, 100)));
    }
}
