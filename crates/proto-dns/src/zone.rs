//! Local authoritative zone: one or more local domains (one per network,
//! or shared), each with `router.<domain>`, static hosts and DHCP
//! hostnames, plus reverse (PTR) records for them, and overrides of
//! single public names.
//!
//! Names under a local domain (and reverse lookups for the router's
//! subnets) are **never forwarded** upstream: unknown ones get NXDOMAIN.
//! Domains may nest (`home.arpa` and `iot.home.arpa`): a name belongs to
//! the longest local domain it ends in.
//!
//! **Views** (split horizon, docs/dns-views.md): every record carries the
//! set of networks it is answered to ([`View`]), and every lookup the
//! network that asks. A name in a local domain without a record for the
//! asking network is NXDOMAIN there ([`Lookup::Hidden`]); the same name may
//! have other records (other addresses) for other networks. A static
//! record wins over a DHCP one for the networks it covers. An override
//! ([`Zone::add_override`]) is an exact name outside the local domains:
//! answered to its networks, forwarded upstream for the others.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Static,
    Dhcp,
}

/// A set of networks: bit `k` = network `k` (config order), plus
/// [`View::ROUTER`] for the router's own lookups. A record's view says who
/// gets it; a query's view is the one network it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View(pub u32);

impl View {
    /// Every network and the router.
    pub const ALL: View = View(u32::MAX);
    /// The router's own lookups (SNTP server names, …).
    pub const ROUTER: View = View(1 << 31);
    /// Nobody.
    pub const NONE: View = View(0);
    /// Networks `0..MAX_NETWORKS` have a bit of their own.
    pub const MAX_NETWORKS: usize = 31;

    /// Network `k` (`k` < [`View::MAX_NETWORKS`]; larger ones get no bit).
    pub const fn network(k: usize) -> View {
        if k < Self::MAX_NETWORKS { View(1 << k) } else { View(0) }
    }

    pub const fn union(self, other: View) -> View {
        View(self.0 | other.0)
    }

    pub const fn overlaps(self, other: View) -> bool {
        self.0 & other.0 != 0
    }
}

/// One answer for a name, given to the networks in `seen_by`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    ip: Ipv4Addr,
    source: Source,
    seen_by: View,
    /// The `[[dns.host]]` entry it comes from (index), for its hit counter.
    host: Option<u16>,
}

/// The record `view` gets from `recs`: static before DHCP, then the
/// earliest added.
fn effective(recs: &[Record], view: View) -> Option<&Record> {
    let mut seen = recs.iter().filter(|r| r.seen_by.overlaps(view));
    let first = seen.next()?;
    if first.source == Source::Static {
        return Some(first);
    }
    Some(seen.find(|r| r.source == Source::Static).unwrap_or(first))
}

/// Add `rec` to `recs`: it takes over its networks from the records of
/// its source (a new lease, a changed static record, a `[[dns.host]]`
/// over a reservation for some networks); they keep the others.
fn put(recs: &mut Vec<Record>, rec: Record) {
    for r in recs.iter_mut().filter(|r| r.source == rec.source) {
        r.seen_by = View(r.seen_by.0 & !rec.seen_by.0);
    }
    recs.retain(|r| r.seen_by != View::NONE);
    recs.push(rec);
}

/// One local domain and its hosts.
struct Domain {
    name: String,
    /// host label → its records
    hosts: BTreeMap<String, Vec<Record>>,
}

pub struct Zone {
    /// The first is the default domain ([`Zone::add`]).
    domains: Vec<Domain>,
    /// The router's subnets (address, prefix length): their reverse zones
    /// are local too.
    subnets: Vec<(Ipv4Addr, u8)>,
    /// Exact names outside the local domains, answered to some networks.
    overrides: BTreeMap<String, Vec<Record>>,
    /// The router's IPv6 addresses: (domain, address) for `router.<domain>`
    /// AAAA and its `ip6.arpa` PTR.
    routers6: Vec<(String, Ipv6Addr)>,
    /// The networks' IPv6 /64s: their `ip6.arpa` names are local.
    subnets6: Vec<Ipv6Addr>,
}

#[derive(Debug)]
pub enum Lookup {
    /// The name is ours and has addresses / PTR targets.
    A(Vec<Ipv4Addr>),
    Aaaa(Vec<Ipv6Addr>),
    Ptr(Vec<String>),
    /// The name is ours but has no record of the requested type.
    NoData,
    /// The name is in our zone but doesn't exist.
    NxDomain,
    /// The name exists, but not for the asking network: answer NXDOMAIN.
    Hidden,
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

/// A full `ip6.arpa` name (32 nibbles, RFC 3596 §2.5).
fn parse_reverse6(name: &str) -> Option<Ipv6Addr> {
    let rest = name.strip_suffix(".ip6.arpa")?;
    let mut v: u128 = 0;
    let mut n = 0;
    for (i, p) in rest.split('.').enumerate() {
        if i >= 32 || p.len() != 1 {
            return None;
        }
        let d = u128::from(char::from(p.as_bytes()[0]).to_digit(16)?);
        v |= d << (4 * i);
        n += 1;
    }
    (n == 32).then(|| Ipv6Addr::from(v))
}

fn prefix64(a: Ipv6Addr) -> u128 {
    u128::from(a) >> 64
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
            overrides: BTreeMap::new(),
            routers6: Vec::new(),
            subnets6: Vec::new(),
        };
        z.add_domain(domain, router_ip);
        z
    }

    /// Another local domain with `router.<domain>` = `router_ip` (for
    /// everyone). A domain that is already local keeps its hosts (and its
    /// router address).
    pub fn add_domain(&mut self, domain: &str, router_ip: Ipv4Addr) {
        let name = normalize(domain);
        if self.domains.iter().any(|d| d.name == name) {
            return;
        }
        self.domains.push(Domain {
            name: name.clone(),
            hosts: BTreeMap::new(),
        });
        self.add_in(&name, "router", router_ip, Source::Static, View::ALL);
    }

    /// The router's IPv6 address in a network whose domain is `domain`
    /// (already local): `router.<domain>` AAAA, its PTR, and the /64's
    /// `ip6.arpa` names local.
    pub fn add_router6(&mut self, domain: &str, addr: Ipv6Addr) {
        let name = normalize(domain);
        if !self.routers6.iter().any(|(d, a)| *d == name && *a == addr) {
            self.routers6.push((name, addr));
        }
        if !self.subnets6.iter().any(|&s| prefix64(s) == prefix64(addr)) {
            self.subnets6.push(addr);
        }
    }

    /// Another subnet whose reverse zone is local (a second network).
    pub fn add_subnet(&mut self, subnet: (Ipv4Addr, u8)) {
        self.subnets.push(subnet);
    }

    /// The default (first) domain.
    pub fn domain(&self) -> &str {
        &self.domains[0].name
    }

    /// `name` (lowercase, no trailing dot) is in a local domain. Overrides
    /// are not: upstream answers for them keep rebind protection.
    pub fn is_local_name(&self, name: &str) -> bool {
        self.domains.iter().any(|d| under(name, &d.name))
    }

    fn find_mut(&mut self, domain: &str) -> Option<&mut Domain> {
        let name = normalize(domain);
        self.domains.iter_mut().find(|d| d.name == name)
    }

    /// Add or replace a host in the default domain, for everyone.
    pub fn add(&mut self, host: &str, ip: Ipv4Addr, source: Source) {
        let first = self.domains[0].name.clone();
        self.add_in(&first, host, ip, source, View::ALL);
    }

    /// Add a host in local domain `domain` (ignored if it is not local),
    /// answered to `seen_by`. It takes over those networks from the host's
    /// records of the same source; for the networks a static record
    /// covers, DHCP records stay unseen.
    pub fn add_in(&mut self, domain: &str, host: &str, ip: Ipv4Addr, source: Source, seen_by: View) {
        self.add_record_in(domain, host, Record { ip, source, seen_by, host: None });
    }

    /// [`Self::add_in`] for `[[dns.host]]` entry `index` (static): queries
    /// it answers are counted for it ([`Self::lookup_host`]).
    pub fn add_host_in(&mut self, domain: &str, host: &str, ip: Ipv4Addr, seen_by: View, index: u16) {
        let rec = Record { ip, source: Source::Static, seen_by, host: Some(index) };
        self.add_record_in(domain, host, rec);
    }

    fn add_record_in(&mut self, domain: &str, host: &str, rec: Record) {
        let Some(d) = self.find_mut(domain) else {
            return;
        };
        let recs = d.hosts.entry(host.to_ascii_lowercase()).or_default();
        put(recs, rec);
    }

    /// Override the public name `name` (exact, outside the local domains;
    /// ignored otherwise) with `ip` for `seen_by`. Other networks resolve
    /// it upstream.
    pub fn add_override(&mut self, name: &str, ip: Ipv4Addr, seen_by: View) {
        self.add_override_record(name, Record { ip, source: Source::Static, seen_by, host: None });
    }

    /// [`Self::add_override`] for `[[dns.host]]` entry `index`.
    pub fn add_host_override(&mut self, name: &str, ip: Ipv4Addr, seen_by: View, index: u16) {
        self.add_override_record(name, Record { ip, source: Source::Static, seen_by, host: Some(index) });
    }

    fn add_override_record(&mut self, name: &str, rec: Record) {
        let name = normalize(name);
        if name.is_empty() || self.is_local_name(&name) {
            return;
        }
        let recs = self.overrides.entry(name).or_default();
        put(recs, rec);
    }

    /// Remove a DHCP host from the default domain (only if it still points
    /// at `ip`).
    pub fn remove_dhcp(&mut self, host: &str, ip: Ipv4Addr) {
        let first = self.domains[0].name.clone();
        self.remove_dhcp_in(&first, host, ip);
    }

    /// Remove a DHCP host from `domain` (only its records pointing at
    /// `ip`).
    pub fn remove_dhcp_in(&mut self, domain: &str, host: &str, ip: Ipv4Addr) {
        let Some(d) = self.find_mut(domain) else {
            return;
        };
        let host = host.to_ascii_lowercase();
        if let Some(recs) = d.hosts.get_mut(&host) {
            recs.retain(|r| r.source != Source::Dhcp || r.ip != ip);
            if recs.is_empty() {
                d.hosts.remove(&host);
            }
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

    /// The names (`host.domain`) whose record for `view` is `ip`.
    fn names_of(&self, ip: Ipv4Addr, view: View) -> Vec<String> {
        self.domains
            .iter()
            .flat_map(|d| {
                d.hosts
                    .iter()
                    .filter(move |(_, recs)| effective(recs, view).is_some_and(|r| r.ip == ip))
                    .map(move |(h, _)| format!("{h}.{}", d.name))
            })
            .collect()
    }

    /// Resolve `name` (lowercase, no trailing dot) for `qtype`, asked from
    /// `view` (one network, [`View::ROUTER`], or [`View::ALL`] to see
    /// everything).
    pub fn lookup(&self, name: &str, qtype: u16, view: View) -> Lookup {
        self.lookup_host(name, qtype, view).0
    }

    /// [`Self::lookup`], plus the `[[dns.host]]` entry that answered a
    /// forward name (A, or no data for another type), if one did.
    pub fn lookup_host(&self, name: &str, qtype: u16, view: View) -> (Lookup, Option<u16>) {
        use crate::wire::{TYPE_A, TYPE_AAAA, TYPE_PTR};
        if let Some(ip6) = parse_reverse6(name) {
            if !self.subnets6.iter().any(|&s| prefix64(s) == prefix64(ip6)) {
                return (Lookup::NotLocal, None);
            }
            let names: Vec<String> = self
                .routers6
                .iter()
                .filter(|(_, a)| *a == ip6)
                .map(|(d, _)| format!("router.{d}"))
                .collect();
            return match (names.is_empty(), qtype == TYPE_PTR) {
                (true, _) => (Lookup::NxDomain, None),
                (false, true) => (Lookup::Ptr(names), None),
                (false, false) => (Lookup::NoData, None),
            };
        }
        if let Some(ip) = parse_reverse(name) {
            if !self.in_subnet(ip) {
                return (Lookup::NotLocal, None);
            }
            let names = self.names_of(ip, view);
            if names.is_empty() {
                let anywhere = self
                    .domains
                    .iter()
                    .any(|d| d.hosts.values().flatten().any(|r| r.ip == ip));
                return (if anywhere { Lookup::Hidden } else { Lookup::NxDomain }, None);
            }
            return (if qtype == TYPE_PTR { Lookup::Ptr(names) } else { Lookup::NoData }, None);
        }
        // The longest local domain the name is in.
        let Some(d) = self
            .domains
            .iter()
            .filter(|d| under(name, &d.name))
            .max_by_key(|d| d.name.len())
        else {
            // An override, for its networks only; any other type is NoData
            // there (a dual-stack client must not take the public AAAA).
            return match self.overrides.get(name).and_then(|recs| effective(recs, view)) {
                Some(r) if qtype == TYPE_A => (Lookup::A(alloc::vec![r.ip]), r.host),
                Some(r) => (Lookup::NoData, r.host),
                None => (Lookup::NotLocal, None),
            };
        };
        if name == d.name {
            return (Lookup::NoData, None);
        }
        let host = &name[..name.len() - d.name.len() - 1];
        if host == "router" && qtype == TYPE_AAAA {
            let v6: Vec<Ipv6Addr> = self.routers6.iter().filter(|(dn, _)| *dn == d.name).map(|&(_, a)| a).collect();
            if !v6.is_empty() {
                return (Lookup::Aaaa(v6), None);
            }
        }
        match d.hosts.get(host) {
            Some(recs) => match effective(recs, view) {
                Some(r) if qtype == TYPE_A => (Lookup::A(alloc::vec![r.ip]), r.host),
                Some(r) => (Lookup::NoData, r.host),
                None => (Lookup::Hidden, None),
            },
            None => (Lookup::NxDomain, None),
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

    const ALL: View = View::ALL;

    fn zone() -> Zone {
        let mut z = Zone::new(
            "lan",
            Ipv4Addr::new(192, 168, 1, 1),
            (Ipv4Addr::new(192, 168, 1, 0), 24),
        );
        z.add("nas", Ipv4Addr::new(192, 168, 1, 10), Source::Static);
        z
    }

    fn a_of(z: &Zone, n: &str, view: View) -> Option<Ipv4Addr> {
        match z.lookup(n, TYPE_A, view) {
            Lookup::A(v) => Some(v[0]),
            _ => None,
        }
    }

    #[test]
    fn forward_and_reverse() {
        let mut z = zone();
        z.add("laptop", Ipv4Addr::new(192, 168, 1, 100), Source::Dhcp);
        assert!(
            matches!(z.lookup("nas.lan", TYPE_A, ALL), Lookup::A(v) if v == [Ipv4Addr::new(192, 168, 1, 10)])
        );
        assert!(matches!(z.lookup("router.lan", TYPE_A, ALL), Lookup::A(_)));
        assert!(matches!(z.lookup("nas.lan", TYPE_AAAA, ALL), Lookup::NoData));
        assert!(matches!(z.lookup("ghost.lan", TYPE_A, ALL), Lookup::NxDomain));
        assert!(matches!(z.lookup("example.com", TYPE_A, ALL), Lookup::NotLocal));
        assert!(
            matches!(z.lookup("100.1.168.192.in-addr.arpa", TYPE_PTR, ALL), Lookup::Ptr(v) if v == ["laptop.lan"])
        );
        assert!(matches!(
            z.lookup("200.1.168.192.in-addr.arpa", TYPE_PTR, ALL),
            Lookup::NxDomain
        ));
        assert!(matches!(
            z.lookup("8.8.8.8.in-addr.arpa", TYPE_PTR, ALL),
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
        assert_eq!(a_of(&z, "nas.lan", ALL), Some(Ipv4Addr::new(192, 168, 1, 10)));
        z.add("pc", Ipv4Addr::new(192, 168, 1, 101), Source::Dhcp);
        z.remove_dhcp("pc", Ipv4Addr::new(192, 168, 1, 199)); // stale removal: ignored
        assert!(matches!(z.lookup("pc.lan", TYPE_A, ALL), Lookup::A(_)));
        z.remove_dhcp("pc", Ipv4Addr::new(192, 168, 1, 101));
        assert!(matches!(z.lookup("pc.lan", TYPE_A, ALL), Lookup::NxDomain));
    }

    #[test]
    fn reverse_zones_of_every_subnet_are_local() {
        let mut z = Zone::new("lan", Ipv4Addr::new(10, 10, 0, 1), (Ipv4Addr::new(10, 10, 0, 1), 24));
        z.add("tv", Ipv4Addr::new(10, 20, 0, 5), Source::Dhcp);
        let q = Zone::reverse_of(Ipv4Addr::new(10, 20, 0, 5));
        assert!(matches!(z.lookup(&q, TYPE_PTR, ALL), Lookup::NotLocal));
        z.add_subnet((Ipv4Addr::new(10, 20, 0, 1), 24));
        assert!(matches!(z.lookup(&q, TYPE_PTR, ALL), Lookup::Ptr(_)));
        let other = Zone::reverse_of(Ipv4Addr::new(10, 20, 0, 6));
        assert!(matches!(z.lookup(&other, TYPE_PTR, ALL), Lookup::NxDomain));
    }

    #[test]
    fn several_domains_nested() {
        let mut z = Zone::new("home.arpa", Ipv4Addr::new(192, 168, 1, 1), (Ipv4Addr::new(192, 168, 1, 1), 24));
        z.add_domain("IoT.home.arpa.", Ipv4Addr::new(192, 168, 2, 1));
        z.add_subnet((Ipv4Addr::new(192, 168, 2, 1), 24));
        z.add_domain("home.arpa", Ipv4Addr::new(10, 0, 0, 1)); // already local: kept
        z.add("pc", Ipv4Addr::new(192, 168, 1, 100), Source::Dhcp);
        z.add_in("iot.home.arpa", "boiler", Ipv4Addr::new(192, 168, 2, 82), Source::Static, ALL);
        z.add_in("other.example", "x", Ipv4Addr::new(192, 168, 2, 9), Source::Static, ALL); // not local
        assert_eq!(a_of(&z, "router.home.arpa", ALL), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(a_of(&z, "router.iot.home.arpa", ALL), Some(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(a_of(&z, "boiler.iot.home.arpa", ALL), Some(Ipv4Addr::new(192, 168, 2, 82)));
        assert_eq!(a_of(&z, "pc.home.arpa", ALL), Some(Ipv4Addr::new(192, 168, 1, 100)));
        // Each name in its own domain only.
        assert!(matches!(z.lookup("boiler.home.arpa", TYPE_A, ALL), Lookup::NxDomain));
        assert!(matches!(z.lookup("pc.iot.home.arpa", TYPE_A, ALL), Lookup::NxDomain));
        assert!(matches!(z.lookup("iot.home.arpa", TYPE_A, ALL), Lookup::NoData));
        assert!(matches!(z.lookup("x.other.example", TYPE_A, ALL), Lookup::NotLocal));
        assert!(z.is_local_name("a.iot.home.arpa") && z.is_local_name("home.arpa"));
        assert!(!z.is_local_name("xhome.arpa") && !z.is_local_name("example.com"));
        let ptr = Zone::reverse_of(Ipv4Addr::new(192, 168, 2, 82));
        assert!(matches!(z.lookup(&ptr, TYPE_PTR, ALL), Lookup::Ptr(v) if v == ["boiler.iot.home.arpa"]));
        // Removal is per domain.
        z.add_in("iot.home.arpa", "pc", Ipv4Addr::new(192, 168, 2, 100), Source::Dhcp, ALL);
        z.remove_dhcp("pc", Ipv4Addr::new(192, 168, 2, 100)); // wrong domain: no effect
        assert_eq!(a_of(&z, "pc.iot.home.arpa", ALL), Some(Ipv4Addr::new(192, 168, 2, 100)));
        z.remove_dhcp_in("iot.home.arpa", "pc", Ipv4Addr::new(192, 168, 2, 100));
        assert!(matches!(z.lookup("pc.iot.home.arpa", TYPE_A, ALL), Lookup::NxDomain));
        assert_eq!(a_of(&z, "pc.home.arpa", ALL), Some(Ipv4Addr::new(192, 168, 1, 100)));
    }

    // ---- views (docs/dns-views.md) ----

    const LAN: View = View::network(0);
    const GUEST: View = View::network(1);
    const IOT: View = View::network(2);

    /// lan 192.168.1.0/24 (network 0), guest 192.168.20.0/24 (1), iot
    /// 192.168.2.0/24 (2), all in `lan`.
    fn three() -> Zone {
        let mut z = zone();
        z.add_subnet((Ipv4Addr::new(192, 168, 20, 1), 24));
        z.add_subnet((Ipv4Addr::new(192, 168, 2, 1), 24));
        z
    }

    #[test]
    fn view_hides_a_name_forward_and_reverse() {
        let mut z = three();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        z.add_in("lan", "laptop", ip, Source::Dhcp, LAN.union(IOT));
        assert_eq!(a_of(&z, "laptop.lan", LAN), Some(ip));
        assert_eq!(a_of(&z, "laptop.lan", IOT), Some(ip));
        assert!(matches!(z.lookup("laptop.lan", TYPE_A, GUEST), Lookup::Hidden));
        assert!(matches!(z.lookup("laptop.lan", TYPE_AAAA, GUEST), Lookup::Hidden));
        let ptr = Zone::reverse_of(ip);
        assert!(matches!(z.lookup(&ptr, TYPE_PTR, LAN), Lookup::Ptr(v) if v == ["laptop.lan"]));
        assert!(matches!(z.lookup(&ptr, TYPE_PTR, GUEST), Lookup::Hidden));
        // Unknown stays NXDOMAIN (not Hidden), for every view.
        assert!(matches!(z.lookup("ghost.lan", TYPE_A, GUEST), Lookup::NxDomain));
        let none = Zone::reverse_of(Ipv4Addr::new(192, 168, 1, 222));
        assert!(matches!(z.lookup(&none, TYPE_PTR, GUEST), Lookup::NxDomain));
        // The router's own lookups and ALL see it.
        assert_eq!(a_of(&z, "laptop.lan", View::ROUTER.union(LAN)), Some(ip));
        assert_eq!(a_of(&z, "laptop.lan", ALL), Some(ip));
        assert!(matches!(z.lookup("laptop.lan", TYPE_A, View::ROUTER), Lookup::Hidden));
        // `router.<domain>` is everyone's.
        assert!(a_of(&z, "router.lan", GUEST).is_some());
    }

    #[test]
    fn same_name_other_answer_per_view() {
        let mut z = three();
        let (a, b) = (Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(192, 168, 2, 10));
        z.add_in("lan", "srv", a, Source::Static, LAN);
        z.add_in("lan", "srv", b, Source::Static, IOT.union(GUEST));
        assert_eq!(a_of(&z, "srv.lan", LAN), Some(a));
        assert_eq!(a_of(&z, "srv.lan", IOT), Some(b));
        assert_eq!(a_of(&z, "srv.lan", GUEST), Some(b));
        // A newer static record takes over its networks only.
        let c = Ipv4Addr::new(192, 168, 2, 11);
        z.add_in("lan", "srv", c, Source::Static, IOT);
        assert_eq!(a_of(&z, "srv.lan", IOT), Some(c));
        assert_eq!(a_of(&z, "srv.lan", LAN), Some(a));
        assert_eq!(a_of(&z, "srv.lan", GUEST), Some(b));
        // Taking over every network of a record removes it.
        z.add_in("lan", "srv", a, Source::Static, LAN.union(GUEST));
        assert_eq!(a_of(&z, "srv.lan", GUEST), Some(a));
        assert!(!matches!(z.lookup(&Zone::reverse_of(b), TYPE_PTR, ALL), Lookup::Ptr(_)));
        // PTR per view.
        let ptr = Zone::reverse_of(c);
        assert!(matches!(z.lookup(&ptr, TYPE_PTR, IOT), Lookup::Ptr(v) if v == ["srv.lan"]));
        assert!(matches!(z.lookup(&ptr, TYPE_PTR, LAN), Lookup::Hidden));
    }

    #[test]
    fn static_wins_over_dhcp_only_within_its_view() {
        let mut z = three();
        let (st, dh) = (Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(192, 168, 1, 150));
        z.add_in("lan", "box", st, Source::Static, LAN);
        z.add_in("lan", "box", dh, Source::Dhcp, ALL);
        assert_eq!(a_of(&z, "box.lan", LAN), Some(st));
        assert_eq!(a_of(&z, "box.lan", IOT), Some(dh));
        // Order of adding does not matter.
        let mut y = three();
        y.add_in("lan", "box", dh, Source::Dhcp, ALL);
        y.add_in("lan", "box", st, Source::Static, LAN);
        assert_eq!(a_of(&y, "box.lan", LAN), Some(st));
        assert_eq!(a_of(&y, "box.lan", IOT), Some(dh));
        // The shadowed DHCP address has no PTR where the static one wins.
        let ptr = Zone::reverse_of(dh);
        assert!(matches!(y.lookup(&ptr, TYPE_PTR, LAN), Lookup::Hidden));
        assert!(matches!(y.lookup(&ptr, TYPE_PTR, IOT), Lookup::Ptr(_)));
        // Removing the lease leaves the static record.
        y.remove_dhcp_in("lan", "box", dh);
        assert_eq!(a_of(&y, "box.lan", LAN), Some(st));
        assert!(matches!(y.lookup("box.lan", TYPE_A, IOT), Lookup::Hidden));
    }

    #[test]
    fn dhcp_lease_in_two_networks_of_one_domain() {
        let mut z = three();
        let (a, b) = (Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 2, 50));
        z.add_in("lan", "phone", a, Source::Dhcp, LAN);
        z.add_in("lan", "phone", b, Source::Dhcp, IOT);
        assert_eq!(a_of(&z, "phone.lan", LAN), Some(a));
        assert_eq!(a_of(&z, "phone.lan", IOT), Some(b));
        z.remove_dhcp_in("lan", "phone", a);
        assert!(matches!(z.lookup("phone.lan", TYPE_A, LAN), Lookup::Hidden));
        assert_eq!(a_of(&z, "phone.lan", IOT), Some(b));
        z.remove_dhcp_in("lan", "phone", b);
        assert!(matches!(z.lookup("phone.lan", TYPE_A, IOT), Lookup::NxDomain));
    }

    #[test]
    fn override_of_a_public_name() {
        let mut z = three();
        let ip = Ipv4Addr::new(192, 168, 1, 200);
        z.add_override("Files.Example.com.", ip, LAN);
        assert_eq!(a_of(&z, "files.example.com", LAN), Some(ip));
        assert!(matches!(z.lookup("files.example.com", TYPE_AAAA, LAN), Lookup::NoData));
        // Others go upstream; exact name only; not a local name.
        assert!(matches!(z.lookup("files.example.com", TYPE_A, GUEST), Lookup::NotLocal));
        assert!(matches!(z.lookup("files.example.com", TYPE_AAAA, GUEST), Lookup::NotLocal));
        assert!(matches!(z.lookup("a.files.example.com", TYPE_A, LAN), Lookup::NotLocal));
        assert!(matches!(z.lookup("example.com", TYPE_A, LAN), Lookup::NotLocal));
        assert!(!z.is_local_name("files.example.com"));
        // Under a local domain it is not an override (use add_in).
        z.add_override("x.lan", ip, LAN);
        assert!(matches!(z.lookup("x.lan", TYPE_A, LAN), Lookup::NxDomain));
    }

    #[test]
    fn router_aaaa_and_ip6_arpa() {
        let mut z = zone();
        z.add_domain("guest.lan", Ipv4Addr::new(10, 20, 0, 1));
        let lan6: Ipv6Addr = "fd12:3456:789a::1".parse().unwrap();
        let guest6: Ipv6Addr = "fd12:3456:789a:1::1".parse().unwrap();
        z.add_router6("lan", lan6);
        z.add_router6("guest.lan", guest6);
        z.add_router6("lan", lan6); // twice: once
        assert!(matches!(z.lookup("router.lan", TYPE_AAAA, ALL), Lookup::Aaaa(v) if v == [lan6]));
        assert!(matches!(z.lookup("router.guest.lan", TYPE_AAAA, ALL), Lookup::Aaaa(v) if v == [guest6]));
        // A stays IPv4; other hosts have no AAAA.
        assert!(matches!(z.lookup("router.lan", TYPE_A, ALL), Lookup::A(_)));
        assert!(matches!(z.lookup("nas.lan", TYPE_AAAA, ALL), Lookup::NoData));
        let rev = |a: Ipv6Addr| {
            let mut n = String::new();
            for i in 0..32 {
                n.push_str(&format!("{:x}.", (u128::from(a) >> (4 * i)) & 0xf));
            }
            n + "ip6.arpa"
        };
        assert!(matches!(z.lookup(&rev(guest6), TYPE_PTR, ALL), Lookup::Ptr(v) if v == ["router.guest.lan"]));
        assert!(matches!(z.lookup(&rev(lan6), TYPE_AAAA, ALL), Lookup::NoData));
        // Other addresses in our /64s: NXDOMAIN; outside them: upstream.
        let host: Ipv6Addr = "fd12:3456:789a::99".parse().unwrap();
        assert!(matches!(z.lookup(&rev(host), TYPE_PTR, ALL), Lookup::NxDomain));
        let public: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(matches!(z.lookup(&rev(public), TYPE_PTR, ALL), Lookup::NotLocal));
        // Not 32 nibbles: not parsed as an address.
        assert!(matches!(z.lookup("a.8.9.7.ip6.arpa", TYPE_PTR, ALL), Lookup::NotLocal));
        assert!(matches!(z.lookup(&rev(lan6).replacen("1.", "x.", 1), TYPE_PTR, ALL), Lookup::NotLocal));
    }
}
