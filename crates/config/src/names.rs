//! Local DNS names per network (docs/dns-views.md): which networks resolve
//! the names of which addresses ([`NameVisibility`]), and `[[dns.host]]`
//! resolved into a local domain + label or an override of a public name
//! ([`LocalHost`]).
//!
//! Network masks: bit `k` = `networks[k]` (config order; at most
//! [`crate::MAX_NETWORKS`]).

use crate::{Cidr, Config, DnsViews, Net, Rule, ZONE_WAN};
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

/// Who resolves the names of an address: built by
/// [`Config::name_visibility`], asked per address
/// ([`NameVisibility::seen_by`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameVisibility {
    /// `dns.views = "firewall"`; else everyone sees everything.
    firewall: bool,
    /// Every network.
    all: u32,
    /// The networks' subnets (owner = config index), then the subnets
    /// routed through a router on a network (owner = that network),
    /// longest first: the first match owns an address.
    subnets: Vec<(Cidr, usize)>,
    /// Per owner network: the networks that see its names through the
    /// zones (same zone, or `forward_to` its zone).
    by_zone: Vec<u32>,
    /// Accept rules: (networks they are from, networks they go to, `dst`).
    rules: Vec<(u32, u32, Option<Net>)>,
}

impl NameVisibility {
    /// Every network.
    pub fn all_networks(&self) -> u32 {
        self.all
    }

    /// The networks that resolve a name of `ip` (docs/dns-views.md §4):
    /// with `views = "firewall"`, those whose zone is the zone of `ip`'s
    /// network or may forward to it, or that an accept rule lets reach
    /// `ip`. An address outside every network is nobody's to hide: all.
    pub fn seen_by(&self, ip: Ipv4Addr) -> u32 {
        if !self.firewall {
            return self.all;
        }
        let Some(&(_, owner)) = self.subnets.iter().find(|(s, _)| s.contains(ip)) else {
            return self.all;
        };
        let bit = 1u32 << owner;
        self.rules
            .iter()
            .filter(|(_, to, dst)| to & bit != 0 && dst.is_none_or(|d| d.contains(ip)))
            .fold(self.by_zone[owner], |m, (from, _, _)| m | from)
    }
}

/// Where a `[[dns.host]]` name lives.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostName {
    /// `label` in the local domain `domain` (lowercase).
    Local { domain: String, label: String },
    /// An exact name outside the local domains (lowercase): an override
    /// of a public name.
    Override(String),
}

/// A `[[dns.host]]` entry, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalHost {
    pub name: HostName,
    pub ip: Ipv4Addr,
    /// The networks listed (mask); `None` = as [`NameVisibility`] decides.
    pub networks: Option<u32>,
}

/// `name` relative to `dns.domain` without a dot; with one, in the longest
/// local domain it ends in, else an override. A name that is a local
/// domain itself gets an empty label.
pub(crate) fn split_name(name: &str, default: &str, domains: &[String]) -> HostName {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !name.contains('.') {
        return HostName::Local {
            domain: default.into(),
            label: name,
        };
    }
    let under = |d: &&String| name == **d || name.strip_suffix(d.as_str()).is_some_and(|r| r.ends_with('.'));
    match domains.iter().filter(under).max_by_key(|d| d.len()) {
        Some(d) => HostName::Local {
            domain: d.clone(),
            label: name[..name.len() - d.len()].trim_end_matches('.').into(),
        },
        None => HostName::Override(name),
    }
}

impl Config {
    /// The local domains: `dns.domain` first, then the networks' own
    /// (lowercase, each once).
    pub fn local_domains(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let all = core::iter::once(self.dns.domain.as_str()).chain(self.networks.iter().map(|n| n.domain(&self.dns)));
        for d in all {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if !v.contains(&d) {
                v.push(d);
            }
        }
        v
    }

    /// The networks named in `names` as a mask (unknown names: no bit).
    pub(crate) fn network_mask(&self, names: &[String]) -> u32 {
        names
            .iter()
            .filter_map(|n| self.networks.iter().position(|m| m.name == *n))
            .fold(0, |m, k| m | 1 << k)
    }

    /// The networks in zone `zone`, or every network for `any`.
    fn zone_mask(&self, zone: &str) -> u32 {
        self.networks
            .iter()
            .enumerate()
            .filter(|(_, n)| zone == "any" || n.zone == zone)
            .fold(0, |m, (k, _)| m | 1 << k)
    }

    /// Who resolves which names (docs/dns-views.md §4).
    pub fn name_visibility(&self) -> NameVisibility {
        let all = self.zone_mask("any");
        let zone_sees = |viewer: &str, owner: &str| {
            viewer == owner || self.zone(viewer).is_some_and(|z| z.forward_to.iter().any(|t| t == owner))
        };
        let by_zone = self
            .networks
            .iter()
            .map(|o| {
                self.networks
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| zone_sees(&v.zone, &o.zone))
                    .fold(0, |m, (k, _)| m | 1 << k)
            })
            .collect();
        let accepts = |r: &&Rule| r.enabled && r.action == crate::Action::Accept && r.to != "router" && r.from != ZONE_WAN;
        let rules = self
            .firewall
            .rules
            .iter()
            .filter(accepts)
            // IPv6-only rules open no path to IPv4 addresses.
            .filter(|r| r.dst_iid.is_none() && !r.src.is_some_and(|n| n.v6().is_some()) && !r.dst.is_some_and(|n| n.v6().is_some()))
            .map(|r| (self.zone_mask(&r.from), self.zone_mask(&r.to), r.dst.and_then(|n| n.v4())))
            .filter(|(from, to, _)| *from != 0 && *to != 0)
            .collect();
        let mut subnets: Vec<(Cidr, usize)> = self.networks.iter().enumerate().map(|(k, n)| (n.ipv4, k)).collect();
        let mut routed: Vec<(Cidr, usize)> = self
            .routes
            .iter()
            .filter(|r| r.enabled)
            .filter_map(|r| match self.route_via(r) {
                crate::RouteVia::Network(n) => Some((r.dst.0, self.networks.iter().position(|m| m.name == n.name)?)),
                crate::RouteVia::Wan => None,
            })
            .collect();
        routed.sort_by_key(|(c, _)| core::cmp::Reverse(c.prefix));
        subnets.extend(routed);
        NameVisibility {
            firewall: self.dns.views == DnsViews::Firewall,
            all,
            subnets,
            by_zone,
            rules,
        }
    }

    /// `[[dns.host]]`, resolved (in order).
    pub fn local_hosts(&self) -> Vec<LocalHost> {
        let domains = self.local_domains();
        self.dns
            .hosts
            .iter()
            .map(|h| LocalHost {
                name: split_name(&h.name, &domains[0], &domains),
                ip: h.ip,
                networks: (!h.networks.is_empty()).then(|| self.network_mask(&h.networks)),
            })
            .collect()
    }
}
