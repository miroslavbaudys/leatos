//! Cross-field checks of a parsed [`Config`].

use crate::{Config, VERSION, WanMode};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// Most reservations accepted (bounded work and memory in the DHCP server).
pub const MAX_STATICS: usize = 1024;
const MIN_LEASE_SECS: u32 = 60;
const MAX_LEASE_SECS: u32 = 30 * 86400;
const MIN_RATE_KBIT: u64 = 64;
const MAX_RATE_KBIT: u64 = 10_000_000;
const MAX_OVERHEAD: u32 = 256;
/// Highest usable 802.1Q VLAN ID (4095 is reserved, 0 means untagged).
pub const MAX_VLAN_ID: u16 = 4094;
/// Longest PPPoE user name, password, service or AC name.
pub const MAX_PPPOE_STRING: usize = 255;
/// Most SNTP servers accepted.
pub const MAX_NTP_SERVERS: usize = 4;

/// One problem: where (`lan.dhcp.static[2].ip`, list indices from 0) and
/// what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub path: String,
    pub msg: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.msg)
    }
}

struct Issues(Vec<Issue>);

impl Issues {
    fn add(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.0.push(Issue {
            path: path.into(),
            msg: msg.into(),
        });
    }
}

pub(crate) fn check(c: &Config) -> Result<(), Vec<Issue>> {
    let mut x = Issues(Vec::new());
    if c.version != VERSION {
        x.add("version", format!("must be {VERSION}"));
    }
    if let Some(v) = c.wan.vlan
        && !(1..=MAX_VLAN_ID).contains(&v)
    {
        x.add(
            "wan.vlan",
            format!("must be 1–{MAX_VLAN_ID} (omit it for an untagged WAN)"),
        );
    }
    if c.wan.vlan_pcp > 7 {
        x.add("wan.vlan_pcp", "must be 0–7");
    }
    pppoe(c, &mut x);
    lan(c, &mut x);
    if !(16..=65536).contains(&c.dns.cache_entries) {
        x.add("dns.cache_entries", "must be 16–65536");
    }
    let s = &c.shaping;
    for (name, rate) in [
        ("shaping.up_kbit", s.up_kbit),
        ("shaping.down_kbit", s.down_kbit),
    ] {
        if let Some(r) = rate
            && !(MIN_RATE_KBIT..=MAX_RATE_KBIT).contains(&r)
        {
            x.add(
                name,
                format!("must be {MIN_RATE_KBIT}–{MAX_RATE_KBIT} kbit/s (omit it to not shape)"),
            );
        }
    }
    if s.overhead > MAX_OVERHEAD {
        x.add(
            "shaping.overhead",
            format!("must be at most {MAX_OVERHEAD} bytes"),
        );
    }
    let ntp = &c.time.ntp_servers;
    if ntp.len() > MAX_NTP_SERVERS {
        x.add(
            "time.ntp_servers",
            format!("at most {MAX_NTP_SERVERS} servers"),
        );
    }
    for (i, n) in ntp.iter().enumerate() {
        if n.parse::<core::net::Ipv4Addr>().is_err() && !is_domain(n) {
            x.add(
                format!("time.ntp_servers[{i}]"),
                "must be a host name or an IPv4 address",
            );
        }
    }
    if x.0.is_empty() { Ok(()) } else { Err(x.0) }
}

fn pppoe(c: &Config, x: &mut Issues) {
    let p = &c.wan.pppoe;
    if c.wan.mode == WanMode::Pppoe && p.username.is_empty() {
        x.add("wan.pppoe.username", "required for wan.mode = \"pppoe\"");
    }
    let fields = [
        ("wan.pppoe.username", p.username.as_str()),
        ("wan.pppoe.password", p.password.as_deref().unwrap_or("")),
        ("wan.pppoe.service", p.service.as_str()),
        ("wan.pppoe.ac_name", p.ac_name.as_str()),
    ];
    for (path, v) in fields {
        // PAP carries them with one length byte.
        if v.len() > MAX_PPPOE_STRING {
            x.add(path, format!("at most {MAX_PPPOE_STRING} bytes"));
        }
        if v.chars().any(char::is_control) {
            x.add(path, "must not contain control characters");
        }
    }
    if !(1280..=1492).contains(&p.mtu) {
        x.add("wan.pppoe.mtu", "must be 1280–1492");
    }
    if p.lcp_echo_interval > 3600 {
        x.add("wan.pppoe.lcp_echo_interval", "must be 0–3600 seconds (0 = off)");
    }
    if !(1..=100).contains(&p.lcp_echo_failure) {
        x.add("wan.pppoe.lcp_echo_failure", "must be 1–100");
    }
}

fn lan(c: &Config, x: &mut Issues) {
    let net = c.lan.ipv4;
    if !(8..=29).contains(&net.prefix) {
        x.add("lan.ipv4", "prefix length must be 8–29");
        return; // the other LAN checks depend on a sane subnet
    }
    if !net.is_host(net.addr) {
        x.add(
            "lan.ipv4",
            format!(
                "{} is the network or broadcast address of {}/{}",
                net.addr,
                net.network(),
                net.prefix
            ),
        );
    }
    if !is_domain(&c.lan.domain) {
        x.add(
            "lan.domain",
            "must be a DNS name (letters, digits, '-', labels separated by '.')",
        );
    }

    let d = &c.lan.dhcp;
    let subnet = format!("{}/{}", net.network(), net.prefix);
    if let Some([lo, hi]) = d.range {
        for (i, ip) in [lo, hi].into_iter().enumerate() {
            if !net.is_host(ip) {
                x.add(
                    format!("lan.dhcp.range[{i}]"),
                    format!("{ip} is not a host address in {subnet}"),
                );
            }
        }
        if u32::from(lo) > u32::from(hi) {
            x.add("lan.dhcp.range", "first address is above the last");
        }
    }
    if !(MIN_LEASE_SECS..=MAX_LEASE_SECS).contains(&d.lease_secs) {
        x.add(
            "lan.dhcp.lease_secs",
            format!("must be {MIN_LEASE_SECS}–{MAX_LEASE_SECS}"),
        );
    }

    if d.statics.len() > MAX_STATICS {
        x.add(
            "lan.dhcp.static",
            format!("at most {MAX_STATICS} reservations"),
        );
    }
    let mut macs = BTreeMap::new();
    let mut ips = BTreeMap::new();
    let mut names = BTreeMap::new();
    for (i, s) in d.statics.iter().enumerate() {
        let p = |f: &str| format!("lan.dhcp.static[{i}].{f}");
        if s.mac.is_zero() || s.mac.is_multicast() {
            x.add(p("mac"), "must be a unicast MAC address");
        }
        if let Some(j) = macs.insert(s.mac, i) {
            x.add(
                p("mac"),
                format!("{} is already reserved in lan.dhcp.static[{j}]", s.mac),
            );
        }
        if !net.is_host(s.ip) {
            x.add(
                p("ip"),
                format!("{} is not a host address in {subnet}", s.ip),
            );
        } else if s.ip == net.addr {
            x.add(p("ip"), "is the router's own address");
        }
        if let Some(j) = ips.insert(s.ip, i) {
            x.add(
                p("ip"),
                format!("{} is already reserved in lan.dhcp.static[{j}]", s.ip),
            );
        }
        if let Some(h) = &s.hostname {
            if !is_label(h) {
                x.add(
                    p("hostname"),
                    "must be one DNS label (1–63 letters, digits or '-')",
                );
            }
            if let Some(j) = names.insert(h.to_ascii_lowercase().to_string(), i) {
                x.add(
                    p("hostname"),
                    format!("\"{h}\" is already used in lan.dhcp.static[{j}]"),
                );
            }
        }
    }
}

/// One DNS label: 1–63 ASCII letters, digits or `-`, not starting or
/// ending with `-`.
fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

fn is_domain(s: &str) -> bool {
    (1..=253).contains(&s.len()) && s.split('.').all(is_label)
}
