//! Cross-field checks of a parsed [`Config`] (docs/config-v2.md §4).
//!
//! Issue paths name list entries by their key when it is usable
//! (`network.guest.dhcp.range[0]`, `firewall.rule.ssh.dst_port`), else by
//! index (`network[2].name`); reservations by index
//! (`network.lan.dhcp.static[3].ip`).

use crate::{
    Cidr, Config, Network, Policy, Proto, VERSION, WanMode, ZONE_WAN,
};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;

/// Most reservations accepted, over all networks (bounded work and memory
/// in the DHCP servers).
pub const MAX_STATICS: usize = 1024;
pub const MAX_NETWORKS: usize = 16;
pub const MAX_ZONES: usize = 16;
pub const MAX_RULES: usize = 256;
pub const MAX_FORWARDS: usize = 128;
pub const MAX_DNS_HOSTS: usize = 256;
/// Most ports a network may be on.
pub const MAX_PORTS: usize = 8;
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
/// The router's own client ports start here (`fwd`'s
/// `ROUTER_CLIENT_PORTS`): no port forward there.
pub const ROUTER_PORTS: u16 = 60_000;
/// Names that mean something else where zones are expected.
const RESERVED: [&str; 3] = ["wan", "router", "any"];

/// One problem: where (`network.lan.dhcp.static[2].ip`) and what.
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

/// A key: `[a-z][a-z0-9-]{0,max-1}`.
pub(crate) fn is_key(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    (1..=max).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Paths for the entries of a keyed list (`network`, `zone`, …): by key
/// where it is valid and unique, else by index.
fn entry_paths<'a>(list: &str, names: impl Iterator<Item = &'a str>, max: usize) -> Vec<String> {
    let names: Vec<&str> = names.collect();
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            if is_key(n, max) && names.iter().filter(|m| *m == n).count() == 1 {
                format!("{list}.{n}")
            } else {
                format!("{list}[{i}]")
            }
        })
        .collect()
}

/// Names must be keys, unique and not reserved.
fn check_names<'a>(
    x: &mut Issues,
    paths: &[String],
    names: impl Iterator<Item = &'a str>,
    max: usize,
    reserved: &[&str],
) {
    let mut seen = BTreeSet::new();
    for (p, n) in paths.iter().zip(names) {
        if !is_key(n, max) {
            x.add(
                format!("{p}.name"),
                format!("must be 1–{max} of a-z, 0-9, '-', starting with a letter"),
            );
        } else if reserved.contains(&n) {
            x.add(format!("{p}.name"), format!("\"{n}\" is reserved"));
        }
        if !seen.insert(n) {
            x.add(format!("{p}.name"), format!("\"{n}\" is used twice"));
        }
    }
}

pub(crate) fn check(c: &Config) -> Result<(), Vec<Issue>> {
    let mut x = Issues(Vec::new());
    if c.version != VERSION {
        x.add("version", format!("must be {VERSION}"));
    }
    wan(c, &mut x);
    mgmt(c, &mut x);
    networks(c, &mut x);
    zones(c, &mut x);
    rules(c, &mut x);
    forwards(c, &mut x);
    dns(c, &mut x);
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
        if n.parse::<Ipv4Addr>().is_err() && !is_domain(n) {
            x.add(
                format!("time.ntp_servers[{i}]"),
                "must be a host name or an IPv4 address",
            );
        }
    }
    if x.0.is_empty() { Ok(()) } else { Err(x.0) }
}

// ---- WAN -------------------------------------------------------------------

fn wan(c: &Config, x: &mut Issues) {
    let w = &c.wan;
    if !is_key(&w.port, 15) {
        x.add("wan.port", "must be a port name such as wan0");
    }
    if let Some(v) = w.vlan
        && !(1..=MAX_VLAN_ID).contains(&v)
    {
        x.add(
            "wan.vlan",
            format!("must be 1–{MAX_VLAN_ID} (omit it for an untagged WAN)"),
        );
    }
    if w.vlan_pcp > 7 {
        x.add("wan.vlan_pcp", "must be 0–7");
    }
    pppoe(c, x);
    match (&w.static_ip, w.mode) {
        (None, WanMode::Static) => x.add("wan.static", "required for wan.mode = \"static\""),
        (Some(s), _) => {
            if !(8..=30).contains(&s.ipv4.prefix) {
                x.add("wan.static.ipv4", "prefix length must be 8–30");
            } else {
                if !s.ipv4.is_host(s.ipv4.addr) {
                    x.add(
                        "wan.static.ipv4",
                        "is the network or broadcast address of its subnet",
                    );
                }
                if !s.ipv4.is_host(s.gateway) || s.gateway == s.ipv4.addr {
                    x.add(
                        "wan.static.gateway",
                        format!("must be another host in {}", subnet(&s.ipv4)),
                    );
                }
            }
            if s.dns.len() > MAX_NTP_SERVERS {
                x.add("wan.static.dns", format!("at most {MAX_NTP_SERVERS} servers"));
            }
        }
        _ => {}
    }
}

fn mgmt(c: &Config, x: &mut Issues) {
    let m = &c.mgmt;
    if let Some(h) = &m.password_hash
        && !h.is_empty()
        && !auth::is_hash(h)
    {
        x.add("mgmt.password_hash", "not a password hash (set mgmt.password instead)");
    }
    if let Some(p) = &m.password {
        if !(8..=128).contains(&p.chars().count()) {
            x.add("mgmt.password", "must be 8–128 characters");
        }
        if p.chars().any(char::is_control) {
            x.add("mgmt.password", "must not contain control characters");
        }
    }
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

// ---- networks --------------------------------------------------------------

fn subnet(c: &Cidr) -> String {
    format!("{}/{}", c.network(), c.prefix)
}

fn net_paths(c: &Config) -> Vec<String> {
    entry_paths("network", c.networks.iter().map(|n| n.name.as_str()), 15)
}

fn networks(c: &Config, x: &mut Issues) {
    let nets = &c.networks;
    if nets.is_empty() {
        x.add("network", "at least one network is needed");
        return;
    }
    if nets.len() > MAX_NETWORKS {
        x.add("network", format!("at most {MAX_NETWORKS} networks"));
    }
    let paths = net_paths(c);
    check_names(x, &paths, nets.iter().map(|n| n.name.as_str()), 15, &RESERVED);

    // Ports and VLANs: (port, vid) once; one untagged network per port.
    let mut on_port: BTreeMap<(&str, u16), usize> = BTreeMap::new();
    for (i, (n, p)) in nets.iter().zip(&paths).enumerate() {
        if n.vlan > MAX_VLAN_ID {
            x.add(format!("{p}.vlan"), format!("must be 0–{MAX_VLAN_ID} (0 = untagged)"));
        }
        if n.ports.is_empty() || n.ports.len() > MAX_PORTS {
            x.add(format!("{p}.ports"), format!("1–{MAX_PORTS} ports"));
        }
        let mut mine = BTreeSet::new();
        for (j, port) in n.ports.iter().enumerate() {
            let pp = format!("{p}.ports[{j}]");
            if !is_key(port, 15) {
                x.add(&pp, "must be a port name such as lan0");
                continue;
            }
            if *port == c.wan.port {
                x.add(&pp, format!("{port} is the WAN port"));
            }
            if !mine.insert(port.as_str()) {
                x.add(&pp, format!("{port} is listed twice"));
            }
            if let Some(k) = on_port.insert((port.as_str(), n.vlan), i).filter(|k| *k != i) {
                let what = if n.vlan == 0 {
                    String::from("untagged")
                } else {
                    format!("VLAN {}", n.vlan)
                };
                x.add(
                    &pp,
                    format!("{port} already carries {what} for {}", paths[k]),
                );
            }
        }
        if n.zone == ZONE_WAN {
            x.add(format!("{p}.zone"), "a network cannot be in the wan zone");
        } else if c.zone(&n.zone).is_none() {
            x.add(format!("{p}.zone"), format!("no zone \"{}\"", n.zone));
        }
        address(n, p, x);
    }

    // Subnets must not overlap each other or a static WAN.
    let mut subnets: Vec<(String, Cidr)> = nets
        .iter()
        .zip(&paths)
        .map(|(n, p)| (format!("{p}.ipv4"), n.ipv4))
        .collect();
    if let Some(s) = &c.wan.static_ip {
        subnets.push(("wan.static.ipv4".into(), s.ipv4));
    }
    for i in 0..subnets.len() {
        for j in i + 1..subnets.len() {
            let (a, b) = (&subnets[i].1, &subnets[j].1);
            let short = if a.prefix <= b.prefix { a } else { b };
            let other = if a.prefix <= b.prefix { b } else { a };
            if short.contains(other.network()) {
                x.add(
                    &subnets[j].0,
                    format!("{} overlaps {} ({})", subnet(b), subnets[i].0, subnet(a)),
                );
            }
        }
    }

    // Reservations: MACs unique over all networks, bounded in total.
    let total: usize = nets.iter().map(|n| n.dhcp.statics.len()).sum();
    if total > MAX_STATICS {
        x.add("network", format!("at most {MAX_STATICS} reservations in all"));
    }
    let mut macs = BTreeMap::new();
    for (n, p) in nets.iter().zip(&paths) {
        for (i, s) in n.dhcp.statics.iter().enumerate() {
            let sp = format!("{p}.dhcp.static[{i}]");
            if let Some(prev) = macs.insert(s.mac, sp.clone()) {
                x.add(
                    format!("{sp}.mac"),
                    format!("{} is already reserved in {prev}", s.mac),
                );
            }
        }
    }
}

/// One network's address and DHCP settings.
fn address(n: &Network, p: &str, x: &mut Issues) {
    let net = n.ipv4;
    if !(8..=29).contains(&net.prefix) {
        x.add(format!("{p}.ipv4"), "prefix length must be 8–29");
        return; // the other checks depend on a sane subnet
    }
    if !net.is_host(net.addr) {
        x.add(
            format!("{p}.ipv4"),
            format!(
                "{} is the network or broadcast address of {}",
                net.addr,
                subnet(&net)
            ),
        );
    }
    let d = &n.dhcp;
    let sub = subnet(&net);
    if let Some([lo, hi]) = d.range {
        for (i, ip) in [lo, hi].into_iter().enumerate() {
            if !net.is_host(ip) {
                x.add(
                    format!("{p}.dhcp.range[{i}]"),
                    format!("{ip} is not a host address in {sub}"),
                );
            }
        }
        if u32::from(lo) > u32::from(hi) {
            x.add(format!("{p}.dhcp.range"), "first address is above the last");
        }
    }
    if !(MIN_LEASE_SECS..=MAX_LEASE_SECS).contains(&d.lease_secs) {
        x.add(
            format!("{p}.dhcp.lease_secs"),
            format!("must be {MIN_LEASE_SECS}–{MAX_LEASE_SECS}"),
        );
    }
    let mut ips = BTreeMap::new();
    let mut names = BTreeMap::new();
    for (i, s) in d.statics.iter().enumerate() {
        let sp = format!("{p}.dhcp.static[{i}]");
        if s.mac.is_zero() || s.mac.is_multicast() {
            x.add(format!("{sp}.mac"), "must be a unicast MAC address");
        }
        if !net.is_host(s.ip) {
            x.add(
                format!("{sp}.ip"),
                format!("{} is not a host address in {sub}", s.ip),
            );
        } else if s.ip == net.addr {
            x.add(format!("{sp}.ip"), "is the router's own address");
        }
        if let Some(j) = ips.insert(s.ip, i) {
            x.add(
                format!("{sp}.ip"),
                format!("{} is already reserved in {p}.dhcp.static[{j}]", s.ip),
            );
        }
        if let Some(h) = &s.hostname {
            if !is_label(h) {
                x.add(
                    format!("{sp}.hostname"),
                    "must be one DNS label (1–63 letters, digits or '-')",
                );
            }
            if let Some(j) = names.insert(h.to_ascii_lowercase().to_string(), i) {
                x.add(
                    format!("{sp}.hostname"),
                    format!("\"{h}\" is already used in {p}.dhcp.static[{j}]"),
                );
            }
        }
    }
}

// ---- firewall --------------------------------------------------------------

fn zones(c: &Config, x: &mut Issues) {
    if c.zones.len() > MAX_ZONES {
        x.add("zone", format!("at most {MAX_ZONES} zones"));
    }
    let paths = entry_paths("zone", c.zones.iter().map(|z| z.name.as_str()), 15);
    check_names(x, &paths, c.zones.iter().map(|z| z.name.as_str()), 15, &RESERVED);
    for (z, p) in c.zones.iter().zip(&paths) {
        let mut seen = BTreeSet::new();
        for (i, t) in z.forward_to.iter().enumerate() {
            if *t == z.name {
                x.add(
                    format!("{p}.forward_to[{i}]"),
                    "networks of one zone always reach each other",
                );
            } else if c.zone(t).is_none() {
                x.add(format!("{p}.forward_to[{i}]"), format!("no zone \"{t}\""));
            }
            if !seen.insert(t) {
                x.add(format!("{p}.forward_to[{i}]"), format!("\"{t}\" is listed twice"));
            }
        }
        let mut seen = BTreeSet::new();
        for (i, s) in z.allow.iter().enumerate() {
            if !seen.insert(s) {
                x.add(format!("{p}.allow[{i}]"), "listed twice");
            }
        }
        if z.input == Policy::Accept && !z.allow.is_empty() {
            x.add(
                format!("{p}.allow"),
                "only with input = \"drop\" or \"reject\" (accept allows everything)",
            );
        }
    }
}

fn net_ok(x: &mut Issues, path: String, n: &Option<crate::Net>) {
    if let Some(n) = n
        && !n.is_network()
    {
        x.add(
            path,
            format!(
                "host bits set: did you mean {}/{}?",
                n.0.network(),
                n.0.prefix
            ),
        );
    }
}

fn rules(c: &Config, x: &mut Issues) {
    let r = &c.firewall.rules;
    if r.len() > MAX_RULES {
        x.add("firewall.rule", format!("at most {MAX_RULES} rules"));
    }
    let paths = entry_paths("firewall.rule", r.iter().map(|r| r.name.as_str()), 32);
    check_names(x, &paths, r.iter().map(|r| r.name.as_str()), 32, &[]);
    for (r, p) in r.iter().zip(&paths) {
        if r.from != "any" && c.zone(&r.from).is_none() {
            x.add(format!("{p}.from"), format!("no zone \"{}\" (or \"any\")", r.from));
        }
        if !matches!(r.to.as_str(), "any" | "router") && c.zone(&r.to).is_none() {
            x.add(
                format!("{p}.to"),
                format!("no zone \"{}\" (or \"router\", \"any\")", r.to),
            );
        }
        if r.dst_port.is_some() && !r.proto.has_ports() {
            x.add(
                format!("{p}.dst_port"),
                "needs proto = \"tcp\", \"udp\" or \"tcp+udp\"",
            );
        }
        net_ok(x, format!("{p}.src"), &r.src);
        net_ok(x, format!("{p}.dst"), &r.dst);
    }
}

fn forwards(c: &Config, x: &mut Issues) {
    let f = &c.firewall.forwards;
    if f.len() > MAX_FORWARDS {
        x.add("firewall.forward", format!("at most {MAX_FORWARDS} forwards"));
    }
    let paths = entry_paths("firewall.forward", f.iter().map(|f| f.name.as_str()), 32);
    check_names(x, &paths, f.iter().map(|f| f.name.as_str()), 32, &[]);
    for (i, (fw, p)) in f.iter().zip(&paths).enumerate() {
        if !fw.proto.has_ports() {
            x.add(format!("{p}.proto"), "must be \"tcp\", \"udp\" or \"tcp+udp\"");
        }
        match c.networks.iter().find(|n| n.ipv4.prefix <= 30 && n.ipv4.is_host(fw.to.ip)) {
            None => x.add(format!("{p}.to"), format!("{} is in none of the networks", fw.to.ip)),
            Some(n) if n.ipv4.addr == fw.to.ip => {
                x.add(format!("{p}.to"), "is the router's own address")
            }
            Some(_) => {}
        }
        if fw.wan_port.hi >= ROUTER_PORTS {
            x.add(
                format!("{p}.wan_port"),
                format!("{ROUTER_PORTS}–65535 are the router's own (DNS, time)"),
            );
        }
        if let Some(tp) = fw.to.port
            && u32::from(tp) + u32::from(fw.wan_port.span()) > 65535
        {
            x.add(format!("{p}.to"), "the port range would end above 65535");
        }
        net_ok(x, format!("{p}.src"), &fw.src);
        if c.mgmt.on_wan && fw.proto.overlaps(&Proto::Tcp) && fw.wan_port.contains(80) {
            x.add(
                format!("{p}.wan_port"),
                "80 is the web interface on the WAN (mgmt.on_wan)",
            );
        }
        for (j, other) in f.iter().enumerate().take(i) {
            if fw.proto.overlaps(&other.proto) && fw.wan_port.overlaps(&other.wan_port) {
                x.add(
                    format!("{p}.wan_port"),
                    format!("overlaps {}", paths[j]),
                );
            }
        }
    }
}

// ---- DNS -------------------------------------------------------------------

fn dns(c: &Config, x: &mut Issues) {
    let d = &c.dns;
    if !(16..=65536).contains(&d.cache_entries) {
        x.add("dns.cache_entries", "must be 16–65536");
    }
    if !is_domain(&d.domain) {
        x.add(
            "dns.domain",
            "must be a DNS name (letters, digits, '-', labels separated by '.')",
        );
    }
    if d.hosts.len() > MAX_DNS_HOSTS {
        x.add("dns.host", format!("at most {MAX_DNS_HOSTS} records"));
    }
    let mut seen = BTreeMap::new();
    for (i, h) in d.hosts.iter().enumerate() {
        if !is_domain(&h.name) {
            x.add(format!("dns.host[{i}].name"), "must be a DNS name");
        }
        if let Some(j) = seen.insert(h.name.to_ascii_lowercase(), i) {
            x.add(
                format!("dns.host[{i}].name"),
                format!("\"{}\" is already in dns.host[{j}]", h.name),
            );
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
