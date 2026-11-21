//! Cross-field checks of a parsed [`Config`] (docs/config-v2.md §4).
//!
//! Issue paths name list entries by their key when it is usable
//! (`network.guest.dhcp.range[0]`, `firewall.rule.ssh.dst_port`), else by
//! index (`network[2].name`); reservations by index
//! (`network.lan.dhcp.static[3].ip`).

use crate::{
    Cidr, Config, Network, Policy, Proto, Service, VERSION, WanMode, ZONE_WAN,
};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use crate::Cidr6;

/// Most reservations accepted, over all networks (bounded work and memory
/// in the DHCP servers).
pub const MAX_STATICS: usize = 1024;
pub const MAX_NETWORKS: usize = 16;
pub const MAX_ZONES: usize = 16;
pub const MAX_RULES: usize = 256;
pub const MAX_FORWARDS: usize = 128;
pub const MAX_REDIRECTS: usize = 32;
/// Static routes (each smoltcp interface holds the ones of its link, and
/// DHCP option 121 must fit one option: 16 × 9 bytes + the default).
pub const MAX_ROUTES: usize = 16;
pub const MAX_DNS_HOSTS: usize = 256;
/// `dns.upstreams` entries.
pub const MAX_DNS_UPSTREAMS: usize = 4;
/// `dns.tls_ca`: size and certificates.
pub const MAX_TLS_CA_LEN: usize = 16 * 1024;
pub const MAX_TLS_CAS: usize = 8;
pub const MAX_MDNS_RULES: usize = 32;
/// Most ports a network may be on.
pub const MAX_PORTS: usize = 8;
const MIN_LEASE_SECS: u32 = 60;
const MAX_LEASE_SECS: u32 = 30 * 86400;
const MIN_RATE_KBIT: u64 = 64;
const MAX_RATE_KBIT: u64 = 10_000_000;
const MAX_OVERHEAD: u32 = 256;
/// `shaping.queue_ms`: below one CoDel target's worth of bursts the queue
/// overflows on ordinary bursts; above a second it bounds nothing.
const MIN_QUEUE_MS: u32 = 10;
const MAX_QUEUE_MS: u32 = 1000;
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
    redirects(c, &mut x);
    routes(c, &mut x);
    dns(c, &mut x);
    mdns(c, &mut x);
    ipv6(c, &mut x);
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
    if s.queue_ms != 0 && !(MIN_QUEUE_MS..=MAX_QUEUE_MS).contains(&s.queue_ms) {
        x.add(
            "shaping.queue_ms",
            format!("must be {MIN_QUEUE_MS}–{MAX_QUEUE_MS} ms, or 0 for the fixed limit"),
        );
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
        if n.parse::<core::net::IpAddr>().is_err() && !is_domain(n) {
            x.add(
                format!("time.ntp_servers[{i}]"),
                "must be a host name or an IP address",
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

fn ipv6(c: &Config, x: &mut Issues) {
    if let Some(p) = c.ipv6.ula_prefix {
        let fc00 = u128::from(p.addr) >> 121 == 0x7e; // fc00::/7
        if p.prefix != 48 || !fc00 || p.addr != p.network() {
            x.add("ipv6.ula_prefix", "must be a unique local /48 such as fd12:3456:789a::/48");
        }
    }
    if c.networks.len() > 0xffff {
        x.add("ipv6", "too many networks for /64 subnets");
    }
    if !(48..=64).contains(&c.ipv6.prefix_hint) {
        x.add("ipv6.prefix_hint", "must be 48–64");
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
    // The user name is optional: some ISPs (O2 CZ on VLAN 848) ask for no
    // authentication at all.
    let p = &c.wan.pppoe;
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
    if !(1280..=1500).contains(&p.mtu) {
        x.add("wan.pppoe.mtu", "must be 1280–1500 (above 1492: RFC 4638, if the ISP and the modem carry it)");
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
        if n.domain.as_deref().is_some_and(|d| !is_domain(d)) {
            x.add(
                format!("{p}.domain"),
                "must be a DNS name (letters, digits, '-', labels separated by '.')",
            );
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
        for (f, n) in [("src", &r.src), ("dst", &r.dst)] {
            if let Some(n) = n
                && !n.is_network()
            {
                x.add(format!("{p}.{f}"), format!("host bits set: did you mean {}?", n.network_text()));
            }
        }
        let v4 = r.src.is_some_and(|n| n.v4().is_some()) || r.dst.is_some_and(|n| n.v4().is_some());
        let v6 = r.src.is_some_and(|n| n.v6().is_some()) || r.dst.is_some_and(|n| n.v6().is_some()) || r.dst_iid.is_some();
        if v4 && v6 {
            x.add(format!("{p}.dst"), "IPv4 and IPv6 addresses in one rule: make two rules");
        }
        if let Some(i) = r.dst_iid {
            let b = u128::from(i);
            if b >> 64 != 0 || b == 0 {
                x.add(format!("{p}.dst_iid"), "an interface identifier: the low 64 bits only, e.g. ::5054:ff:fe00:10");
            }
            if r.to == "router" {
                x.add(format!("{p}.dst_iid"), "not for rules to the router");
            }
        }
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
        target_ok(c, x, format!("{p}.to"), &fw.to, fw.wan_port.span());
        if fw.wan_port.hi >= ROUTER_PORTS {
            x.add(
                format!("{p}.wan_port"),
                format!("{ROUTER_PORTS}–65535 are the router's own (DNS, time)"),
            );
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

/// The target must be a host on one of the networks (not the router).
fn target_ok(c: &Config, x: &mut Issues, path: String, to: &crate::Target, span: u16) {
    match c.networks.iter().find(|n| n.ipv4.prefix <= 30 && n.ipv4.is_host(to.ip)) {
        None => x.add(path.clone(), format!("{} is in none of the networks", to.ip)),
        Some(n) if n.ipv4.addr == to.ip => x.add(path.clone(), "is the router's own address"),
        Some(_) => {}
    }
    if let Some(tp) = to.port
        && u32::from(tp) + u32::from(span) > 65535
    {
        x.add(path, "the port range would end above 65535");
    }
}

fn redirects(c: &Config, x: &mut Issues) {
    let r = &c.firewall.redirects;
    if r.len() > MAX_REDIRECTS {
        x.add("firewall.redirect", format!("at most {MAX_REDIRECTS} redirects"));
    }
    let paths = entry_paths("firewall.redirect", r.iter().map(|r| r.name.as_str()), 32);
    check_names(x, &paths, r.iter().map(|r| r.name.as_str()), 32, &[]);
    for (i, (rd, p)) in r.iter().zip(&paths).enumerate() {
        if rd.from == crate::ZONE_WAN {
            x.add(format!("{p}.from"), "redirects are for the networks, not the WAN");
        } else if rd.from != "any" && c.zone(&rd.from).is_none() {
            x.add(format!("{p}.from"), format!("no zone \"{}\" (or \"any\")", rd.from));
        }
        if !rd.proto.has_ports() {
            x.add(format!("{p}.proto"), "must be \"tcp\", \"udp\" or \"tcp+udp\"");
        }
        target_ok(c, x, format!("{p}.to"), &rd.to, rd.dst_port.span());
        for (j, other) in r.iter().enumerate().take(i) {
            let zones = rd.from == "any" || other.from == "any" || rd.from == other.from;
            if zones && rd.proto.overlaps(&other.proto) && rd.dst_port.overlaps(&other.dst_port) {
                x.add(format!("{p}.dst_port"), format!("overlaps {}", paths[j]));
            }
        }
    }
}

// ---- routes ----------------------------------------------------------------

fn routes(c: &Config, x: &mut Issues) {
    let r = &c.routes;
    if r.len() > MAX_ROUTES {
        x.add("route", format!("at most {MAX_ROUTES} routes"));
    }
    let paths = entry_paths("route", r.iter().map(|r| r.name.as_str()), 32);
    check_names(x, &paths, r.iter().map(|r| r.name.as_str()), 32, &[]);
    let mut subnets: Vec<(String, Cidr)> =
        c.networks.iter().zip(net_paths(c)).map(|(n, np)| (format!("{np}.ipv4"), n.ipv4)).collect();
    if let Some(s) = &c.wan.static_ip {
        subnets.push(("wan.static.ipv4".into(), s.ipv4));
    }
    for (i, (rt, p)) in r.iter().zip(&paths).enumerate() {
        let dp = format!("{p}.dst");
        let vp = format!("{p}.via");
        if let Some((dst6, via6)) = rt.v6() {
            route6(c, x, rt, (dst6, via6), (&dp, &vp));
            if let Some(j) = r[..i].iter().position(|o| o.dst == rt.dst) {
                x.add(&dp, format!("the same destination as {}", paths[j]));
            }
            continue;
        }
        let Some((dst, via)) = rt.v4() else {
            x.add(&vp, "of another address family than dst");
            continue;
        };
        if dst.prefix == 0 {
            x.add(&dp, "the default route is the WAN's");
        } else if !rt.dst.is_network() {
            x.add(&dp, format!("host bits set: did you mean {}?", rt.dst.network_text()));
        } else if let Some(why) = special(&dst) {
            x.add(&dp, format!("{} is {why}", subnet(&dst)));
        }
        // Inside a network's subnet: that stays connected. Around one is
        // fine (the subnet is the longer match).
        for (np, net) in &subnets {
            if inside(&dst, net) {
                x.add(&dp, format!("{} is inside {np} ({})", subnet(&dst), subnet(net)));
            }
        }
        if let Some(j) = r[..i].iter().position(|o| o.dst == rt.dst) {
            x.add(&dp, format!("the same destination as {}", paths[j]));
        }
        match c.route_via(rt) {
            crate::RouteVia::Network(n) => {
                if n.ipv4.addr == via {
                    x.add(&vp, "is the router's own address");
                } else if !n.ipv4.is_host(via) {
                    x.add(&vp, format!("is not a host address in {}", subnet(&n.ipv4)));
                }
            }
            // Only the WAN's (DHCP) subnet could hold it, and the route
            // would take that over.
            crate::RouteVia::Wan if dst.prefix > 0 && dst.contains(via) => {
                x.add(&vp, "is inside the destination itself");
            }
            crate::RouteVia::Wan => match (&c.wan.static_ip, c.wan.mode) {
                (_, WanMode::Pppoe) => x.add(
                    &vp,
                    format!("{via} is in none of the networks (a PPPoE WAN has no other routers)"),
                ),
                (Some(s), _) if !s.ipv4.is_host(via) || s.ipv4.addr == via => x.add(
                    &vp,
                    format!("must be a host in one of the networks or in the WAN's {}", subnet(&s.ipv4)),
                ),
                _ if special(&Cidr::new(via, 32)).is_some() || via.is_broadcast() => {
                    x.add(&vp, "must be a unicast address")
                }
                _ => {}
            },
        }
    }
}

/// An IPv6 route: a global or unique local destination outside the
/// networks' unique local /48's own /64s, through a host in a network's
/// unique local /64 (`<ula>:<i>::/64`: network `i`).
fn route6(c: &Config, x: &mut Issues, rt: &crate::Route, (dst, via): (Cidr6, Ipv6Addr), (dp, vp): (&str, &str)) {
    let first = dst.addr.segments()[0];
    if dst.prefix == 0 {
        x.add(dp, "the default route is the WAN's");
    } else if dst.addr != dst.network() {
        x.add(dp, format!("host bits set: did you mean {}/{}?", dst.network(), dst.prefix));
    } else if !(first & 0xe000 == 0x2000 || first & 0xfe00 == 0xfc00) {
        x.add(dp, "must be a global (2000::/3) or unique local (fc00::/7) prefix");
    }
    let s = via.segments();
    if s[0] & 0xfe00 != 0xfc00 {
        x.add(vp, "an IPv6 route's router must be in a network's unique local /64 (<ula>:<network index>::/64)");
    } else if !matches!(c.route_via(rt), crate::RouteVia::Network(_)) {
        x.add(vp, format!("no network {} (its unique local /64 has subnet id {:x})", s[3], s[3]));
    } else if let crate::RouteVia::Network(n) = c.route_via(rt)
        && !n.ipv6
    {
        x.add(vp, format!("network {} has IPv6 off", n.name));
    } else if u128::from(via) as u64 == 1 {
        x.add(vp, "is the router's own address");
    } else if let Some(u) = c.ipv6.ula_prefix
        && Cidr6::new(via, 48).network() != u.network()
    {
        x.add(vp, format!("not in ipv6.ula_prefix {u}"));
    }
}

/// Address ranges no route may point into.
fn special(c: &Cidr) -> Option<&'static str> {
    let ranges = [
        (Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 8), "\"this network\" (0.0.0.0/8)"),
        (Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8), "loopback"),
        (Cidr::new(Ipv4Addr::new(169, 254, 0, 0), 16), "link-local"),
        (Cidr::new(Ipv4Addr::new(224, 0, 0, 0), 3), "multicast or reserved"),
    ];
    ranges.into_iter().find(|(r, _)| inside(c, r)).map(|(_, w)| w)
}

/// `a` is `b` or a part of it.
fn inside(a: &Cidr, b: &Cidr) -> bool {
    a.prefix >= b.prefix && b.contains(a.network())
}

// ---- DNS -------------------------------------------------------------------

fn dns(c: &Config, x: &mut Issues) {
    let d = &c.dns;
    if !(16..=65536).contains(&d.cache_entries) {
        x.add("dns.cache_entries", "must be 16–65536");
    }
    if d.stale_secs > crate::MAX_STALE_SECS {
        x.add("dns.stale_secs", "must be 0 (off) to 604800 (a week)");
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
    upstreams(d, x);
    dns_hosts(c, x);
}

/// `[[dns.host]]` (docs/dns-views.md §5): names, networks, overlaps.
fn dns_hosts(c: &Config, x: &mut Issues) {
    use crate::HostName;
    let hosts = c.local_hosts();
    for (i, (h, l)) in c.dns.hosts.iter().zip(&hosts).enumerate() {
        let path = format!("dns.host[{i}]");
        let mut seen = BTreeSet::new();
        for (j, n) in h.networks.iter().enumerate() {
            if c.network(n).is_none() {
                x.add(format!("{path}.networks[{j}]"), format!("no network \"{n}\""));
            } else if !seen.insert(n) {
                x.add(format!("{path}.networks[{j}]"), format!("\"{n}\" is listed twice"));
            }
        }
        if !is_domain(&h.name) {
            x.add(format!("{path}.name"), "must be a DNS name");
            continue;
        }
        match &l.name {
            HostName::Local { domain, label } if label.is_empty() => {
                x.add(format!("{path}.name"), format!("\"{domain}\" is a local domain itself"));
                continue;
            }
            HostName::Override(n) if n.ends_with(".arpa") => {
                x.add(format!("{path}.name"), "reverse names are made from the records");
                continue;
            }
            HostName::Override(_) if h.networks.is_empty() => x.add(
                format!("{path}.networks"),
                "a name outside the local domains overrides a public name: list the networks that get it",
            ),
            _ => {}
        }
        // Each name once per network.
        let mask = |l: &crate::LocalHost| l.networks.unwrap_or(u32::MAX);
        if let Some(j) = hosts[..i].iter().position(|o| o.name == l.name && mask(o) & mask(l) != 0) {
            x.add(
                format!("{path}.name"),
                format!("\"{}\" is already in dns.host[{j}] for some of the same networks", h.name),
            );
        }
        // A reservation's hostname: only for some networks (they take it over).
        if let (HostName::Local { domain, label }, None) = (&l.name, l.networks)
            && let Some(n) = c.networks.iter().find(|n| {
                n.domain(&c.dns).eq_ignore_ascii_case(domain)
                    && n.dhcp.statics.iter().any(|s| s.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(label)))
            })
        {
            x.add(
                format!("{path}.name"),
                format!(
                    "\"{}\" is a reservation's hostname in network {}: list the networks this record is for",
                    h.name, n.name
                ),
            );
        }
    }
}

/// `dns.upstreams`, `dns.tls`, `dns.tls_ca`.
fn upstreams(d: &crate::Dns, x: &mut Issues) {
    if d.upstreams.len() > MAX_DNS_UPSTREAMS {
        x.add("dns.upstreams", format!("at most {MAX_DNS_UPSTREAMS} servers"));
    }
    let mut seen = BTreeMap::new();
    for (i, u) in d.upstreams.iter().enumerate() {
        let path = format!("dns.upstreams[{i}]");
        match crate::Upstream::parse(u) {
            Err(e) => x.add(path, e),
            Ok(up) => {
                if d.tls && up.name.is_none() {
                    x.add(
                        path,
                        format!("DNS over TLS needs the name on the server's certificate: \"{}#dns.example\"", up.ip),
                    );
                } else if let Some(j) = seen.insert((up.ip, up.port(d.tls)), i) {
                    x.add(path, format!("the same server as dns.upstreams[{j}]"));
                }
            }
        }
    }
    if d.tls && d.upstreams.is_empty() {
        x.add(
            "dns.upstreams",
            "DNS over TLS needs servers with their certificate names, e.g. \"1.1.1.1#cloudflare-dns.com\"",
        );
    }
    if let Some(pem) = &d.tls_ca {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;
        let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
        match certs {
            _ if pem.len() > MAX_TLS_CA_LEN => x.add("dns.tls_ca", format!("at most {MAX_TLS_CA_LEN} bytes")),
            Err(_) => x.add("dns.tls_ca", "must be PEM certificates (-----BEGIN CERTIFICATE-----)"),
            Ok(c) if c.is_empty() => x.add("dns.tls_ca", "no certificate in it (-----BEGIN CERTIFICATE-----)"),
            Ok(c) if c.len() > MAX_TLS_CAS => x.add("dns.tls_ca", format!("at most {MAX_TLS_CAS} certificates")),
            Ok(_) => {}
        }
    }
}

// ---- mDNS ------------------------------------------------------------------

fn mdns(c: &Config, x: &mut Issues) {
    let r = &c.mdns.reflect;
    if r.len() > MAX_MDNS_RULES {
        x.add("mdns.reflect", format!("at most {MAX_MDNS_RULES} entries"));
    }
    let paths = entry_paths("mdns.reflect", r.iter().map(|r| r.name.as_str()), 32);
    check_names(x, &paths, r.iter().map(|r| r.name.as_str()), 32, &[]);
    // A network takes part only if its zone lets mDNS reach the router.
    let zone_ok = |x: &mut Issues, path: String, net: &str| {
        let Some(n) = c.network(net) else {
            x.add(path, format!("no network \"{net}\""));
            return;
        };
        if let Some(z) = c.zone(&n.zone)
            && z.input != Policy::Accept
            && !z.allow.contains(&Service::Mdns)
        {
            x.add(path, format!("zone \"{}\" must allow \"mdns\" (zone.{}.allow)", z.name, z.name));
        }
    };
    let mut types = BTreeSet::new();
    for (e, p) in r.iter().zip(&paths) {
        zone_ok(x, format!("{p}.from"), &e.from);
        if e.to.is_empty() {
            x.add(format!("{p}.to"), "at least one network");
        }
        let mut seen = BTreeSet::new();
        for (i, t) in e.to.iter().enumerate() {
            let path = format!("{p}.to[{i}]");
            if *t == e.from {
                x.add(path, "the services are already on that network");
            } else if !seen.insert(t) {
                x.add(path, format!("\"{t}\" is listed twice"));
            } else {
                zone_ok(x, path, t);
            }
        }
        if e.services.is_empty() {
            x.add(format!("{p}.services"), "at least one service type, e.g. \"_ipp._tcp\"");
        }
        let mut seen = BTreeSet::new();
        for (i, s) in e.services.iter().enumerate() {
            let path = format!("{p}.services[{i}]");
            match proto_mdns::ServiceType::parse(s) {
                None => x.add(path, "must be a service type like \"_ipp._tcp\" or \"_sleep-proxy._udp\""),
                Some(t) => {
                    let t = t.to_string();
                    if !seen.insert(t.clone()) {
                        x.add(path, format!("\"{s}\" is listed twice"));
                    }
                    if e.enabled {
                        types.insert(t);
                    }
                }
            }
        }
    }
    if types.len() > proto_mdns::MAX_SERVICES {
        x.add("mdns.reflect", format!("at most {} service types in all", proto_mdns::MAX_SERVICES));
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

pub(crate) fn is_domain(s: &str) -> bool {
    (1..=253).contains(&s.len()) && s.split('.').all(is_label)
}
