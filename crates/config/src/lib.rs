//! Router configuration (`docs/config-and-storage.md` §5,
//! `docs/config-v2.md`): the schema of `config.toml` with its defaults,
//! validation, and TOML in/out.
//!
//! - [`parse`]: text → checked [`Config`] (size limit, schema version,
//!   TOML, unknown fields, [`Config::validate`]). Version 1 documents
//!   (`[lan]`) are no longer read: they are refused with a hint.
//! - [`Config::to_toml`]: the canonical text (what the store holds)
//! - [`parse_json`], [`Config::to_json`]: the same schema as JSON, for the
//!   web interface
//! - [`Config::needs_trial`]: does a change need confirm-or-revert?
//! - [`Config::unsupported`]: settings the kernel does not implement yet
//! - [`Config::with_assignment`], [`Config::without`], [`diff_lines`]: one
//!   setting at a time (the serial CLI); list entries by name
//!   (`network.guest.vlan`)
//! - [`Config::default`]: what the router runs without a stored config
//!
//! Every section and most fields have a default, so a file may set only
//! what it changes. Unknown fields are errors (typos are reported, not
//! ignored).
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod edit;
mod names;
mod types;
mod validate;

pub use edit::{diff_lines, flat_lines};
pub use names::{HostName, LocalHost, NameVisibility};
pub use types::{Cidr, Mac, Net, PortRange, Target};
pub use validate::Issue;
pub use validate::{MAX_NETWORKS, MAX_VLAN_ID};

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

/// Schema version this crate reads and writes.
pub const VERSION: u32 = 2;
/// Largest `config.toml` accepted, checked before parsing.
pub const MAX_LEN: usize = 64 * 1024;
/// The built-in zones: the WAN, and the zone of networks that set none.
pub const ZONE_WAN: &str = "wan";
pub const ZONE_LAN: &str = "lan";
/// The default LAN port and WAN port names.
pub const PORT_LAN: &str = "lan0";
pub const PORT_WAN: &str = "wan0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Always [`VERSION`].
    pub version: u32,
    #[serde(skip_serializing_if = "Wan::is_default")]
    pub wan: Wan,
    /// The router's networks; the first is "the LAN" ([`Self::lan`]).
    #[serde(rename = "network")]
    pub networks: Vec<Network>,
    /// Firewall zones beyond the built-in `lan` and `wan`.
    #[serde(rename = "zone", skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<Zone>,
    #[serde(skip_serializing_if = "Firewall::is_empty")]
    pub firewall: Firewall,
    /// Static routes to subnets behind other routers.
    #[serde(rename = "route", skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
    pub dns: Dns,
    #[serde(skip_serializing_if = "Mdns::is_empty")]
    pub mdns: Mdns,
    pub shaping: Shaping,
    pub mgmt: Mgmt,
    pub time: Time,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: VERSION,
            wan: Wan::default(),
            networks: vec![Network::default()],
            zones: Vec::new(),
            firewall: Firewall::default(),
            routes: Vec::new(),
            dns: Dns::default(),
            mdns: Mdns::default(),
            shaping: Shaping::default(),
            mgmt: Mgmt::default(),
            time: Time::default(),
        }
    }
}

// ---- networks --------------------------------------------------------------

/// One routed network: a VLAN on some ports, the router's address in it,
/// its DHCP server and its firewall zone (docs/config-v2.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Key: `[a-z][a-z0-9-]{0,14}`.
    pub name: String,
    /// Physical ports it is on; more than one = bridged (later).
    #[serde(default = "lan_ports")]
    pub ports: Vec<String>,
    /// 802.1Q VLAN ID on its ports; 0 = untagged.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub vlan: u16,
    /// The router's address and the subnet.
    pub ipv4: Cidr,
    #[serde(default = "zone_lan")]
    pub zone: String,
    /// The DNS domain of this network's clients (`<hostname>.<domain>`,
    /// DHCP option 15); `None` = `dns.domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default)]
    pub dhcp: Dhcp,
}

fn lan_ports() -> Vec<String> {
    vec![PORT_LAN.into()]
}
fn zone_lan() -> String {
    ZONE_LAN.into()
}
fn is_zero(v: &u16) -> bool {
    *v == 0
}
/// `dns.stale_secs` by default: one day.
pub const DEFAULT_STALE_SECS: u32 = 86_400;
/// Upper bound of `dns.stale_secs`: a week (RFC 8767 suggests 1–3 days;
/// RRSIGs of stale answers may expire beyond).
pub const MAX_STALE_SECS: u32 = 604_800;
fn is_default_stale(v: &u32) -> bool {
    *v == DEFAULT_STALE_SECS
}
fn is_true(v: &bool) -> bool {
    *v
}
fn yes() -> bool {
    true
}

impl Default for Network {
    fn default() -> Self {
        Network {
            name: "lan".into(),
            ports: lan_ports(),
            vlan: 0,
            ipv4: Cidr::new(Ipv4Addr::new(192, 168, 1, 1), 24),
            zone: zone_lan(),
            domain: None,
            dhcp: Dhcp::default(),
        }
    }
}

impl Network {
    /// The network's DNS domain: its own, else `dns.domain`.
    pub fn domain<'a>(&'a self, dns: &'a Dns) -> &'a str {
        self.domain.as_deref().unwrap_or(&dns.domain)
    }

    /// The dynamic pool: `dhcp.range` if set, else hosts .100–.199 of the
    /// subnet (subnets with fewer than 200 hosts: all hosts but the last).
    pub fn dhcp_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        if let Some([lo, hi]) = self.dhcp.range {
            return (lo, hi);
        }
        let hosts = !self.ipv4.mask();
        let (lo, hi) = if hosts >= 200 {
            (100, 199)
        } else {
            (2, hosts.saturating_sub(1))
        };
        let last = u32::from(self.ipv4.broadcast()) - 1;
        let h = |n| Ipv4Addr::from(u32::from(self.ipv4.host(n)).min(last));
        (h(lo), h(hi))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dhcp {
    /// Serve DHCP on this network.
    #[serde(skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Inclusive dynamic range; unset = derived from the subnet
    /// ([`Network::dhcp_range`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<[Ipv4Addr; 2]>,
    pub lease_secs: u32,
    /// Reservations: always the same address for a MAC.
    #[serde(rename = "static", skip_serializing_if = "Vec::is_empty")]
    pub statics: Vec<StaticLease>,
}

impl Default for Dhcp {
    fn default() -> Self {
        Dhcp {
            enabled: true,
            range: None,
            lease_secs: 12 * 3600,
            statics: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLease {
    pub mac: Mac,
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

// ---- firewall --------------------------------------------------------------

/// What happens to traffic a zone sends to the router itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    #[default]
    Accept,
    Drop,
    /// TCP RST / ICMP port unreachable (rate-limited).
    Reject,
}

/// Router services a zone with `input = drop/reject` may still reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Service {
    Dhcp,
    Dns,
    Ntp,
    Ping,
    /// The web interface.
    Mgmt,
    /// mDNS (UDP 5353): networks of the zone take part in
    /// `[[mdns.reflect]]`.
    Mdns,
}

/// A firewall zone (docs/config-v2.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub name: String,
    #[serde(default)]
    pub input: Policy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Service>,
    /// Zones this zone may open new flows to (replies always pass).
    #[serde(default = "to_wan")]
    pub forward_to: Vec<String>,
}

fn to_wan() -> Vec<String> {
    vec![ZONE_WAN.into()]
}

impl Zone {
    /// Built-in `lan`: everything to the router, forwards to the WAN.
    pub fn builtin_lan() -> Zone {
        Zone {
            name: ZONE_LAN.into(),
            input: Policy::Accept,
            allow: Vec::new(),
            forward_to: to_wan(),
        }
    }

    /// Built-in `wan`: nothing new to the router or onwards (rules and
    /// forwards open it).
    pub fn builtin_wan() -> Zone {
        Zone {
            name: ZONE_WAN.into(),
            input: Policy::Drop,
            allow: Vec::new(),
            forward_to: Vec::new(),
        }
    }

    /// The web interface is reachable from this zone.
    pub fn reaches_mgmt(&self) -> bool {
        self.input == Policy::Accept || self.allow.contains(&Service::Mgmt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Proto {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "tcp+udp")]
    TcpUdp,
    #[serde(rename = "icmp")]
    Icmp,
    #[default]
    #[serde(rename = "any")]
    Any,
}

impl Proto {
    pub fn is_any(&self) -> bool {
        *self == Proto::Any
    }
    /// Has ports (TCP and/or UDP).
    pub fn has_ports(&self) -> bool {
        matches!(self, Proto::Tcp | Proto::Udp | Proto::TcpUdp)
    }
    fn tcp(&self) -> bool {
        matches!(self, Proto::Tcp | Proto::TcpUdp)
    }
    fn udp(&self) -> bool {
        matches!(self, Proto::Udp | Proto::TcpUdp)
    }
    /// Both match some packets (TCP/UDP overlap).
    pub fn overlaps(&self, o: &Proto) -> bool {
        (self.tcp() && o.tcp()) || (self.udp() && o.udp())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

fn proto_tcp() -> Proto {
    Proto::Tcp
}
fn is_tcp(p: &Proto) -> bool {
    *p == Proto::Tcp
}

/// An exception to the zone policy, checked in order for new flows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// A zone or `any`.
    pub from: String,
    /// A zone, `router` (traffic to the router itself) or `any`.
    pub to: String,
    #[serde(default, skip_serializing_if = "Proto::is_any")]
    pub proto: Proto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<Net>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<Net>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<PortRange>,
    pub action: Action,
}

/// Port forwarding (DNAT) from the WAN address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    #[serde(default = "proto_tcp", skip_serializing_if = "is_tcp")]
    pub proto: Proto,
    pub wan_port: PortRange,
    /// `ip` (same ports) or `ip:port` (a range maps onto port..).
    pub to: Target,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<Net>,
    /// Also from inside, via the WAN address.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub hairpin: bool,
}

fn proto_udp() -> Proto {
    Proto::Udp
}
fn is_udp(p: &Proto) -> bool {
    *p == Proto::Udp
}

/// A redirect (DNAT inside): new connections from the networks of zone
/// `from` to `dst_port` of an address outside them (the internet, or the
/// router itself) go to `to` instead; clients keep thinking they talk to
/// the server they chose. For devices with hard-coded servers (NTP, DNS).
/// The target's own connections and connections to it are left alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// A zone or `any` (every network; never the WAN).
    pub from: String,
    #[serde(default = "proto_udp", skip_serializing_if = "is_udp")]
    pub proto: Proto,
    pub dst_port: PortRange,
    /// `ip` (same ports) or `ip:port` (a range maps onto port..).
    pub to: Target,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Firewall {
    #[serde(rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(rename = "forward", skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<Forward>,
    #[serde(rename = "redirect", skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<Redirect>,
}

impl Firewall {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.forwards.is_empty() && self.redirects.is_empty()
    }
}

// ---- routes ----------------------------------------------------------------

/// A static route (docs/config-v2.md §3a): `dst` is reached through the
/// router `via`. A `via` inside a network makes it a route on that network
/// (its DHCP clients learn it through option 121 and go there directly);
/// otherwise `via` must be on the WAN's subnet (the route is used while
/// the WAN lease's subnet holds it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Destination subnet (host bits zero) or address.
    pub dst: Net,
    /// The next router.
    pub via: Ipv4Addr,
}

/// Where a [`Route`] leaves the router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteVia<'a> {
    /// A network: `via` is a host on it.
    Network(&'a Network),
    /// The WAN (a gateway next to the ISP's).
    Wan,
}

// ---- services --------------------------------------------------------------

/// mDNS across networks (docs/mdns.md).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mdns {
    #[serde(rename = "reflect", skip_serializing_if = "Vec::is_empty")]
    pub reflect: Vec<MdnsReflect>,
}

impl Mdns {
    pub fn is_empty(&self) -> bool {
        self.reflect.is_empty()
    }
}

/// Makes the services of one network discoverable on others: queries go
/// `to` → `from`, answers and announcements `from` → `to`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdnsReflect {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// The network the services are on.
    pub from: String,
    /// The networks they become discoverable on.
    pub to: Vec<String>,
    /// DNS-SD service types: `_ipp._tcp`, `_airplay._tcp`, …
    pub services: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub cache_entries: u32,
    /// Drop upstream answers that point into private ranges.
    pub rebind_protection: bool,
    /// Renew popular cache entries shortly before they expire (a hit in
    /// the last tenth of the TTL sends the query again in the background).
    #[serde(skip_serializing_if = "is_true")]
    pub prefetch: bool,
    /// Serve-stale (RFC 8767): keep expired answers this long (seconds) and
    /// give them, with TTL 30 s, when the upstream fails or takes over
    /// 1.8 s; 0 = off. Default one day, RFC 8767's lower bound.
    #[serde(skip_serializing_if = "is_default_stale")]
    pub stale_secs: u32,
    /// Local DNS zone of all networks: DHCP clients become
    /// `<hostname>.<domain>` (version 1: `lan.domain`).
    pub domain: String,
    /// Which networks resolve each other's local names
    /// (docs/dns-views.md): `all` (default) or by the `firewall`.
    #[serde(skip_serializing_if = "DnsViews::is_all")]
    pub views: DnsViews,
    /// Local A records beside the DHCP names, and overrides of public
    /// names for some networks.
    #[serde(rename = "host", skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<DnsHost>,
    /// Upstream resolvers instead of the WAN lease's, in order of
    /// preference ([`Upstream`]): `ip`, `ip:port`, and with the name its
    /// certificate must carry (DNS over TLS) `ip#name`, `ip:port#name`.
    /// Empty = the servers from the WAN lease (DHCP or PPPoE).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
    /// Strict DNS over TLS (RFC 7858, RFC 8310 strict profile): every
    /// upstream query goes through TLS to `upstreams` (port 853 unless
    /// given), whose certificates must chain to Mozilla's roots (or
    /// `tls_ca`) and carry the `#name`. Never plain DNS, also not when
    /// TLS fails: clients then get SERVFAIL.
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub tls: bool,
    /// Extra trust anchors in PEM, beside Mozilla's (a private DNS-over-TLS
    /// server with its own CA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<String>,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            cache_entries: 4096,
            rebind_protection: true,
            prefetch: true,
            stale_secs: DEFAULT_STALE_SECS,
            domain: "lan".into(),
            views: DnsViews::All,
            hosts: Vec::new(),
            upstreams: Vec::new(),
            tls: false,
            tls_ca: None,
        }
    }
}

/// One entry of `dns.upstreams`: `ip[:port][#name]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub ip: Ipv4Addr,
    /// Unset: 53, or 853 for DNS over TLS.
    pub port: Option<u16>,
    /// The name the server's certificate must carry: a host name, or the
    /// address itself (some resolvers have IP certificates).
    pub name: Option<String>,
}

impl Upstream {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let (addr, name) = match s.split_once('#') {
            Some((a, n)) => (a, Some(n)),
            None => (s, None),
        };
        let (ip, port) = match addr.split_once(':') {
            Some((ip, p)) => (ip, Some(p.parse::<u16>().ok().filter(|&p| p != 0).ok_or("port must be 1–65535")?)),
            None => (addr, None),
        };
        let ip: Ipv4Addr = ip.parse().map_err(|_| "must be an IPv4 address, e.g. 1.1.1.1 or 1.1.1.1#cloudflare-dns.com")?;
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
            return Err("not a server address");
        }
        let name = match name {
            None => None,
            Some(n) if n.parse::<Ipv4Addr>().is_ok() || validate::is_domain(n) => Some(n.to_ascii_lowercase()),
            Some(_) => return Err("the name after '#' must be a DNS name (the server's certificate name)"),
        };
        Ok(Upstream { ip, port, name })
    }

    /// The port in use: given, else 853 with TLS, 53 without.
    pub fn port(&self, tls: bool) -> u16 {
        self.port.unwrap_or(if tls { 853 } else { 53 })
    }
}

impl core::fmt::Display for Upstream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.ip)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        if let Some(n) = &self.name {
            write!(f, "#{n}")?;
        }
        Ok(())
    }
}

impl Dns {
    /// `upstreams`, parsed (validated configs parse completely).
    pub fn upstream_list(&self) -> Vec<Upstream> {
        self.upstreams.iter().filter_map(|u| Upstream::parse(u).ok()).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsHost {
    /// A label (in `dns.domain`), a name in a local domain
    /// (`nas.iot.home.arpa`), or a public name to override
    /// (`files.example.com`, needs `networks`).
    pub name: String,
    pub ip: Ipv4Addr,
    /// The networks that get this answer; empty = as `dns.views` decides
    /// for the address (docs/dns-views.md).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<String>,
}

/// `dns.views` (docs/dns-views.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsViews {
    /// Every network resolves every local name (before views).
    #[default]
    All,
    /// A network resolves the names of the networks its zone reaches
    /// (same zone, `forward_to`, accept rules to the address).
    Firewall,
}

impl DnsViews {
    pub fn is_all(&self) -> bool {
        *self == DnsViews::All
    }
}

/// Egress AQM (`docs/bufferbloat-cake.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Qdisc {
    #[default]
    #[serde(rename = "cake")]
    Cake,
    #[serde(rename = "fq_codel")]
    FqCodel,
    /// FQ-CoDel with one queue.
    #[serde(rename = "codel")]
    Codel,
}

/// CAKE's flow and host fairness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Isolation {
    #[default]
    #[serde(rename = "triple-isolate")]
    Triple,
    #[serde(rename = "dual-srchost")]
    DualSrcHost,
    #[serde(rename = "dual-dsthost")]
    DualDstHost,
    #[serde(rename = "flows")]
    Flows,
}

/// Shaping and AQM; the same settings as the boot arguments `shape_up=`,
/// `shape_down=`, `shape_overhead=`, `ecn_up=`, `ecn_down=`, `qdisc=`,
/// `isolation=`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Shaping {
    /// WAN egress rate in kbit/s; unset = not shaped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_kbit: Option<u64>,
    /// LAN egress (download) rate in kbit/s; unset = not shaped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_kbit: Option<u64>,
    /// Per-packet link overhead in bytes.
    pub overhead: u32,
    /// ECN marking instead of dropping. Default: off for upload, on for
    /// download (see `kernel/src/config.rs`).
    pub ecn_up: bool,
    pub ecn_down: bool,
    pub qdisc: Qdisc,
    pub isolation: Isolation,
}

impl Default for Shaping {
    fn default() -> Self {
        Shaping {
            up_kbit: None,
            down_kbit: None,
            overhead: 0,
            ecn_up: false,
            ecn_down: true,
            qdisc: Qdisc::Cake,
            isolation: Isolation::Triple,
        }
    }
}

// ---- WAN -------------------------------------------------------------------

/// The WAN link. Same settings as the boot arguments `wan_vlan=`,
/// `wan_pcp=`, `wan_mode=`, `pppoe_user=`, `pppoe_pass=`, … Fields at
/// their defaults are left out of the canonical form, so a config that
/// does not use them stays readable by older kernels (rollback).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Wan {
    /// The physical port.
    #[serde(skip_serializing_if = "is_wan0")]
    pub port: String,
    /// 802.1Q VLAN ID (1–4094) the ISP expects on the WAN; unset =
    /// untagged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// Priority (PCP, 0–7) in the tag of frames sent on the WAN VLAN.
    pub vlan_pcp: u8,
    /// How the WAN gets its address.
    #[serde(skip_serializing_if = "WanMode::is_dhcp")]
    pub mode: WanMode,
    #[serde(skip_serializing_if = "Pppoe::is_default")]
    pub pppoe: Pppoe,
    /// `mode = "static"`.
    #[serde(rename = "static", skip_serializing_if = "Option::is_none")]
    pub static_ip: Option<WanStatic>,
}

fn is_wan0(p: &str) -> bool {
    p == PORT_WAN
}

impl Default for Wan {
    fn default() -> Self {
        Wan {
            port: PORT_WAN.into(),
            vlan: None,
            vlan_pcp: 0,
            mode: WanMode::Dhcp,
            pppoe: Pppoe::default(),
            static_ip: None,
        }
    }
}

impl Wan {
    pub fn is_default(&self) -> bool {
        *self == Wan::default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WanMode {
    /// DHCPv4 client on the WAN Ethernet.
    #[default]
    #[serde(rename = "dhcp")]
    Dhcp,
    /// PPPoE session (`[wan.pppoe]`); DHCP is not used.
    #[serde(rename = "pppoe")]
    Pppoe,
    /// Fixed address (`[wan.static]`).
    #[serde(rename = "static")]
    Static,
}

impl WanMode {
    pub fn is_dhcp(&self) -> bool {
        *self == WanMode::Dhcp
    }
}

/// A fixed WAN address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WanStatic {
    pub ipv4: Cidr,
    pub gateway: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
}

/// PPPoE credentials and link settings (`wan.mode = "pppoe"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pppoe {
    pub username: String,
    /// A secret: stored in clear (PAP and CHAP need it), but left out of
    /// what the web interface and the CLI show ([`Config::without_secrets`]);
    /// a save without it keeps the current one ([`Config::keep_secrets`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Service-Name to ask the access concentrator for; empty = any.
    pub service: String,
    /// Only use the access concentrator with this name; empty = the first
    /// that answers.
    pub ac_name: String,
    /// MRU asked for and largest IP packet sent (1280–1492).
    pub mtu: u16,
    /// Seconds between LCP echo requests (0 = no keepalive).
    pub lcp_echo_interval: u32,
    /// Unanswered echo requests before the session is restarted.
    pub lcp_echo_failure: u32,
}

impl Default for Pppoe {
    fn default() -> Self {
        Pppoe {
            username: String::new(),
            password: None,
            service: String::new(),
            ac_name: String::new(),
            mtu: 1492,
            lcp_echo_interval: 10,
            lcp_echo_failure: 5,
        }
    }
}

impl Pppoe {
    pub fn is_default(&self) -> bool {
        *self == Pppoe::default()
    }
}

// ---- system ----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mgmt {
    /// Also serve the web interface on the WAN. Development only.
    pub on_wan: bool,
    /// The web interface's password (user `admin`) as a PBKDF2-SHA256
    /// hash (`auth::hash_password`). A secret like the PPPoE password:
    /// never shown, kept when a save leaves it out, an empty string
    /// removes it. The boot argument `mgmt_pass=` wins over it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// A new password in clear, only on the way in (the web form, the
    /// CLI): the kernel replaces it with `password_hash` before the config
    /// is stored or used ([`Config::hash_new_password`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// The wall clock: SNTP servers, asked over the WAN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Time {
    /// Host names (resolved through the router's DNS forwarder) or IPv4
    /// addresses, in order of preference; empty = no SNTP. Same as the
    /// boot argument `ntp=a,b`.
    pub ntp_servers: Vec<String>,
}

impl Default for Time {
    fn default() -> Self {
        Time {
            ntp_servers: alloc::vec!["pool.ntp.org".into()],
        }
    }
}

// ---- parsing ---------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge {
        len: usize,
    },
    /// Not TOML, a wrong type or an unknown field: the parser's message,
    /// with line and column.
    Syntax(String),
    /// Written by a newer rrouter.
    NewerVersion(u32),
    /// An older schema this rrouter no longer reads (version 1: `[lan]`).
    OldVersion(u32),
    /// Parsed, but the settings are inconsistent (or, from
    /// [`Config::unsupported`], not implemented yet).
    Invalid(Vec<Issue>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge { len } => {
                write!(f, "config is {len} bytes, at most {MAX_LEN} allowed")
            }
            Error::Syntax(m) => f.write_str(m.trim_end()),
            Error::NewerVersion(v) => {
                write!(
                    f,
                    "config version {v} is newer than this rrouter supports ({VERSION})"
                )
            }
            Error::OldVersion(v) => {
                write!(
                    f,
                    "config version {v} is no longer supported (version {VERSION} needed): \
                     write [lan] as [[network]] with name = \"lan\", lan.domain as dns.domain \
                     (docs/config-v2.md)"
                )
            }
            Error::Invalid(issues) => {
                for (i, x) in issues.iter().enumerate() {
                    if i > 0 {
                        f.write_str("\n")?;
                    }
                    write!(f, "{x}")?;
                }
                Ok(())
            }
        }
    }
}

/// The `version` field and whether there is a `[lan]`, ignoring
/// everything else: a document without a version is the current one,
/// unless it has version 1's `[lan]`.
#[derive(Deserialize)]
struct VersionOnly {
    version: Option<u32>,
    lan: Option<serde::de::IgnoredAny>,
}

impl VersionOnly {
    fn check(&self) -> Result<(), Error> {
        match self.version {
            None if self.lan.is_some() => Err(Error::OldVersion(1)),
            None | Some(VERSION) => Ok(()),
            Some(v) if v > VERSION => Err(Error::NewerVersion(v)),
            Some(v) if v >= 1 => Err(Error::OldVersion(v)),
            Some(_) => Err(Error::Invalid(vec![Issue {
                path: "version".into(),
                msg: alloc::format!("must be {VERSION}"),
            }])),
        }
    }
}

/// `config.toml` → a checked [`Config`].
pub fn parse(text: &str) -> Result<Config, Error> {
    if text.len() > MAX_LEN {
        return Err(Error::TooLarge { len: text.len() });
    }
    let syntax = |e: toml::de::Error| Error::Syntax(e.to_string());
    toml::from_str::<VersionOnly>(text).map_err(syntax)?.check()?;
    let c = toml::from_str::<Config>(text).map_err(syntax)?;
    c.validate().map_err(Error::Invalid)?;
    Ok(c)
}

/// JSON (the web interface's form) → a checked [`Config`]: the same
/// schema, defaults and checks as [`parse`].
pub fn parse_json(text: &str) -> Result<Config, Error> {
    if text.len() > MAX_LEN {
        return Err(Error::TooLarge { len: text.len() });
    }
    let syntax = |e: serde_json::Error| Error::Syntax(e.to_string());
    serde_json::from_str::<VersionOnly>(text).map_err(syntax)?.check()?;
    let c = serde_json::from_str::<Config>(text).map_err(syntax)?;
    c.validate().map_err(Error::Invalid)?;
    Ok(c)
}

impl Config {
    /// The canonical `config.toml`.
    pub fn to_toml(&self) -> String {
        // Serialisation fails only for types TOML cannot express; the
        // schema has none (tested).
        toml::to_string(self).unwrap_or_default()
    }

    /// The config as JSON (the web interface's shape).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Settings this kernel does not implement yet (docs/config-v2.md §9):
    /// a save or a stored config with them is refused. Implemented:
    /// networks on `lan0` (untagged or VLANs), zones, DHCP per network,
    /// rules, port forwards, redirects, mDNS reflection, DNS hosts and
    /// views, a static WAN. Not yet: other ports (bridging), another WAN
    /// port.
    pub fn unsupported(&self) -> Vec<Issue> {
        let mut out = Vec::new();
        let mut add = |path: String, what: &str| {
            out.push(Issue {
                path,
                msg: alloc::format!("{what}: not supported by this kernel yet"),
            })
        };
        for n in &self.networks {
            if n.ports.len() != 1 || n.ports[0] != PORT_LAN {
                add(alloc::format!("network.{}.ports", n.name), "ports other than lan0");
            }
        }
        if self.wan.port != PORT_WAN {
            add("wan.port".into(), "a WAN port other than wan0");
        }
        out
    }

    /// Applied by rebooting into the saved config: which physical ports
    /// the networks use (the port layout is built at boot). Networks
    /// themselves (added, removed, VLAN, address, zone), zones, DHCP and
    /// everything else apply live (docs/config-v2.md §7).
    pub fn needs_reboot(&self, old: &Config) -> bool {
        let ports = |c: &Config| -> Vec<(String, Vec<String>)> {
            c.networks.iter().map(|n| (n.name.clone(), n.ports.clone())).collect()
        };
        let mut a = ports(self);
        let mut b = ports(old);
        // A network added or removed on lan0 changes nothing at boot.
        a.retain(|(_, p)| p.len() != 1 || p[0] != PORT_LAN);
        b.retain(|(_, p)| p.len() != 1 || p[0] != PORT_LAN);
        a != b
    }

    /// The first network ("the LAN"), where boot argument `lan=`
    /// applies. `None` only for an unchecked config without networks.
    pub fn lan(&self) -> Option<&Network> {
        self.networks.first()
    }

    pub fn network(&self, name: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.name == name)
    }

    /// Where a route leaves: the network whose subnet holds `via`, else
    /// the WAN.
    pub fn route_via(&self, r: &Route) -> RouteVia<'_> {
        match self.networks.iter().find(|n| n.ipv4.contains(r.via)) {
            Some(n) => RouteVia::Network(n),
            None => RouteVia::Wan,
        }
    }

    /// The enabled routes through a router on network `net`, as DHCP
    /// option 121 sends them: (subnet, prefix length, router).
    pub fn network_routes(&self, net: &str) -> Vec<(Ipv4Addr, u8, Ipv4Addr)> {
        self.routes
            .iter()
            .filter(|r| r.enabled && matches!(self.route_via(r), RouteVia::Network(n) if n.name == net))
            .map(|r| (r.dst.0.network(), r.dst.0.prefix, r.via))
            .collect()
    }

    /// A zone's policy, built-in ones included.
    pub fn zone(&self, name: &str) -> Option<Zone> {
        if name == ZONE_WAN {
            return Some(Zone::builtin_wan());
        }
        match self.zones.iter().find(|z| z.name == name) {
            Some(z) => Some(z.clone()),
            None if name == ZONE_LAN => Some(Zone::builtin_lan()),
            None => None,
        }
    }

    /// Networks the web interface is reachable from.
    fn mgmt_networks(&self) -> impl Iterator<Item = &Network> {
        self.networks
            .iter()
            .filter(|n| self.zone(&n.zone).is_some_and(|z| z.reaches_mgmt()))
    }

    /// Changing from `old` to `self` could cut the user off from the web
    /// interface: a network it is reachable from changes address, VLAN,
    /// ports or zone (or goes away), such a zone's input policy changes,
    /// rules for traffic to the router change, management settings
    /// change, or the WAN changes while the interface is served on it.
    /// Such a save boots as a trial that must be confirmed
    /// (docs/config-and-storage.md §6, docs/config-v2.md §7).
    pub fn needs_trial(&self, old: &Config) -> bool {
        let link = |n: &Network| (n.ipv4, n.vlan, n.ports.clone(), n.zone.clone());
        // Only the networks the user may be connected through now: a new
        // network cannot cut anyone off.
        let nets = old
            .mgmt_networks()
            .any(|n| Some(link(n)) != self.network(&n.name).map(link));
        let zones = old
            .mgmt_networks()
            .any(|n| old.zone(&n.zone) != self.zone(&n.zone));
        let to_router = |c: &Config| -> Vec<Rule> {
            c.firewall
                .rules
                .iter()
                .filter(|r| r.to == "router" || r.to == "any")
                .cloned()
                .collect()
        };
        nets || zones
            || to_router(self) != to_router(old)
            || self.mgmt.on_wan != old.mgmt.on_wan
            || (self.wan != old.wan && (self.mgmt.on_wan || old.mgmt.on_wan))
    }

    /// This config without secrets (the PPPoE password): what the web
    /// interface and the CLI show and export.
    pub fn without_secrets(&self) -> Config {
        let mut c = self.clone();
        c.wan.pppoe.password = None;
        c.mgmt.password_hash = None;
        c.mgmt.password = None;
        c
    }

    /// A new password in clear (`mgmt.password`) becomes `password_hash`
    /// (fresh salt from `pool`); an empty `password_hash` means none.
    /// Returns whether the password changed (sessions should end).
    pub fn hash_new_password(&mut self, pool: &mut auth::Pool) -> bool {
        let m = &mut self.mgmt;
        if m.password_hash.as_deref() == Some("") {
            m.password_hash = None;
        }
        match m.password.take() {
            Some(p) => {
                m.password_hash = Some(auth::hash_password(&p, pool, auth::ITERATIONS));
                true
            }
            None => false,
        }
    }

    /// A submitted config left secrets out (it came from
    /// [`Self::without_secrets`]): keep `current`'s. An empty string
    /// clears one.
    pub fn keep_secrets(&mut self, current: &Config) {
        if self.wan.pppoe.password.is_none() {
            self.wan.pppoe.password = current.wan.pppoe.password.clone();
        }
        if self.mgmt.password_hash.is_none() {
            self.mgmt.password_hash = current.mgmt.password_hash.clone();
        }
    }

    /// Cross-field checks; every problem found, not just the first.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        validate::check(self)
    }
}

#[cfg(test)]
mod tests;
