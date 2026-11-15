//! Router configuration (`docs/config-and-storage.md` §5,
//! `docs/config-v2.md`): the schema of `config.toml` with its defaults,
//! validation, and TOML in/out.
//!
//! - [`parse`]: text → checked [`Config`] (size limit, schema version,
//!   TOML, unknown fields, [`Config::validate`]). Version 1 documents
//!   (`[lan]`) are migrated on load ([`v1`]).
//! - [`Config::to_toml`]: the canonical text (what the store holds). It is
//!   written as version 1 while the config fits it, so a kernel that only
//!   reads version 1 (after a rollback) still finds its LAN.
//! - [`parse_json`], [`Config::to_json`]: the same schema as JSON (always
//!   version 2), for the web interface
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
mod types;
pub mod v1;
mod validate;

pub use edit::{diff_lines, flat_lines};
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
    /// Always [`VERSION`] in memory; [`Self::to_toml`] picks what it writes.
    pub version: u32,
    #[serde(skip_serializing_if = "Wan::is_default")]
    pub wan: Wan,
    /// The router's networks; the first is "the LAN" of version 1.
    #[serde(rename = "network")]
    pub networks: Vec<Network>,
    /// Firewall zones beyond the built-in `lan` and `wan`.
    #[serde(rename = "zone", skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<Zone>,
    #[serde(skip_serializing_if = "Firewall::is_empty")]
    pub firewall: Firewall,
    pub dns: Dns,
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
            dns: Dns::default(),
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
            dhcp: Dhcp::default(),
        }
    }
}

impl Network {
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

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Firewall {
    #[serde(rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(rename = "forward", skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<Forward>,
}

impl Firewall {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.forwards.is_empty()
    }
}

// ---- services --------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub cache_entries: u32,
    /// Drop upstream answers that point into private ranges.
    pub rebind_protection: bool,
    /// Local DNS zone of all networks: DHCP clients become
    /// `<hostname>.<domain>` (version 1: `lan.domain`).
    pub domain: String,
    /// Local A records beside the DHCP names.
    #[serde(rename = "host", skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<DnsHost>,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            cache_entries: 4096,
            rebind_protection: true,
            domain: "lan".into(),
            hosts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsHost {
    /// A label (in `dns.domain`) or a full name.
    pub name: String,
    pub ip: Ipv4Addr,
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
/// everything else: a document without a version is version 1 if it has
/// `[lan]` (hand-written files from before version 2), else the current
/// one.
#[derive(Deserialize)]
struct VersionOnly {
    version: Option<u32>,
    lan: Option<serde::de::IgnoredAny>,
}

impl VersionOnly {
    fn get(&self) -> u32 {
        self.version
            .unwrap_or(if self.lan.is_some() { 1 } else { VERSION })
    }
}

fn check_version(v: u32) -> Result<(), Error> {
    match v {
        1..=VERSION => Ok(()),
        v if v > VERSION => Err(Error::NewerVersion(v)),
        _ => Err(Error::Invalid(vec![Issue {
            path: "version".into(),
            msg: alloc::format!("must be 1–{VERSION}"),
        }])),
    }
}

/// The schema version a `config.toml` is written in (not validated
/// otherwise): for a store record's header when the text is stored as is.
pub fn document_version(text: &str) -> Result<u32, Error> {
    let v = toml::from_str::<VersionOnly>(text)
        .map_err(|e| Error::Syntax(e.to_string()))?
        .get();
    check_version(v)?;
    Ok(v)
}

/// `config.toml` (version 1 or 2) → a checked [`Config`].
pub fn parse(text: &str) -> Result<Config, Error> {
    if text.len() > MAX_LEN {
        return Err(Error::TooLarge { len: text.len() });
    }
    let syntax = |e: toml::de::Error| Error::Syntax(e.to_string());
    let v = toml::from_str::<VersionOnly>(text).map_err(syntax)?.get();
    check_version(v)?;
    let c = if v == 1 {
        toml::from_str::<v1::Config>(text).map_err(syntax)?.into()
    } else {
        toml::from_str::<Config>(text).map_err(syntax)?
    };
    c.validate().map_err(Error::Invalid)?;
    Ok(c)
}

/// JSON (the web interface's form) → a checked [`Config`]: the same
/// schemas, defaults and checks as [`parse`].
pub fn parse_json(text: &str) -> Result<Config, Error> {
    if text.len() > MAX_LEN {
        return Err(Error::TooLarge { len: text.len() });
    }
    let syntax = |e: serde_json::Error| Error::Syntax(e.to_string());
    let v = serde_json::from_str::<VersionOnly>(text).map_err(syntax)?.get();
    check_version(v)?;
    let c = if v == 1 {
        serde_json::from_str::<v1::Config>(text).map_err(syntax)?.into()
    } else {
        serde_json::from_str::<Config>(text).map_err(syntax)?
    };
    c.validate().map_err(Error::Invalid)?;
    Ok(c)
}

impl Config {
    /// The canonical `config.toml`: version 1 while the config fits it
    /// ([`Self::fits_v1`]), else version 2.
    pub fn to_toml(&self) -> String {
        // Serialisation fails only for types TOML cannot express; the
        // schema has none (tested).
        match v1::Config::try_from(self) {
            Ok(old) => toml::to_string(&old),
            Err(_) => toml::to_string(self),
        }
        .unwrap_or_default()
    }

    /// The config as JSON, always version 2 (the web interface's shape).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The schema version [`Self::to_toml`] writes: the version for the
    /// store's record header, so a kernel that reads only version 1 skips
    /// a version 2 record and keeps the one before it.
    pub fn doc_version(&self) -> u32 {
        if self.fits_v1() { 1 } else { VERSION }
    }

    /// Expressible as a version 1 document (docs/config-v2.md §5).
    pub fn fits_v1(&self) -> bool {
        self.beyond_v1().is_empty()
    }

    pub(crate) fn beyond_v1_paths(&self) -> Vec<String> {
        self.beyond_v1().into_iter().map(|(p, _)| p).collect()
    }

    /// The settings that need version 2, with their paths.
    fn beyond_v1(&self) -> Vec<(String, &'static str)> {
        let mut out = Vec::new();
        let mut add = |p: String, why: &'static str| out.push((p, why));
        if self.networks.len() != 1 {
            add("network".into(), "more than one network");
        }
        for n in self.networks.iter().take(1) {
            let p = |f: &str| alloc::format!("network.{}.{f}", n.name);
            if n.name != "lan" {
                add(p("name"), "a network not named \"lan\"");
            }
            if n.ports.len() != 1 || n.ports[0] != PORT_LAN {
                add(p("ports"), "ports other than lan0");
            }
            if n.vlan != 0 {
                add(p("vlan"), "a tagged network");
            }
            if n.zone != ZONE_LAN {
                add(p("zone"), "a network outside the lan zone");
            }
            if !n.dhcp.enabled {
                add(p("dhcp.enabled"), "DHCP switched off");
            }
        }
        if !self.zones.is_empty() {
            add("zone".into(), "firewall zones");
        }
        if !self.firewall.rules.is_empty() {
            add("firewall.rule".into(), "firewall rules");
        }
        if !self.firewall.forwards.is_empty() {
            add("firewall.forward".into(), "port forwards");
        }
        if !self.dns.hosts.is_empty() {
            add("dns.host".into(), "local DNS records");
        }
        if self.wan.port != PORT_WAN {
            add("wan.port".into(), "a WAN port other than wan0");
        }
        if self.wan.mode == WanMode::Static || self.wan.static_ip.is_some() {
            add("wan.static".into(), "a static WAN address");
        }
        out
    }

    /// Settings this kernel does not implement yet (docs/config-v2.md §9):
    /// a save or a stored config with them is refused. Today that is
    /// everything beyond version 1.
    pub fn unsupported(&self) -> Vec<Issue> {
        self.beyond_v1()
            .into_iter()
            .map(|(path, what)| Issue {
                path,
                msg: alloc::format!("{what}: not supported by this kernel yet"),
            })
            .collect()
    }

    /// The first network: version 1's `[lan]`, where boot argument `lan=`
    /// applies. `None` only for an unchecked config without networks.
    pub fn lan(&self) -> Option<&Network> {
        self.networks.first()
    }

    pub fn network(&self, name: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.name == name)
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
            || self.mgmt != old.mgmt
            || (self.wan != old.wan && (self.mgmt.on_wan || old.mgmt.on_wan))
    }

    /// This config without secrets (the PPPoE password): what the web
    /// interface and the CLI show and export.
    pub fn without_secrets(&self) -> Config {
        let mut c = self.clone();
        c.wan.pppoe.password = None;
        c
    }

    /// A submitted config left secrets out (it came from
    /// [`Self::without_secrets`]): keep `current`'s. An empty string
    /// clears one.
    pub fn keep_secrets(&mut self, current: &Config) {
        if self.wan.pppoe.password.is_none() {
            self.wan.pppoe.password = current.wan.pppoe.password.clone();
        }
    }

    /// Cross-field checks; every problem found, not just the first.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        validate::check(self)
    }
}

#[cfg(test)]
mod tests;
