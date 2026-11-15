//! Router configuration (`docs/config-and-storage.md` §5): the schema of
//! `config.toml` with its defaults, validation, and TOML in/out.
//!
//! - [`parse`]: text → checked [`Config`] (size limit, schema version,
//!   TOML, unknown fields, [`Config::validate`])
//! - [`Config::to_toml`]: the canonical text (what the store holds)
//! - [`parse_json`], [`Config::to_json`]: the same schema as JSON, for the
//!   web interface's forms
//! - [`Config::needs_trial`]: does a change need confirm-or-revert?
//! - [`Config::with_assignment`], [`Config::without`], [`diff_lines`]: one
//!   setting at a time (the serial CLI)
//! - [`Config::default`]: what the router runs without a stored config
//!
//! Every section and field has a default, so a file may set only what it
//! changes. Unknown fields are errors (typos are reported, not ignored).
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod edit;
mod types;
mod validate;

pub use edit::{diff_lines, flat_lines};
pub use types::{Cidr, Mac};
pub use validate::MAX_VLAN_ID;
pub use validate::Issue;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

/// Schema version this crate reads and writes.
pub const VERSION: u32 = 1;
/// Largest `config.toml` accepted, checked before parsing.
pub const MAX_LEN: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    /// Written only when set, so a config without WAN settings stays
    /// readable by kernels from before `[wan]` (rollback of an upgrade).
    #[serde(skip_serializing_if = "Wan::is_default")]
    pub wan: Wan,
    pub lan: Lan,
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
            lan: Lan::default(),
            dns: Dns::default(),
            shaping: Shaping::default(),
            mgmt: Mgmt::default(),
            time: Time::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lan {
    /// The router's LAN address and subnet.
    pub ipv4: Cidr,
    /// Local DNS zone: DHCP clients become `<hostname>.<domain>`.
    pub domain: String,
    pub dhcp: Dhcp,
}

impl Default for Lan {
    fn default() -> Self {
        Lan {
            ipv4: Cidr::new(Ipv4Addr::new(192, 168, 1, 1), 24),
            domain: "lan".into(),
            dhcp: Dhcp::default(),
        }
    }
}

impl Lan {
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
    /// Inclusive dynamic range; unset = derived from the subnet
    /// ([`Lan::dhcp_range`]).
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub cache_entries: u32,
    /// Drop upstream answers that point into private ranges.
    pub rebind_protection: bool,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            cache_entries: 4096,
            rebind_protection: true,
        }
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

/// The WAN link. Same settings as the boot arguments `wan_vlan=`,
/// `wan_pcp=`, `wan_mode=`, `pppoe_user=`, `pppoe_pass=`, … Fields at
/// their defaults are left out of the canonical form, so a config that
/// does not use them stays readable by older kernels (rollback).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Wan {
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
}

impl WanMode {
    pub fn is_dhcp(&self) -> bool {
        *self == WanMode::Dhcp
    }
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
    /// Parsed, but the settings are inconsistent.
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

/// `config.toml` → a checked [`Config`].
pub fn parse(text: &str) -> Result<Config, Error> {
    if text.len() > MAX_LEN {
        return Err(Error::TooLarge { len: text.len() });
    }
    let v = version_of(text)?;
    if v > VERSION {
        return Err(Error::NewerVersion(v));
    }
    // Versions below VERSION would be migrated here; 1 is the first.
    let c: Config = toml::from_str(text).map_err(|e| Error::Syntax(e.to_string()))?;
    c.validate().map_err(Error::Invalid)?;
    Ok(c)
}

/// JSON (the web interface's form) → a checked [`Config`]: the same
/// schema, defaults and checks as [`parse`].
pub fn parse_json(text: &str) -> Result<Config, Error> {
    if text.len() > MAX_LEN {
        return Err(Error::TooLarge { len: text.len() });
    }
    let c: Config = serde_json::from_str(text).map_err(|e| Error::Syntax(e.to_string()))?;
    if c.version > VERSION {
        return Err(Error::NewerVersion(c.version));
    }
    c.validate().map_err(Error::Invalid)?;
    Ok(c)
}

/// The `version` field alone, ignoring everything else, so a newer
/// document is reported as newer rather than as full of unknown fields.
fn version_of(text: &str) -> Result<u32, Error> {
    #[derive(Deserialize)]
    struct V {
        #[serde(default = "current")]
        version: u32,
    }
    fn current() -> u32 {
        VERSION
    }
    toml::from_str::<V>(text)
        .map(|v| v.version)
        .map_err(|e| Error::Syntax(e.to_string()))
}

impl Config {
    /// The canonical `config.toml`: every field written, defaults included.
    pub fn to_toml(&self) -> String {
        // Serialisation fails only for types TOML cannot express; the
        // schema has none (tested).
        toml::to_string(self).unwrap_or_default()
    }

    /// The config as JSON (every field, like [`Self::to_toml`]).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Changing from `old` to `self` could cut the user off from the web
    /// interface (another LAN address or subnet, management settings, the
    /// WAN link while the interface is served on the WAN): such a save
    /// boots as a trial that must be confirmed
    /// (docs/config-and-storage.md §6).
    pub fn needs_trial(&self, old: &Config) -> bool {
        self.lan.ipv4 != old.lan.ipv4
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
