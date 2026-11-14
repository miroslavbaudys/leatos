//! Router configuration (`docs/config-and-storage.md` §5): the schema of
//! `config.toml` with its defaults, validation, and TOML in/out.
//!
//! - [`parse`]: text → checked [`Config`] (size limit, schema version,
//!   TOML, unknown fields, [`Config::validate`])
//! - [`Config::to_toml`]: the canonical text (what the store holds)
//! - [`Config::default`]: what the router runs without a stored config
//!
//! Every section and field has a default, so a file may set only what it
//! changes. Unknown fields are errors (typos are reported, not ignored).
//!
//! `#![no_std]` + `alloc`, sans-IO, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod types;
mod validate;

pub use types::{Cidr, Mac};
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
    pub lan: Lan,
    pub dns: Dns,
    pub shaping: Shaping,
    pub mgmt: Mgmt,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: VERSION,
            lan: Lan::default(),
            dns: Dns::default(),
            shaping: Shaping::default(),
            mgmt: Mgmt::default(),
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

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mgmt {
    /// Also serve the web interface on the WAN. Development only.
    pub on_wan: bool,
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

    /// Cross-field checks; every problem found, not just the first.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        validate::check(self)
    }
}

#[cfg(test)]
mod tests;
