//! Schema version 1: one `[lan]` instead of `[[network]]`, the local
//! domain in `lan.domain`. Read and migrated on load; written while a
//! config fits it ([`crate::Config::to_toml`]), so kernels that know only
//! version 1 can still read what a newer one saved (docs/config-v2.md §5).

use crate::{Cidr, Dhcp, Mgmt, Network, PORT_LAN, Shaping, Time, Wan, ZONE_LAN};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A version 1 document. The WAN, shaping, management and time sections
/// are the same as in version 2 (version 2's additions to `[wan]` are left
/// out of the canonical form while unused).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(skip_serializing_if = "Wan::is_default")]
    pub wan: Wan,
    pub lan: Lan,
    pub dns: Dns,
    pub shaping: Shaping,
    pub mgmt: Mgmt,
    pub time: Time,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lan {
    pub ipv4: Cidr,
    pub domain: String,
    pub dhcp: Dhcp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub cache_entries: u32,
    pub rebind_protection: bool,
}

impl Default for Config {
    fn default() -> Self {
        // Kept equal to version 2's defaults (tested).
        let c = crate::Config::default();
        let n = c.networks[0].clone();
        Config {
            version: 1,
            wan: c.wan,
            lan: Lan {
                ipv4: n.ipv4,
                domain: c.dns.domain,
                dhcp: n.dhcp,
            },
            dns: Dns {
                cache_entries: c.dns.cache_entries,
                rebind_protection: c.dns.rebind_protection,
            },
            shaping: c.shaping,
            mgmt: c.mgmt,
            time: c.time,
        }
    }
}

impl Default for Lan {
    fn default() -> Self {
        Config::default().lan
    }
}

impl Default for Dns {
    fn default() -> Self {
        Config::default().dns
    }
}

/// Migration: `[lan]` becomes network `lan` (untagged on `lan0`, zone
/// `lan`), `lan.domain` becomes `dns.domain`.
impl From<Config> for crate::Config {
    fn from(o: Config) -> Self {
        let mut c = crate::Config {
            wan: o.wan,
            networks: vec![Network {
                name: "lan".into(),
                ports: vec![PORT_LAN.into()],
                vlan: 0,
                ipv4: o.lan.ipv4,
                zone: ZONE_LAN.into(),
                domain: None,
                dhcp: o.lan.dhcp,
            }],
            shaping: o.shaping,
            mgmt: o.mgmt,
            time: o.time,
            ..crate::Config::default()
        };
        c.dns.cache_entries = o.dns.cache_entries;
        c.dns.rebind_protection = o.dns.rebind_protection;
        c.dns.domain = o.lan.domain;
        c
    }
}

/// The version 1 form, if the config fits it; else the paths that need
/// version 2.
impl TryFrom<&crate::Config> for Config {
    type Error = Vec<String>;
    fn try_from(c: &crate::Config) -> Result<Self, Self::Error> {
        if !c.fits_v1() {
            return Err(c.beyond_v1_paths());
        }
        let n = &c.networks[0];
        Ok(Config {
            version: 1,
            wan: c.wan.clone(),
            lan: Lan {
                ipv4: n.ipv4,
                domain: c.dns.domain.clone(),
                dhcp: n.dhcp.clone(),
            },
            dns: Dns {
                cache_entries: c.dns.cache_entries,
                rebind_protection: c.dns.rebind_protection,
            },
            shaping: c.shaping.clone(),
            mgmt: c.mgmt.clone(),
            time: c.time.clone(),
        })
    }
}
