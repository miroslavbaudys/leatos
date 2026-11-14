//! Value types written as strings in `config.toml`: `a.b.c.d/len`,
//! `aa:bb:cc:dd:ee:ff`.

use alloc::string::String;
use core::fmt;
use core::net::Ipv4Addr;
use core::str::FromStr;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An interface address with its prefix length: `10.10.0.1/24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub const fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        Cidr { addr, prefix }
    }

    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix.min(32) as u32)
        }
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.mask())
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.addr) & self.mask()
    }

    /// Inside the subnet and neither the network nor the broadcast address.
    pub fn is_host(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip) && ip != self.network() && ip != self.broadcast()
    }

    /// Host number `n` of the subnet (network + n).
    pub fn host(&self, n: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()).wrapping_add(n))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = s.split_once('/').ok_or("expected a.b.c.d/len")?;
        let addr = a.parse().map_err(|_| "bad IPv4 address")?;
        let prefix: u8 = p.parse().map_err(|_| "bad prefix length")?;
        if prefix > 32 {
            return Err("prefix length above 32");
        }
        Ok(Cidr { addr, prefix })
    }
}

/// A MAC address: `52:54:00:00:00:05` (written in lower case; upper case
/// is accepted).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 != 0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl FromStr for Mac {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut m = [0; 6];
        let mut parts = s.split(':');
        for b in &mut m {
            let p = parts.next().ok_or("expected six bytes aa:bb:cc:dd:ee:ff")?;
            if p.len() != 2 || !p.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err("expected two hex digits per byte");
            }
            *b = u8::from_str_radix(p, 16).map_err(|_| "bad hex digit")?;
        }
        if parts.next().is_some() {
            return Err("expected six bytes aa:bb:cc:dd:ee:ff");
        }
        Ok(Mac(m))
    }
}

macro_rules! string_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(D::Error::custom)
            }
        }
    };
}

string_serde!(Cidr);
string_serde!(Mac);
