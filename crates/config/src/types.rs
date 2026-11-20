//! Value types written as strings in `config.toml`: `a.b.c.d/len`,
//! `aa:bb:cc:dd:ee:ff`.

use alloc::string::String;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
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

/// An IPv6 prefix: `fd12:3456:789a::/48`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr6 {
    pub addr: Ipv6Addr,
    pub prefix: u8,
}

impl Cidr6 {
    pub const fn new(addr: Ipv6Addr, prefix: u8) -> Self {
        Cidr6 { addr, prefix }
    }

    /// The address with the host bits cleared.
    pub fn network(&self) -> Ipv6Addr {
        let p = u32::from(self.prefix.min(128));
        let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
        Ipv6Addr::from(u128::from(self.addr) & mask)
    }
}

impl fmt::Display for Cidr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Cidr6 {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = s.split_once('/').ok_or("expected an IPv6 prefix such as fd12:3456:789a::/48")?;
        let addr = a.parse().map_err(|_| "bad IPv6 address")?;
        let prefix: u8 = p.parse().map_err(|_| "bad prefix length")?;
        if prefix > 128 {
            return Err("prefix length above 128");
        }
        Ok(Cidr6 { addr, prefix })
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
string_serde!(Cidr6);
string_serde!(Mac);

/// An address or subnet in a firewall rule: `10.10.0.20` (= /32) or
/// `10.10.0.0/24`. Host bits must be zero (checked by validation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net(pub Cidr);

impl Net {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.0.contains(ip)
    }
    /// No host bits set: `10.0.0.0/24`, not `10.0.0.5/24`.
    pub fn is_network(&self) -> bool {
        self.0.addr == self.0.network()
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.prefix == 32 {
            write!(f, "{}", self.0.addr)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl FromStr for Net {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('/') {
            return s.parse().map(Net);
        }
        let addr = s.parse().map_err(|_| "expected a.b.c.d or a.b.c.d/len")?;
        Ok(Net(Cidr::new(addr, 32)))
    }
}

/// An address or prefix of either family, for firewall rules and routes:
/// `10.10.0.20`, `10.10.0.0/24`, `2001:db8::5` (= /128), `2001:db8::/48`.
/// Host bits must be zero (checked by validation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnyNet {
    V4(Net),
    V6(Cidr6),
}

impl AnyNet {
    pub fn v4(&self) -> Option<Net> {
        match self {
            AnyNet::V4(n) => Some(*n),
            AnyNet::V6(_) => None,
        }
    }
    pub fn v6(&self) -> Option<Cidr6> {
        match self {
            AnyNet::V6(n) => Some(*n),
            AnyNet::V4(_) => None,
        }
    }
    pub fn is_network(&self) -> bool {
        match self {
            AnyNet::V4(n) => n.is_network(),
            AnyNet::V6(n) => n.addr == n.network(),
        }
    }
    /// The same prefix with the host bits cleared (for "did you mean").
    pub fn network_text(&self) -> String {
        match self {
            AnyNet::V4(n) => alloc::format!("{}/{}", n.0.network(), n.0.prefix),
            AnyNet::V6(n) => alloc::format!("{}/{}", n.network(), n.prefix),
        }
    }
}

impl fmt::Display for AnyNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnyNet::V4(n) => n.fmt(f),
            AnyNet::V6(n) if n.prefix == 128 => write!(f, "{}", n.addr),
            AnyNet::V6(n) => n.fmt(f),
        }
    }
}

impl FromStr for AnyNet {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(':') {
            return s.parse().map(AnyNet::V4);
        }
        match s.split_once('/') {
            Some(_) => s.parse().map(AnyNet::V6),
            None => {
                let a: Ipv6Addr = s.parse().map_err(|_| "expected an address or prefix (a.b.c.d/len, 2001:db8::/48)")?;
                Ok(AnyNet::V6(Cidr6::new(a, 128)))
            }
        }
    }
}

string_serde!(AnyNet);

impl From<Net> for AnyNet {
    fn from(n: Net) -> Self {
        AnyNet::V4(n)
    }
}

/// A port or an inclusive range: `443`, `"443"`, `"8000-8100"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub const fn one(p: u16) -> Self {
        PortRange { lo: p, hi: p }
    }
    pub fn contains(&self, p: u16) -> bool {
        (self.lo..=self.hi).contains(&p)
    }
    pub fn overlaps(&self, o: &PortRange) -> bool {
        self.lo <= o.hi && o.lo <= self.hi
    }
    /// Number of ports minus one.
    pub fn span(&self) -> u16 {
        self.hi.saturating_sub(self.lo)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl FromStr for PortRange {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port = |x: &str| -> Result<u16, &'static str> {
            match x.trim().parse::<u16>() {
                Ok(p) if p > 0 => Ok(p),
                _ => Err("ports are 1–65535"),
            }
        };
        let (lo, hi) = match s.split_once('-') {
            Some((a, b)) => (port(a)?, port(b)?),
            None => (port(s)?, port(s)?),
        };
        if lo > hi {
            return Err("range must go from low to high");
        }
        Ok(PortRange { lo, hi })
    }
}

/// A forward's target: `10.10.0.10` (same ports) or `10.10.0.10:443`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: Option<u16>,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(p) => write!(f, "{}:{p}", self.ip),
            None => write!(f, "{}", self.ip),
        }
    }
}

impl FromStr for Target {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = match s.split_once(':') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip = a.parse().map_err(|_| "expected a.b.c.d or a.b.c.d:port")?;
        let port = match p {
            None => None,
            Some(p) => match p.parse::<u16>() {
                Ok(p) if p > 0 => Some(p),
                _ => return Err("ports are 1–65535"),
            },
        };
        Ok(Target { ip, port })
    }
}

string_serde!(Net);
string_serde!(Target);

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// An integer (`wan_port = 8443`) or a string (`"8000-8100"`).
impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = PortRange;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a port (1–65535) or a range \"lo-hi\"")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<PortRange, E> {
                match u16::try_from(v) {
                    Ok(p) if p > 0 => Ok(PortRange::one(p)),
                    _ => Err(E::custom("ports are 1–65535")),
                }
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<PortRange, E> {
                self.visit_i64(i64::try_from(v).unwrap_or(-1))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<PortRange, E> {
                v.parse().map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }
}
