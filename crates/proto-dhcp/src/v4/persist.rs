//! Lease snapshots for the store's `leases` area (docs/config-and-storage.md):
//! the bound leases of every network, so a router restart does not forget
//! who holds which address.
//!
//! Format (version [`FORMAT`], all integers big-endian):
//! `u8 networks`, then per network `u8 name length, name, u16 leases`, then
//! per lease `mac[6], ipv4[4], u8 hostname length (0 = none), hostname`.
//!
//! No expiry is stored: [`super::server::Server::restore`] gives every
//! restored lease a full lease time again. A client's lease never outlives
//! its last renewal plus the lease time, so the router may hold an address
//! too long, never too short, and renewals need not be saved: only changes
//! to the set of (network, MAC, address, hostname).

use super::server::Mac;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

/// Version of the payload, for the store record header.
pub const FORMAT: u32 = 1;

/// Upper bounds, so a damaged record cannot ask for much memory.
pub const MAX_NETWORKS: usize = 64;
pub const MAX_LEASES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Saved {
    pub mac: Mac,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
}

/// One network's leases, by the network's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub name: String,
    pub leases: Vec<Saved>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    TooMany,
    BadText,
    TrailingBytes,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated",
            Error::TooMany => "too many entries",
            Error::BadText => "a name is not UTF-8",
            Error::TrailingBytes => "bytes after the last lease",
        })
    }
}

fn put_text(out: &mut Vec<u8>, s: &str) {
    // Names and hostnames are at most 63 bytes (labels); cut defensively.
    let b = &s.as_bytes()[..s.len().min(255)];
    out.push(b.len() as u8);
    out.extend_from_slice(b);
}

/// Encode a snapshot. Networks beyond [`MAX_NETWORKS`] and leases beyond
/// [`MAX_LEASES`] in total are left out.
pub fn encode(nets: &[Network]) -> Vec<u8> {
    let nets = &nets[..nets.len().min(MAX_NETWORKS)];
    let mut out = Vec::new();
    out.push(nets.len() as u8);
    let mut budget = MAX_LEASES;
    for n in nets {
        put_text(&mut out, &n.name);
        let leases = &n.leases[..n.leases.len().min(budget)];
        budget -= leases.len();
        out.extend_from_slice(&(leases.len() as u16).to_be_bytes());
        for l in leases {
            out.extend_from_slice(&l.mac);
            out.extend_from_slice(&l.ip.octets());
            put_text(&mut out, l.hostname.as_deref().unwrap_or(""));
        }
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn text(&mut self) -> Result<String, Error> {
        let n = self.u8()? as usize;
        core::str::from_utf8(self.take(n)?)
            .map(String::from)
            .map_err(|_| Error::BadText)
    }
}

/// Decode a snapshot written by [`encode`].
pub fn decode(data: &[u8]) -> Result<Vec<Network>, Error> {
    let mut r = Reader(data);
    let count = r.u8()? as usize;
    if count > MAX_NETWORKS {
        return Err(Error::TooMany);
    }
    let mut total = 0;
    let mut nets = Vec::with_capacity(count);
    for _ in 0..count {
        let name = r.text()?;
        let b = r.take(2)?;
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        total += n;
        if total > MAX_LEASES {
            return Err(Error::TooMany);
        }
        let mut leases = Vec::with_capacity(n);
        for _ in 0..n {
            let mut mac = [0; 6];
            mac.copy_from_slice(r.take(6)?);
            let o = r.take(4)?;
            let ip = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
            let h = r.text()?;
            leases.push(Saved {
                mac,
                ip,
                hostname: (!h.is_empty()).then_some(h),
            });
        }
        nets.push(Network { name, leases });
    }
    if !r.0.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok(nets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample() -> Vec<Network> {
        vec![
            Network {
                name: "lan".into(),
                leases: vec![
                    Saved { mac: [0x52, 0x54, 0, 0, 0, 0x10], ip: Ipv4Addr::new(192, 168, 1, 100), hostname: Some("laptop".into()) },
                    Saved { mac: [0x52, 0x54, 0, 0, 0, 0x11], ip: Ipv4Addr::new(192, 168, 1, 101), hostname: None },
                ],
            },
            Network { name: "iot".into(), leases: vec![] },
        ]
    }

    #[test]
    fn round_trip() {
        let s = sample();
        assert_eq!(decode(&encode(&s)).unwrap(), s);
        assert_eq!(decode(&encode(&[])).unwrap(), []);
    }

    #[test]
    fn damaged_records_are_refused() {
        let b = encode(&sample());
        for n in 0..b.len() {
            assert_eq!(decode(&b[..n]), Err(Error::Truncated), "cut at {n}");
        }
        let mut long = b.clone();
        long.push(0);
        assert_eq!(decode(&long), Err(Error::TrailingBytes));
        assert_eq!(decode(&[MAX_NETWORKS as u8 + 1]), Err(Error::TooMany));
        // One network claiming more leases than allowed.
        let mut many = vec![1, 1, b'x'];
        many.extend_from_slice(&(MAX_LEASES as u16 + 1).to_be_bytes());
        assert_eq!(decode(&many), Err(Error::TooMany));
        let bad_utf8 = [1, 1, 0xff, 0, 0];
        assert_eq!(decode(&bad_utf8), Err(Error::BadText));
        // Every byte flipped: never a panic.
        for i in 0..b.len() {
            let mut x = b.clone();
            x[i] ^= 0xa5;
            let _ = decode(&x);
        }
    }

    #[test]
    fn encode_keeps_within_bounds() {
        let lease = Saved { mac: [2, 0, 0, 0, 0, 1], ip: Ipv4Addr::new(10, 0, 0, 2), hostname: None };
        let big = vec![Network { name: "a".into(), leases: vec![lease; MAX_LEASES + 5] }; 2];
        let d = decode(&encode(&big)).unwrap();
        assert_eq!(d.iter().map(|n| n.leases.len()).sum::<usize>(), MAX_LEASES);
    }
}
