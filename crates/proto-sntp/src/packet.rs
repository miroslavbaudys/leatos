//! The NTP packet (RFC 5905 §7.3), as far as a client needs it.
//!
//! ```text
//!  0: LI(2) VN(3) Mode(3) | Stratum | Poll | Precision
//!  4: Root delay    8: Root dispersion    12: Reference ID
//! 16: Reference timestamp   24: Origin timestamp
//! 32: Receive timestamp     40: Transmit timestamp
//! ```
//!
//! Timestamps are 32.32 fixed point seconds since 1900. The request
//! carries a random cookie in its transmit timestamp instead of the
//! local time (the client has none yet); a valid reply echoes it as the
//! origin timestamp (RFC 5905 §8, "bogus" check), which also defeats
//! blind spoofing.

/// UDP port of NTP servers.
pub const PORT: u16 = 123;
/// Size of a packet without extensions.
pub const LEN: usize = 48;

const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;
const VERSION: u8 = 4;
const LEAP_UNSYNC: u8 = 3;

/// Seconds from 1900-01-01 (NTP) to 1970-01-01 (Unix).
pub const UNIX_EPOCH_NTP: u64 = 2_208_988_800;
/// NTP seconds of 2026-01-01T00:00:00Z. Era 0 ends in 2036; a timestamp
/// below this pivot is read as era 1 (2036–2162), so this code keeps
/// working across the wrap and until 2162.
const PIVOT_NTP: u64 = UNIX_EPOCH_NTP + 1_767_225_600;

/// Why a datagram is not an acceptable reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Short,
    /// Not a server reply (mode ≠ 4).
    Mode,
    Version,
    /// The origin timestamp is not our cookie: not an answer to our request.
    Origin,
    /// Stratum 0: a kiss-o'-death with its code (`RATE`, `DENY`, …).
    Kiss([u8; 4]),
    /// Stratum 16 or above: the server has no time either.
    Stratum,
    /// Leap indicator 3: the server's clock is not synchronised.
    Unsynchronised,
    /// Receive or transmit timestamp is zero.
    NoTime,
}

/// The fields of an acceptable reply. Times are Unix ns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub leap: u8,
    pub stratum: u8,
    /// When the server received the request.
    pub receive: i64,
    /// When the server sent the reply.
    pub transmit: i64,
}

/// A client request whose transmit timestamp is `cookie`.
pub fn request(cookie: u64) -> [u8; LEN] {
    let mut p = [0u8; LEN];
    p[0] = (VERSION << 3) | MODE_CLIENT;
    p[40..48].copy_from_slice(&cookie.to_be_bytes());
    p
}

fn ts(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}

/// A 32.32 NTP timestamp → Unix ns (era by pivot, see [`PIVOT_NTP`]).
pub fn ntp_to_unix_ns(t: u64) -> i64 {
    let mut secs = t >> 32;
    if secs < PIVOT_NTP {
        secs += 1 << 32; // era 1
    }
    let frac_ns = ((t & 0xffff_ffff) * 1_000_000_000) >> 32;
    let unix = secs as i64 - UNIX_EPOCH_NTP as i64;
    unix * 1_000_000_000 + frac_ns as i64
}

/// Unix ns → a 32.32 NTP timestamp (for tests and servers).
pub fn unix_ns_to_ntp(ns: i64) -> u64 {
    let secs = ns.div_euclid(1_000_000_000);
    let sub = ns.rem_euclid(1_000_000_000) as u64;
    let ntp_secs = (secs + UNIX_EPOCH_NTP as i64) as u64 & 0xffff_ffff;
    let frac = (sub << 32).div_ceil(1_000_000_000);
    (ntp_secs << 32) | frac
}

/// Check a datagram against the request with `cookie` (RFC 4330 §5).
pub fn parse_reply(b: &[u8], cookie: u64) -> Result<Reply, Reject> {
    if b.len() < LEN {
        return Err(Reject::Short);
    }
    let leap = b[0] >> 6;
    let version = (b[0] >> 3) & 7;
    let mode = b[0] & 7;
    let stratum = b[1];
    if mode != MODE_SERVER {
        return Err(Reject::Mode);
    }
    if ts(b, 24) != cookie {
        return Err(Reject::Origin);
    }
    if !(3..=4).contains(&version) {
        return Err(Reject::Version);
    }
    if stratum == 0 {
        let mut code = [0u8; 4];
        code.copy_from_slice(&b[12..16]);
        return Err(Reject::Kiss(code));
    }
    if stratum >= 16 {
        return Err(Reject::Stratum);
    }
    if leap == LEAP_UNSYNC {
        return Err(Reject::Unsynchronised);
    }
    let (rx, tx) = (ts(b, 32), ts(b, 40));
    if rx == 0 || tx == 0 {
        return Err(Reject::NoTime);
    }
    Ok(Reply {
        leap,
        stratum,
        receive: ntp_to_unix_ns(rx),
        transmit: ntp_to_unix_ns(tx),
    })
}

/// A server reply to `request` (tests and a future LAN NTP server):
/// stratum `stratum`, received at `rx_ns`, sent at `tx_ns` (Unix ns).
pub fn reply(request: &[u8; LEN], stratum: u8, rx_ns: i64, tx_ns: i64) -> [u8; LEN] {
    let mut p = [0u8; LEN];
    p[0] = (VERSION << 3) | MODE_SERVER;
    p[1] = stratum;
    p[24..32].copy_from_slice(&request[40..48]);
    p[32..40].copy_from_slice(&unix_ns_to_ntp(rx_ns).to_be_bytes());
    p[40..48].copy_from_slice(&unix_ns_to_ntp(tx_ns).to_be_bytes());
    p
}
