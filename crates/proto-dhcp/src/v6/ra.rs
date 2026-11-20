//! Router Advertisements (RFC 4861 §6.2, sans-IO): what a network's clients
//! learn about it by SLAAC: the prefix (RFC 4862), the link MTU, the DNS
//! server (RDNSS, RFC 8106) and search domains (DNSSL).
//!
//! An [`Advertiser`] per network sends unsolicited RAs (the first three at
//! most 16 s apart, then every 200–600 s) and answers Router Solicitations
//! ([`Advertiser::solicited`]) with a multicast RA, at most one per 3 s
//! (§6.2.6). [`RaConfig::router_lifetime`] is 0 while the router has no
//! IPv6 default route (clients take the prefixes and DNS server but no
//! default route through us), else [`ROUTER_SECS`]. [`Advertiser::retire`] sends a last RA that
//! deprecates the prefix, when the network or IPv6 goes away.
//!
//! [`Advertiser::poll`] returns a whole Ethernet frame to ff02::1 from the
//! router's link-local address (EUI-64 of `mac`). A prefix that leaves the
//! config (a new delegated prefix, a lost one) is still advertised as
//! deprecated for [`DEPRECATED_MS`] (preferred 0, valid 2 h), so clients
//! stop using their addresses in it (RFC 7084 L-13).
//!
//! [`parse_frame`] reads the RA of an upstream router (the ISP's, on the
//! WAN): default router lifetime, M/O flags, MTU, prefixes, DNS servers.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv6Addr;

/// RFC 4861 §6.2.1 defaults (ms).
pub const MAX_INTERVAL_MS: u64 = 600_000;
pub const MIN_INTERVAL_MS: u64 = 200_000;
pub const MAX_INITIAL_INTERVAL_MS: u64 = 16_000;
pub const MAX_INITIAL_ADVERTS: u8 = 3;
/// Between two multicast RAs (§10: MIN_DELAY_BETWEEN_RAS).
pub const MIN_DELAY_MS: u64 = 3_000;
/// A solicited RA waits a random 0–500 ms (§10: MAX_RA_DELAY_TIME).
pub const MAX_RA_DELAY_MS: u64 = 500;

/// Prefix lifetimes (s): valid 1 day, preferred 4 h; RDNSS/DNSSL 3 × the
/// maximum interval (RFC 8106 §5.1).
pub const VALID_SECS: u32 = 86_400;
pub const PREFERRED_SECS: u32 = 14_400;
pub const DNS_SECS: u32 = 1_800;
/// A retired prefix stays valid this long (hosts never shorten the valid
/// lifetime below 2 h on an unauthenticated RA: RFC 4862 §5.5.3 e).
pub const RETIRED_VALID_SECS: u32 = 7_200;
/// How long a prefix that left the config is advertised as deprecated.
pub const DEPRECATED_MS: u64 = RETIRED_VALID_SECS as u64 * 1000;
/// Router lifetime while the router forwards IPv6 to a default route
/// (RFC 4861 §6.2.1 default: 3 × the maximum interval).
pub const ROUTER_SECS: u16 = 1_800;

const ICMPV6_RA: u8 = 134;
const OPT_SLLA: u8 = 1;
const OPT_PREFIX: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;
const OPT_DNSSL: u8 = 31;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaConfig {
    /// The interface's MAC: the RA's source link-layer address and, as
    /// EUI-64, its source address.
    pub mac: [u8; 6],
    /// The network's /64s (host bits ignored; its ULA, its global one),
    /// advertised on-link and for SLAAC.
    pub prefixes: Vec<Ipv6Addr>,
    /// 0: not a default router.
    pub router_lifetime: u16,
    /// The link MTU (option 5).
    pub mtu: u32,
    /// DNS servers (the router's own address on the network).
    pub rdnss: Vec<Ipv6Addr>,
    /// Search domains.
    pub dnssl: Vec<String>,
}

pub struct Advertiser {
    cfg: RaConfig,
    next: u64,
    initial_left: u8,
    last_sent: Option<u64>,
    rng: u64,
    retiring: bool,
    done: bool,
    /// Prefixes no longer in the config, advertised as deprecated until
    /// the time given.
    deprecated: Vec<(Ipv6Addr, u64)>,
    /// RAs sent.
    pub sent: u64,
    /// Router Solicitations seen.
    pub solicits: u64,
}

impl Advertiser {
    /// Starts at once: the first RA is due at `now`.
    pub fn new(cfg: RaConfig, now: u64, seed: u64) -> Self {
        Advertiser {
            cfg,
            next: now,
            initial_left: MAX_INITIAL_ADVERTS,
            last_sent: None,
            rng: seed | 1,
            retiring: false,
            done: false,
            deprecated: Vec::new(),
            sent: 0,
            solicits: 0,
        }
    }

    pub fn config(&self) -> &RaConfig {
        &self.cfg
    }

    /// New information (domain, DNS server, MTU): advertised soon, like
    /// a new interface (§6.2.4), keeping the 3 s spacing.
    pub fn set_config(&mut self, cfg: RaConfig, now: u64) {
        if cfg == self.cfg || self.retiring {
            return;
        }
        let same = |a: Ipv6Addr, b: Ipv6Addr| prefix64(a) == prefix64(b);
        for &old in &self.cfg.prefixes {
            if !cfg.prefixes.iter().any(|&n| same(n, old)) && !self.deprecated.iter().any(|&(d, _)| same(d, old)) {
                self.deprecated.push((old, now + DEPRECATED_MS));
            }
        }
        // Back in the config: no longer deprecated.
        self.deprecated.retain(|&(d, _)| !cfg.prefixes.iter().any(|&n| same(n, d)));
        self.cfg = cfg;
        self.initial_left = MAX_INITIAL_ADVERTS;
        self.next = self.next.min(self.earliest(now));
    }

    /// A Router Solicitation arrived (§6.2.6): a multicast RA within
    /// 0–500 ms, but not sooner than 3 s after the last one.
    pub fn solicited(&mut self, now: u64) {
        self.solicits += 1;
        if self.retiring {
            return;
        }
        let at = (now + self.random(MAX_RA_DELAY_MS + 1)).max(self.earliest(now));
        self.next = self.next.min(at);
    }

    /// Send a final RA that deprecates the prefix and the DNS options, at
    /// once; then the advertiser is done.
    pub fn retire(&mut self, now: u64) {
        if !self.retiring {
            self.retiring = true;
            self.next = now;
        }
    }

    /// The final RA went out.
    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn next_deadline(&self) -> Option<u64> {
        (!self.done).then_some(self.next)
    }

    /// The RA due at `now`, as an Ethernet frame.
    pub fn poll(&mut self, now: u64) -> Option<Vec<u8>> {
        if self.done || now < self.next {
            return None;
        }
        self.deprecated.retain(|&(_, until)| until > now);
        let frame = self.frame();
        self.sent += 1;
        self.last_sent = Some(now);
        if self.retiring {
            self.done = true;
            return Some(frame);
        }
        let mut interval = MIN_INTERVAL_MS + self.random(MAX_INTERVAL_MS - MIN_INTERVAL_MS + 1);
        if self.initial_left > 0 {
            self.initial_left -= 1;
            interval = interval.min(MAX_INITIAL_INTERVAL_MS);
        }
        self.next = now + interval;
        Some(frame)
    }

    fn earliest(&self, now: u64) -> u64 {
        self.last_sent.map_or(now, |t| (t + MIN_DELAY_MS).max(now))
    }

    /// xorshift64*: timer jitter (not a secret).
    fn random(&mut self, below: u64) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d) % below.max(1)
    }

    fn frame(&self) -> Vec<u8> {
        let c = &self.cfg;
        let (valid, preferred, dns) = if self.retiring {
            (RETIRED_VALID_SECS, 0, 0)
        } else {
            (VALID_SECS, PREFERRED_SECS, DNS_SECS)
        };
        let mut icmp = Vec::with_capacity(128);
        icmp.extend_from_slice(&[ICMPV6_RA, 0, 0, 0]);
        icmp.push(64); // current hop limit for the clients
        icmp.push(0); // M = O = 0: SLAAC, no DHCPv6
        let lifetime = if self.retiring { 0 } else { c.router_lifetime };
        icmp.extend_from_slice(&lifetime.to_be_bytes());
        icmp.extend_from_slice(&[0; 8]); // reachable time, retrans timer: unspecified
        icmp.extend_from_slice(&[OPT_SLLA, 1]);
        icmp.extend_from_slice(&c.mac);
        icmp.extend_from_slice(&[OPT_MTU, 1, 0, 0]);
        icmp.extend_from_slice(&c.mtu.to_be_bytes());
        for &p in c.prefixes.iter().take(4) {
            icmp.extend_from_slice(&[OPT_PREFIX, 4, 64, 0xc0]); // /64, on-link + autonomous
            icmp.extend_from_slice(&valid.to_be_bytes());
            icmp.extend_from_slice(&preferred.to_be_bytes());
            icmp.extend_from_slice(&[0; 4]);
            icmp.extend_from_slice(&prefix64(p).octets());
        }
        for &(p, _) in self.deprecated.iter().take(4) {
            icmp.extend_from_slice(&[OPT_PREFIX, 4, 64, 0xc0]);
            icmp.extend_from_slice(&RETIRED_VALID_SECS.to_be_bytes());
            icmp.extend_from_slice(&0u32.to_be_bytes());
            icmp.extend_from_slice(&[0; 4]);
            icmp.extend_from_slice(&prefix64(p).octets());
        }
        if !c.rdnss.is_empty() {
            let n = c.rdnss.len().min(8);
            icmp.extend_from_slice(&[OPT_RDNSS, (1 + 2 * n) as u8, 0, 0]);
            icmp.extend_from_slice(&dns.to_be_bytes());
            for a in &c.rdnss[..n] {
                icmp.extend_from_slice(&a.octets());
            }
        }
        let names = dnssl_names(&c.dnssl);
        if !names.is_empty() {
            let len = (8 + names.len()).div_ceil(8);
            icmp.extend_from_slice(&[OPT_DNSSL, len as u8, 0, 0]);
            icmp.extend_from_slice(&dns.to_be_bytes());
            icmp.extend_from_slice(&names);
            icmp.resize(icmp.len() + len * 8 - 8 - names.len(), 0);
        }
        let src = link_local(c.mac);
        let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let sum = icmpv6_checksum(src, dst, &icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut f = Vec::with_capacity(14 + 40 + icmp.len());
        f.extend_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
        f.extend_from_slice(&c.mac);
        f.extend_from_slice(&0x86ddu16.to_be_bytes());
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
        f.push(58);
        f.push(255); // hop limit 255: on-link only (§6.1.2)
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&icmp);
        f
    }
}

/// A prefix an upstream router advertises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_secs: u32,
    pub preferred_secs: u32,
}

/// What an upstream router's RA says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterInfo {
    /// Its link-local address (the default route's next hop).
    pub router: Ipv6Addr,
    /// As a default router (0: not one).
    pub lifetime_secs: u16,
    /// M: addresses by DHCPv6. O: other configuration by DHCPv6.
    pub managed: bool,
    pub other: bool,
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInfo>,
    pub rdnss: Vec<Ipv6Addr>,
}

/// An RA in an Ethernet frame (untagged): from a link-local address with
/// hop limit 255 (RFC 4861 §6.1.2), right behind the fixed header, valid
/// checksum. `None` for anything else.
pub fn parse_frame(f: &[u8]) -> Option<RouterInfo> {
    let ip = 14;
    if f.get(12..14)? != [0x86, 0xdd] || f.get(ip)? >> 4 != 6 || *f.get(ip + 6)? != 58 || *f.get(ip + 7)? != 255 {
        return None;
    }
    let plen = usize::from(u16::from_be_bytes([f[ip + 4], f[ip + 5]]));
    let msg = f.get(ip + 40..ip + 40 + plen)?;
    let addr = |at: usize| -> Option<Ipv6Addr> {
        let b: [u8; 16] = f.get(at..at + 16)?.try_into().ok()?;
        Some(Ipv6Addr::from(b))
    };
    let (src, dst) = (addr(ip + 8)?, addr(ip + 24)?);
    if src.segments()[0] & 0xffc0 != 0xfe80 || msg.len() < 16 || msg[0] != ICMPV6_RA || msg[1] != 0 {
        return None;
    }
    if icmpv6_checksum(src, dst, msg) != 0 {
        return None;
    }
    let mut r = RouterInfo {
        router: src,
        lifetime_secs: u16::from_be_bytes([msg[6], msg[7]]),
        managed: msg[5] & 0x80 != 0,
        other: msg[5] & 0x40 != 0,
        mtu: None,
        prefixes: Vec::new(),
        rdnss: Vec::new(),
    };
    let be32 = |b: &[u8], i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let mut o = &msg[16..];
    while o.len() >= 2 {
        let len = usize::from(o[1]) * 8;
        if len == 0 || len > o.len() {
            return None;
        }
        let body = &o[..len];
        match (o[0], len) {
            (OPT_MTU, 8) => r.mtu = Some(be32(body, 4)),
            (OPT_PREFIX, 32) if r.prefixes.len() < 16 => {
                let b: [u8; 16] = body[16..32].try_into().ok()?;
                r.prefixes.push(PrefixInfo {
                    prefix: Ipv6Addr::from(b),
                    len: body[2],
                    on_link: body[3] & 0x80 != 0,
                    autonomous: body[3] & 0x40 != 0,
                    valid_secs: be32(body, 4),
                    preferred_secs: be32(body, 8),
                });
            }
            (OPT_RDNSS, l) if l >= 24 && (l - 8) % 16 == 0 && be32(body, 4) > 0 => {
                for a in body[8..].chunks(16).take(8) {
                    let b: [u8; 16] = a.try_into().ok()?;
                    r.rdnss.push(Ipv6Addr::from(b));
                }
            }
            _ => {}
        }
        o = &o[len..];
    }
    Some(r)
}

/// The /64 of `a`.
pub fn prefix64(a: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(a) & !((1u128 << 64) - 1))
}

/// Modified EUI-64 link-local address of `mac` (RFC 4291 §2.5.1).
pub fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
        u16::from_be_bytes([mac[2], 0xff]),
        u16::from_be_bytes([0xfe, mac[3]]),
        u16::from_be_bytes([mac[4], mac[5]]),
    )
}

/// Search domains as DNS names (labels, no compression); names that do not
/// fit (labels of 1–63 bytes) are left out.
fn dnssl_names(domains: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for d in domains.iter().take(4) {
        let d = d.trim_end_matches('.');
        if d.is_empty() || d.len() > 253 || d.split('.').any(|l| l.is_empty() || l.len() > 63) {
            continue;
        }
        for l in d.split('.') {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
    }
    out
}

/// RFC 8200 §8.1 pseudo-header + the ICMPv6 message.
fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |b: &[u8]| {
        for c in b.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(msg.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 58]);
    add(msg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests;
