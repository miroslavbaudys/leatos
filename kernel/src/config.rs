//! Router configuration. Compiled-in defaults until the config store
//! (TOML on virtio-blk, M8) exists; the shape mirrors docs/soho-features.md.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use proto_dhcp::v4::server::StaticLease;

pub struct Lan {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub domain: &'static str,
    pub dhcp_range: (Ipv4Addr, Ipv4Addr),
    pub lease_secs: u32,
    pub statics: Vec<StaticLease>,
}

impl Lan {
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        })
    }
}

pub struct Dns {
    pub cache_entries: usize,
    pub rebind_protection: bool,
}

/// The kernel command line, stored once at boot ([`init`]).
static BOOTARGS: spin::Once<&'static str> = spin::Once::new();

pub fn init(bootargs: &'static str) {
    BOOTARGS.call_once(|| bootargs);
}

/// A command line for logs, `mgmt_pass=` values masked. Formats without
/// allocating (the boot report prints it before the heap exists).
pub struct Redacted<'a>(pub &'a str);

impl core::fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, kv) in self.0.split_whitespace().enumerate() {
            let kv = if kv.starts_with("mgmt_pass=") { "mgmt_pass=***" } else { kv };
            write!(f, "{}{kv}", if i > 0 { " " } else { "" })?;
        }
        Ok(())
    }
}

pub fn bootargs() -> &'static str {
    BOOTARGS.get().copied().unwrap_or("")
}

/// Default LAN: 192.168.1.1/24. Boot argument `lan=10.10.0.1/24` moves it
/// (needed when the upstream network uses the same subnet). The DHCP pool
/// is host .100–.199 of the subnet (clamped for small subnets), the static
/// `nas` entry host .10.
pub fn lan() -> Lan {
    let (addr, prefix) = arg(bootargs(), "lan")
        .and_then(parse_cidr)
        .filter(|&(_, p)| (8..=29).contains(&p))
        .unwrap_or((Ipv4Addr::new(192, 168, 1, 1), 24));
    let mask = u32::MAX << (32 - prefix as u32);
    let net = u32::from(addr) & mask;
    let last = net | !mask; // broadcast
    let host = |n: u32| Ipv4Addr::from((net + n).min(last - 1));
    let (lo, hi) = if !mask >= 200 { (100, 199) } else { (2, !mask - 1) };
    Lan {
        addr,
        prefix,
        domain: "lan",
        dhcp_range: (host(lo), host(hi)),
        lease_secs: 12 * 3600,
        statics: vec![StaticLease {
            mac: [0x52, 0x54, 0x00, 0x00, 0x00, 0x05],
            ip: host(10),
            hostname: Some(String::from("nas")),
        }],
    }
}

/// `a.b.c.d/len`
fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (a, p) = s.split_once('/')?;
    Some((a.parse().ok()?, p.parse().ok()?))
}

/// Management web interface (`net::mgmt`): HTTP on port 80.
pub struct Mgmt {
    /// Also listen on the WAN (`mgmt=wan`). Development only: a router's
    /// management belongs on the LAN.
    pub on_wan: bool,
    /// HTTP Basic password (user `admin`), `mgmt_pass=`. Without one,
    /// pages are readable but upgrades are refused.
    pub password: Option<&'static str>,
}

pub fn mgmt() -> Mgmt {
    Mgmt {
        on_wan: arg(bootargs(), "mgmt") == Some("wan"),
        password: arg(bootargs(), "mgmt_pass").filter(|p| !p.is_empty()),
    }
}

/// `key=value` from the kernel command line.
fn arg<'a>(bootargs: &'a str, key: &str) -> Option<&'a str> {
    // `key=value` only: `lan=` must not match `lan_x=`.
    bootargs
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn arg_u64(bootargs: &str, key: &str) -> Option<u64> {
    arg(bootargs, key).and_then(|v| v.parse().ok())
}

/// Shaping (docs/bufferbloat-cake.md): set rates slightly below the real
/// bottleneck so the queue forms in rrouter. Boot arguments, in kbit/s:
/// `shape_up=42000` (WAN egress), `shape_down=50000` (LAN egress, i.e. the
/// download direction), `shape_overhead=38` (bytes per packet, default 0),
/// `ecn_up=0|1` / `ecn_down=0|1` (ECN marking instead of dropping, per
/// direction; default up off, down on; `ecn=` sets both), `qdisc=cake|fq_codel|codel`
/// (egress AQM, default `cake`; `codel` = one queue, for A/B tests) and
/// `isolation=triple-isolate|dual-srchost|dual-dsthost|flows` (CAKE's
/// fairness, default `triple-isolate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AqmKind {
    Cake,
    FqCodel,
    /// FQ-CoDel with one queue: plain CoDel.
    Codel,
}

#[derive(Clone, Copy, Debug)]
pub struct Qos {
    pub up_kbit: Option<u64>,
    pub down_kbit: Option<u64>,
    pub overhead: u32,
    /// ECN marking in the AQM, per direction. Default (as OpenWrt's SQM):
    /// **off for upload** (WAN egress): the senders are local, a drop costs
    /// one retransmission on a short path and works on every path, while
    /// marks can be bleached on the way (seen on the developer's line,
    /// docs/bufferbloat-cake.md); **on for download** (LAN egress), where a
    /// mark saves data that already crossed the bottleneck.
    pub ecn_up: bool,
    pub ecn_down: bool,
    pub aqm: AqmKind,
    pub isolation: qdisc::cake::Isolation,
}

pub fn qos(bootargs: &str) -> Qos {
    Qos {
        up_kbit: arg_u64(bootargs, "shape_up").filter(|&r| r > 0),
        down_kbit: arg_u64(bootargs, "shape_down").filter(|&r| r > 0),
        overhead: arg_u64(bootargs, "shape_overhead").unwrap_or(0) as u32,
        ecn_up: arg_u64(bootargs, "ecn_up")
            .or(arg_u64(bootargs, "ecn"))
            .is_some_and(|v| v != 0),
        ecn_down: arg_u64(bootargs, "ecn_down")
            .or(arg_u64(bootargs, "ecn"))
            .is_none_or(|v| v != 0),
        aqm: match arg(bootargs, "qdisc") {
            Some("fq_codel") => AqmKind::FqCodel,
            Some("codel") => AqmKind::Codel,
            _ => AqmKind::Cake,
        },
        isolation: match arg(bootargs, "isolation") {
            Some("flows") => qdisc::cake::Isolation::Flows,
            Some("dual-srchost") => qdisc::cake::Isolation::DualSrcHost,
            Some("dual-dsthost") => qdisc::cake::Isolation::DualDstHost,
            _ => qdisc::cake::Isolation::Triple,
        },
    }
}

impl Qos {
    pub fn rate(&self, kbit: Option<u64>) -> Option<qdisc::shaper::Rate> {
        kbit.map(|k| qdisc::shaper::Rate {
            overhead: self.overhead,
            ..qdisc::shaper::Rate::kbit(k)
        })
    }
}

/// Hybrid-idle spin window (docs/bufferbloat-cake.md §3.2). Under QEMU on
/// macOS/HVF an idle vCPU wakes from `wfi` up to ~3 ms late (measured,
/// roughly 25 % of the sleep, capped at ~3 ms), so deadlines closer than
/// 4 ms are spun out and longer sleeps wake 4 ms early. Real hardware wakes
/// in microseconds: no spinning. Override: boot argument `idle_spin_us=N`.
pub fn idle_spin_window(virtual_machine: bool, bootargs: &str) -> core::time::Duration {
    if let Some(us) = arg_u64(bootargs, "idle_spin_us") {
        return core::time::Duration::from_micros(us);
    }
    if virtual_machine {
        core::time::Duration::from_micros(4_000)
    } else {
        core::time::Duration::ZERO
    }
}

pub fn dns() -> Dns {
    Dns {
        cache_entries: 4096,
        rebind_protection: true,
    }
}
