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

pub fn lan() -> Lan {
    Lan {
        addr: Ipv4Addr::new(192, 168, 1, 1),
        prefix: 24,
        domain: "lan",
        dhcp_range: (
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 199),
        ),
        lease_secs: 12 * 3600,
        statics: vec![StaticLease {
            mac: [0x52, 0x54, 0x00, 0x00, 0x00, 0x05],
            ip: Ipv4Addr::new(192, 168, 1, 10),
            hostname: Some(String::from("nas")),
        }],
    }
}

/// `key=value` from the kernel command line.
fn arg<'a>(bootargs: &'a str, key: &str) -> Option<&'a str> {
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
/// `ecn=0` (AQM drops instead of ECN-marking), `fq_flows=1024` (flow queues;
/// `fq_flows=1` = a single CoDel queue, for A/B tests).
#[derive(Clone, Copy, Debug)]
pub struct Qos {
    pub up_kbit: Option<u64>,
    pub down_kbit: Option<u64>,
    pub overhead: u32,
    /// ECN marking in the AQM (boot argument `ecn=0` disables: drop only).
    pub ecn: bool,
    /// FQ-CoDel flow queues per port.
    pub flows: usize,
}

pub fn qos(bootargs: &str) -> Qos {
    Qos {
        up_kbit: arg_u64(bootargs, "shape_up").filter(|&r| r > 0),
        down_kbit: arg_u64(bootargs, "shape_down").filter(|&r| r > 0),
        overhead: arg_u64(bootargs, "shape_overhead").unwrap_or(0) as u32,
        ecn: arg_u64(bootargs, "ecn").is_none_or(|v| v != 0),
        flows: arg_u64(bootargs, "fq_flows")
            .filter(|&n| (1..=65536).contains(&n))
            .unwrap_or(1024) as usize,
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
