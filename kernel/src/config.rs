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

/// Hybrid-idle spin window (docs/bufferbloat-cake.md §3.2). Under QEMU on
/// macOS/HVF an idle vCPU wakes from `wfi` up to ~3 ms late (measured,
/// roughly 25 % of the sleep, capped at ~3 ms), so deadlines closer than
/// 4 ms are spun out and longer sleeps wake 4 ms early. Real hardware wakes
/// in microseconds: no spinning.
pub fn idle_spin_window(virtual_machine: bool) -> core::time::Duration {
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
