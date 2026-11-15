//! Router configuration (docs/config-and-storage.md §5): one
//! [`schema::Config`] built at boot, read by every service.
//!
//! ```text
//! compiled-in defaults ← stored config.toml (`crate::store`) ← boot arguments
//! ```
//!
//! [`init`] keeps the command line (before the heap exists); [`load`]
//! builds the config once the store is found (after PCI). [`lan`], [`dns`],
//! [`qos`] and [`mgmt`] are views of it in the types the services use.
//! [`base`] is the config without boot arguments: what `GET /api/config`
//! shows and a save starts from. Boot argument `config=defaults` ignores
//! the store (recovery).

use crate::println;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use proto_dhcp::v4::server::StaticLease;

/// The `config` crate (`crates/config`): schema, defaults, validation.
pub use ::config as schema;

/// The kernel command line, stored once at boot ([`init`]).
static BOOTARGS: spin::Once<&'static str> = spin::Once::new();
// Replaced as a whole when a saved config is applied live ([`apply`]).
// Readers take a snapshot (`Arc`), never hold the lock.
static CONFIG: spin::Mutex<Option<Arc<schema::Config>>> = spin::Mutex::new(None);
static BASE: spin::Mutex<Option<Arc<schema::Config>>> = spin::Mutex::new(None);
static SOURCE: spin::Mutex<String> = spin::Mutex::new(String::new());
static TRIAL: spin::Once<(config_store::Slot, config_store::RecordHeader)> = spin::Once::new();

pub fn init(bootargs: &'static str) {
    BOOTARGS.call_once(|| bootargs);
}

pub fn bootargs() -> &'static str {
    BOOTARGS.get().copied().unwrap_or("")
}

/// Build the configuration (needs the heap): defaults or the store's
/// `config.toml`, then boot arguments. Called once, before any service
/// starts and before anything reads [`get`].
/// `virtual_machine`: the lab's fixtures (the `nas` reservation) are added
/// to the defaults only there, never on hardware.
pub fn load(store: Option<&mut crate::store::Store>, virtual_machine: bool) {
    let (stored, source) = stored(store);
    let from_store = stored.is_some();
    let mut c = stored.unwrap_or_default();
    if !from_store && virtual_machine {
        add_lab_reservation(&mut c);
    }
    *BASE.lock() = Some(Arc::new(c.clone()));
    apply_bootargs(&mut c, bootargs());
    println!(
        "  config          : {source}, lan {}, dhcp {}–{}, {} reservation(s)",
        c.lan.ipv4,
        c.lan.dhcp_range().0,
        c.lan.dhcp_range().1,
        c.lan.dhcp.statics.len()
    );
    // Boot arguments are a developer override: report what validation
    // would reject, but run with it.
    if let Err(issues) = c.validate() {
        for i in issues {
            println!("  config          : warning: {i}");
        }
    }
    *SOURCE.lock() = source;
    *CONFIG.lock() = Some(Arc::new(c));
}

/// `config.toml` from the store's `config` area, and where the config came
/// from (for the log and the status page). Never fails the boot: any
/// problem means defaults (docs/config-and-storage.md §1).
///
/// Trials (§6): a trial record is marked booted, then used ([`trial`]);
/// one found already marked was never confirmed (the router lost power,
/// crashed or was reset first), so it is erased and the previous record
/// is used.
fn stored(store: Option<&mut crate::store::Store>) -> (Option<schema::Config>, String) {
    use crate::executor::block_on;
    use crate::store::{describe, slot_name};
    use config_store::{FLAG_BOOTED, FLAG_TRIAL};
    if arg(bootargs(), "config") == Some("defaults") {
        return (None, String::from("defaults (config=defaults: store ignored)"));
    }
    let Some(store) = store else {
        return (None, String::from("defaults (no store)"));
    };
    let mut reverted = None;
    let rec = loop {
        let (rec, state) = match block_on(store.read_current("config", schema::VERSION)) {
            Ok(r) => r,
            Err(e) => return (None, alloc::format!("defaults (store: {e})")),
        };
        println!(
            "  store config    : slot A {}, slot B {}",
            describe(&state.a),
            describe(&state.b)
        );
        let Some(rec) = rec else { break None };
        if !rec.header.is_trial() {
            break Some(rec);
        }
        let h = rec.header;
        if h.flags & FLAG_BOOTED == 0 && reverted.is_none() {
            let marked = h.with_flags(FLAG_TRIAL | FLAG_BOOTED);
            match block_on(store.rewrite_header("config", rec.slot, marked)) {
                Ok(()) => {
                    TRIAL.call_once(|| (rec.slot, marked));
                    println!(
                        "  config          : trial (slot {}, seq {}): confirm within {} s or the router reverts",
                        slot_name(rec.slot),
                        h.seq,
                        trial_secs()
                    );
                    break Some(rec);
                }
                Err(e) => println!("  config          : cannot mark the trial booted ({e}): reverting"),
            }
        } else {
            println!(
                "  config          : trial (slot {}, seq {}) was never confirmed: reverting",
                slot_name(rec.slot),
                h.seq
            );
        }
        if reverted.is_some() {
            // Erasing did not take: never boot an unconfirmable trial.
            return (None, String::from("defaults (trial could not be reverted)"));
        }
        if let Err(e) = block_on(store.erase("config", rec.slot)) {
            println!("  config          : erasing the trial failed: {e}");
        }
        reverted = Some(h.seq);
    };
    let note = reverted
        .map(|seq| alloc::format!(", trial seq {seq} reverted"))
        .unwrap_or_default();
    let Some(rec) = rec else {
        return (None, alloc::format!("defaults (store has no valid config{note})"));
    };
    let parsed = core::str::from_utf8(&rec.payload)
        .map_err(|_| String::from("not UTF-8"))
        .and_then(|t| schema::parse(t).map_err(|e| alloc::format!("{e}")));
    match parsed {
        Ok(c) => (
            Some(c),
            alloc::format!(
                "stored (slot {}, seq {}{note})",
                slot_name(rec.slot),
                rec.header.seq
            ),
        ),
        Err(e) => (
            None,
            alloc::format!(
                "defaults (stored config slot {} rejected: {}{note})",
                slot_name(rec.slot),
                e.replace('\n', "; ")
            ),
        ),
    }
}

/// The trial this boot runs (its slot and marked header), if the current
/// config is one: the web interface must confirm it within [`trial_secs`].
pub fn trial() -> Option<(config_store::Slot, config_store::RecordHeader)> {
    TRIAL.get().copied()
}

/// Seconds a trial waits for Confirm: 120, boot argument `trial_secs=`
/// (tests).
pub fn trial_secs() -> u64 {
    arg_u64(bootargs(), "trial_secs")
        .filter(|&s| s >= 5)
        .unwrap_or(120)
}

/// The config without boot-argument overrides ([`load`] must have run).
pub fn base() -> Arc<schema::Config> {
    BASE.lock().clone().expect("config::load not called")
}

/// Where the config came from, e.g. `stored (slot B, seq 2)`.
pub fn source() -> String {
    SOURCE.lock().clone()
}

/// A saved config becomes the running one without a reboot: `stored` is
/// the new base (what the store now holds); boot arguments still apply on
/// top. The services re-read their views ([`lan`], [`dns`], [`qos`]) and
/// reconfigure (`net::svc`). Not for trial changes (LAN address,
/// management): those reboot.
pub fn apply(stored: schema::Config, source: String) {
    let mut c = stored.clone();
    apply_bootargs(&mut c, bootargs());
    *BASE.lock() = Some(Arc::new(stored));
    *CONFIG.lock() = Some(Arc::new(c));
    *SOURCE.lock() = source;
}

/// The configuration ([`load`] must have run).
pub fn get() -> Arc<schema::Config> {
    CONFIG.lock().clone().expect("config::load not called")
}

/// Config fields a boot argument sets in this boot, as (field path, the
/// argument): such a field ignores the stored value, so the web form must
/// say so. Same keys as [`apply_bootargs`].
pub fn overrides() -> Vec<(&'static str, &'static str)> {
    const MAP: &[(&str, &str)] = &[
        ("lan", "lan.ipv4"),
        ("wan_vlan", "wan.vlan"),
        ("wan_pcp", "wan.vlan_pcp"),
        ("shape_up", "shaping.up_kbit"),
        ("shape_down", "shaping.down_kbit"),
        ("shape_overhead", "shaping.overhead"),
        ("ecn_up", "shaping.ecn_up"),
        ("ecn_down", "shaping.ecn_down"),
        ("ecn", "shaping.ecn_up"),
        ("ecn", "shaping.ecn_down"),
        ("qdisc", "shaping.qdisc"),
        ("isolation", "shaping.isolation"),
        ("ntp", "time.ntp_servers"),
    ];
    let args = bootargs();
    let mut v = Vec::new();
    for kv in args.split_whitespace() {
        let key = kv.split('=').next().unwrap_or("");
        for &(k, path) in MAP {
            // ecn= only where no ecn_up= / ecn_down= takes precedence.
            let shadowed = k == "ecn" && arg(args, path.trim_start_matches("shaping.")).is_some();
            if k == key && !shadowed && !v.iter().any(|&(p, _)| p == path) {
                v.push((path, kv));
            }
        }
    }
    if arg(args, "mgmt") == Some("wan") {
        v.push(("mgmt.on_wan", "mgmt=wan"));
    }
    v
}

/// Boot arguments on top of the defaults or the stored config. Invalid
/// values are ignored, as before the config existed.
fn apply_bootargs(c: &mut schema::Config, args: &str) {
    if let Some(net) = arg(args, "lan")
        .and_then(|v| v.parse::<schema::Cidr>().ok())
        .filter(|n| (8..=29).contains(&n.prefix))
    {
        c.lan.ipv4 = net;
        // Settings tied to the old subnet would point outside the new one.
        if c.lan
            .dhcp
            .range
            .is_some_and(|[lo, hi]| !net.is_host(lo) || !net.is_host(hi))
        {
            c.lan.dhcp.range = None;
        }
        c.lan
            .dhcp
            .statics
            .retain(|s| net.is_host(s.ip) && s.ip != net.addr);
    }
    match arg_u64(args, "wan_vlan") {
        Some(0) => c.wan.vlan = None,
        Some(v) if v <= u64::from(schema::MAX_VLAN_ID) => c.wan.vlan = Some(v as u16),
        _ => {}
    }
    if let Some(p) = arg_u64(args, "wan_pcp").filter(|&p| p <= 7) {
        c.wan.vlan_pcp = p as u8;
    }
    let s = &mut c.shaping;
    if let Some(r) = arg_u64(args, "shape_up") {
        s.up_kbit = Some(r).filter(|&r| r > 0);
    }
    if let Some(r) = arg_u64(args, "shape_down") {
        s.down_kbit = Some(r).filter(|&r| r > 0);
    }
    if let Some(o) = arg_u64(args, "shape_overhead") {
        s.overhead = o as u32;
    }
    if let Some(v) = arg_u64(args, "ecn_up").or(arg_u64(args, "ecn")) {
        s.ecn_up = v != 0;
    }
    if let Some(v) = arg_u64(args, "ecn_down").or(arg_u64(args, "ecn")) {
        s.ecn_down = v != 0;
    }
    match arg(args, "qdisc") {
        Some("cake") => s.qdisc = schema::Qdisc::Cake,
        Some("fq_codel") => s.qdisc = schema::Qdisc::FqCodel,
        Some("codel") => s.qdisc = schema::Qdisc::Codel,
        _ => {}
    }
    match arg(args, "isolation") {
        Some("triple-isolate") => s.isolation = schema::Isolation::Triple,
        Some("dual-srchost") => s.isolation = schema::Isolation::DualSrcHost,
        Some("dual-dsthost") => s.isolation = schema::Isolation::DualDstHost,
        Some("flows") => s.isolation = schema::Isolation::Flows,
        _ => {}
    }
    if arg(args, "mgmt") == Some("wan") {
        c.mgmt.on_wan = true;
    }
    if let Some(list) = arg(args, "ntp") {
        // `ntp=` alone (or `ntp=off`): no SNTP.
        c.time.ntp_servers = list
            .split(',')
            .filter(|n| !n.is_empty() && *n != "off")
            .map(String::from)
            .collect();
    }
}

/// Without a stored config, on a virtual machine: the lab's `nas` reservation (host .10, MAC
/// 52:54:00:00:00:05), which `scripts/lab-test.sh` resolves as `nas.lan`.
fn add_lab_reservation(c: &mut schema::Config) {
    let ip = c.lan.ipv4.host(10);
    if c.lan.ipv4.is_host(ip) && ip != c.lan.ipv4.addr {
        c.lan.dhcp.statics.push(schema::StaticLease {
            mac: schema::Mac([0x52, 0x54, 0x00, 0x00, 0x00, 0x05]),
            ip,
            hostname: Some(String::from("nas")),
        });
    }
}

/// A command line for logs, `mgmt_pass=` values masked. Formats without
/// allocating (the boot report prints it before the heap exists).
pub struct Redacted<'a>(pub &'a str);

impl core::fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, kv) in self.0.split_whitespace().enumerate() {
            let kv = if kv.starts_with("mgmt_pass=") {
                "mgmt_pass=***"
            } else {
                kv
            };
            write!(f, "{}{kv}", if i > 0 { " " } else { "" })?;
        }
        Ok(())
    }
}

pub struct Lan {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub domain: String,
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

/// The LAN: `[lan]` (default 192.168.1.1/24, boot argument
/// `lan=10.10.0.1/24`), pool `lan.dhcp.range` or hosts .100–.199.
pub fn lan() -> Lan {
    let c = get();
    let l = &c.lan;
    Lan {
        addr: l.ipv4.addr,
        prefix: l.ipv4.prefix,
        domain: l.domain.clone(),
        dhcp_range: l.dhcp_range(),
        lease_secs: l.dhcp.lease_secs,
        statics: l
            .dhcp
            .statics
            .iter()
            .map(|s| StaticLease {
                mac: s.mac.0,
                ip: s.ip,
                hostname: s.hostname.clone(),
            })
            .collect(),
    }
}

/// The WAN's 802.1Q tag (TCI: VLAN ID + priority), `None` = untagged:
/// `[wan] vlan` / `vlan_pcp`, boot arguments `wan_vlan=848` (`0` = off),
/// `wan_pcp=0..7`.
pub fn wan_tci() -> Option<u16> {
    let c = get();
    c.wan
        .vlan
        .map(|v| fwd::wire::vlan_tci_of(v, c.wan.vlan_pcp))
}

pub struct Dns {
    pub cache_entries: usize,
    pub rebind_protection: bool,
}

pub fn dns() -> Dns {
    let c = get();
    let d = &c.dns;
    Dns {
        cache_entries: d.cache_entries as usize,
        rebind_protection: d.rebind_protection,
    }
}

/// Management web interface (`net::mgmt`): HTTP on port 80.
pub struct Mgmt {
    /// Also listen on the WAN (`mgmt.on_wan`, boot argument `mgmt=wan`).
    /// Development only: a router's management belongs on the LAN.
    pub on_wan: bool,
    /// HTTP Basic password (user `admin`), boot argument `mgmt_pass=`
    /// (not part of the stored config yet). Without one, pages are
    /// readable but upgrades are refused.
    pub password: Option<&'static str>,
}

pub fn mgmt() -> Mgmt {
    Mgmt {
        on_wan: get().mgmt.on_wan,
        password: arg(bootargs(), "mgmt_pass").filter(|p| !p.is_empty()),
    }
}

/// SNTP servers (`time.ntp_servers`, boot argument `ntp=a,b`).
pub fn ntp_servers() -> Vec<String> {
    get().time.ntp_servers.clone()
}

/// Watchdog settings (boot arguments only: platform and debugging knobs).
#[derive(Clone, Copy, Debug)]
pub struct Watchdog {
    /// `watchdog=0` turns the software check and the hardware timer off
    /// (debugging with gdb, where a stopped core looks hung).
    pub enabled: bool,
    /// Hardware timeout in seconds (`watchdog_secs=`, 10–600, default 30).
    pub hw_secs: u32,
}

pub fn watchdog() -> Watchdog {
    let args = bootargs();
    Watchdog {
        enabled: arg_u64(args, "watchdog") != Some(0),
        hw_secs: arg_u64(args, "watchdog_secs")
            .filter(|s| (10..=600).contains(s))
            .map_or(30, |s| s as u32),
    }
}

/// `panic=halt`: a panic or an unhandled exception halts (as before, for
/// debugging) instead of rebooting the machine.
pub fn panic_halts() -> bool {
    arg(bootargs(), "panic") == Some("halt")
}

/// Boot argument `cores=N`: use at most N cores (default: all, up to
/// `smp::MAX_CORES`). `cores=1` runs everything on the boot core (A/B tests).
pub fn cores() -> Option<usize> {
    arg_u64(bootargs(), "cores")
        .map(|c| c as usize)
        .filter(|&c| c >= 1)
}

/// `key=value` from the kernel command line.
/// The boot argument `key=value`'s value (works before [`load`]).
pub fn arg_of(key: &str) -> Option<&'static str> {
    arg(bootargs(), key)
}

fn arg<'a>(bootargs: &'a str, key: &str) -> Option<&'a str> {
    // `key=value` only: `lan=` must not match `lan_x=`.
    bootargs
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn arg_u64(bootargs: &str, key: &str) -> Option<u64> {
    arg(bootargs, key).and_then(|v| v.parse().ok())
}

/// Shaping (docs/bufferbloat-cake.md): `[shaping]`, or boot arguments in
/// kbit/s: `shape_up=42000` (WAN egress), `shape_down=50000` (LAN egress,
/// i.e. the download direction), `shape_overhead=38` (bytes per packet,
/// default 0), `ecn_up=0|1` / `ecn_down=0|1` (ECN marking instead of
/// dropping, per direction; default up off, down on; `ecn=` sets both),
/// `qdisc=cake|fq_codel|codel` (egress AQM, default `cake`; `codel` = one
/// queue, for A/B tests) and
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
    /// The WAN is VLAN-tagged: its frames are 4 bytes longer on the wire
    /// than the qdisc sees (the tag is added after it, in
    /// `datapath::flush_port`), so the upload shaper adds them to
    /// `overhead`. `shape_overhead` must not include the tag.
    pub wan_vlan: bool,
}

pub fn qos() -> Qos {
    let c = get();
    let s = &c.shaping;
    Qos {
        up_kbit: s.up_kbit,
        down_kbit: s.down_kbit,
        overhead: s.overhead,
        ecn_up: s.ecn_up,
        ecn_down: s.ecn_down,
        aqm: match s.qdisc {
            schema::Qdisc::Cake => AqmKind::Cake,
            schema::Qdisc::FqCodel => AqmKind::FqCodel,
            schema::Qdisc::Codel => AqmKind::Codel,
        },
        isolation: match s.isolation {
            schema::Isolation::Triple => qdisc::cake::Isolation::Triple,
            schema::Isolation::DualSrcHost => qdisc::cake::Isolation::DualSrcHost,
            schema::Isolation::DualDstHost => qdisc::cake::Isolation::DualDstHost,
            schema::Isolation::Flows => qdisc::cake::Isolation::Flows,
        },
        wan_vlan: c.wan.vlan.is_some(),
    }
}

impl Qos {
    /// The shaper of a port: WAN egress (`up`) at the upload rate, LAN
    /// egress at the download rate; unset = not shaped.
    pub fn port_rate(&self, up: bool) -> Option<qdisc::shaper::Rate> {
        let kbit = if up { self.up_kbit } else { self.down_kbit };
        let tag = if up && self.wan_vlan {
            fwd::wire::VLAN_HDR as u32
        } else {
            0
        };
        kbit.map(|k| qdisc::shaper::Rate {
            overhead: self.overhead + tag,
            ..qdisc::shaper::Rate::kbit(k)
        })
    }
}

/// Hybrid-idle spin window (docs/bufferbloat-cake.md §3.2). Under QEMU on
/// macOS/HVF an idle vCPU wakes from `wfi` up to ~3 ms late (measured,
/// roughly 25 % of the sleep, capped at ~3 ms), so deadlines closer than
/// 4 ms are spun out and longer sleeps wake 4 ms early. Real hardware wakes
/// in microseconds: no spinning. Override: boot argument `idle_spin_us=N`.
/// A platform tuning knob, so a boot argument only (not in `config.toml`).
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
