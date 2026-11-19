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
/// The NICs found at bring-up (`set_ports`): networks on a port this
/// machine lacks are left out of [`networks`].
static PORTS_PRESENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);

/// Port names by index, in PCI order: the first NIC is the WAN, the
/// others the LAN ports (docs/config-v2.md, `network.ports`).
pub use schema::PORTS;

/// A port's index in [`PORTS`] (= `net::shared::Shared::ports`).
pub fn port_index(name: &str) -> Option<usize> {
    PORTS.iter().position(|p| *p == name)
}

/// Bring-up found `n` NICs (ports `PORTS[..n]`).
pub fn set_ports(n: usize) {
    PORTS_PRESENT.store(n, core::sync::atomic::Ordering::Relaxed);
}

fn port_present(i: usize) -> bool {
    i < PORTS_PRESENT.load(core::sync::atomic::Ordering::Relaxed)
}
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
    if let Some(n) = c.lan() {
        println!(
            "  config          : {source}, lan {}, dhcp {}–{}, {} reservation(s)",
            n.ipv4,
            n.dhcp_range().0,
            n.dhcp_range().1,
            n.dhcp.statics.len()
        );
    }
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
        .and_then(|t| schema::parse(t).map_err(|e| alloc::format!("{e}")))
        .and_then(|c| match supported(&c) {
            Ok(()) => Ok(c),
            Err(e) => Err(alloc::format!("{e}")),
        });
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

/// Settings this kernel does not implement yet (`schema::Config::
/// unsupported`) as an error: a save with them is refused, a stored config
/// with them is not used.
pub fn supported(c: &schema::Config) -> Result<(), schema::Error> {
    let u = c.unsupported();
    if u.is_empty() { Ok(()) } else { Err(schema::Error::Invalid(u)) }
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
pub fn overrides() -> Vec<(String, &'static str)> {
    const MAP: &[(&str, &str)] = &[
        ("lan", "network.*.ipv4"),
        ("wan_vlan", "wan.vlan"),
        ("wan_pcp", "wan.vlan_pcp"),
        ("wan_mode", "wan.mode"),
        ("pppoe_user", "wan.pppoe.username"),
        ("pppoe_pass", "wan.pppoe.password"),
        ("pppoe_service", "wan.pppoe.service"),
        ("pppoe_ac", "wan.pppoe.ac_name"),
        ("pppoe_mtu", "wan.pppoe.mtu"),
        ("wan_ip", "wan.static.ipv4"),
        ("wan_gw", "wan.static.gateway"),
        ("wan_dns", "wan.static.dns"),
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
        ("dns", "dns.upstreams"),
        ("dns_tls", "dns.tls"),
        ("dns_prefetch", "dns.prefetch"),
        ("dns_stale", "dns.stale_secs"),
    ];
    let args = bootargs();
    let mut v = Vec::new();
    for kv in args.split_whitespace() {
        let key = kv.split('=').next().unwrap_or("");
        for &(k, path) in MAP {
            // ecn= only where no ecn_up= / ecn_down= takes precedence.
            let shadowed = k == "ecn" && arg(args, path.trim_start_matches("shaping.")).is_some();
            // `lan=` sets the first network.
            let path = match base().lan() {
                Some(n) => path.replace('*', &n.name),
                None => String::from(path),
            };
            if k == key && !shadowed && !v.iter().any(|(p, _)| *p == path) {
                v.push((path, if k == "pppoe_pass" { "pppoe_pass=***" } else { kv }));
            }
        }
    }
    if arg(args, "mgmt") == Some("wan") {
        v.push((String::from("mgmt.on_wan"), "mgmt=wan"));
    }
    v
}

/// Boot arguments on top of the defaults or the stored config. Invalid
/// values are ignored, as before the config existed.
fn apply_bootargs(c: &mut schema::Config, args: &str) {
    if let Some(net) = arg(args, "lan")
        .and_then(|v| v.parse::<schema::Cidr>().ok())
        .filter(|n| (8..=29).contains(&n.prefix))
        && let Some(lan) = c.networks.first_mut()
    {
        lan.ipv4 = net;
        // Settings tied to the old subnet would point outside the new one.
        if lan
            .dhcp
            .range
            .is_some_and(|[lo, hi]| !net.is_host(lo) || !net.is_host(hi))
        {
            lan.dhcp.range = None;
        }
        lan.dhcp
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
    match arg(args, "wan_mode") {
        Some("pppoe") => c.wan.mode = schema::WanMode::Pppoe,
        Some("dhcp") => c.wan.mode = schema::WanMode::Dhcp,
        Some("static") => c.wan.mode = schema::WanMode::Static,
        _ => {}
    }
    // A static WAN: `wan_ip=a.b.c.d/len wan_gw=a.b.c.d [wan_dns=a,b]`
    // (`wan_dns=` = none). Each replaces its field of a stored
    // `[wan.static]`; without one, address and gateway are both needed.
    let ip = arg(args, "wan_ip").and_then(|v| v.parse::<schema::Cidr>().ok());
    let gw = arg(args, "wan_gw").and_then(|v| v.parse::<core::net::Ipv4Addr>().ok());
    let dns = arg(args, "wan_dns").map(|l| {
        l.split(',')
            .filter_map(|d| d.parse::<core::net::Ipv4Addr>().ok())
            .collect::<Vec<_>>()
    });
    match (&mut c.wan.static_ip, ip, gw) {
        (Some(s), ip, gw) => {
            if let Some(ip) = ip {
                s.ipv4 = ip;
            }
            if let Some(gw) = gw {
                s.gateway = gw;
            }
            if let Some(dns) = dns {
                s.dns = dns;
            }
        }
        (None, Some(ipv4), Some(gateway)) => {
            c.wan.static_ip = Some(schema::WanStatic {
                ipv4,
                gateway,
                dns: dns.unwrap_or_default(),
            })
        }
        _ => {}
    }
    let p = &mut c.wan.pppoe;
    if let Some(u) = arg(args, "pppoe_user") {
        p.username = String::from(u);
    }
    if let Some(pw) = arg(args, "pppoe_pass") {
        p.password = Some(String::from(pw));
    }
    if let Some(v) = arg(args, "pppoe_service") {
        p.service = String::from(v);
    }
    if let Some(v) = arg(args, "pppoe_ac") {
        p.ac_name = String::from(v);
    }
    if let Some(m) = arg_u64(args, "pppoe_mtu").filter(|m| (1280..=1500).contains(m)) {
        p.mtu = m as u16;
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
    // `dns=1.1.1.1#cloudflare-dns.com,1.0.0.1#cloudflare-dns.com`; `dns=`
    // alone: the WAN lease's servers again. Entries that do not parse are
    // ignored.
    if let Some(list) = arg(args, "dns") {
        c.dns.upstreams = list
            .split(',')
            .filter(|u| schema::Upstream::parse(u).is_ok())
            .map(String::from)
            .collect();
    }
    if let Some(v) = arg_u64(args, "dns_tls") {
        c.dns.tls = v != 0;
    }
    if let Some(v) = arg_u64(args, "dns_prefetch") {
        c.dns.prefetch = v != 0;
    }
    // Seconds; validated with the rest (at most a week).
    if let Some(v) = arg_u64(args, "dns_stale") {
        c.dns.stale_secs = v.min(schema::MAX_STALE_SECS as u64) as u32;
    }
    // Strict fails closed: servers without a certificate name cannot be
    // used over TLS and are left out, never asked in plain text; with none
    // left, every query gets SERVFAIL.
    if c.dns.tls {
        c.dns.upstreams.retain(|u| schema::Upstream::parse(u).is_ok_and(|u| u.name.is_some()));
    }
}

/// Without a stored config, on a virtual machine: the lab's `nas` reservation (host .10, MAC
/// 52:54:00:00:00:05), which `scripts/lab-test.sh` resolves as `nas.lan`.
fn add_lab_reservation(c: &mut schema::Config) {
    let Some(lan) = c.networks.first_mut() else { return };
    let ip = lan.ipv4.host(10);
    if lan.ipv4.is_host(ip) && ip != lan.ipv4.addr {
        lan.dhcp.statics.push(schema::StaticLease {
            mac: schema::Mac([0x52, 0x54, 0x00, 0x00, 0x00, 0x05]),
            ip,
            hostname: Some(String::from("nas")),
        });
    }
}

/// A command line for logs, `mgmt_pass=` and `pppoe_pass=` values masked. Formats without
/// allocating (the boot report prints it before the heap exists).
pub struct Redacted<'a>(pub &'a str);

impl core::fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, kv) in self.0.split_whitespace().enumerate() {
            let kv = if kv.starts_with("mgmt_pass=") {
                "mgmt_pass=***"
            } else if kv.starts_with("pppoe_pass=") {
                "pppoe_pass=***"
            } else {
                kv
            };
            write!(f, "{}{kv}", if i > 0 { " " } else { "" })?;
        }
        Ok(())
    }
}

/// One network as the datapath and the services use it
/// (docs/config-v2.md): the first is the LAN (`lan=` applies to it).
#[derive(Clone)]
pub struct Lan {
    pub name: String,
    /// Its port: the index in [`PORTS`] (1 = `lan0`).
    pub port: usize,
    /// 802.1Q VLAN ID on its port, 0 = untagged.
    pub vid: u16,
    pub addr: Ipv4Addr,
    pub prefix: u8,
    /// The network's DNS domain (its own `domain`, else `dns.domain`).
    pub domain: String,
    /// Serve DHCP.
    pub dhcp: bool,
    pub dhcp_range: (Ipv4Addr, Ipv4Addr),
    pub lease_secs: u32,
    pub statics: Vec<StaticLease>,
    /// Firewall zone index ([`firewall`]) and name.
    pub zone: u8,
    pub zone_name: String,
    /// The web interface is reachable from this network's zone.
    pub mgmt: bool,
    /// Enabled `[[route]]`s through a router on this network: (subnet,
    /// prefix length, router), for DHCP option 121 and the router stack.
    pub routes: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
}

impl Lan {
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let m = u32::from(self.netmask());
        u32::from(ip) & m == u32::from(self.addr) & m
    }
}

/// Zone names by index: `wan` is 0, then `lan` (built in or defined), then
/// the other defined zones in their order.
fn zone_names(c: &schema::Config) -> Vec<String> {
    let mut v = alloc::vec![String::from(schema::ZONE_WAN), String::from(schema::ZONE_LAN)];
    for z in &c.zones {
        if !v.contains(&z.name) {
            v.push(z.name.clone());
        }
    }
    v
}

fn zone_index(names: &[String], name: &str) -> u8 {
    names.iter().position(|n| n == name).unwrap_or(1) as u8
}

/// A network's port index: its (only) port, if this machine has it.
fn network_port(n: &schema::Network) -> Option<usize> {
    n.ports.first().and_then(|p| port_index(p)).filter(|&i| i > 0 && port_present(i))
}

/// The networks, in config order (the first is the LAN), without those
/// on a port this machine lacks ([`missing_networks`]).
pub fn networks() -> Vec<Lan> {
    let c = get();
    let names = zone_names(&c);
    c.networks
        .iter()
        .filter_map(|n| Some((n, network_port(n)?)))
        .map(|(n, port)| Lan {
            name: n.name.clone(),
            port,
            vid: n.vlan,
            addr: n.ipv4.addr,
            prefix: n.ipv4.prefix,
            domain: n.domain(&c.dns).into(),
            dhcp: n.dhcp.enabled,
            dhcp_range: n.dhcp_range(),
            lease_secs: n.dhcp.lease_secs,
            statics: n
                .dhcp
                .statics
                .iter()
                .map(|s| StaticLease {
                    mac: s.mac.0,
                    ip: s.ip,
                    hostname: s.hostname.clone(),
                })
                .collect(),
            zone: zone_index(&names, &n.zone),
            zone_name: n.zone.clone(),
            mgmt: c.zone(&n.zone).is_some_and(|z| z.reaches_mgmt()),
            routes: c.network_routes(&n.name),
        })
        .collect()
}

/// Networks left out because their port is missing here: (name, port).
pub fn missing_networks() -> Vec<(String, String)> {
    get()
        .networks
        .iter()
        .filter(|n| network_port(n).is_none())
        .map(|n| (n.name.clone(), n.ports.join(",")))
        .collect()
}

/// The enabled `[[route]]`s: (subnet, prefix length, router). The
/// forwarder puts each on the interface whose subnet holds its router.
pub fn static_routes() -> Vec<(Ipv4Addr, u8, Ipv4Addr)> {
    let c = get();
    c.routes
        .iter()
        .filter(|r| r.enabled)
        .map(|r| (r.dst.0.network(), r.dst.0.prefix, r.via))
        .collect()
}

/// The enabled `[[route]]`s with their names: (name, subnet, prefix
/// length, router).
pub fn named_routes() -> Vec<(String, Ipv4Addr, u8, Ipv4Addr)> {
    let c = get();
    c.routes
        .iter()
        .filter(|r| r.enabled)
        .map(|r| (r.name.clone(), r.dst.0.network(), r.dst.0.prefix, r.via))
        .collect()
}

/// The enabled `[[route]]`s through a router on the WAN's subnet.
pub fn wan_routes() -> Vec<(Ipv4Addr, u8, Ipv4Addr)> {
    let c = get();
    c.routes
        .iter()
        .filter(|r| r.enabled && c.route_via(r) == schema::RouteVia::Wan)
        .map(|r| (r.dst.0.network(), r.dst.0.prefix, r.via))
        .collect()
}

/// The zone firewall for the forwarder (docs/config-v2.md §6): zone
/// indices as in [`networks`]. The WAN zone drops everything for the
/// router (no RST, no port unreachable, no ping reply: nothing tells a
/// scanner a host is there) except the web interface with `mgmt.on_wan`;
/// replies to the router's own clients (DHCP, DNS upstream, SNTP, ICMP
/// errors) pass before the policy (`fwd::forwarder` `input`), PPPoE is
/// not IP, and `[[firewall.rule]]`s from `wan` to `router` can open more.
/// `reject` (zone input, rule action) answers: TCP RST, else ICMP port
/// unreachable, rate-limited; the WAN zone's input is never answered,
/// only an explicit `reject` rule from `wan` is.
pub fn firewall() -> fwd::forwarder::Policy {
    use fwd::forwarder::svc;
    let c = get();
    let names = zone_names(&c);
    let mut forward = Vec::new();
    let mut input = Vec::new();
    let mut reject_input = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let z = c.zone(name).unwrap_or_else(schema::Zone::builtin_lan);
        forward.push(
            z.forward_to
                .iter()
                .map(|t| 1u32 << zone_index(&names, t))
                .fold(0, |a, b| a | b),
        );
        reject_input.push(i != 0 && z.input == schema::Policy::Reject);
        input.push(match z.input {
            _ if i == 0 => Some(if c.mgmt.on_wan { svc::MGMT } else { 0 }),
            schema::Policy::Accept => None,
            schema::Policy::Drop | schema::Policy::Reject => Some(
                z.allow
                    .iter()
                    .map(|s| match s {
                        schema::Service::Dhcp => svc::DHCP,
                        schema::Service::Dns => svc::DNS,
                        schema::Service::Ntp => svc::NTP,
                        schema::Service::Ping => svc::PING,
                        schema::Service::Mgmt => svc::MGMT,
                        schema::Service::Mdns => svc::MDNS,
                    })
                    .fold(0, |a, b| a | b),
            ),
        });
    }
    use fwd::forwarder::{Action, Rule, RuleTo, proto};
    let net = |n: &Option<schema::Net>| n.map(|n| (n.0.network(), n.0.prefix));
    let rules = c
        .firewall
        .rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| Rule {
            from: (r.from != "any").then(|| zone_index(&names, &r.from)),
            to: match r.to.as_str() {
                "any" => RuleTo::Any,
                "router" => RuleTo::Router,
                z => RuleTo::Zone(zone_index(&names, z)),
            },
            protos: match r.proto {
                schema::Proto::Tcp => proto::TCP,
                schema::Proto::Udp => proto::UDP,
                schema::Proto::TcpUdp => proto::TCP | proto::UDP,
                schema::Proto::Icmp => proto::ICMP,
                schema::Proto::Any => proto::ANY,
            },
            src: net(&r.src),
            dst: net(&r.dst),
            dport: r.dst_port.map(|p| (p.lo, p.hi)),
            action: match r.action {
                schema::Action::Accept => Action::Accept,
                schema::Action::Drop => Action::Drop,
                schema::Action::Reject => Action::Reject,
            },
        })
        .collect();
    let forwards = c
        .firewall
        .forwards
        .iter()
        .filter(|f| f.enabled)
        .map(|f| fwd::forwarder::PortForward {
            protos: match f.proto {
                schema::Proto::Udp => proto::UDP,
                schema::Proto::TcpUdp => proto::TCP | proto::UDP,
                _ => proto::TCP,
            },
            lo: f.wan_port.lo,
            hi: f.wan_port.hi,
            to: f.to.ip,
            to_port: f.to.port,
            src: net(&f.src),
            hairpin: f.hairpin,
        })
        .collect();
    let redirects = c
        .firewall
        .redirects
        .iter()
        .filter(|r| r.enabled)
        .map(|r| fwd::forwarder::Redirect {
            from: (r.from != "any").then(|| zone_index(&names, &r.from)),
            protos: match r.proto {
                schema::Proto::Tcp => proto::TCP,
                schema::Proto::TcpUdp => proto::TCP | proto::UDP,
                _ => proto::UDP,
            },
            lo: r.dst_port.lo,
            hi: r.dst_port.hi,
            to: r.to.ip,
            to_port: r.to.port,
        })
        .collect();
    // Replies from the DNS-over-TLS servers to the router's connections.
    let router_tcp_peers = if c.dns.tls {
        c.dns.upstream_list().iter().map(|u| (u.ip, u.port(true))).collect()
    } else {
        Vec::new()
    };
    fwd::forwarder::Policy {
        forward,
        input,
        reject_input,
        rules,
        forwards,
        redirects,
        router_tcp_peers,
    }
}

/// The enabled `[[mdns.reflect]]` entries for `proto_mdns::Reflector`,
/// networks as indices into [`networks`] (validated: names exist, types
/// parse).
pub fn mdns_rules() -> Vec<proto_mdns::Rule> {
    let c = get();
    let idx = |name: &str| c.networks.iter().position(|n| n.name == name);
    c.mdns
        .reflect
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| {
            Some(proto_mdns::Rule {
                from: idx(&r.from)?,
                to: r.to.iter().filter_map(|t| idx(t)).collect(),
                services: r.services.iter().filter_map(|s| proto_mdns::ServiceType::parse(s)).collect(),
            })
        })
        .collect()
}

/// Names of the enabled port forwards, in the order of the forwarder's
/// `forward_hits` (status page).
pub fn forward_names() -> Vec<String> {
    get()
        .firewall
        .forwards
        .iter()
        .filter(|f| f.enabled)
        .map(|f| f.name.clone())
        .collect()
}

/// Names of the enabled redirects, in the order of the forwarder's
/// `redirect_hits` (status page).
pub fn redirect_names() -> Vec<String> {
    get()
        .firewall
        .redirects
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.name.clone())
        .collect()
}

/// Names of the enabled rules, in the order of the forwarder's
/// `rule_hits` (status page).
pub fn rule_names() -> Vec<String> {
    get()
        .firewall
        .rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.name.clone())
        .collect()
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

/// The PPPoE client's settings when `wan.mode = "pppoe"` (boot argument
/// `wan_mode=pppoe`, credentials `pppoe_user=` / `pppoe_pass=`), else
/// `None` (DHCP on the WAN).
pub fn pppoe() -> Option<proto_pppoe::Config> {
    let c = get();
    if c.wan.mode != schema::WanMode::Pppoe {
        return None;
    }
    let p = &c.wan.pppoe;
    Some(proto_pppoe::Config {
        username: p.username.clone(),
        password: p.password.clone().unwrap_or_default(),
        service: p.service.clone(),
        ac_name: p.ac_name.clone(),
        mtu: p.mtu,
        echo_interval_secs: p.lcp_echo_interval,
        echo_failures: p.lcp_echo_failure,
    })
}

/// A fixed WAN address (`wan.mode = "static"`, `[wan.static]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WanStatic {
    pub addr: core::net::Ipv4Addr,
    pub prefix: u8,
    pub gateway: core::net::Ipv4Addr,
    /// The WAN's DNS servers (used unless `dns.upstreams` names its own).
    pub dns: Vec<core::net::Ipv4Addr>,
}

/// How the WAN gets its address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WanLink {
    /// DHCP client on the WAN Ethernet.
    Dhcp,
    /// A PPPoE session ([`pppoe`]).
    Pppoe(proto_pppoe::Config),
    /// A fixed address on the WAN Ethernet.
    Static(WanStatic),
}

impl WanLink {
    pub fn name(&self) -> &'static str {
        match self {
            WanLink::Dhcp => "DHCP",
            WanLink::Pppoe(_) => "PPPoE",
            WanLink::Static(_) => "static",
        }
    }
}

/// The WAN link in use: `wan.mode` with its settings. `mode = "static"`
/// without `[wan.static]` (only possible through boot arguments, reported
/// as a warning at boot) falls back to DHCP.
pub fn wan_link() -> WanLink {
    if let Some(p) = pppoe() {
        return WanLink::Pppoe(p);
    }
    let c = get();
    match (&c.wan.static_ip, c.wan.mode) {
        (Some(s), schema::WanMode::Static) => WanLink::Static(WanStatic {
            addr: s.ipv4.addr,
            prefix: s.ipv4.prefix,
            gateway: s.gateway,
            dns: s.dns.clone(),
        }),
        _ => WanLink::Dhcp,
    }
}

pub struct Dns {
    pub cache_entries: usize,
    pub rebind_protection: bool,
    pub prefetch: bool,
    pub stale_secs: u32,
    /// Servers of its own (`dns.upstreams`); empty = the WAN lease's.
    pub upstreams: Vec<schema::Upstream>,
    /// Strict DNS over TLS to `upstreams` (`dns.tls`).
    pub tls: bool,
    /// Extra trust anchors, PEM (`dns.tls_ca`).
    pub tls_ca: Option<String>,
}

pub fn dns() -> Dns {
    let c = get();
    let d = &c.dns;
    Dns {
        cache_entries: d.cache_entries as usize,
        rebind_protection: d.rebind_protection,
        prefetch: d.prefetch,
        stale_secs: d.stale_secs,
        upstreams: d.upstream_list(),
        tls: d.tls,
        tls_ca: d.tls_ca.clone(),
    }
}

/// Local DNS names per network (docs/dns-views.md): who resolves which
/// addresses' names, and the `[[dns.host]]` records.
pub fn dns_names() -> (schema::NameVisibility, Vec<schema::LocalHost>) {
    let c = get();
    (c.name_visibility(), c.local_hosts())
}

/// Management web interface (`net::mgmt`): HTTP on port 80.
pub struct Mgmt {
    /// Also listen on the WAN (`mgmt.on_wan`, boot argument `mgmt=wan`).
    /// Development only: a router's management belongs on the LAN.
    pub on_wan: bool,
    /// The password from the boot argument `mgmt_pass=` (user `admin`):
    /// wins over the config's `mgmt.password_hash` (development,
    /// recovery). Without either, pages are readable but nothing can be
    /// changed.
    pub password: Option<&'static str>,
}

pub fn mgmt() -> Mgmt {
    Mgmt {
        on_wan: get().mgmt.on_wan,
        password: arg(bootargs(), "mgmt_pass").filter(|p| !p.is_empty()),
    }
}

/// The stored management password hash (`mgmt.password_hash`), if any.
pub fn password_hash() -> Option<String> {
    get().mgmt.password_hash.clone().filter(|h| !h.is_empty())
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

/// `log=console`: log messages keep going to the serial console after
/// boot (tests read them there). Default: the RAM log (CLI `log`).
pub fn log_to_console() -> bool {
    arg(bootargs(), "log") == Some("console")
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

/// `fw_recheck=0`: a new firewall policy leaves tracked connections alone
/// (`Forwarder::recheck` skipped): the negative control of the lab check.
pub fn fw_recheck() -> bool {
    arg_u64(bootargs(), "fw_recheck") != Some(0)
}

/// `wan_antispoof=0`: WAN packets with a source in our own networks (or
/// loopback) are not dropped: the negative control of the lab check.
pub fn wan_antispoof() -> bool {
    arg_u64(bootargs(), "wan_antispoof") != Some(0)
}

/// Forward IP fragments through NAT and the firewall (`fwd::frag`);
/// boot argument `fw_frag=0` drops them as before (the lab's negative
/// control).
pub fn fw_fragments() -> bool {
    arg_u64(bootargs(), "fw_frag") != Some(0)
}

/// `ct_bench=1`: time conntrack operations on a full synthetic table at
/// boot (`selftest::conntrack_bench`), for the target CPU's numbers.
pub fn ct_bench() -> bool {
    arg_u64(bootargs(), "ct_bench") == Some(1)
}

/// Connections one host may initiate (`conn_per_host=N`, `0` = no limit):
/// default a quarter of the table, so one host never takes it all.
pub fn conn_per_host(table: usize) -> usize {
    arg_u64(bootargs(), "conn_per_host").map_or(table / 4, |n| n as usize)
}

/// Split packets without DF that exceed the egress MTU (RFC 791); boot
/// argument `fw_split=0` drops them as `too-big` (the lab's negative
/// control).
pub fn fw_split() -> bool {
    arg_u64(bootargs(), "fw_split") != Some(0)
}

/// DNS over TCP from clients (port 53, RFC 7766); boot argument
/// `dns_tcp=0` serves UDP only (the lab's negative control).
pub fn dns_tcp() -> bool {
    arg_u64(bootargs(), "dns_tcp") != Some(0)
}

fn arg_u64(bootargs: &str, key: &str) -> Option<u64> {
    arg(bootargs, key).and_then(|v| v.parse().ok())
}

/// Shaping (docs/bufferbloat-cake.md): `[shaping]`, or boot arguments in
/// kbit/s: `shape_up=42000` (WAN egress), `shape_down=50000` (the WAN
/// ingress stage: what arrives from the WAN, before it is forwarded; with
/// `shape_ingress=0`, a boot argument for A/B tests, LAN egress as before
/// M10, which caps traffic between networks too), `shape_overhead=38` (bytes per packet,
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
    /// The WAN runs PPPoE: 8 more bytes per frame (PPPoE header and PPP
    /// protocol, added in `datapath::flush_port`), likewise added.
    pub wan_pppoe: bool,
    /// The download is shaped in the WAN ingress stage (default), not on
    /// LAN egress (boot argument `shape_ingress=0`; fixed at boot).
    pub ingress: bool,
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
        wan_pppoe: c.wan.mode == schema::WanMode::Pppoe,
        ingress: arg_u64(bootargs(), "shape_ingress") != Some(0),
    }
}

impl Qos {
    /// The shaper of a port's egress: the WAN (`up`) at the upload rate;
    /// the LAN only with `shape_ingress=0`, at the download rate. Unset =
    /// not shaped.
    pub fn port_rate(&self, up: bool) -> Option<qdisc::shaper::Rate> {
        if up {
            self.rate(self.up_kbit, self.wan_encap())
        } else if self.ingress {
            None
        } else {
            self.rate(self.down_kbit, 0)
        }
    }

    /// The WAN ingress stage's shaper: the download rate. It sees frames
    /// with the WAN's VLAN tag and PPPoE header already removed, so their
    /// bytes are added like on the upload. `None` = no ingress stage
    /// (unshaped, or `shape_ingress=0`).
    pub fn ingress_rate(&self) -> Option<qdisc::shaper::Rate> {
        if self.ingress {
            self.rate(self.down_kbit, self.wan_encap())
        } else {
            None
        }
    }

    /// Bytes per frame on the WAN that the qdiscs do not see.
    fn wan_encap(&self) -> u32 {
        let mut tag = 0;
        if self.wan_vlan {
            tag += fwd::wire::VLAN_HDR as u32;
        }
        if self.wan_pppoe {
            tag += proto_pppoe::wire::SESSION_OVERHEAD as u32;
        }
        tag
    }

    fn rate(&self, kbit: Option<u64>, encap: u32) -> Option<qdisc::shaper::Rate> {
        kbit.map(|k| qdisc::shaper::Rate {
            overhead: self.overhead + encap,
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
