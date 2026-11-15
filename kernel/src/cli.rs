//! The serial CLI (M8): status and config editing on the console, for
//! when the network is not an option (`crates/cli`: line editor + parser).
//!
//! Runs inside the services task (`net::svc`), like the web interface:
//! [`Cli::step`] polls the UART (`arch::console::read_byte`; COM1's
//! interrupt would need IOAPIC routing), echoes, and runs commands.
//! Polling: every 50 ms, every 2 ms for 2 s after input (pasted lines
//! outrun a 16-byte FIFO otherwise). The services task does what needs
//! the store or a reboot ([`CliAction`]).
//!
//! Config edits are TOML assignments on a pending copy of the stored
//! config (`config::schema::Config::with_assignment`). `config save`
//! validates, stores and applies it like a web save; changes the web
//! interface would boot as a trial (LAN address, management) are saved
//! for good and reboot: on the console nobody locks themselves out.
//!
//! No authentication: the serial port is physical access.

use crate::config::{self, schema};
use crate::net::services::LanServices;
use crate::net::shared::Shared;
use crate::net::svc::HostIf;
use crate::{print, println, timer, wallclock};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use cli::{Command, LineEditor, Output, Which};
use qdisc::Qdisc as _;
use core::fmt::Write as _;
use core::time::Duration;

const PROMPT: &str = "rrouter> ";
const POLL_IDLE: Duration = Duration::from_millis(50);
const POLL_ACTIVE: Duration = Duration::from_millis(2);
const ACTIVE_FOR: Duration = Duration::from_secs(2);
/// Bytes read per step (more wait for the next one, 2 ms later).
const READ_BATCH: usize = 256;

/// Work for the services task.
pub enum CliAction {
    /// Store this (validated) config and apply it; [`Cli::save_done`] after.
    Save(Box<schema::Config>),
    Reboot,
}

/// What the CLI may look at (lent by the services task each step).
pub struct Ctx<'a> {
    pub hosts: &'a [HostIf],
    pub sh: &'a Shared,
    pub services: Option<&'a LanServices>,
}

pub struct Cli {
    ed: LineEditor,
    pending: Option<schema::Config>,
    /// Lines received while a save was in progress.
    queued: VecDeque<String>,
    busy: bool,
    has_store: bool,
    next_poll: timer::Instant,
    active_until: timer::Instant,
    started: bool,
    wan: String,
}

fn after(d: Duration) -> timer::Instant {
    timer::Instant::now().checked_add(d).expect("deadline overflow")
}

impl Cli {
    pub fn new(has_store: bool) -> Self {
        Cli {
            ed: LineEditor::new(),
            pending: None,
            queued: VecDeque::new(),
            busy: false,
            has_store,
            next_poll: timer::Instant::now(),
            active_until: timer::Instant::now(),
            started: false,
            wan: String::from("no lease"),
        }
    }

    /// The WAN lease changed (for `status`).
    pub fn set_wan(&mut self, text: String) {
        self.wan = text;
    }

    /// When [`Self::step`] wants to run next.
    pub fn wake_at(&self) -> timer::Instant {
        self.next_poll
    }

    /// Poll the UART and run what was typed. At most one action per step.
    pub fn step(&mut self, ctx: &Ctx) -> Option<CliAction> {
        let now = timer::Instant::now();
        if now < self.next_poll {
            return None;
        }
        if !self.started {
            self.started = true;
            println!("  cli             : serial console ready (type help)");
            print!("{PROMPT}");
        }
        let mut bytes = Vec::new();
        while bytes.len() < READ_BATCH {
            match crate::arch::console::read_byte() {
                Some(b) => bytes.push(b),
                None => break,
            }
        }
        if !bytes.is_empty() {
            self.active_until = after(ACTIVE_FOR);
            for out in self.ed.feed(&bytes) {
                match out {
                    Output::Echo(e) => print!("{}", core::str::from_utf8(&e).unwrap_or("")),
                    Output::Line(l) => self.queued.push_back(l),
                    Output::Cancel => print!("{PROMPT}"),
                }
            }
        }
        self.next_poll = after(if timer::Instant::now() < self.active_until {
            POLL_ACTIVE
        } else {
            POLL_IDLE
        });
        while !self.busy {
            let line = self.queued.pop_front()?;
            let action = self.run(&line, ctx);
            if action.is_some() {
                return action;
            }
            print!("{PROMPT}");
        }
        None
    }

    /// The services task finished a [`CliAction::Save`].
    pub fn save_done(&mut self, result: Result<String, String>, rebooting: bool) {
        self.busy = false;
        match result {
            Ok(detail) if rebooting => {
                self.pending = None;
                println!("saved ({detail}); the LAN or management settings changed: rebooting");
            }
            Ok(detail) => {
                self.pending = None;
                println!("saved and applied ({detail})");
            }
            Err(e) => println!("error: not saved: {e}"),
        }
        if !rebooting {
            print!("{PROMPT}");
        }
    }

    fn run(&mut self, line: &str, ctx: &Ctx) -> Option<CliAction> {
        let cmd = match cli::parse(line) {
            Ok(Some(c)) => c,
            Ok(None) => return None,
            Err(e) => {
                println!("error: {e}");
                return None;
            }
        };
        match cmd {
            Command::Help => println!("{}", cli::HELP),
            Command::Status => status(ctx, &self.wan),
            Command::Leases => leases(ctx),
            Command::Show(w) => {
                let c = match w {
                    Which::Running => Some(config::get().as_ref().clone()),
                    Which::Stored => Some(config::base().as_ref().clone()),
                    Which::Pending => self.pending.clone(),
                };
                match c {
                    Some(c) => {
                        let what = match w {
                            Which::Running => "running: stored + boot arguments",
                            Which::Stored => &*alloc::format!("stored: {}", config::source()),
                            Which::Pending => "pending edit (config save to apply)",
                        };
                        println!("# {what}");
                        // Secrets stay off the console (and its logs).
                        print!("{}", c.without_secrets().to_toml());
                    }
                    None => println!("no pending edit"),
                }
            }
            Command::Set(a) => self.edit(|c| c.with_assignment(&a)),
            Command::Unset(p) => self.edit(|c| c.without(&p)),
            Command::Diff => match &self.pending {
                None => println!("no pending edit"),
                Some(p) => {
                    let d = schema::diff_lines(&config::base(), p);
                    if d.is_empty() {
                        println!("no changes");
                    }
                    for l in d {
                        if l[2..].starts_with("wan.pppoe.password") {
                            println!("{} wan.pppoe.password = (secret)", &l[..1]);
                        } else {
                            println!("{l}");
                        }
                    }
                }
            },
            Command::Discard => {
                println!(
                    "{}",
                    if self.pending.take().is_some() {
                        "pending edit dropped"
                    } else {
                        "no pending edit"
                    }
                );
            }
            Command::Save => return self.save(),
            Command::Reboot => {
                println!("rebooting");
                return Some(CliAction::Reboot);
            }
        }
        None
    }

    fn edit(&mut self, f: impl FnOnce(&schema::Config) -> Result<schema::Config, schema::Error>) {
        let cur = self.pending.clone().unwrap_or_else(|| config::base().as_ref().clone());
        match f(&cur) {
            Ok(c) => {
                let n = schema::diff_lines(&config::base(), &c).len();
                self.pending = Some(c);
                println!("pending: {n} changed line(s) against the stored config (config diff, config save)");
            }
            Err(e) => println!("error: {e}"),
        }
    }

    fn save(&mut self) -> Option<CliAction> {
        let Some(p) = &self.pending else {
            println!("no pending edit");
            return None;
        };
        if let Err(issues) = p.validate() {
            println!("error: not saved:");
            for i in issues {
                println!("  {i}");
            }
            return None;
        }
        if !self.has_store {
            println!("error: no store: changes cannot be saved");
            return None;
        }
        if schema::diff_lines(&config::base(), p).is_empty() {
            println!("no changes");
            self.pending = None;
            return None;
        }
        self.busy = true;
        Some(CliAction::Save(Box::new(p.clone())))
    }
}

fn dur(s: u64) -> String {
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    let mut out = String::new();
    if d > 0 {
        let _ = write!(out, "{d}d ");
    }
    let _ = write!(out, "{h}h {m}m {}s", s % 60);
    out
}

fn status(ctx: &Ctx, wan: &str) {
    println!(
        "rrouter {} ({}), up {}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(target_arch = "x86_64") { "x86_64" } else { "aarch64" },
        dur(timer::uptime().as_secs())
    );
    println!("config   : {}", config::source());
    println!("cmdline  : {}", config::Redacted(config::bootargs()));
    println!("wan      : {wan}");
    for (host, p) in ctx.hosts.iter().zip(&ctx.sh.ports) {
        let snap = *p.snap.lock();
        let (q, rate) = {
            let q = p.qdisc.lock();
            (q.stats(), q.rate())
        };
        let link = match snap.link {
            Some((true, mbps, full)) => alloc::format!("up {mbps} Mbit/s{}", if full { "" } else { " half" }),
            Some((false, ..)) => String::from("down"),
            None => String::from("link -"),
        };
        let addrs: Vec<String> = host.iface.ip_addrs().iter().map(|a| alloc::format!("{a}")).collect();
        println!(
            "{:<9}: {} {link}, {}, rx {} / tx {} pkts, {}, qdisc sent {} drops {} ecn {} backlog {}",
            p.name,
            p.model,
            if addrs.is_empty() { String::from("no address") } else { addrs.join(" ") },
            snap.stats.rx_packets,
            snap.stats.tx_packets,
            rate.map(|r| alloc::format!("shaped {} kbit/s", r.bits_per_sec / 1000))
                .unwrap_or_else(|| String::from("unshaped")),
            q.dequeued,
            q.dropped,
            q.marked,
            q.backlog_packets
        );
    }
    let ntp = ctx.services.and_then(LanServices::ntp_status);
    match (wallclock::now(), &ntp) {
        (Some(t), Some(n)) if n.synced.is_some() => {
            let s = n.synced.unwrap();
            println!(
                "time     : {t} (ntp {}, stratum {}, delay {} ms)",
                n.server.map(|a| alloc::format!("{a}")).unwrap_or_default(),
                s.stratum,
                s.delay / 1_000_000
            );
        }
        (Some(t), _) => println!("time     : {t}"),
        (None, Some(n)) if n.servers.is_empty() => println!("time     : unknown (no NTP servers)"),
        (None, Some(n)) => println!("time     : not synced (ntp {})", n.servers.join(", ")),
        (None, None) => println!("time     : unknown"),
    }
    match crate::watchdog::status() {
        Some(w) if !w.enabled => println!("watchdog : off (watchdog=0)"),
        Some(w) => println!(
            "watchdog : {} + cross-core check{}",
            w.hw.map(|h| alloc::format!("{h} {} s", w.hw_secs))
                .unwrap_or_else(|| String::from("software only")),
            if w.fired_last_boot { "; last reset by the watchdog" } else { "" }
        ),
        None => println!("watchdog : -"),
    }
    let mut cpu = String::new();
    for core in 0..crate::smp::online() {
        let mut last = None;
        crate::cpuload::history(core, |x| last = Some(x));
        if let Some(x) = last {
            let _ = write!(cpu, "{}core {core} {}.{}%", if core > 0 { ", " } else { "" }, x.busy / 10, x.busy % 10);
        }
    }
    println!("cpu      : {} (last second)", if cpu.is_empty() { "-" } else { &cpu });
    let (used, free) = crate::mm::heap::usage();
    println!(
        "memory   : heap {} KiB used, {} MiB free; forwarded {}, connections {}",
        used >> 10,
        free >> 20,
        crate::net::datapath::FORWARDED.load(core::sync::atomic::Ordering::Relaxed),
        ctx.sh.conntrack()
    );
}

fn leases(ctx: &Ctx) {
    let Some(svc) = ctx.services else {
        println!("no LAN services");
        return;
    };
    let now = timer::uptime().as_secs();
    let mut n = 0;
    for l in svc.leases() {
        n += 1;
        println!(
            "{:<15} {}  {:<20} {} {}",
            l.ip,
            smoltcp::wire::EthernetAddress(l.mac),
            l.hostname.as_deref().unwrap_or("-"),
            if l.state == proto_dhcp::v4::server::LeaseState::Bound { "bound, expires in" } else { "offered, expires in" },
            dur(l.expires.saturating_sub(now))
        );
    }
    if n == 0 {
        println!("no leases");
    }
}
