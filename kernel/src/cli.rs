//! The serial CLI (M8): status and config editing on the console, for
//! when the network is not an option (`crates/cli`: line editor + parser).
//!
//! Runs inside the services task (`net::svc`), like the web interface:
//! [`Cli::step`] reads what the UART's RX interrupt put in the console's
//! ring (`console::read_byte`; a pasted config does not outrun the 16-byte
//! FIFO), echoes, and runs each finished line before reading on, so
//! command output follows its line. The FIFO is also polled (every 50 ms,
//! every 2 ms for 2 s after polling found input): the fallback without an
//! interrupt. The services task does what needs the store or a reboot
//! ([`CliAction`]).
//!
//! **Console use**: the console knows the CLI's line (`console::prompt`,
//! `console::echo`) and redraws it after other output. Once the CLI is
//! ready, log messages go to the RAM log (`console::log_to_ram`, the `log`
//! command) unless the boot argument `log=console` keeps them on the UART
//! (tests); the CLI's own output always goes to the UART
//! (`console::cli_output`).
//!
//! Config edits are TOML assignments on a pending copy of the stored
//! config (`config::schema::Config::with_assignment`). `config save`
//! validates, stores and applies it like a web save; changes the web
//! interface would boot as a trial (LAN address, management) are saved
//! for good and reboot: on the console nobody locks themselves out.
//!
//! No authentication: the serial port is physical access.

use crate::config::{self, schema};
use crate::console;
use crate::net::services::LanServices;
use crate::net::shared::Shared;
use crate::net::svc::HostIf;
use crate::{print, println, timer, wallclock};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use cli::{Command, LineEditor, LogArg, Output, Which};
use qdisc::Qdisc as _;
use core::fmt::Write as _;
use core::time::Duration;

const PROMPT: &str = "leatos> ";
const POLL_IDLE: Duration = Duration::from_millis(50);
const POLL_ACTIVE: Duration = Duration::from_millis(2);
const ACTIVE_FOR: Duration = Duration::from_secs(2);
/// Bytes read per step (more wait for the next step, which comes at once).
const READ_BATCH: usize = 256;
/// Bytes of long output (`log all`) written per step: about 45 ms at
/// 115200 baud, so the services task and its core's watchdog keep running.
const WRITE_CHUNK: usize = 512;

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
    /// Finished lines not run yet (one at a time; held while a save runs).
    queued: VecDeque<String>,
    busy: bool,
    has_store: bool,
    next_poll: timer::Instant,
    active_until: timer::Instant,
    started: bool,
    /// The prompt is on the current line (it prefixes the echoed line).
    prompted: bool,
    /// Long output still being written (text, bytes written).
    stream: Option<(String, usize)>,
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
            prompted: false,
            stream: None,
            wan: String::from("no lease"),
        }
    }

    /// The WAN lease changed (for `status`).
    pub fn set_wan(&mut self, text: String) {
        self.wan = text;
    }

    /// When [`Self::step`] wants to run next (input wakes the task too:
    /// `console::rx_event`).
    pub fn wake_at(&self) -> timer::Instant {
        self.next_poll
    }

    /// More to do right away (output to write, input to read): the
    /// services task yields and steps again.
    pub fn more(&self) -> bool {
        !self.busy && (self.stream.is_some() || !self.queued.is_empty() || console::rx_pending())
    }

    fn prompt(&mut self) {
        self.prompted = true;
        console::prompt(PROMPT);
    }

    /// Read what was typed and run it. At most one action per step.
    pub fn step(&mut self, ctx: &Ctx) -> Option<CliAction> {
        if !self.started {
            self.started = true;
            println!("  cli             : serial console ready (type help)");
            if !config::log_to_console() {
                println!(
                    "  log             : further messages go to the RAM log (CLI: log; boot argument log=console keeps them here)"
                );
                console::log_to_ram();
            }
            self.prompt();
        }
        let now = timer::Instant::now();
        if now >= self.next_poll {
            // The fallback (no RX interrupt) and a safety net.
            if console::poll_rx() > 0 {
                self.active_until = after(ACTIVE_FOR);
            }
            self.next_poll = after(if now < self.active_until {
                POLL_ACTIVE
            } else {
                POLL_IDLE
            });
        }
        console::cli_output(|| self.work(ctx))
    }

    fn work(&mut self, ctx: &Ctx) -> Option<CliAction> {
        if self.write_stream() {
            return None;
        }
        let mut budget = READ_BATCH;
        while !self.busy {
            if let Some(line) = self.queued.pop_front() {
                let action = self.run(&line, ctx);
                if action.is_some() {
                    return action;
                }
                if self.stream.is_some() {
                    return None; // the prompt follows the output
                }
                self.prompt();
                continue;
            }
            if budget == 0 {
                break;
            }
            let Some(b) = console::read_byte() else { break };
            budget -= 1;
            for out in self.ed.feed(&[b]) {
                match out {
                    Output::Echo(e) => {
                        let mut now = String::from(if self.prompted { PROMPT } else { "" });
                        now.push_str(self.ed.current());
                        console::echo(core::str::from_utf8(&e).unwrap_or(""), &now);
                    }
                    Output::Line(l) => {
                        self.prompted = false;
                        self.queued.push_back(l);
                    }
                    Output::Cancel => self.prompt(),
                }
            }
        }
        None
    }

    /// Write the next chunk of long output; true while some is left.
    fn write_stream(&mut self) -> bool {
        let Some((text, done)) = self.stream.as_mut() else {
            return false;
        };
        let mut end = (*done + WRITE_CHUNK).min(text.len());
        while !text.is_char_boundary(end) {
            end += 1;
        }
        print!("{}", &text[*done..end]);
        *done = end;
        if end < text.len() {
            return true;
        }
        self.stream = None;
        self.prompt();
        true
    }

    /// The services task finished a [`CliAction::Save`].
    pub fn save_done(&mut self, result: Result<String, String>, rebooting: bool) {
        self.busy = false;
        console::cli_output(|| {
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
                self.prompt();
            }
        });
    }

    fn log(&mut self, arg: LogArg) {
        let lines = match arg {
            LogArg::Clear => {
                console::log_clear();
                println!("log cleared");
                return;
            }
            LogArg::All => None,
            LogArg::Last(n) => Some(n),
        };
        if !console::logging_to_ram() {
            println!("log messages go to the console (boot argument log=console)");
            return;
        }
        let (text, dropped) = console::log_tail(lines, usize::MAX);
        if text.is_empty() {
            println!("log is empty");
            return;
        }
        let mut out = String::new();
        if dropped > 0 && lines.is_none() {
            let _ = writeln!(out, "({dropped} older lines dropped: the RAM log keeps 64 KiB)");
        }
        out.push_str(&text);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        self.stream = Some((out, 0));
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
            Command::Routes => routes(ctx),
            Command::Log(arg) => self.log(arg),
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
                        if let Some(k) = ["wan.pppoe.password", "mgmt.password_hash", "mgmt.password"]
                            .iter()
                            .find(|k| l[2..].starts_with(*k))
                        {
                            println!("{} {k} = (secret)", &l[..1]);
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
        if let Err(issues) = p.validate().and_then(|()| {
            config::supported(p).map_err(|e| match e {
                schema::Error::Invalid(v) => v,
                _ => alloc::vec::Vec::new(),
            })
        }) {
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
        "leatos {} ({}), up {}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(target_arch = "x86_64") { "x86_64" } else { "aarch64" },
        dur(timer::uptime().as_secs())
    );
    println!("config   : {}", config::source());
    println!("cmdline  : {}", config::Redacted(config::bootargs()));
    println!(
        "console  : rx {}, {} byte(s) lost, log {}",
        if console::rx_irq() { "interrupt" } else { "polled" },
        console::rx_dropped(),
        if console::logging_to_ram() { "in RAM (log)" } else { "on the console" }
    );
    println!("wan      : {wan}");
    for (pi, p) in ctx.sh.ports.iter().enumerate() {
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
        // Every link on the port: the WAN, or the networks on lan0.
        let addrs: Vec<String> = ctx
            .hosts
            .iter()
            .zip(&ctx.sh.links)
            .filter(|(_, l)| l.port() == pi)
            .flat_map(|(h, l)| {
                h.iface
                    .ip_addrs()
                    .iter()
                    .map(|a| match l.vid() {
                        0 => alloc::format!("{a}"),
                        v => alloc::format!("{a} (vlan {v})"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
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
    if config::qos().ingress {
        let (q, rate) = {
            let q = ctx.sh.ingress.lock();
            (q.stats(), q.rate())
        };
        println!(
            "ingress  : download {}, qdisc sent {} drops {} ecn {} backlog {}",
            rate.map(|r| alloc::format!("shaped {} kbit/s", r.bits_per_sec / 1000))
                .unwrap_or_else(|| String::from("unshaped")),
            q.dequeued,
            q.dropped,
            q.marked,
            q.backlog_packets
        );
    }
    for (name, m) in ctx.services.map(LanServices::mdns_status).unwrap_or_default() {
        println!(
            "mdns     : {name}: {} in, {} out, {} filtered, {} dup, {} rate-limited, {} bad, {} foreign",
            m.received, m.sent, m.filtered, m.duplicate, m.rate_limited, m.malformed, m.foreign
        );
    }
    if let Some(svc) = ctx.services {
        let ups: Vec<String> = svc.upstreams().iter().map(|a| alloc::format!("{a}")).collect();
        println!(
            "dns      : {} ({})",
            if ups.is_empty() { String::from("no upstreams") } else { ups.join(", ") },
            svc.upstream_source()
        );
        let (st, cached) = svc.dns_stats();
        println!(
            "dns      : {} queries: {} local ({} hidden), {} cache hits, {} forwarded, {} merged, {} timeouts; {} cached; prefetch {} sent, {} failed; {} stale",
            st.queries,
            st.local_answers,
            st.hidden,
            st.cache_hits,
            st.forwarded,
            st.merged,
            st.timeouts,
            cached,
            st.prefetches,
            st.prefetch_failed,
            st.stale_answers
        );
        let (accepted, open) = svc.dns_tcp_status();
        println!("dns-tcp  : {} queries, {} connections ({} open)", st.tcp_queries, accepted, open);
        for l in svc.dot_status_lines() {
            println!("dns-tls  : {l}");
        }
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
    {
        use crate::drivers::cputemp;
        match cputemp::read() {
            Some(t) => println!(
                "temp     : {}{}",
                cputemp::fmt_mc(t),
                cputemp::htc().map(|h| alloc::format!(" (throttles at {})", cputemp::fmt_mc(h))).unwrap_or_default()
            ),
            None => println!("temp     : - (no sensor)"),
        }
    }
    let (used, free) = crate::mm::heap::usage();
    println!(
        "memory   : heap {} KiB used, {} MiB free; forwarded {}, connections {} ({} early-dropped)",
        used >> 10,
        free >> 20,
        crate::net::datapath::FORWARDED.load(core::sync::atomic::Ordering::Relaxed),
        ctx.sh.conntrack(),
        crate::net::datapath::EARLY_DROPS.load(core::sync::atomic::Ordering::Relaxed)
    );
}

fn routes(ctx: &Ctx) {
    for r in ctx.sh.route_rows() {
        let dst = alloc::format!("{}/{}", r.dst.0, r.dst.1);
        let via = r.via.map_or_else(|| String::from("-"), |v| alloc::format!("{v}"));
        println!(
            "{dst:<18} via {via:<15} dev {:<8} {}{}{}",
            r.dev,
            r.kind,
            r.name.map(|n| alloc::format!(" {n}")).unwrap_or_default(),
            if r.active { "" } else { " (inactive: no network holds its router)" }
        );
    }
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
