//! Management web interface: HTTP on port 80 (smoltcp TCP ↔ `proto_http`).
//!
//! - `GET /`: the status page (`mgmt.html`, compiled in), which polls
//! - `GET /api/status`: JSON (interfaces, link, qdisc, DHCP leases, memory)
//! - `POST /api/upgrade`: body = a kernel ELF; streamed straight into the
//!   staging area (`mm::heap::take_staging`), checked (`crate::upgrade`,
//!   optional `X-Image-CRC32` header), then the network task hands over to
//!   it in RAM. `X-Cmdline` replaces the kernel command line for the new
//!   kernel (default: keep the current one).
//! - `POST /api/upgrade/persist`: the same upload and checks, then the
//!   kernel is written to the store's `images` area as a trial and the
//!   router reboots into it (`crate::upgrade`, docs/upgrades.md). The
//!   stored kernel boots with the boot partition's command line, so
//!   `X-Cmdline` is refused. `POST /api/upgrade/confirm` keeps it; `POST
//!   /api/upgrade/revert`, or no confirm within `config::trial_secs`,
//!   erases it and reboots into the previous kernel. While a trial kernel
//!   runs, no upgrade and no config save is accepted (a config saved by a
//!   newer kernel might not be readable by the one a rollback returns to).
//! - `POST /api/reboot`: firmware reset.
//! - `GET /api/config` (TOML, export) and `GET /api/config.json` (the
//!   page's form): the configuration without boot-argument overrides
//!   (`config::base`).
//! - `GET /api/config/effective` (TOML) and `/api/config/effective.json`:
//!   the config in effect, boot arguments applied (`config::get`): what
//!   to save to move boot arguments into the stored config.
//! - `POST /api/config`: body = `config.toml`, or JSON with
//!   `Content-Type: application/json`; parsed and validated
//!   (`crates/config`; 422 with the message and, for inconsistencies, the
//!   `issues` with their paths), saved to the store by the services task
//!   (`crate::store`, canonical TOML from the parsed structs), then
//!   applied live (`net::svc`); only a trial reboots. 501 without a store.
//! - **Trials** (docs/config-and-storage.md §6): a save that changes the
//!   LAN address or management settings (`Config::needs_trial`) is stored
//!   as a trial. The next boot runs it; `POST /api/config/confirm` keeps it,
//!   `POST /api/config/revert` or no confirm within `config::trial_secs`
//!   erases it and reboots into the previous record. No save while a trial
//!   is pending (it would overwrite the only confirmed record).
//!
//! - `POST /api/login`: checks the credentials and does nothing else (the
//!   page's login form). `GET /api/log`: the RAM log's tail as JSON
//!   (`{ram, dropped, text}`), with auth: it names hosts and addresses.
//! - Requests with `X-Rrouter-UI: 1` (the page's own) get a 401 without
//!   `WWW-Authenticate`, so the browser shows the page's login form
//!   instead of its own password dialog.
//!
//! Upgrade, reboot, log and config changes need HTTP Basic auth (user `admin`, password from the
//! `mgmt_pass=` boot argument); without a password they are refused.
//! Listens on the LAN; on the WAN too only with `mgmt=wan` (development:
//! a router's management belongs on the LAN). Plain HTTP: the password
//! crosses the network unencrypted, acceptable on a lab network only.
//!
//! Each connection serves one request (`Connection: close`). A response is
//! queued whole; the socket is closed once it is sent.

use crate::net::datapath;
use crate::net::services::LanServices;
use crate::net::shared::Shared;
use crate::net::svc::HostIf;
use crate::upgrade::{self, Prepared};
use crate::{config, println, timer};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;
use core::time::Duration;
use config_store::{RecordHeader, Slot};
use proto_http::{Error as HttpError, Head, Method, Parser, json_str, response};
use qdisc::Qdisc;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;

const PORT: u16 = 80;
const LAN_SOCKETS: usize = 4;
const WAN_SOCKETS: usize = 4;
const RX_BUF: usize = 64 * 1024;
const TX_BUF: usize = 16 * 1024;
const MAX_HEAD: usize = 8 * 1024;
/// Bodies of requests other than an upload are read and ignored, up to this.
const MAX_SMALL_BODY: usize = 64 * 1024;
/// A connection that takes longer is aborted (uploads get more time).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// After the response to an upgrade/reboot: wait at most this long for the
/// client to receive it before acting anyway.
const FLUSH_TIMEOUT: Duration = Duration::from_millis(1000);
/// After our response is fully sent and acknowledged, the peer gets this
/// long to close; then the socket is aborted (a client that stopped an
/// upload early can leave the connection half-open).
const LINGER: Duration = Duration::from_secs(2);
const PAGE: &str = include_str!("mgmt.html");
/// `GET /api/log`: at most this much of the RAM log's tail (all of it).
const LOG_MAX: usize = 64 * 1024;

/// What the network task must do after [`Mgmt::step`].
pub enum Action {
    /// Stop the devices and enter the prepared kernel.
    Exec(&'static mut [u8], Prepared, String),
    Reboot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Index,
    Status,
    Upgrade,
    UpgradePersist,
    UpgradeConfirm,
    UpgradeRevert,
    Reboot,
    ConfigGet,
    ConfigJson,
    /// The config in effect: stored or defaults, plus boot arguments.
    EffectiveGet,
    EffectiveJson,
    ConfigPut,
    ConfigConfirm,
    ConfigRevert,
    /// Credentials check for the page's login form.
    Login,
    Log,
}

/// Work for the store, done by the services task (it may take a while and
/// must not block this state machine): [`Mgmt::take_op`], then
/// [`Mgmt::op_done`].
pub enum StoreOp {
    /// Write a new `config` record (`flags`: trial or not); without a
    /// trial, the services task then applies `cfg` live.
    Save {
        toml: String,
        flags: u32,
        cfg: alloc::boxed::Box<config::schema::Config>,
    },
    /// Write a kernel ELF to the `images` area as a trial (then reboot).
    SaveImage(Vec<u8>),
    /// Clear the trial flags of this boot's record in an area (`config`
    /// or `images`).
    Confirm(&'static str, Slot, RecordHeader),
    /// Erase this boot's trial record in an area.
    Revert(&'static str, Slot),
}

/// A trial this boot runs (a config or a kernel).
struct Trial {
    area: &'static str,
    slot: Slot,
    header: RecordHeader,
    deadline: timer::Instant,
}

enum After {
    Nothing,
    Exec(Prepared, String),
    Reboot,
}

struct Conn {
    ifx: usize,
    handle: SocketHandle,
    parser: Parser,
    route: Option<Route>,
    head: Option<Head>,
    /// Upload: bytes received into the staging area, running CRC.
    upload_len: usize,
    crc: u32,
    /// `POST /api/config`: the body.
    body: Vec<u8>,
    /// Queued response and how much of it has been sent.
    out: Vec<u8>,
    sent: usize,
    after: After,
    /// Connection start (for the timeouts).
    since: Option<timer::Instant>,
    responded_at: Option<timer::Instant>,
    /// `X-Rrouter-UI`: answer 401 without `WWW-Authenticate`.
    no_prompt: bool,
}

impl Conn {
    fn new(ifx: usize, handle: SocketHandle) -> Self {
        Self {
            ifx,
            handle,
            parser: Parser::new(MAX_HEAD, usize::MAX),
            route: None,
            head: None,
            upload_len: 0,
            crc: 0,
            body: Vec::new(),
            out: Vec::new(),
            sent: 0,
            after: After::Nothing,
            since: None,
            responded_at: None,
            no_prompt: false,
        }
    }

    fn reset(&mut self) {
        *self = Self::new(self.ifx, self.handle);
    }

    fn respond(&mut self, status: u16, content_type: &str, extra: &[(&str, &str)], body: &[u8]) {
        if self.responded_at.is_none() {
            self.out = response(status, content_type, extra, body);
            self.sent = 0;
            self.responded_at = Some(timer::Instant::now());
        }
    }

    fn respond_json(&mut self, status: u16, body: &str) {
        self.respond(status, "application/json", &[], body.as_bytes());
    }

    fn error(&mut self, status: u16, msg: &str) {
        let body = format!("{{\"ok\":false,\"error\":{}}}", json_str(msg));
        if status == 401 && !self.no_prompt {
            self.respond(
                status,
                "application/json",
                &[("WWW-Authenticate", "Basic realm=\"rrouter\"")],
                body.as_bytes(),
            );
        } else {
            self.respond_json(status, &body);
        }
    }
}

pub struct Mgmt {
    conns: Vec<Conn>,
    /// The staging area while no upload owns it.
    staging: Option<&'static mut [u8]>,
    /// Connection index currently uploading into the staging area.
    uploader: Option<usize>,
    password: Option<&'static str>,
    on_wan: bool,
    wan_lease: String,
    wan_pppoe: Option<String>,
    /// A store exists: `POST /api/config` can save.
    has_store: bool,
    /// Store work waiting for the services task, and for which connection
    /// (`None`: the trial timed out).
    op: Option<(Option<usize>, StoreOp)>,
    /// A store operation is queued or running.
    op_busy: bool,
    trial: Option<Trial>,
    /// This boot's kernel is a trial from the store (`crate::upgrade`).
    image_trial: Option<Trial>,
    /// Reboot at the next step (after a timed-out trial was reverted).
    reboot_pending: bool,
    /// The LAN address of the config being saved (for the answer).
    saved_lan: Option<String>,
}

impl Trial {
    fn new(area: &'static str, slot: Slot, header: RecordHeader) -> Self {
        Self {
            area,
            slot,
            header,
            deadline: timer::Instant::now()
                .checked_add(Duration::from_secs(config::trial_secs()))
                .expect("trial deadline"),
        }
    }

    fn json(t: Option<&Trial>) -> String {
        match t {
            Some(t) => format!(
                "{{\"seq\":{},\"remaining_s\":{}}}",
                t.header.seq,
                t.deadline
                    .saturating_duration_since(timer::Instant::now())
                    .as_secs()
            ),
            None => String::from("null"),
        }
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0; RX_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0; TX_BUF]);
    let mut s = tcp::Socket::new(rx, tx);
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(10))); // unacknowledged data
    s.listen(PORT).expect("mgmt: listen");
    s
}

impl Mgmt {
    /// `hosts[0]` = WAN, `hosts[1]` = LAN.
    pub fn new(ifs: &mut [HostIf], has_store: bool) -> Self {
        let cfg = config::mgmt();
        let mut conns = Vec::new();
        for (ifx, nif) in ifs.iter_mut().enumerate().take(2) {
            let n = match ifx {
                1 => LAN_SOCKETS,
                _ if cfg.on_wan => WAN_SOCKETS,
                _ => 0,
            };
            for _ in 0..n {
                conns.push(Conn::new(ifx, nif.sockets.add(tcp_socket())));
            }
        }
        let staging = crate::mm::heap::take_staging();
        println!(
            "  mgmt            : http :{PORT} on {}, upgrade {}",
            if cfg.on_wan {
                "lan + WAN (mgmt=wan: development only!)"
            } else {
                "lan"
            },
            match (&staging, cfg.password) {
                (None, _) => "unavailable (no staging area on this platform)",
                (Some(_), None) => "disabled (boot with mgmt_pass=...)",
                (Some(_), Some(_)) => "enabled (admin + mgmt_pass)",
            }
        );
        Self {
            conns,
            staging,
            uploader: None,
            password: cfg.password,
            on_wan: cfg.on_wan,
            wan_lease: String::from("null"),
            wan_pppoe: None,
            has_store,
            op: None,
            op_busy: false,
            trial: config::trial().map(|(slot, header)| Trial::new("config", slot, header)),
            image_trial: upgrade::trial()
                .map(|(slot, header)| Trial::new(upgrade::AREA, slot, header)),
            reboot_pending: false,
            saved_lan: None,
        }
    }

    /// Store work for the services task.
    pub fn take_op(&mut self) -> Option<(Option<usize>, StoreOp)> {
        self.op.take()
    }

    /// The services task finished `op` (for connection `conn`): answer;
    /// reboot after a save or a revert.
    pub fn op_done(&mut self, conn: Option<usize>, op: &StoreOp, result: Result<String, String>) {
        self.op_busy = false;
        let (status, body, reboot) = match (op, result) {
            (StoreOp::Save { flags, .. }, Ok(detail)) => {
                // A trial must boot to be confirmed; everything else was
                // applied live by the services task.
                let trial = *flags != 0;
                let what = if trial {
                    "saved as a trial, rebooting"
                } else {
                    "saved and applied"
                };
                println!("  mgmt            : config {what} ({detail})");
                let lan = self.saved_lan.take().unwrap_or_default();
                (
                    200,
                    format!(
                        "{{\"ok\":true,\"detail\":{},\"trial\":{trial},\"applied\":{},\"confirm_within_s\":{},\"lan\":{}}}",
                        json_str(&format!("{what} ({detail})")),
                        !trial,
                        if trial { config::trial_secs() } else { 0 },
                        json_str(&lan)
                    ),
                    trial,
                )
            }
            (StoreOp::SaveImage(_), Ok(detail)) => {
                println!("  mgmt            : kernel stored as a trial ({detail}), rebooting");
                (
                    200,
                    format!(
                        "{{\"ok\":true,\"detail\":{},\"trial\":true,\"confirm_within_s\":{}}}",
                        json_str(&format!("stored as a trial ({detail}), rebooting")),
                        config::trial_secs()
                    ),
                    true,
                )
            }
            (StoreOp::Confirm(area, ..), Ok(_)) => {
                let what = what_trial(area);
                println!("  mgmt            : trial {what} confirmed");
                if *area == upgrade::AREA {
                    self.image_trial = None;
                } else {
                    self.trial = None;
                }
                (200, String::from("{\"ok\":true,\"detail\":\"confirmed\"}"), false)
            }
            (StoreOp::Revert(area, _), r) => {
                // Reboot even if erasing failed: the record is marked
                // booted, so the next boot reverts it.
                let what = what_trial(area);
                match &r {
                    Ok(_) => println!("  mgmt            : trial {what} reverted, rebooting"),
                    Err(e) => println!("  mgmt            : reverting the trial {what} failed ({e}), rebooting"),
                }
                if conn.is_none() {
                    self.reboot_pending = true;
                }
                (
                    200,
                    String::from("{\"ok\":true,\"detail\":\"reverted, rebooting\"}"),
                    true,
                )
            }
            (_, Err(e)) => {
                println!("  mgmt            : store operation failed: {e}");
                (
                    500,
                    format!("{{\"ok\":false,\"error\":{}}}", json_str(&format!("store: {e}"))),
                    false,
                )
            }
        };
        if let Some(i) = conn {
            let c = &mut self.conns[i];
            c.respond_json(status, &body);
            if reboot {
                c.after = After::Reboot;
            }
        }
    }

    /// When a trial times out ([`Self::step`] reverts it then).
    pub fn wake_at(&self) -> Option<timer::Instant> {
        [&self.trial, &self.image_trial]
            .into_iter()
            .flatten()
            .map(|t| t.deadline)
            .min()
    }

    /// This boot's kernel is an unconfirmed trial: no config saves (the
    /// serial console asks too).
    pub fn image_trial_pending(&self) -> bool {
        self.image_trial.is_some()
    }

    /// The WAN lease for the status page (already JSON).
    pub fn set_wan_lease(&mut self, json: String) {
        self.wan_lease = json;
    }

    /// The PPPoE client's state for the status page (JSON), `None` in
    /// DHCP mode.
    pub fn set_wan_pppoe(&mut self, json: Option<String>) {
        self.wan_pppoe = json;
    }

    fn authorized(&self, head: &Head) -> Result<(), (u16, &'static str)> {
        let Some(pass) = self.password else {
            return Err((403, "disabled: boot with mgmt_pass=<password>"));
        };
        match proto_http::basic_auth(head) {
            Some((u, p)) if u == "admin" && proto_http::ct_eq(p.as_bytes(), pass.as_bytes()) => {
                Ok(())
            }
            _ => Err((401, "wrong or missing credentials (user admin)")),
        }
    }

    /// A request head arrived: route it, check auth, claim the staging area.
    fn on_head(&mut self, i: usize, head: Head) {
        self.conns[i].no_prompt = head.header("x-rrouter-ui").is_some();
        let route = match (head.method, head.path.as_str()) {
            (Method::Get, "/" | "/index.html") => Ok(Route::Index),
            (Method::Get, "/api/status") => Ok(Route::Status),
            (Method::Post, "/api/upgrade") => Ok(Route::Upgrade),
            (Method::Post, "/api/upgrade/persist") => Ok(Route::UpgradePersist),
            (Method::Post, "/api/upgrade/confirm") => Ok(Route::UpgradeConfirm),
            (Method::Post, "/api/upgrade/revert") => Ok(Route::UpgradeRevert),
            (Method::Post, "/api/reboot") => Ok(Route::Reboot),
            (Method::Get, "/api/config") => Ok(Route::ConfigGet),
            (Method::Get, "/api/config.json") => Ok(Route::ConfigJson),
            (Method::Get, "/api/config/effective") => Ok(Route::EffectiveGet),
            (Method::Get, "/api/config/effective.json") => Ok(Route::EffectiveJson),
            (Method::Post, "/api/config") => Ok(Route::ConfigPut),
            (Method::Post, "/api/config/confirm") => Ok(Route::ConfigConfirm),
            (Method::Post, "/api/config/revert") => Ok(Route::ConfigRevert),
            (Method::Post, "/api/login") => Ok(Route::Login),
            (Method::Get, "/api/log") => Ok(Route::Log),
            (
                _,
                "/" | "/index.html" | "/api/status" | "/api/upgrade" | "/api/upgrade/persist"
                | "/api/upgrade/confirm" | "/api/upgrade/revert" | "/api/reboot"
                | "/api/config" | "/api/config.json" | "/api/config/effective"
                | "/api/config/effective.json" | "/api/config/confirm"
                | "/api/config/revert" | "/api/login" | "/api/log",
            ) => {
                Err((405, "method not allowed"))
            }
            _ => Err((404, "not found")),
        };
        let route = route.and_then(|r| {
            let changes_config =
                matches!(r, Route::ConfigPut | Route::ConfigConfirm | Route::ConfigRevert);
            let changes_image =
                matches!(r, Route::UpgradePersist | Route::UpgradeConfirm | Route::UpgradeRevert);
            if changes_config
                || changes_image
                || matches!(r, Route::Upgrade | Route::Reboot | Route::Login | Route::Log)
            {
                self.authorized(&head)?;
            }
            if changes_config && !self.has_store {
                return Err((501, "no store: the config cannot be saved"));
            }
            if changes_image && !self.has_store {
                return Err((501, "no store: the kernel cannot be stored"));
            }
            if (changes_config || changes_image) && self.op_busy {
                return Err((409, "another store operation is in progress"));
            }
            match r {
                Route::ConfigPut if self.trial.is_some() => {
                    return Err((409, "a trial config is pending: confirm or revert it first"));
                }
                Route::ConfigPut if self.image_trial.is_some() => {
                    return Err((409, "a trial kernel is pending: confirm or revert it first"));
                }
                Route::ConfigConfirm | Route::ConfigRevert if self.trial.is_none() => {
                    return Err((409, "no trial config pending"));
                }
                Route::Upgrade | Route::UpgradePersist if self.image_trial.is_some() => {
                    return Err((409, "a trial kernel is pending: confirm or revert it first"));
                }
                Route::UpgradePersist if self.trial.is_some() => {
                    return Err((409, "a trial config is pending: confirm or revert it first"));
                }
                Route::UpgradePersist if head.header("x-cmdline").is_some() => {
                    return Err((
                        422,
                        "X-Cmdline: a stored kernel boots with the boot partition's command line",
                    ));
                }
                Route::UpgradeConfirm | Route::UpgradeRevert if self.image_trial.is_none() => {
                    return Err((409, "no trial kernel pending"));
                }
                _ => {}
            }
            Ok(r)
        });
        let route = route.and_then(|r| {
            if !matches!(r, Route::Upgrade | Route::UpgradePersist) {
                return if head.content_length > MAX_SMALL_BODY {
                    Err((413, "body too large"))
                } else {
                    Ok(r)
                };
            }
            let Some(staging) = self.staging.as_deref() else {
                return Err((501, "in-RAM upgrade unavailable on this platform"));
            };
            if head.content_length == 0 {
                return Err((411, "send the kernel ELF as the request body"));
            }
            if head.content_length > upgrade::max_image(staging) {
                return Err((413, "image larger than the staging area allows"));
            }
            if self.uploader.is_some() {
                return Err((409, "another upload is in progress"));
            }
            self.uploader = Some(i);
            Ok(r)
        });
        let c = &mut self.conns[i];
        match route {
            Ok(r) => c.route = Some(r),
            Err((status, msg)) => c.error(status, msg),
        }
        c.head = Some(head);
    }

    /// The whole request is in: build the response.
    fn on_done(&mut self, i: usize, status_json: &mut dyn FnMut() -> String) {
        let Some(route) = self.conns[i].route else {
            return; // already answered with an error
        };
        match route {
            Route::Index => {
                self.conns[i].respond(200, "text/html; charset=utf-8", &[], PAGE.as_bytes())
            }
            Route::Status => {
                let s = status_json();
                self.conns[i].respond_json(200, &s);
            }
            Route::Reboot => {
                println!("  mgmt            : reboot requested");
                let c = &mut self.conns[i];
                c.respond_json(200, "{\"ok\":true,\"detail\":\"rebooting\"}");
                c.after = After::Reboot;
            }
            Route::Upgrade | Route::UpgradePersist => self.finish_upload(i, route),
            Route::ConfigGet => {
                let toml = config::base().without_secrets().to_toml();
                self.conns[i].respond(200, "application/toml", &[], toml.as_bytes());
            }
            Route::ConfigJson => {
                let json = config::base().without_secrets().to_json();
                self.conns[i].respond_json(200, &json);
            }
            Route::EffectiveGet => {
                let toml = config::get().without_secrets().to_toml();
                self.conns[i].respond(200, "application/toml", &[], toml.as_bytes());
            }
            Route::EffectiveJson => {
                let json = config::get().without_secrets().to_json();
                self.conns[i].respond_json(200, &json);
            }
            Route::ConfigPut => self.check_config(i),
            Route::Login => self.conns[i].respond_json(200, "{\"ok\":true}"),
            Route::Log => {
                let ram = crate::console::logging_to_ram();
                let (text, dropped) = crate::console::log_tail(None, LOG_MAX);
                let body = format!(
                    "{{\"ram\":{ram},\"dropped\":{dropped},\"text\":{}}}",
                    json_str(&text)
                );
                self.conns[i].respond_json(200, &body);
            }
            Route::ConfigConfirm
            | Route::ConfigRevert
            | Route::UpgradeConfirm
            | Route::UpgradeRevert => {
                let image = matches!(route, Route::UpgradeConfirm | Route::UpgradeRevert);
                let t = if image { &self.image_trial } else { &self.trial };
                let Some(t) = t else { return };
                let op = if matches!(route, Route::ConfigConfirm | Route::UpgradeConfirm) {
                    StoreOp::Confirm(t.area, t.slot, t.header.with_flags(0))
                } else {
                    StoreOp::Revert(t.area, t.slot)
                };
                self.op = Some((Some(i), op));
                self.op_busy = true;
            }
        }
    }

    /// `POST /api/config`: parse (TOML, or JSON by content type) and
    /// validate; queue the save, as a trial if it could lock the user out.
    fn check_config(&mut self, i: usize) {
        use config::schema;
        let c = &mut self.conns[i];
        let json = c
            .head
            .as_ref()
            .and_then(|h| h.header("content-type"))
            .is_some_and(|t| t.trim_start().starts_with("application/json"));
        let parsed = match core::str::from_utf8(&c.body) {
            Err(_) => Err(schema::Error::Syntax(String::from("not UTF-8"))),
            Ok(t) if json => schema::parse_json(t),
            Ok(t) => schema::parse(t),
        };
        match parsed {
            Err(e) => {
                let msg = format!("{e}");
                println!("  mgmt            : config rejected: {}", msg.replace('\n', "; "));
                let issues = match &e {
                    schema::Error::Invalid(v) => v
                        .iter()
                        .map(|x| {
                            format!(
                                "{{\"path\":{},\"msg\":{}}}",
                                json_str(&x.path),
                                json_str(&x.msg)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    _ => String::new(),
                };
                c.respond_json(
                    422,
                    &format!(
                        "{{\"ok\":false,\"error\":{},\"issues\":[{issues}]}}",
                        json_str(&msg)
                    ),
                );
            }
            Ok(mut cfg) => {
                // What GET returned has no secrets: keep the stored ones.
                cfg.keep_secrets(&config::base());
                let flags = if cfg.needs_trial(&config::base()) {
                    config_store::FLAG_TRIAL
                } else {
                    0
                };
                self.saved_lan = Some(format!("{}", cfg.lan.ipv4.addr));
                self.op = Some((
                    Some(i),
                    StoreOp::Save {
                        toml: cfg.to_toml(),
                        flags,
                        cfg: alloc::boxed::Box::new(cfg),
                    },
                ));
                self.op_busy = true;
            }
        }
    }

    fn finish_upload(&mut self, i: usize, route: Route) {
        let c = &mut self.conns[i];
        let len = c.upload_len;
        let head = c.head.as_ref().expect("upload without head");
        let want_crc = head
            .header("x-image-crc32")
            .map(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16));
        // `image=ram`: the new kernel must not act as the loader and enter
        // the store's kernel instead of itself.
        let cmdline = upgrade::with_arg(
            head.header("x-cmdline").unwrap_or(config::bootargs()),
            "image",
            "ram",
        );
        let staging = self.staging.as_deref_mut().expect("upload without staging");
        let result = match want_crc {
            Some(Err(_)) => Err(String::from("X-Image-CRC32: not a hex number")),
            Some(Ok(want)) if want != c.crc => Err(format!(
                "CRC mismatch: received {:08x}, header says {want:08x}",
                c.crc
            )),
            _ => upgrade::prepare(staging, len),
        };
        match result {
            Ok(p) if route == Route::UpgradePersist => {
                println!(
                    "  mgmt            : kernel accepted for the store: {} bytes, crc32 {:08x}, {}",
                    len,
                    c.crc,
                    p.describe()
                );
                let image = staging[..len].to_vec();
                self.op = Some((Some(i), StoreOp::SaveImage(image)));
                self.op_busy = true;
            }
            Ok(p) => {
                let detail = format!("{} bytes, crc32 {:08x}, {}", len, c.crc, p.describe());
                println!("  mgmt            : upgrade accepted: {detail}");
                println!(
                    "  mgmt            : new command line: \"{}\"",
                    config::Redacted(&cmdline)
                );
                c.respond_json(
                    200,
                    &format!("{{\"ok\":true,\"detail\":{}}}", json_str(&detail)),
                );
                c.after = After::Exec(p, cmdline);
            }
            Err(e) => {
                println!("  mgmt            : upgrade rejected: {e}");
                c.error(422, &e);
                self.uploader = None;
            }
        }
    }

    /// Received bytes for connection `i`: parse; route the head as soon as
    /// it is complete; body bytes go to the staging area (upload) or are
    /// dropped.
    fn on_bytes(&mut self, i: usize, buf: &[u8]) {
        let c = &mut self.conns[i];
        if c.parser.is_done() || c.responded_at.is_some() && self.uploader != Some(i) {
            return; // request complete, or already answered: discard
        }
        let step = match c.parser.push(buf) {
            Ok(step) => step,
            Err(e) => {
                let msg = match e {
                    HttpError::BodyTooLarge => "body too large",
                    HttpError::HeadTooLarge => "request head too large",
                    HttpError::LengthRequired => "Content-Length required (no chunked uploads)",
                    HttpError::BadRequest => "bad request",
                };
                c.error(e.status(), msg);
                return;
            }
        };
        if let Some(h) = step.head {
            self.on_head(i, h);
        }
        let c = &mut self.conns[i];
        if self.uploader == Some(i) && c.responded_at.is_none() {
            let st = self
                .staging
                .as_deref_mut()
                .expect("uploader without staging");
            let end = c.upload_len + step.body.len();
            st[c.upload_len..end].copy_from_slice(step.body);
            c.crc = boot_image::crc32(c.crc, step.body);
            c.upload_len = end;
        } else if c.route == Some(Route::ConfigPut) && c.responded_at.is_none() {
            c.body.extend_from_slice(step.body);
        }
    }

    /// Serve all connections. Returns an action once its response is sent.
    pub fn step(
        &mut self,
        ifs: &mut [HostIf],
        sh: &Shared,
        services: Option<&LanServices>,
    ) -> Option<Action> {
        let mut action = None;
        if self.reboot_pending {
            return Some(Action::Reboot);
        }
        for image in [false, true] {
            let t = if image { &mut self.image_trial } else { &mut self.trial };
            if let Some(tr) = t
                && !self.op_busy
                && timer::Instant::now() >= tr.deadline
            {
                println!(
                    "  mgmt            : trial {} not confirmed within {} s: reverting",
                    what_trial(tr.area),
                    config::trial_secs()
                );
                self.op = Some((None, StoreOp::Revert(tr.area, tr.slot)));
                self.op_busy = true;
                *t = None;
            }
        }
        for i in 0..self.conns.len() {
            let (ifx, handle) = (self.conns[i].ifx, self.conns[i].handle);
            let sock = ifs[ifx].sockets.get_mut::<tcp::Socket>(handle);
            if sock.is_active() && self.conns[i].since.is_none() {
                self.conns[i].since = Some(timer::Instant::now());
            }
            while sock.can_recv() {
                if sock.recv(|buf| (buf.len(), self.on_bytes(i, buf))).is_err() {
                    break;
                }
            }
            let c = &self.conns[i];
            if c.head.is_some() && c.responded_at.is_none() && c.parser.is_done() {
                let mut json = (c.route == Some(Route::Status))
                    .then(|| status_json(ifs, sh, services, &self.wan_lease, self));
                self.on_done(i, &mut || json.take().unwrap_or_default());
            }
            // Send, close, recycle.
            let sock = ifs[ifx].sockets.get_mut::<tcp::Socket>(handle);
            let c = &mut self.conns[i];
            if c.sent < c.out.len() && sock.can_send() {
                if let Ok(n) = sock.send_slice(&c.out[c.sent..]) {
                    c.sent += n;
                }
                if c.sent == c.out.len() {
                    sock.close();
                }
            }
            let flushed = c.responded_at.is_some()
                && c.sent == c.out.len()
                && (sock.send_queue() == 0 || !sock.is_active());
            let flush_timeout = c.responded_at.is_some_and(|t| t.elapsed() > FLUSH_TIMEOUT);
            if (flushed || flush_timeout) && !matches!(c.after, After::Nothing) {
                match core::mem::replace(&mut c.after, After::Nothing) {
                    After::Reboot => action = Some(Action::Reboot),
                    After::Exec(p, cmdline) => {
                        if let Some(st) = self.staging.take() {
                            action = Some(Action::Exec(st, p, cmdline));
                        }
                    }
                    After::Nothing => {}
                }
            }
            let limit = if self.uploader == Some(i) {
                UPLOAD_TIMEOUT
            } else {
                REQUEST_TIMEOUT
            };
            // Answered before the body was read (an early error): the client
            // has its answer, the rest of the body is unwanted.
            let early = flushed && !c.parser.is_done();
            let lingering = flushed && c.responded_at.is_some_and(|t| t.elapsed() > LINGER);
            let lingering = lingering || early;
            if lingering || c.since.is_some_and(|t| t.elapsed() > limit) {
                sock.abort();
            }
            if !sock.is_open() {
                if self.uploader == Some(i) {
                    self.uploader = None;
                }
                c.reset();
                let _ = sock.listen(PORT);
            }
        }
        action
    }

    /// A connection is in progress (poll again soon).
    pub fn busy(&self) -> bool {
        self.conns.iter().any(|c| c.since.is_some())
    }
}

/// "config" or "kernel", for logs.
fn what_trial(area: &str) -> &'static str {
    if area == upgrade::AREA { "kernel" } else { "config" }
}

fn status_json(
    ifs: &[HostIf],
    sh: &Shared,
    services: Option<&LanServices>,
    wan_lease: &str,
    mgmt: &Mgmt,
) -> String {
    let mut s = String::with_capacity(2048);
    let trial = Trial::json(mgmt.trial.as_ref());
    let image = format!(
        "{{\"source\":{},\"trial\":{}}}",
        json_str(upgrade::source()),
        Trial::json(mgmt.image_trial.as_ref())
    );
    let (pool_free, pool_cap, pool_fail) = crate::net::packet::pool_stats();
    let (heap_used, heap_free) = crate::mm::heap::usage();
    // CPU load history per core: [busy, datapath, service] in permille,
    // oldest first.
    let mut cpu = format!(
        "{{\"interval_s\":{},\"cores\":[",
        crate::cpuload::INTERVAL.as_secs()
    );
    for core in 0..crate::smp::online() {
        cpu.push_str(if core > 0 { ",[" } else { "[" });
        let mut first = true;
        crate::cpuload::history(core, |x| {
            let _ = write!(
                cpu,
                "{}[{},{},{}]",
                if first { "" } else { "," },
                x.busy,
                x.datapath,
                x.service
            );
            first = false;
        });
        cpu.push(']');
    }
    cpu.push_str("]}");
    let _ = write!(
        s,
        "{{\"version\":{},\"build\":{},\"image\":{image},\"arch\":{},\"cmdline\":{},\"config\":{},\"overrides\":{{{}}},\"store\":{},\"disks\":[{}],\"trial\":{},\"uptime_s\":{},\"forwarded\":{},\"dropped\":{},\"vlan_drops\":{},\"conntrack\":{},\
         \"pool\":{{\"free\":{pool_free},\"capacity\":{pool_cap},\"alloc_failures\":{pool_fail}}},\
         \"heap\":{{\"used\":{heap_used},\"free\":{heap_free}}},\"cpu\":{cpu},\"wan_lease\":{wan_lease},\"pppoe\":{},\"pppoe_drops\":{},\
         \"drop_reasons\":{{{}}},\"mgmt\":{{\"on_wan\":{},\"auth\":{},\"upgrade\":{},\"persist\":{}}},\"interfaces\":[",
        json_str(env!("CARGO_PKG_VERSION")),
        json_str(env!("RROUTER_BUILD")),
        json_str(if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "aarch64"
        }),
        json_str(&format!("{}", config::Redacted(config::bootargs()))),
        json_str(&config::source()),
        config::overrides()
            .iter()
            .map(|(path, kv)| format!("{}:{}", json_str(path), json_str(kv)))
            .collect::<Vec<_>>()
            .join(","),
        mgmt.has_store,
        crate::store::probes()
            .iter()
            .map(|d| json_str(d))
            .collect::<Vec<_>>()
            .join(","),
        trial,
        timer::uptime().as_secs(),
        datapath::FORWARDED.load(Ordering::Relaxed),
        datapath::DROPPED.load(Ordering::Relaxed),
        datapath::VLAN_DROPS.load(Ordering::Relaxed),
        sh.conntrack(),
        mgmt.wan_pppoe.as_deref().unwrap_or("null"),
        datapath::PPPOE_DROPS.load(Ordering::Relaxed),
        fwd::forwarder::DropReason::all()
            .iter()
            .map(|r| format!(
                "{}:{}",
                json_str(r.name()),
                datapath::DROP_REASONS[r.index()].load(Ordering::Relaxed)
            ))
            .collect::<Vec<_>>()
            .join(","),
        mgmt.on_wan,
        mgmt.password.is_some(),
        mgmt.password.is_some() && (mgmt.staging.is_some() || mgmt.uploader.is_some()),
        mgmt.password.is_some()
            && mgmt.has_store
            && (mgmt.staging.is_some() || mgmt.uploader.is_some()),
    );
    for (n, (host, nif)) in ifs.iter().zip(&sh.ports).enumerate() {
        let snap = *nif.snap.lock();
        let st = snap.stats;
        let (q, rate) = {
            let q = nif.qdisc.lock();
            (q.stats(), q.rate())
        };
        let link = match snap.link {
            Some((up, mbps, full)) => {
                format!("{{\"up\":{up},\"mbps\":{mbps},\"full_duplex\":{full}}}")
            }
            None => String::from("null"),
        };
        let addrs: Vec<String> = host
            .iface
            .ip_addrs()
            .iter()
            .map(|a| json_str(&format!("{a}")))
            .collect();
        let vlan = nif
            .vlan()
            .map(|t| format!("{{\"id\":{},\"pcp\":{}}}", t & 0x0fff, t >> 13))
            .unwrap_or_else(|| String::from("null"));
        let rate = rate
            .map(|r| format!("{}", r.bits_per_sec / 1000))
            .unwrap_or_else(|| String::from("null"));
        let _ = write!(
            s,
            "{}{{\"name\":{},\"model\":{},\"mac\":{},\"vlan\":{vlan},\"link\":{link},\"addrs\":[{}],\
             \"rx_packets\":{},\"rx_bytes\":{},\"rx_no_buf\":{},\"tx_packets\":{},\"tx_bytes\":{},\
             \"qdisc\":{{\"shaped_kbit\":{rate},\"sent\":{},\"dropped\":{},\"ecn_marked\":{},\"backlog_packets\":{}}}}}",
            if n > 0 { "," } else { "" },
            json_str(nif.name),
            json_str(nif.model),
            json_str(&format!("{}", smoltcp::wire::EthernetAddress(nif.mac))),
            addrs.join(","),
            st.rx_packets,
            st.rx_bytes,
            st.rx_dropped_no_buf,
            st.tx_packets,
            st.tx_bytes,
            q.dequeued,
            q.dropped,
            q.marked,
            q.backlog_packets,
        );
    }
    s.push_str("],\"dhcp_leases\":[");
    if let Some(svc) = services {
        let now = timer::uptime().as_secs();
        for (n, l) in svc.leases().enumerate() {
            let _ = write!(
                s,
                "{}{{\"mac\":{},\"ip\":{},\"hostname\":{},\"bound\":{},\"expires_in_s\":{}}}",
                if n > 0 { "," } else { "" },
                json_str(&format!("{}", smoltcp::wire::EthernetAddress(l.mac))),
                json_str(&format!("{}", l.ip)),
                l.hostname
                    .as_deref()
                    .map(json_str)
                    .unwrap_or_else(|| String::from("null")),
                l.state == proto_dhcp::v4::server::LeaseState::Bound,
                l.expires.saturating_sub(now),
            );
        }
    }
    s.push(']');
    // Wall clock (SNTP) and watchdog.
    let ntp = services.and_then(LanServices::ntp_status);
    let _ = write!(
        s,
        ",\"time\":{{\"utc\":{},\"unix_s\":{},\"servers\":[{}],\"server\":{},\"offset_from_boot_ms\":{},\"delay_ms\":{},\"stratum\":{},\"poll_s\":{}}}",
        crate::wallclock::now()
            .map(|t| json_str(&format!("{t}")))
            .unwrap_or_else(|| String::from("null")),
        crate::wallclock::now()
            .map(|t| format!("{}", t.secs()))
            .unwrap_or_else(|| String::from("null")),
        ntp.as_ref()
            .map(|n| n.servers.iter().map(|x| json_str(x)).collect::<Vec<_>>().join(","))
            .unwrap_or_default(),
        ntp.as_ref()
            .and_then(|n| n.server)
            .map(|a| json_str(&format!("{a}")))
            .unwrap_or_else(|| String::from("null")),
        ntp.as_ref()
            .and_then(|n| n.synced)
            .map(|x| format!("{}", x.offset / 1_000_000))
            .unwrap_or_else(|| String::from("null")),
        ntp.as_ref()
            .and_then(|n| n.synced)
            .map(|x| format!("{:.1}", x.delay as f64 / 1e6))
            .unwrap_or_else(|| String::from("null")),
        ntp.as_ref()
            .and_then(|n| n.synced)
            .map(|x| format!("{}", x.stratum))
            .unwrap_or_else(|| String::from("null")),
        ntp.as_ref().map_or(0, |n| n.interval_s),
    );
    match crate::watchdog::status() {
        Some(w) => {
            let _ = write!(
                s,
                ",\"watchdog\":{{\"enabled\":{},\"hardware\":{},\"hw_secs\":{},\"last_reset_by_watchdog\":{}}}",
                w.enabled,
                w.hw.map(json_str).unwrap_or_else(|| String::from("null")),
                w.hw_secs,
                w.fired_last_boot
            );
        }
        None => s.push_str(",\"watchdog\":null"),
    }
    s.push('}');
    s
}
