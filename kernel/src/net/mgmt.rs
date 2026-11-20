//! Management web interface: HTTP on port 80 (smoltcp TCP ↔ `proto_http`).
//!
//! - `GET /`: the page (`mgmt.html`, compiled in): a login screen first
//!   when a password exists, then the interface, which polls
//! - `GET /api/status`: JSON (interfaces, link, qdisc, DHCP leases, memory)
//! - `GET /api/info`: `{auth}`, without auth: whether a password exists
//!   (the page shows its login screen then). Nothing else is public.
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
//! - `GET /api/log`: the RAM log's tail as JSON (`{ram, dropped, text}`),
//!   always with auth: it names hosts and addresses.
//! - `POST /api/login` (Basic auth, the page's login screen): a session
//!   token (`{ok, token}`), sent as `Authorization: Bearer <token>`; it
//!   lasts while used at least every 12 h. `POST /api/logout` ends it.
//! - Requests with `X-Leatos-UI: 1` (the page's own) get a 401 without
//!   `WWW-Authenticate`, so the browser shows the page's login screen
//!   instead of its own password dialog.
//!
//! With a password, everything but the page itself and `/api/info` needs
//! auth, status and config reads included (as in OpenWrt's LuCI); without
//! one, reads are public and changes refused. Auth is a session token, or
//! HTTP Basic (user `admin`, scripts) with the password from the
//! `mgmt_pass=` boot argument or else the config's `mgmt.password_hash`
//! (PBKDF2-SHA256, checked once per login; scripts' repeats are cached).
//! A wrong password blocks password attempts for a second. A saved `mgmt.password` (clear text, from the form or the
//! CLI) is hashed before it is stored, and ends all sessions.
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
/// Login sessions at once, and how long one lasts unused.
const SESSIONS: usize = 8;
const SESSION_IDLE_MS: u64 = 12 * 3600 * 1000;
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

/// Listening sockets on each network that reaches the web interface and
/// has none yet (`LAN_SOCKETS` per link). Returns the networks' names.
fn add_lan_sockets(conns: &mut Vec<Conn>, ifs: &mut [HostIf], links: &[usize]) -> Vec<String> {
    let nets = config::networks();
    let mut on = Vec::new();
    for (net, &link) in nets.iter().zip(links) {
        if !net.mgmt || conns.iter().any(|c| c.ifx == link) {
            continue;
        }
        for _ in 0..LAN_SOCKETS {
            conns.push(Conn::new(link, ifs[link].sockets.add(tcp_socket())));
        }
        on.push(net.name.clone());
    }
    on
}

/// What the network task must do after [`Mgmt::step`].
pub enum Action {
    /// Stop the devices and enter the prepared kernel.
    Exec(&'static mut [u8], Prepared, String),
    Reboot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Index,
    /// Public: whether a password exists.
    Info,
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
    Logout,
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
        /// Reboot into it instead of applying it live: a trial, or a
        /// change to the networks (`Config::needs_reboot`).
        reboot: bool,
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
    /// `X-Leatos-UI`: answer 401 without `WWW-Authenticate`.
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
                &[("WWW-Authenticate", "Basic realm=\"leatos\"")],
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
    /// `mgmt_pass=` (wins over the config's hash).
    boot_pass: Option<&'static str>,
    sessions: auth::Sessions,
    /// The last password that verified against the stored hash.
    pass_cache: auth::Cache,
    /// After a wrong password: no password checks until then.
    fail_until: Option<timer::Instant>,
    /// The save being written changes the password: end the sessions.
    password_changing: bool,
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
    /// `ifs[0]` is the WAN; network `k` of `config::networks` is on
    /// `ifs[links[k]]`.
    pub fn new(ifs: &mut [HostIf], links: &[usize], has_store: bool) -> Self {
        let cfg = config::mgmt();
        let mut conns = Vec::new();
        // The WAN only with mgmt=wan.
        if cfg.on_wan {
            for _ in 0..WAN_SOCKETS {
                conns.push(Conn::new(0, ifs[0].sockets.add(tcp_socket())));
            }
        }
        let on = add_lan_sockets(&mut conns, ifs, links);
        let staging = crate::mm::heap::take_staging();
        println!(
            "  mgmt            : http :{PORT} on {}{}, upgrade {}",
            on.join(" + "),
            if cfg.on_wan {
                " + WAN (mgmt=wan: development only!)"
            } else {
                ""
            },
            match (&staging, cfg.password, config::password_hash()) {
                (None, ..) => "unavailable (no staging area on this platform)",
                (Some(_), None, None) => "disabled (no password: mgmt.password or mgmt_pass=)",
                (Some(_), Some(_), _) => "enabled (admin + mgmt_pass)",
                (Some(_), None, Some(_)) => "enabled (admin + the configured password)",
            }
        );
        Self {
            conns,
            staging,
            uploader: None,
            boot_pass: cfg.password,
            sessions: auth::Sessions::new(SESSIONS, SESSION_IDLE_MS),
            pass_cache: crate::entropy::with(auth::Cache::new),
            fail_until: None,
            password_changing: false,
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

    /// Networks changed (live): listen on those whose zone now lets the
    /// web interface be reached. Sockets are never taken away (connection
    /// indices stay valid); the forwarder's input policy refuses what a
    /// zone may no longer reach, and a slot without a network has no
    /// address.
    pub fn add_sockets(&mut self, ifs: &mut [HostIf], links: &[usize]) {
        let on = add_lan_sockets(&mut self.conns, ifs, links);
        if !on.is_empty() {
            println!("  mgmt            : http :{PORT} now also on {}", on.join(" + "));
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
            (StoreOp::Save { flags, reboot, .. }, Ok(detail)) => {
                // A new password: every session ends (log in again).
                if core::mem::take(&mut self.password_changing) {
                    self.sessions.clear();
                    println!("  mgmt            : password changed: sessions ended");
                }
                // A trial must boot to be confirmed, a new network layout
                // is built at boot; everything else was applied live by
                // the services task.
                let trial = *flags != 0;
                let reboot = *reboot || trial;
                let what = if trial {
                    "saved as a trial, rebooting"
                } else if reboot {
                    "saved, rebooting into the new networks"
                } else {
                    "saved and applied"
                };
                println!("  mgmt            : config {what} ({detail})");
                let lan = self.saved_lan.take().unwrap_or_default();
                (
                    200,
                    format!(
                        "{{\"ok\":true,\"detail\":{},\"trial\":{trial},\"reboot\":{reboot},\"applied\":{},\"confirm_within_s\":{},\"lan\":{}}}",
                        json_str(&format!("{what} ({detail})")),
                        !reboot,
                        if trial { config::trial_secs() } else { 0 },
                        json_str(&lan)
                    ),
                    reboot,
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

    /// A management password exists (boot argument or config).
    fn auth_configured(&self) -> bool {
        self.boot_pass.is_some() || config::password_hash().is_some()
    }

    /// A session token, or Basic auth with the password: Ok, or the error
    /// status and message.
    fn authorized(&mut self, head: &Head) -> Result<(), (u16, &'static str)> {
        if !self.auth_configured() {
            return Err((
                403,
                "disabled: no password (serial CLI: config set mgmt.password = \"...\", or boot with mgmt_pass=)",
            ));
        }
        let now = timer::uptime().as_millis() as u64;
        if let Some(token) = head
            .header("authorization")
            .and_then(|a| a.trim().strip_prefix("Bearer "))
        {
            return if self.sessions.check(token.trim(), now) {
                Ok(())
            } else {
                Err((401, "session expired: log in again"))
            };
        }
        let Some((u, p)) = proto_http::basic_auth(head) else {
            return Err((401, "wrong or missing credentials (user admin)"));
        };
        if self.fail_until.is_some_and(|t| timer::Instant::now() < t) {
            return Err((429, "wrong password just now: wait a second"));
        }
        let ok = u == "admin"
            && match (self.boot_pass, config::password_hash()) {
                (Some(pass), _) => proto_http::ct_eq(p.as_bytes(), pass.as_bytes()),
                (None, Some(hash)) => self.pass_cache.verify(&p, &hash),
                (None, None) => false,
            };
        if ok {
            Ok(())
        } else {
            self.fail_until = timer::Instant::now().checked_add(Duration::from_secs(1));
            Err((401, "wrong or missing credentials (user admin)"))
        }
    }

    /// Who the password comes from (status page).
    fn auth_source(&self) -> &'static str {
        match (self.boot_pass, config::password_hash()) {
            (Some(_), _) => "boot argument",
            (None, Some(_)) => "config",
            (None, None) => "none",
        }
    }

    /// A request head arrived: route it, check auth, claim the staging area.
    fn on_head(&mut self, i: usize, head: Head) {
        crate::entropy::mix(head.path.as_bytes());
        self.conns[i].no_prompt = head.header("x-leatos-ui").is_some();
        let route = match (head.method, head.path.as_str()) {
            (Method::Get, "/" | "/index.html") => Ok(Route::Index),
            (Method::Get, "/api/info") => Ok(Route::Info),
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
            (Method::Post, "/api/logout") => Ok(Route::Logout),
            (Method::Get, "/api/log") => Ok(Route::Log),
            (
                _,
                "/" | "/index.html" | "/api/info" | "/api/status" | "/api/upgrade" | "/api/upgrade/persist"
                | "/api/upgrade/confirm" | "/api/upgrade/revert" | "/api/reboot"
                | "/api/config" | "/api/config.json" | "/api/config/effective"
                | "/api/config/effective.json" | "/api/config/confirm"
                | "/api/config/revert" | "/api/login" | "/api/logout" | "/api/log",
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
            // Reads are public only while there is no password at all.
            let reads = matches!(
                r,
                Route::Status
                    | Route::ConfigGet
                    | Route::ConfigJson
                    | Route::EffectiveGet
                    | Route::EffectiveJson
            );
            if reads && self.auth_configured() {
                self.authorized(&head)?;
            }
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
            Route::Info => {
                let body = format!("{{\"auth\":{}}}", self.auth_configured());
                self.conns[i].respond_json(200, &body);
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
            Route::Login => {
                let now = timer::uptime().as_millis() as u64;
                let token = crate::entropy::with(|p| self.sessions.create(p, now));
                self.conns[i].respond_json(200, &format!("{{\"ok\":true,\"token\":{}}}", json_str(&token)));
            }
            Route::Logout => {
                let token = self.conns[i]
                    .head
                    .as_ref()
                    .and_then(|h| h.header("authorization"))
                    .and_then(|a| a.trim().strip_prefix("Bearer "))
                    .map(String::from);
                if let Some(t) = token {
                    self.sessions.remove(t.trim());
                }
                self.conns[i].respond_json(200, "{\"ok\":true}");
            }
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
        }
        .and_then(|cfg| config::supported(&cfg).map(|()| cfg));
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
                // A new password in clear is stored as a hash only.
                self.password_changing = crate::entropy::with(|p| cfg.hash_new_password(p));
                let flags = if cfg.needs_trial(&config::base()) {
                    config_store::FLAG_TRIAL
                } else {
                    0
                };
                self.saved_lan = cfg.lan().map(|n| format!("{}", n.ipv4.addr));
                self.op = Some((
                    Some(i),
                    StoreOp::Save {
                        toml: cfg.to_toml(),
                        flags,
                        reboot: cfg.needs_reboot(&config::base()),
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
            // The request gets `limit` to arrive; once answered, the answer
            // gets REQUEST_TIMEOUT to be delivered, counted from the answer
            // (a rejected upload releases the upload slot, but its 422 must
            // still go out after a long body).
            let timed_out = match c.responded_at {
                None => c.since.is_some_and(|t| t.elapsed() > limit),
                Some(t) => t.elapsed() > REQUEST_TIMEOUT,
            };
            if lingering || timed_out {
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
    // Cumulative CPU time per task, as in the log's "cpu" line
    // (scripts/lab-test.sh compares it before/after the load phase).
    cpu.push_str("],\"tasks\":[");
    let mut first = true;
    crate::executor::task_ticks(|name, core, ticks| {
        let _ = write!(
            cpu,
            "{}{{\"name\":{},\"core\":{core},\"ms\":{}}}",
            if first { "" } else { "," },
            json_str(name),
            timer::ticks_to_duration(ticks).as_millis()
        );
        first = false;
    });
    cpu.push_str("]}");
    // CPU temperature (milli-°C; null without a sensor, e.g. in QEMU),
    // with a history at the CPU load's interval.
    let temp = {
        use crate::drivers::cputemp;
        let mut hist = String::new();
        let found = cputemp::history(|t| {
            let _ = write!(hist, "{}{t}", if hist.is_empty() { "" } else { "," });
        });
        match cputemp::read() {
            Some(now) if found => format!(
                "{{\"cpu_mc\":{now},\"htc_mc\":{},\"history_mc\":[{hist}]}}",
                cputemp::htc().map(|h| format!("{h}")).unwrap_or_else(|| "null".into())
            ),
            _ => "null".into(),
        }
    };
    // Heap use history (KiB per cpuload interval) and the RAM layout.
    let memory = {
        let mut hist = String::new();
        crate::cpuload::memory_history(|k| {
            let _ = write!(hist, "{}{k}", if hist.is_empty() { "" } else { "," });
        });
        match crate::mm::heap::layout() {
            Some(l) => format!(
                "{{\"ram\":{},\"kernel\":{},\"staging\":{},\"heap\":{},\"history_used_kib\":[{hist}]}}",
                l.ram, l.kernel, l.staging, l.heap
            ),
            None => "null".into(),
        }
    };
    let _ = write!(
        s,
        "{{\"version\":{},\"build\":{},\"image\":{image},\"arch\":{},\"cmdline\":{},\"config\":{},\"overrides\":{{{}}},\"store\":{},\"disks\":[{}],\"trial\":{},\"uptime_s\":{},\"forwarded\":{},\"dropped\":{},\"vlan_drops\":{},\"conntrack\":{},\"early_drops\":{},\"conntrack_pass_us\":{{\"last\":{},\"max\":{}}},\"revoked\":{},\"rejected\":{},\"icmp_errors\":{},\
         \"pool\":{{\"free\":{pool_free},\"capacity\":{pool_cap},\"alloc_failures\":{pool_fail}}},\
         \"heap\":{{\"used\":{heap_used},\"free\":{heap_free}}},\"cpu\":{cpu},\"temp\":{temp},\"memory\":{memory},\"wan_lease\":{wan_lease},\"pppoe\":{},\"pppoe_drops\":{},\
         \"fragments\":{{\"forwarded\":{},\"parked\":{},\"park_drops\":{},\"split\":{},\"split_drops\":{}}},\"drop_reasons\":{{{}}},\"entropy\":{},\"mgmt\":{{\"on_wan\":{},\"auth\":{},\"password\":{},\"upgrade\":{},\"persist\":{}}},\"interfaces\":[",
        json_str(env!("CARGO_PKG_VERSION")),
        json_str(env!("LEATOS_BUILD")),
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
        datapath::EARLY_DROPS.load(Ordering::Relaxed),
        datapath::EXPIRE_LAST_US.load(Ordering::Relaxed),
        datapath::EXPIRE_MAX_US.load(Ordering::Relaxed),
        datapath::REVOKED.load(Ordering::Relaxed),
        datapath::REJECTED.load(Ordering::Relaxed),
        datapath::ICMP_ERRORS.load(Ordering::Relaxed),
        mgmt.wan_pppoe.as_deref().unwrap_or("null"),
        datapath::PPPOE_DROPS.load(Ordering::Relaxed),
        datapath::FRAGS_FORWARDED.load(Ordering::Relaxed),
        datapath::FRAGS_PARKED.load(Ordering::Relaxed),
        datapath::FRAGS_PARK_DROPS.load(Ordering::Relaxed),
        datapath::SPLIT.load(Ordering::Relaxed),
        datapath::SPLIT_DROPS.load(Ordering::Relaxed),
        fwd::forwarder::DropReason::all()
            .iter()
            .map(|r| format!(
                "{}:{}",
                json_str(r.name()),
                datapath::DROP_REASONS[r.index()].load(Ordering::Relaxed)
            ))
            .collect::<Vec<_>>()
            .join(","),
        json_str(&crate::entropy::status()),
        mgmt.on_wan,
        mgmt.auth_configured(),
        json_str(mgmt.auth_source()),
        mgmt.auth_configured() && (mgmt.staging.is_some() || mgmt.uploader.is_some()),
        mgmt.auth_configured()
            && mgmt.has_store
            && (mgmt.staging.is_some() || mgmt.uploader.is_some()),
    );
    for (n, nif) in sh.ports.iter().enumerate() {
        let snap = *nif.snap.lock();
        let st = snap.stats;
        let (q, rate, limit, ack_drops) = {
            let q = nif.qdisc.lock();
            (q.stats(), q.rate(), q.inner().limit_bytes(), q.inner().ack_drops())
        };
        let link = match snap.link {
            Some((up, mbps, full)) => {
                format!("{{\"up\":{up},\"mbps\":{mbps},\"full_duplex\":{full}}}")
            }
            None => String::from("null"),
        };
        // The addresses of every link on the port.
        let addrs: Vec<String> = ifs
            .iter()
            .zip(&sh.links)
            .filter(|(_, l)| l.port() == n)
            .flat_map(|(h, _)| h.iface.ip_addrs().iter().map(|a| json_str(&format!("{a}"))).collect::<Vec<_>>())
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
             \"qdisc\":{{\"shaped_kbit\":{rate},\"limit_bytes\":{limit},\"ack_drops\":{ack_drops},\"sent\":{},\"dropped\":{},\"ecn_marked\":{},\"backlog_packets\":{}}}}}",
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
    // The WAN ingress stage (the download's shaper; `null` with
    // `shape_ingress=0`, where lan0 egress shapes it).
    s.push_str("],\"ingress\":");
    {
        let (on, q, rate, charged, limit) = {
            let q = sh.ingress.lock();
            (crate::config::qos().ingress, q.stats(), q.rate(), q.charged_bytes, q.inner().limit_bytes())
        };
        if on {
            let rate = rate
                .map(|r| format!("{}", r.bits_per_sec / 1000))
                .unwrap_or_else(|| String::from("null"));
            let _ = write!(
                s,
                "{{\"shaped_kbit\":{rate},\"limit_bytes\":{limit},\"sent\":{},\"dropped\":{},\"ecn_marked\":{},\"backlog_packets\":{},\"charged_bytes\":{charged}}}",
                q.dequeued, q.dropped, q.marked, q.backlog_packets
            );
        } else {
            s.push_str("null");
        }
    }
    s.push_str(",\"dhcp_leases\":[");
    if let Some(svc) = services {
        let now = timer::uptime().as_secs();
        for (n, (net, l)) in svc.leases_by_network().enumerate() {
            let _ = write!(
                s,
                "{}{{\"network\":{},\"mac\":{},\"ip\":{},\"hostname\":{},\"bound\":{},\"expires_in_s\":{}}}",
                if n > 0 { "," } else { "" },
                json_str(net),
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
    // The networks: router interfaces on the LAN ports (docs/config-v2.md).
    s.push_str(",\"networks\":[");
    let v6 = services.map(LanServices::ipv6_status).unwrap_or_default();
    for (n, net) in config::networks().iter().enumerate() {
        let leases = services.map_or(0, |svc| {
            svc.leases_by_network()
                .filter(|(name, l)| *name == net.name && l.state == proto_dhcp::v4::server::LeaseState::Bound)
                .count()
        });
        // IPv6 (docs/ipv6.md step 1): the router's ULA and its RAs.
        let (ipv6, ra) = match (net.ula, v6.iter().find(|x| x.0 == net.name)) {
            (Some(u), Some(&(_, _, sent, rs))) => (json_str(&format!("{u}/64")), format!("{{\"sent\":{sent},\"solicits\":{rs}}}")),
            (Some(u), None) => (json_str(&format!("{u}/64")), String::from("null")),
            (None, _) => (String::from("null"), String::from("null")),
        };
        let gua = net.gua.map_or_else(|| String::from("null"), |g| json_str(&format!("{g}/64")));
        let _ = write!(
            s,
            "{}{{\"name\":{},\"port\":{},\"vlan\":{},\"ipv4\":{},\"ipv6\":{ipv6},\"ipv6_global\":{gua},\"ra\":{ra},\"zone\":{},\"dhcp\":{},\"mgmt\":{},\"leases\":{leases}}}",
            if n > 0 { "," } else { "" },
            json_str(&net.name),
            json_str(config::PORTS[net.port]),
            net.vid,
            json_str(&format!("{}/{}", net.addr, net.prefix)),
            json_str(&net.zone_name),
            net.dhcp,
            net.mgmt,
        );
    }
    s.push(']');
    // The WAN's IPv6 (development boot arguments, docs/ipv6.md step 2b).
    match (crate::net::wan6::status_json(), config::wan6()) {
        (Some(pd), _) => {
            s.push_str(",\"wan_ipv6\":");
            s.push_str(core::str::from_utf8(&pd).unwrap_or("null"));
        }
        (None, Some(w)) => {
            let addr = w.addr.map_or_else(|| String::from("null"), |(ip, len)| json_str(&format!("{ip}/{len}")));
            let _ = write!(s, ",\"wan_ipv6\":{{\"source\":\"static\",\"addr\":{addr},\"gateway\":{}}}", json_str(&format!("{}", w.gateway)));
        }
        (None, None) => s.push_str(",\"wan_ipv6\":null"),
    }
    // The routing table, then configured routes not in use.
    s.push_str(",\"routes\":[");
    for (n, r) in sh.route_rows().iter().enumerate() {
        let _ = write!(
            s,
            "{}{{\"dst\":\"{}/{}\",\"via\":{},\"dev\":{},\"kind\":\"{}\",\"name\":{},\"active\":{}}}",
            if n > 0 { "," } else { "" },
            r.dst.0,
            r.dst.1,
            r.via.map_or_else(|| "null".into(), |v| format!("\"{v}\"")),
            json_str(&r.dev),
            r.kind,
            r.name.as_deref().map_or_else(|| "null".into(), json_str),
            r.active
        );
    }
    s.push(']');
    // IPv6 [[route]]s: active while their router's /48 is this boot's ULA.
    s.push_str(",\"routes6\":[");
    for (n, (name, dst, len, via, on)) in config::named_routes6().iter().enumerate() {
        let _ = write!(
            s,
            "{}{{\"name\":{},\"dst\":\"{dst}/{len}\",\"via\":\"{via}\",\"active\":{on}}}",
            if n > 0 { "," } else { "" },
            json_str(name)
        );
    }
    s.push(']');
    // Firewall rules in effect (enabled ones) and the packets they decided.
    s.push_str(",\"rules\":[");
    let hits = sh.rule_hits.lock().clone();
    for (n, name) in config::rule_names().iter().enumerate() {
        let _ = write!(
            s,
            "{}{{\"name\":{},\"hits\":{}}}",
            if n > 0 { "," } else { "" },
            json_str(name),
            hits.get(n).copied().unwrap_or(0)
        );
    }
    s.push(']');
    // Port forwards in effect and the connections they took.
    s.push_str(",\"forwards\":[");
    let hits = sh.forward_hits.lock().clone();
    for (n, name) in config::forward_names().iter().enumerate() {
        let _ = write!(
            s,
            "{}{{\"name\":{},\"hits\":{}}}",
            if n > 0 { "," } else { "" },
            json_str(name),
            hits.get(n).copied().unwrap_or(0)
        );
    }
    s.push(']');
    // Redirects in effect and the connections they took.
    s.push_str(",\"redirects\":[");
    let hits = sh.redirect_hits.lock().clone();
    for (n, name) in config::redirect_names().iter().enumerate() {
        let _ = write!(
            s,
            "{}{{\"name\":{},\"hits\":{}}}",
            if n > 0 { "," } else { "" },
            json_str(name),
            hits.get(n).copied().unwrap_or(0)
        );
    }
    s.push(']');
    // mDNS reflector, per network taking part.
    s.push_str(",\"mdns\":[");
    for (n, (name, m)) in services.map(LanServices::mdns_status).unwrap_or_default().iter().enumerate() {
        let _ = write!(
            s,
            "{}{{\"network\":{},\"received\":{},\"sent\":{},\"filtered\":{},\"duplicate\":{},\"rate_limited\":{},\"malformed\":{},\"foreign\":{},\"oversize\":{}}}",
            if n > 0 { "," } else { "" },
            json_str(name),
            m.received,
            m.sent,
            m.filtered,
            m.duplicate,
            m.rate_limited,
            m.malformed,
            m.foreign,
            m.oversize
        );
    }
    s.push(']');
    // DNS upstreams: where from, and the DNS-over-TLS connections.
    if let Some(svc) = services {
        let ups: Vec<String> = svc.upstreams().iter().map(|a| json_str(&format!("{a}"))).collect();
        let (st, cached) = svc.dns_stats();
        // DNS over TCP from clients (null with `dns_tcp=0`).
        let (accepted, open) = svc.dns_tcp_status();
        let tcp = if config::dns_tcp() {
            format!("{{\"queries\":{},\"accepted\":{accepted},\"open\":{open}}}", st.tcp_queries)
        } else {
            String::from("null")
        };
        let _ = write!(
            s,
            ",\"dns\":{{\"source\":{},\"upstreams\":[{}],\"tls\":{},\"cached\":{},\"queries\":{},\"local\":{},\"hidden\":{},\"cache_hits\":{},\"forwarded\":{},\"merged\":{},\"timeouts\":{},\"servfails\":{},\"rebind_blocked\":{},\"prefetches\":{},\"prefetch_failed\":{},\"stale_answers\":{},\"tcp\":{}",
            json_str(svc.upstream_source()),
            ups.join(","),
            svc.dot_status_json().unwrap_or_else(|| "null".into()),
            cached,
            st.queries,
            st.local_answers,
            st.hidden,
            st.cache_hits,
            st.forwarded,
            st.merged,
            st.timeouts,
            st.servfails,
            st.rebind_blocked,
            st.prefetches,
            st.prefetch_failed,
            st.stale_answers,
            tcp
        );
        // Local names ([[dns.host]], config order) and the queries each
        // answered.
        s.push_str(",\"hosts\":[");
        let hits = svc.dns_host_hits();
        for (n, h) in config::get().dns.hosts.iter().enumerate() {
            let _ = write!(
                s,
                "{}{{\"name\":{},\"ip\":\"{}\",\"hits\":{}}}",
                if n > 0 { "," } else { "" },
                json_str(&h.name),
                h.ip,
                hits.get(n).copied().unwrap_or(0)
            );
        }
        s.push_str("]}");
    }
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
