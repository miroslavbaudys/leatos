//! Management web interface: HTTP on port 80 (smoltcp TCP ↔ `proto_http`).
//!
//! - `GET /`: the status page (`mgmt.html`, compiled in), which polls
//! - `GET /api/status`: JSON (interfaces, link, qdisc, DHCP leases, memory)
//! - `POST /api/upgrade`: body = a kernel ELF; streamed straight into the
//!   staging area (`mm::heap::take_staging`), checked (`crate::upgrade`,
//!   optional `X-Image-CRC32` header), then the network task hands over to
//!   it in RAM. `X-Cmdline` replaces the kernel command line for the new
//!   kernel (default: keep the current one).
//! - `POST /api/reboot`: firmware reset.
//!
//! Upgrade and reboot need HTTP Basic auth (user `admin`, password from the
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
    Reboot,
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
    /// Queued response and how much of it has been sent.
    out: Vec<u8>,
    sent: usize,
    after: After,
    /// Connection start (for the timeouts).
    since: Option<timer::Instant>,
    responded_at: Option<timer::Instant>,
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
            out: Vec::new(),
            sent: 0,
            after: After::Nothing,
            since: None,
            responded_at: None,
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
        if status == 401 {
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
    pub fn new(ifs: &mut [HostIf]) -> Self {
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
        }
    }

    /// The WAN lease for the status page (already JSON).
    pub fn set_wan_lease(&mut self, json: String) {
        self.wan_lease = json;
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
        let route = match (head.method, head.path.as_str()) {
            (Method::Get, "/" | "/index.html") => Ok(Route::Index),
            (Method::Get, "/api/status") => Ok(Route::Status),
            (Method::Post, "/api/upgrade") => Ok(Route::Upgrade),
            (Method::Post, "/api/reboot") => Ok(Route::Reboot),
            (_, "/" | "/index.html" | "/api/status" | "/api/upgrade" | "/api/reboot") => {
                Err((405, "method not allowed"))
            }
            _ => Err((404, "not found")),
        };
        let route = route.and_then(|r| {
            if matches!(r, Route::Upgrade | Route::Reboot) {
                self.authorized(&head)?;
            }
            Ok(r)
        });
        let route = route.and_then(|r| {
            if r != Route::Upgrade {
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
            Route::Upgrade => self.finish_upload(i),
        }
    }

    fn finish_upload(&mut self, i: usize) {
        let c = &mut self.conns[i];
        let len = c.upload_len;
        let head = c.head.as_ref().expect("upload without head");
        let want_crc = head
            .header("x-image-crc32")
            .map(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16));
        let cmdline = String::from(head.header("x-cmdline").unwrap_or(config::bootargs()));
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

fn status_json(
    ifs: &[HostIf],
    sh: &Shared,
    services: Option<&LanServices>,
    wan_lease: &str,
    mgmt: &Mgmt,
) -> String {
    let mut s = String::with_capacity(2048);
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
        "{{\"version\":{},\"arch\":{},\"uptime_s\":{},\"forwarded\":{},\"dropped\":{},\"conntrack\":{},\
         \"pool\":{{\"free\":{pool_free},\"capacity\":{pool_cap},\"alloc_failures\":{pool_fail}}},\
         \"heap\":{{\"used\":{heap_used},\"free\":{heap_free}}},\"cpu\":{cpu},\"wan_lease\":{wan_lease},\
         \"mgmt\":{{\"on_wan\":{},\"upgrade\":{}}},\"interfaces\":[",
        json_str(env!("CARGO_PKG_VERSION")),
        json_str(if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "aarch64"
        }),
        timer::uptime().as_secs(),
        datapath::FORWARDED.load(Ordering::Relaxed),
        datapath::DROPPED.load(Ordering::Relaxed),
        sh.conntrack(),
        mgmt.on_wan,
        mgmt.password.is_some() && (mgmt.staging.is_some() || mgmt.uploader.is_some()),
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
        let rate = rate
            .map(|r| format!("{}", r.bits_per_sec / 1000))
            .unwrap_or_else(|| String::from("null"));
        let _ = write!(
            s,
            "{}{{\"name\":{},\"model\":{},\"mac\":{},\"link\":{link},\"addrs\":[{}],\
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
    s.push_str("]}");
    s
}
