//! DNS over TLS to the upstream servers (`dns.tls`, docs/dns-over-tls.md):
//! the forwarder's upstream queries go through `proto_dot` connections
//! instead of UDP.
//!
//! One TCP connection per upstream on the WAN, opened when a query needs
//! it and closed after [`IDLE`] without queries (session resumption makes
//! the next one cheap). Queries are pipelined; the resolver matches the
//! answers by ID and question as for UDP. A failed handshake (a bad
//! certificate, no answer) backs that server off for [`BACKOFF_MIN`]
//! doubling to [`BACKOFF_MAX`]; its queries are dropped meanwhile and the
//! resolver's retry goes to the next server. Strict: nothing falls back to
//! plain DNS.
//!
//! The kernel supplies the TLS layer's randomness (`entropy`), the clock
//! (`wallclock`, unknown until SNTP: `proto_dot::verify`) and the build
//! time as the earliest believable date, and the battery-backed RTC as a
//! hint where it cannot lock DNS out (`proto_dot::verify`). A connection
//! opened before the clock was known is closed once it is, so the next one
//! checks the certificate's dates too.

use crate::config::schema::Upstream;
use crate::net::svc::HostIf;
use crate::{println, timer, wallclock};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::time::Duration;
use proto_dot::rustls::crypto::{GetRandomFailed, SecureRandom};
use proto_dot::{Clock, Conn, ServerName, State, UnixTime};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;

/// Close a connection that carried no query for this long.
const IDLE: Duration = Duration::from_secs(30);
/// TCP connect plus TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A closing socket is removed after this even without the peer's FIN.
const LINGER: Duration = Duration::from_secs(5);
const TCP_BUF: usize = 16 * 1024;
/// Local TCP ports: router-local, like every client of the router
/// (`fwd::forwarder::ROUTER_CLIENT_PORTS` and up).
const PORT_BASE: u16 = 61_000;
const PORT_SPAN: u16 = 4_000;

/// rustls' randomness: the kernel's pool (`entropy`).
#[derive(Debug)]
struct KernelRng;

impl SecureRandom for KernelRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        crate::entropy::with(|p| p.fill(buf));
        Ok(())
    }
}

static RNG: KernelRng = KernelRng;

#[derive(Debug)]
struct WallClock;

fn unix(t: wallclock::UnixTime) -> Option<UnixTime> {
    Some(UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(t.secs()).ok()?)))
}

impl Clock for WallClock {
    fn now(&self) -> Option<UnixTime> {
        unix(wallclock::now()?)
    }
    /// The battery-backed RTC (`wallclock::rtc_hint`), before SNTP.
    fn hint(&self) -> Option<UnixTime> {
        unix(wallclock::rtc_hint()?)
    }
}

/// Unix time of the commit this kernel was built from (`build.rs`).
const BUILD_TIME: u64 = {
    let s = env!("LEATOS_BUILD_TIME").as_bytes();
    let mut v = 0u64;
    let mut i = 0;
    while i < s.len() {
        v = v * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    v
};

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub queries: u64,
    pub answers: u64,
    /// Queries dropped while the server was backed off.
    pub dropped: u64,
    pub connects: u64,
    pub failures: u64,
}

struct Link {
    up: Upstream,
    port: u16,
    name: ServerName<'static>,
    sock: Option<SocketHandle>,
    conn: Option<Conn>,
    /// When the current connection started (its handshake deadline).
    opened: timer::Instant,
    last_used: timer::Instant,
    retry_at: Option<timer::Instant>,
    backoff: Duration,
    /// Logged "connected" for the current connection.
    announced: bool,
    tls: Option<String>,
    error: Option<String>,
    n: Counters,
}

pub struct Dot {
    cfg: proto_dot::Config,
    ca: Option<String>,
    links: Vec<Link>,
    closing: Vec<(SocketHandle, timer::Instant)>,
    next_port: u16,
}

fn later(d: Duration) -> timer::Instant {
    timer::Instant::now().checked_add(d).unwrap_or(timer::Instant::now())
}

fn tls_config(ca: Option<&str>) -> Result<proto_dot::Config, String> {
    let extra = match ca {
        Some(pem) => proto_dot::certs_from_pem(pem).map_err(|e| alloc::format!("dns.tls_ca: {e}"))?,
        None => Vec::new(),
    };
    proto_dot::Config::new(&RNG, Arc::new(WallClock), BUILD_TIME, &extra).map_err(|e| alloc::format!("{e}"))
}

fn link(up: &Upstream) -> Option<Link> {
    let name = up.name.clone()?;
    let name = ServerName::try_from(name).ok()?;
    Some(Link {
        port: up.port(true),
        up: up.clone(),
        name,
        sock: None,
        conn: None,
        opened: timer::Instant::now(),
        last_used: timer::Instant::now(),
        retry_at: None,
        backoff: BACKOFF_MIN,
        announced: false,
        tls: None,
        error: None,
        n: Counters::default(),
    })
}

impl Dot {
    /// Connections to `ups` (each with its `#name`); `None` (logged) if
    /// the trust anchors do not load.
    pub fn new(ups: &[Upstream], ca: Option<&str>) -> Option<Self> {
        let cfg = match tls_config(ca) {
            Ok(c) => c,
            Err(e) => {
                println!("  dns-over-tls    : off: {e}");
                return None;
            }
        };
        let me = Dot {
            cfg,
            ca: ca.map(String::from),
            links: ups.iter().filter_map(link).collect(),
            closing: Vec::new(),
            next_port: (timer::ticks() % u64::from(PORT_SPAN)) as u16,
        };
        me.log();
        Some(me)
    }

    fn log(&self) {
        let names: Vec<String> = self.links.iter().map(|l| alloc::format!("{}", l.up)).collect();
        println!(
            "  dns-over-tls    : strict, {} ({} trust anchors)",
            names.join(", "),
            self.cfg.roots()
        );
    }

    /// New servers or trust anchors: connections to servers that stay
    /// (same address, port and name) are kept.
    pub fn reconfigure(&mut self, wan: &mut HostIf, ups: &[Upstream], ca: Option<&str>) {
        if ca != self.ca.as_deref() {
            match tls_config(ca) {
                Ok(c) => {
                    self.cfg = c;
                    self.ca = ca.map(String::from);
                    // Trust changed: no connection checked under the old one stays.
                    for i in 0..self.links.len() {
                        self.close(i, wan);
                    }
                }
                Err(e) => println!("  dns-over-tls    : keeping the old trust anchors: {e}"),
            }
        }
        let mut old = core::mem::take(&mut self.links);
        for up in ups {
            match old.iter().position(|l| l.up == *up) {
                Some(i) => self.links.push(old.remove(i)),
                None => self.links.extend(link(up)),
            }
        }
        for mut l in old {
            if let Some(c) = l.conn.as_mut() {
                c.close();
            }
            if let Some(h) = l.sock.take() {
                self.closing.push((h, later(LINGER)));
            }
        }
        self.log();
    }

    /// DNS over TLS switched off: every connection and socket goes.
    pub fn shutdown(&mut self, wan: &mut HostIf) {
        for i in 0..self.links.len() {
            self.close(i, wan);
        }
        for (h, _) in self.closing.drain(..) {
            wan.sockets.get_mut::<tcp::Socket>(h).abort();
            wan.sockets.remove(h);
        }
    }

    /// The WAN went up or down: connections on the old address are gone,
    /// and failures while it was down say nothing about the servers.
    pub fn wan_changed(&mut self, wan: &mut HostIf) {
        for i in 0..self.links.len() {
            self.drop_conn(i, wan);
            let l = &mut self.links[i];
            l.retry_at = None;
            l.backoff = BACKOFF_MIN;
        }
    }

    fn local_port(&mut self) -> u16 {
        self.next_port = (self.next_port + 1) % PORT_SPAN;
        PORT_BASE + self.next_port
    }

    /// Queue `query` for the upstream at `ip`, connecting if needed.
    pub fn send(&mut self, wan: &mut HostIf, ip: IpAddr, query: &[u8]) {
        let Some(i) = self.links.iter().position(|l| l.up.ip == ip) else {
            return;
        };
        let now = timer::Instant::now();
        if self.links[i].retry_at.is_some_and(|t| now < t) {
            self.links[i].n.dropped += 1;
            return;
        }
        if !self.links[i].conn.as_ref().is_some_and(Conn::usable) {
            self.open(i, wan);
        }
        let l = &mut self.links[i];
        if let Some(c) = l.conn.as_mut() {
            c.send(query);
            l.n.queries += 1;
            l.last_used = now;
        }
    }

    fn open(&mut self, i: usize, wan: &mut HostIf) {
        self.drop_conn(i, wan);
        let port = self.local_port();
        let l = &mut self.links[i];
        l.n.connects += 1;
        l.opened = timer::Instant::now();
        l.announced = false;
        l.tls = None;
        let conn = match Conn::new(&self.cfg, l.name.clone()) {
            Ok(c) => c,
            Err(e) => return self.fail(i, alloc::format!("{e}")),
        };
        let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
        // Unacknowledged data for this long ends the connection.
        s.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
        let remote = IpEndpoint::new(l.up.ip.into(), l.port);
        if let Err(e) = s.connect(wan.iface.context(), remote, port) {
            return self.fail(i, alloc::format!("connect: {e:?} (no WAN address?)"));
        }
        l.sock = Some(wan.sockets.add(s));
        l.conn = Some(conn);
    }

    /// Close the connection cleanly (close_notify, FIN).
    fn close(&mut self, i: usize, wan: &mut HostIf) {
        let l = &mut self.links[i];
        if let (Some(c), Some(h)) = (l.conn.as_mut(), l.sock) {
            c.close();
            let s = wan.sockets.get_mut::<tcp::Socket>(h);
            let _ = s.send_slice(c.outgoing());
            s.close();
        }
        l.conn = None;
        if let Some(h) = l.sock.take() {
            self.closing.push((h, later(LINGER)));
        }
    }

    /// Forget the connection at once (reset).
    fn drop_conn(&mut self, i: usize, wan: &mut HostIf) {
        let l = &mut self.links[i];
        l.conn = None;
        if let Some(h) = l.sock.take() {
            wan.sockets.get_mut::<tcp::Socket>(h).abort();
            self.closing.push((h, later(LINGER)));
        }
    }

    fn fail(&mut self, i: usize, why: String) {
        let l = &mut self.links[i];
        l.n.failures += 1;
        println!("  dns-over-tls    : {}: {why}; next try in {} s", l.up, l.backoff.as_secs());
        l.error = Some(why);
        l.retry_at = Some(later(l.backoff));
        l.backoff = (l.backoff * 2).min(BACKOFF_MAX);
        l.conn = None;
    }

    /// Move bytes between the TCP sockets and the TLS connections; returns
    /// the answers (server, DNS message).
    pub fn step(&mut self, wan: &mut HostIf) -> Vec<(IpAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let now = timer::Instant::now();
        let clock_known = wallclock::now().is_some();
        for i in 0..self.links.len() {
            let (Some(h), true) = (self.links[i].sock, self.links[i].conn.is_some()) else {
                continue;
            };
            let s = wan.sockets.get_mut::<tcp::Socket>(h);
            let l = &mut self.links[i];
            let c = l.conn.as_mut().expect("checked");
            while s.can_recv() {
                match s.recv_slice(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        c.receive(&buf[..n]);
                        // Arrival times are a little more jitter for the pool.
                        crate::entropy::mix(&(n as u32).to_le_bytes());
                    }
                }
            }
            while let Some(r) = c.pop_response() {
                l.n.answers += 1;
                out.push((l.up.ip, r));
            }
            let peer_gone = matches!(
                s.state(),
                tcp::State::Closed | tcp::State::CloseWait | tcp::State::TimeWait | tcp::State::Closing | tcp::State::LastAck
            );
            match c.state().clone() {
                State::Failed(e) => {
                    self.drop_conn(i, wan);
                    self.fail(i, alloc::format!("{e}"));
                }
                State::Handshaking if peer_gone => {
                    self.drop_conn(i, wan);
                    self.fail(i, String::from("connection refused or closed during the handshake"));
                }
                State::Handshaking if now.saturating_duration_since(l.opened) > CONNECT_TIMEOUT => {
                    self.drop_conn(i, wan);
                    self.fail(i, String::from("no answer (TCP or TLS handshake timed out)"));
                }
                State::Handshaking => {}
                State::Closed => self.close(i, wan),
                State::Open if peer_gone => {
                    // The server closed an idle connection: normal.
                    c.tcp_closed();
                    self.close(i, wan);
                }
                State::Open => {
                    if !l.announced {
                        l.announced = true;
                        l.retry_at = None;
                        l.backoff = BACKOFF_MIN;
                        l.error = None;
                        l.tls = c.tls_info();
                        println!(
                            "  dns-over-tls    : {} up: {}{}",
                            l.up,
                            l.tls.as_deref().unwrap_or("?"),
                            c.dates().map(|d| alloc::format!(" ({d})")).unwrap_or_default()
                        );
                    }
                    if now.saturating_duration_since(l.last_used) > IDLE || (clock_known && c.opened_without_time()) {
                        self.close(i, wan);
                    }
                }
            }
        }
        self.flush(wan);
        // Sockets on their way out.
        self.closing.retain(|&(h, until)| {
            let s = wan.sockets.get_mut::<tcp::Socket>(h);
            let done = s.state() == tcp::State::Closed || now >= until;
            if done {
                s.abort();
                wan.sockets.remove(h);
            }
            !done
        });
        out
    }

    /// Write what the TLS connections have for the TCP sockets.
    pub fn flush(&mut self, wan: &mut HostIf) {
        for l in &mut self.links {
            let (Some(h), Some(c)) = (l.sock, l.conn.as_mut()) else { continue };
            let s = wan.sockets.get_mut::<tcp::Socket>(h);
            while !c.outgoing().is_empty() && s.can_send() {
                match s.send_slice(c.outgoing()) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => c.consume(n),
                }
            }
        }
    }

    /// When [`Self::step`] must run again: handshake timeouts, idle closes,
    /// lingering sockets.
    pub fn next_deadline(&self) -> Option<timer::Instant> {
        let conns = self.links.iter().filter_map(|l| {
            let c = l.conn.as_ref()?;
            let d = if *c.state() == State::Handshaking { l.opened.checked_add(CONNECT_TIMEOUT) } else { l.last_used.checked_add(IDLE) };
            d.map(|d| d.checked_add(Duration::from_millis(10)).unwrap_or(d))
        });
        conns.chain(self.closing.iter().map(|&(_, t)| t)).min()
    }

    fn state_text(l: &Link) -> &'static str {
        let now = timer::Instant::now();
        match l.conn.as_ref().map(Conn::state) {
            Some(State::Open) => "open",
            Some(State::Handshaking) => "connecting",
            _ if l.retry_at.is_some_and(|t| now < t) => "failed",
            _ => "idle",
        }
    }

    /// Per server: state, TLS, counters, last error (`/api/status` `dns.tls`).
    pub fn status_json(&self) -> String {
        use proto_http::json_str;
        let rows: Vec<String> = self
            .links
            .iter()
            .map(|l| {
                alloc::format!(
                    "{{\"server\":{},\"port\":{},\"state\":{},\"tls\":{},\"queries\":{},\"answers\":{},\"dropped\":{},\"connects\":{},\"failures\":{},\"error\":{}}}",
                    json_str(&alloc::format!("{}#{}", l.up.ip, l.up.name.as_deref().unwrap_or(""))),
                    l.port,
                    json_str(Self::state_text(l)),
                    l.tls.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
                    l.n.queries,
                    l.n.answers,
                    l.n.dropped,
                    l.n.connects,
                    l.n.failures,
                    l.error.as_deref().map(json_str).unwrap_or_else(|| "null".into()),
                )
            })
            .collect();
        alloc::format!("[{}]", rows.join(","))
    }

    /// One line per server (CLI `status`).
    pub fn status_lines(&self) -> Vec<String> {
        self.links
            .iter()
            .map(|l| {
                alloc::format!(
                    "{} {}{}: {} queries, {} answers, {} connects, {} failures{}",
                    l.up,
                    Self::state_text(l),
                    l.tls.as_deref().map(|t| alloc::format!(" ({t})")).unwrap_or_default(),
                    l.n.queries,
                    l.n.answers,
                    l.n.connects,
                    l.n.failures,
                    l.error.as_deref().map(|e| alloc::format!(", last error: {e}")).unwrap_or_default()
                )
            })
            .collect()
    }
}
