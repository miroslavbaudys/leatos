//! The WAN's PPPoE client, run by the services task (`net::svc`) instead
//! of the DHCP client when `wan.mode = "pppoe"`:
//!
//! ```text
//!  datapath ── discovery + PPP control ─► PortShared::ctrl_rx ─► proto_pppoe::Client
//!  Client frames ─────────────────────────► WAN qdisc (as they are) ─► datapath
//!  Event::Session ─► PortShared::pppoe_session (datapath encapsulates IPv4)
//!  Event::Up/Down ─► router stack address + route, LeaseChange (forwarder, DNS, status)
//!  Event::Ipv6Up/Down ─► net::wan6::set_ppp_link (the services task starts
//!                        prefix delegation and reapplies the networks)
//! ```
//!
//! The protocol is in `crates/proto-pppoe`; this module only moves frames
//! and applies the results. The router stack's WAN interface is IP-only
//! while the port is in PPPoE mode (`net::device`).

use crate::net::packet::PacketBuf;
use crate::net::shared::PortShared;
use crate::net::stack;
use crate::net::svc::{HostIf, LeaseChange};
use crate::{println, timer};
use alloc::format;
use alloc::string::String;
use core::sync::atomic::Ordering;
use proto_pppoe::{Client, Event, Link};
use qdisc::Qdisc;
use smoltcp::wire::{IpCidr, Ipv4Cidr};

fn now_ms() -> u64 {
    timer::uptime().as_millis() as u64
}

use crate::net::shared::mac_text;

pub struct Pppoe {
    client: Client,
    link: Option<Link>,
    /// Why the last attempt or session ended (status output).
    last_down: Option<String>,
    sessions: u32,
    /// The state the status output last saw ([`Self::status_changed`]).
    shown: Option<(proto_pppoe::State, u32, bool)>,
}

impl Pppoe {
    /// Start discovery on `port` (already in PPPoE mode).
    pub fn new(cfg: proto_pppoe::Config, port: &PortShared) -> Self {
        let seed = timer::ticks() ^ port.mac.iter().fold(0, |a, &b| a << 8 | u64::from(b));
        println!(
            "  pppoe {}     : user {}, {}mtu {}",
            port.name,
            if cfg.username.is_empty() { "(none)" } else { cfg.username.as_str() },
            if cfg.service.is_empty() {
                String::new()
            } else {
                format!("service {}, ", cfg.service)
            },
            cfg.mtu
        );
        let mut client = Client::new(cfg, port.mac, seed);
        client.start(now_ms());
        Pppoe {
            client,
            link: None,
            last_down: None,
            sessions: 0,
            shown: None,
        }
    }

    /// Feed received control frames, run timers, apply events, queue the
    /// client's frames. Returns the WAN change when the link went up or
    /// down; `true` if frames were queued (wake the WAN's TX task).
    pub fn step(&mut self, port: &PortShared, host: &mut HostIf) -> (Option<LeaseChange>, bool) {
        let now = now_ms();
        loop {
            let Some(pkt) = port.ctrl_rx.lock().pop_front() else {
                break;
            };
            self.client.handle_frame(now, pkt.data());
        }
        self.client.poll(now);
        let mut change = None;
        while let Some(ev) = self.client.poll_event() {
            match ev {
                Event::Session(s) => {
                    port.set_pppoe_session(Some(s));
                    println!(
                        "  pppoe {}     : session {:#06x} with {}",
                        port.name,
                        s.id,
                        mac_text(&s.peer)
                    );
                }
                Event::Up(link) => {
                    self.sessions += 1;
                    if let Some(t) = self.client.rfc4638_trace() {
                        let v = |o: Option<u16>| o.map_or(String::from("none"), |m| format!("{m}"));
                        println!(
                            "  pppoe {}     : RFC 4638: PADO {}, PADS {}, our MRU {}, peer MRU {}, echo {}",
                            port.name,
                            v(t.pado),
                            v(t.pads),
                            v(t.our_mru),
                            v(t.peer_mru),
                            t.echo.map_or(String::from("none"), |(g, s)| format!("{g} B back for {s} B"))
                        );
                    }
                    if u32::from(link.mtu) != port.mtu.load(Ordering::Relaxed) {
                        // smoltcp reads the MTU when the interface is made.
                        port.mtu.store(u32::from(link.mtu), Ordering::Relaxed);
                        host.iface = stack::new_iface(port, false);
                    }
                    host.iface.update_ip_addrs(|a| {
                        a.clear();
                        let _ = a.push(IpCidr::Ipv4(Ipv4Cidr::new(link.local, 32)));
                    });
                    let _ = host.iface.routes_mut().add_default_ipv4_route(link.remote);
                    let dns: alloc::vec::Vec<String> =
                        link.dns.iter().map(|d| format!("{d}")).collect();
                    println!(
                        "  pppoe {}     : up, {} peer {} dns [{}] mtu {} (AC {})",
                        port.name,
                        link.local,
                        link.remote,
                        dns.join(", "),
                        link.mtu,
                        link.ac_name
                    );
                    change = Some(LeaseChange {
                        addr: Some((link.local, 32)),
                        gateway: Some(link.remote),
                        dns: link.dns.clone(),
                        mtu: link.mtu,
                        via: Some(format!(
                            "PPPoE session {:#06x}, AC {}",
                            link.session.id, link.ac_name
                        )),
                    });
                    self.link = Some(link);
                }
                Event::Down { reason, was_up } => {
                    port.set_pppoe_session(None);
                    if was_up {
                        host.iface.update_ip_addrs(|a| a.clear());
                        host.iface.routes_mut().remove_default_ipv4_route();
                        change = Some(LeaseChange::lost());
                        println!("  pppoe {}     : down: {reason}", port.name);
                    } else {
                        println!("  pppoe {}     : attempt failed: {reason}", port.name);
                        if reason == proto_pppoe::Reason::JumboFailed
                            && let Some((g, s)) = self.client.last_jumbo_reply()
                        {
                            println!("  pppoe {}     : RFC 4638 echo: {g} B back for {s} B", port.name);
                        }
                    }
                    self.link = None;
                    self.last_down = Some(format!("{reason}"));
                }
                Event::PeerOffersIpv6 { options } => println!(
                    "  pppoe {}     : the access concentrator offers IPv6 (IPv6CP{}); rejected (ipv6 off)",
                    port.name,
                    ipv6cp_options_text(&options)
                ),
                Event::Ipv6Up { local, remote } => {
                    println!(
                        "  pppoe {}     : IPv6CP up, {local} peer {}",
                        port.name,
                        remote.map_or(String::from("(no identifier)"), |r| format!("{r}"))
                    );
                    crate::net::wan6::set_ppp_link(Some((local, remote)));
                }
                Event::Ipv6Down => {
                    println!("  pppoe {}     : IPv6CP down", port.name);
                    crate::net::wan6::set_ppp_link(None);
                }
            }
        }
        (change, self.transmit(port))
    }

    /// Move the client's frames into the WAN qdisc.
    fn transmit(&mut self, port: &PortShared) -> bool {
        let mut queued = false;
        while let Some(f) = self.client.poll_transmit() {
            queued |= self.send(port, &f);
        }
        queued
    }

    /// One frame into the WAN qdisc (pool empty: lost, retransmitted by
    /// the client).
    fn send(&self, port: &PortShared, f: &[u8]) -> bool {
        let now_ns = crate::net::datapath::now_ns();
        let Some(mut pkt) = PacketBuf::alloc() else {
            return false;
        };
        pkt.set_len(f.len());
        pkt.data_mut().copy_from_slice(f);
        pkt.meta.wire_len = f.len() as u32;
        pkt.meta.enqueue_ts = now_ns;
        port.qdisc.lock().enqueue(pkt, now_ns).is_ok()
    }

    /// End the session (LCP Terminate-Request, PADT): before switching the
    /// WAN to DHCP or new PPPoE settings.
    pub fn stop(&mut self, port: &PortShared, host: &mut HostIf) -> bool {
        self.client.stop();
        let (_, queued) = self.step(port, host);
        port.set_pppoe_session(None);
        queued
    }

    /// When [`Self::step`] next has timer work.
    pub fn wake_at(&self) -> Option<timer::Instant> {
        let at = self.client.next_deadline()?;
        let now = now_ms();
        let ms = at.saturating_sub(now);
        timer::Instant::now().checked_add(core::time::Duration::from_millis(ms))
    }

    /// The state changed since the last call (status output is due).
    pub fn status_changed(&mut self) -> bool {
        let now = Some((self.client.state(), self.client.ipv6cp_requests(), self.client.ipv6().is_some()));
        core::mem::replace(&mut self.shown, now) != now
    }

    /// `{"state":…,"session":…,"ac":…,"mtu":…,"sessions":…,"last_error":…,"rfc4638":…,"ipv6cp_offered":…,"ipv6":{"local":…,"peer":…}|null}`
    pub fn status_json(&self) -> String {
        use proto_http::json_str;
        let (session, ac, mtu) = match &self.link {
            Some(l) => (
                format!("{}", l.session.id),
                json_str(&l.ac_name),
                format!("{}", l.mtu),
            ),
            None => ("null".into(), "null".into(), "null".into()),
        };
        format!(
            "{{\"state\":{},\"session\":{session},\"ac\":{ac},\"mtu\":{mtu},\"sessions\":{},\"last_error\":{},\"rfc4638\":{},\"ipv6cp_offered\":{},\"ipv6\":{}}}",
            json_str(&format!("{}", self.client.state())),
            self.sessions,
            self.last_down
                .as_deref()
                .map(json_str)
                .unwrap_or_else(|| "null".into()),
            // Asked for (MTU above 1492): in use, or fell back to 1492.
            {
                let recv_big = self
                    .client
                    .rfc4638_trace()
                    .is_some_and(|t| t.our_mru.is_some_and(|m| m > proto_pppoe::MAX_MTU));
                match (self.client.config().mtu > proto_pppoe::MAX_MTU, self.client.jumbo_failed(), &self.link) {
                    (false, _, _) => "null",
                    (true, true, _) => "\"fell back to 1492: larger frames did not pass\"",
                    (true, false, Some(l)) if l.mtu > proto_pppoe::MAX_MTU => "\"in use\"",
                    (true, false, Some(_)) if recv_big => "\"receive only: the access concentrator takes 1492 from us\"",
                    (true, false, Some(_)) => "\"not offered by the access concentrator\"",
                    (true, false, None) => "\"asked\"",
                }
            },
            self.client.ipv6cp_requests(),
            match self.client.ipv6() {
                Some((l, p)) => format!(
                    "{{\"local\":\"{l}\",\"peer\":{}}}",
                    p.map_or(String::from("null"), |p| format!("\"{p}\""))
                ),
                None => String::from("null"),
            }
        )
    }

    /// One line for the CLI's status while there is no link.
    pub fn status_text(&self) -> String {
        match &self.last_down {
            Some(r) => format!("PPPoE {} (last: {r})", self.client.state()),
            None => format!("PPPoE {}", self.client.state()),
        }
    }
}

/// IPv6CP options for the log: the Interface-Identifier (RFC 5072 type 1)
/// as `, interface id 0000:0000:0000:0001`, other option types by number.
fn ipv6cp_options_text(opts: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = opts;
    while let [t, l, ..] = *rest {
        let l = usize::from(l);
        if l < 2 || l > rest.len() {
            out.push_str(", malformed options");
            break;
        }
        let v = &rest[2..l];
        match (t, v) {
            (1, [a, b, c, d, e, f, g, h]) => out.push_str(&format!(
                ", interface id {:04x}:{:04x}:{:04x}:{:04x}",
                u16::from_be_bytes([*a, *b]),
                u16::from_be_bytes([*c, *d]),
                u16::from_be_bytes([*e, *f]),
                u16::from_be_bytes([*g, *h])
            )),
            _ => out.push_str(&format!(", option {t} ({} B)", v.len())),
        }
        rest = &rest[l..];
    }
    out
}
