//! The WAN's PPPoE client, run by the services task (`net::svc`) instead
//! of the DHCP client when `wan.mode = "pppoe"`:
//!
//! ```text
//!  datapath ── discovery + PPP control ─► PortShared::ctrl_rx ─► proto_pppoe::Client
//!  Client frames ─────────────────────────► WAN qdisc (as they are) ─► datapath
//!  Event::Session ─► PortShared::pppoe_session (datapath encapsulates IPv4)
//!  Event::Up/Down ─► router stack address + route, LeaseChange (forwarder, DNS, status)
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

fn mac_text(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub struct Pppoe {
    client: Client,
    link: Option<Link>,
    /// Why the last attempt or session ended (status output).
    last_down: Option<String>,
    sessions: u32,
    /// The state the status output last saw ([`Self::status_changed`]).
    shown: Option<proto_pppoe::State>,
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
                    if u32::from(link.mtu) != port.mtu.load(Ordering::Relaxed) {
                        // smoltcp reads the MTU when the interface is made.
                        port.mtu.store(u32::from(link.mtu), Ordering::Relaxed);
                        host.iface = stack::new_iface(port);
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
                    }
                    self.link = None;
                    self.last_down = Some(format!("{reason}"));
                }
            }
        }
        (change, self.transmit(port))
    }

    /// Move the client's frames into the WAN qdisc.
    fn transmit(&mut self, port: &PortShared) -> bool {
        let mut queued = false;
        let now_ns = crate::net::datapath::now_ns();
        while let Some(f) = self.client.poll_transmit() {
            let Some(mut pkt) = PacketBuf::alloc() else {
                continue; // pool empty: lost, retransmitted by the client
            };
            pkt.set_len(f.len());
            pkt.data_mut().copy_from_slice(&f);
            pkt.meta.wire_len = f.len() as u32;
            pkt.meta.enqueue_ts = now_ns;
            if port.qdisc.lock().enqueue(pkt, now_ns).is_ok() {
                queued = true;
            }
        }
        queued
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
        let now = Some(self.client.state());
        core::mem::replace(&mut self.shown, now) != now
    }

    /// `{"state":…,"session":…,"ac":…,"mtu":…,"sessions":…,"last_error":…}`
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
            "{{\"state\":{},\"session\":{session},\"ac\":{ac},\"mtu\":{mtu},\"sessions\":{},\"last_error\":{}}}",
            json_str(&format!("{}", self.client.state())),
            self.sessions,
            self.last_down
                .as_deref()
                .map(json_str)
                .unwrap_or_else(|| "null".into())
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
