//! The WAN's DHCPv4 client (docs/local-stack.md step 2b):
//! `proto_dhcp::v4::client` over the router-local UDP path (`net::local`),
//! port 68 on the WAN link. It replaced smoltcp's `dhcpv4::Socket`, which
//! panics on `Medium::Ip`.
//!
//! `svc` steps it: replies in, the message due out (from 0.0.0.0 to
//! broadcast while it has no address, unicast to the server while
//! renewing), and the lease's events, which `svc` applies to the router
//! stack's WAN interface like the socket's (`svc::lease_bound` /
//! `svc::lease_lost`). Counters in `/api/status` `wan_dhcp`.

use crate::net::datapath::WAN;
use crate::net::local;
use crate::net::shared::Shared;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use proto_dhcp::v4::client::{CLIENT_PORT, Client, Config, Event, SERVER_PORT, State};

/// For `/api/status` `wan_dhcp` (one WAN): the state, messages sent,
/// replies taken, NAKs, datagrams ignored, sends that failed.
static STATE: AtomicU8 = AtomicU8::new(0);
static SENT: AtomicU64 = AtomicU64::new(0);
static RECEIVED: AtomicU64 = AtomicU64::new(0);
static NAKS: AtomicU64 = AtomicU64::new(0);
static IGNORED: AtomicU64 = AtomicU64::new(0);
static SEND_FAILED: AtomicU64 = AtomicU64::new(0);

/// `/api/status` `wan_dhcp`: `null` unless this client runs.
pub fn status_json() -> alloc::string::String {
    let state = match STATE.load(Ordering::Relaxed) {
        0 => return alloc::string::String::from("null"),
        1 => State::Rebooting,
        2 => State::Selecting,
        3 => State::Requesting,
        4 => State::Bound,
        5 => State::Renewing,
        _ => State::Rebinding,
    };
    alloc::format!(
        "{{\"state\":\"{}\",\"sent\":{},\"received\":{},\"naks\":{},\"ignored\":{},\"send_failed\":{}}}",
        state.name(),
        SENT.load(Ordering::Relaxed),
        RECEIVED.load(Ordering::Relaxed),
        NAKS.load(Ordering::Relaxed),
        IGNORED.load(Ordering::Relaxed),
        SEND_FAILED.load(Ordering::Relaxed),
    )
}

fn state_code(s: State) -> u8 {
    match s {
        State::Rebooting => 1,
        State::Selecting => 2,
        State::Requesting => 3,
        State::Bound => 4,
        State::Renewing => 5,
        State::Rebinding => 6,
    }
}

pub struct Wan4 {
    client: Client,
    send_failed: u64,
}

impl Wan4 {
    /// Start on the WAN (port 68 bound) with the port's MAC.
    pub fn new(mac: [u8; 6], now_ms: u64) -> Self {
        local::bind(WAN, CLIENT_PORT);
        let cfg = Config { mac, hostname: None, last: None, broadcast: false };
        let w = Wan4 { client: Client::new(cfg, now_ms, crate::entropy::u64()), send_failed: 0 };
        w.publish();
        w
    }

    /// Another WAN mode: port 68 freed, status cleared.
    pub fn stop(self) {
        local::unbind(WAN, CLIENT_PORT);
        STATE.store(0, Ordering::Relaxed);
    }

    /// The link changed (VLAN): ask again.
    pub fn reset(&mut self, now_ms: u64) {
        self.client.reset(now_ms);
    }

    /// Replies in, the due message out; the lease's events in order.
    pub fn step(&mut self, sh: &Shared, now_ms: u64) -> alloc::vec::Vec<Event> {
        while let Some(d) = local::recv(WAN, CLIENT_PORT) {
            if d.ends.sport() == SERVER_PORT && matches!(d.ends, local::Ends::V4(_)) {
                self.client.handle(now_ms, &d.payload);
            }
        }
        while let Some(t) = self.client.poll(now_ms) {
            let e = local::Ends::V4(fwd::udp::Ends { src: t.src, dst: t.dst, sport: CLIENT_PORT, dport: SERVER_PORT });
            if !local::send(sh, WAN, &e, fwd::udp::TTL, &t.payload) {
                self.send_failed += 1;
            }
        }
        self.publish();
        core::iter::from_fn(|| self.client.poll_event()).collect()
    }

    /// When [`Self::step`] has something to do (ms).
    pub fn next_deadline(&self) -> u64 {
        self.client.next_deadline()
    }

    fn publish(&self) {
        let s = self.client.stats();
        STATE.store(state_code(self.client.state()), Ordering::Relaxed);
        SENT.store(s.sent, Ordering::Relaxed);
        RECEIVED.store(s.received, Ordering::Relaxed);
        NAKS.store(s.naks, Ordering::Relaxed);
        IGNORED.store(s.ignored, Ordering::Relaxed);
        SEND_FAILED.store(self.send_failed, Ordering::Relaxed);
    }
}
