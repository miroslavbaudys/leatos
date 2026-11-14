//! State shared between the datapath task (`net::stack::run`) and the
//! services task (`net::svc::run`), docs/architecture.md "Tasks".
//!
//! ```text
//!  datapath ── Verdict::Local ──► PortShared::local_rx ──► svc (smoltcp)   + svc_kick
//!  svc (smoltcp TX) ─────────────► PortShared::qdisc (locked) ──► datapath + dp_kick
//!  svc ── Control (WAN lease, reboot/exec) ──────────────────► datapath   + dp_kick
//!  datapath ── PortSnap, conntrack count ────────────────────► svc (status page)
//! ```
//!
//! Forwarded packets never leave the datapath; the qdisc stays the only
//! place they wait. Everything here is `spin::Mutex` or atomics, so the two
//! tasks can later run on different cores unchanged (M11).

use crate::drivers;
use crate::irq::{self, IrqEvent};
use crate::net::device::PortQdisc;
use crate::net::mgmt::Action;
use crate::net::packet::PacketBuf;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once};

/// Bound on frames waiting for the router stack.
pub const LOCAL_RX_MAX: usize = 64;

/// What the datapath publishes about a port for the status page.
#[derive(Clone, Copy, Debug, Default)]
pub struct PortSnap {
    pub stats: drivers::Stats,
    /// (up, Mbit/s, full duplex), if the NIC reports it.
    pub link: Option<(bool, u32, bool)>,
}

pub struct PortShared {
    pub name: &'static str,
    pub model: &'static str,
    pub mac: [u8; 6],
    /// Egress queue: forwarded traffic and the router's own traffic.
    pub qdisc: Mutex<PortQdisc>,
    /// Frames for the router stack, filled by the datapath.
    pub local_rx: Mutex<VecDeque<PacketBuf>>,
    pub snap: Mutex<PortSnap>,
}

/// A WAN lease change for the forwarder: address/prefix and gateway.
#[derive(Clone, Copy, Debug)]
pub struct WanChange {
    pub addr: Option<(Ipv4Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Default)]
pub struct Control {
    pub wan: Option<WanChange>,
    pub action: Option<Action>,
}

pub struct Shared {
    /// `ports[0]` = WAN, `ports[1]` = LAN.
    pub ports: Vec<PortShared>,
    /// Services → datapath: frames queued for TX, or a control message.
    pub dp_kick: &'static IrqEvent,
    /// Datapath → services: frames in a `local_rx`.
    pub svc_kick: &'static IrqEvent,
    pub control: Mutex<Control>,
    /// Tracked connections (published by the datapath).
    pub conntrack: AtomicUsize,
}

static SHARED: Once<&'static Shared> = Once::new();

/// Create the shared state once (at bring-up).
pub fn init(ports: Vec<PortShared>) -> &'static Shared {
    SHARED.call_once(|| {
        Box::leak(Box::new(Shared {
            ports,
            dp_kick: irq::new_event(),
            svc_kick: irq::new_event(),
            control: Mutex::new(Control::default()),
            conntrack: AtomicUsize::new(0),
        }))
    })
}

impl Shared {
    /// Services → datapath.
    pub fn post_wan(&self, change: WanChange) {
        self.control.lock().wan = Some(change);
        self.dp_kick.signal();
    }

    pub fn post_action(&self, action: Action) {
        self.control.lock().action = Some(action);
        self.dp_kick.signal();
    }

    pub fn conntrack(&self) -> usize {
        self.conntrack.load(Ordering::Relaxed)
    }
}
