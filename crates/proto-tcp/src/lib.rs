//! The router's own TCP (docs/own-tcp.md): the web interface on :80, DNS
//! over TCP on :53 and the DNS-over-TLS client, without a host stack.
//!
//! - [`Socket`]: one connection (RFC 9293 states), its send and receive
//!   rings; the API the kernel's users had from smoltcp (`listen`,
//!   `connect`, `send_slice`, `recv_slice`, `close`, `abort`, ...).
//! - [`Tcp`]: the sockets of one link, demultiplexing by 4-tuple, the
//!   answers nobody's socket gives (RST), timers ([`Tcp::next_deadline`]).
//! - [`wire`]: the TCP header (parse, write, checksum).
//!
//! Sans-IO: the caller passes in time (`now`, ms since boot), feeds each
//! segment addressed to the router with [`Tcp::receive`] (IP addresses and
//! the TCP bytes; the IP layer is the caller's) and sends what
//! [`Tcp::poll`] emits. Randomness comes in once ([`Tcp::new`]'s secret).
//!
//! What it implements: active and passive open, the FIN states and a short
//! TIME-WAIT; retransmission with an RFC 6298 timer, fast retransmit after
//! three duplicate ACKs, a per-connection timeout for unacknowledged data;
//! the MSS option; in-order receive plus a few out-of-order ranges; zero
//! window probes; RFC 5961 (RST and SYN only at the exact sequence number,
//! challenge ACKs, rate-limited); RFC 6528 initial sequence numbers.
//! Not: window scaling, SACK, timestamps, Nagle, keep-alive, congestion
//! control (the kernel's smoltcp had none of them configured either).
//!
//! `#![no_std]` + `alloc`, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod ring;
mod siphash;
mod socket;
mod stack;
pub mod wire;

#[cfg(test)]
mod tests;

pub use socket::Socket;
pub use stack::{Emit, Handle, Stats, Tcp};

use core::net::SocketAddr;

/// The two ends of a connection, as the router sees them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuple {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// RFC 9293 §3.3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// A call that does not fit the socket's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not in a state for this (e.g. `listen` while connected, `send` after
    /// `close`).
    InvalidState,
    /// A port or address that cannot be used (0, unspecified, families mixed).
    Unaddressable,
    /// Receive: the peer closed its side and every byte was read.
    Finished,
}

/// Sequence-number comparisons modulo 2^32 (RFC 9293 §3.4).
pub(crate) mod seq {
    pub fn lt(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) < 0
    }
    pub fn le(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) <= 0
    }
    pub fn gt(a: u32, b: u32) -> bool {
        lt(b, a)
    }
    pub fn ge(a: u32, b: u32) -> bool {
        le(b, a)
    }
    /// `a <= x < b`.
    pub fn in_range(x: u32, a: u32, b: u32) -> bool {
        le(a, x) && lt(x, b)
    }
}
