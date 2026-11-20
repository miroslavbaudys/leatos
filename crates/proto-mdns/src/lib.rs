//! mDNS (RFC 6762) / DNS-SD (RFC 6763) across networks (docs/mdns.md).
//!
//! - [`wire`]: a whole mDNS message parsed into owned parts and written back
//!   (names as raw labels: instance names are UTF-8 and may contain dots)
//! - [`Reflector`]: receives a message from one network and returns the
//!   copies to send on others, rebuilt with only what the rules allow
//!
//! Sans-IO: the caller receives on UDP 5353 per network, passes the bytes,
//! the source and `now` (ms) to [`Reflector::handle`], and sends each
//! [`Output`] to `224.0.0.251:5353` from its own address on that network
//! (TTL 255).
//!
//! `#![no_std]` + `alloc`, no unsafe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod reflector;
pub mod wire;

#[cfg(test)]
mod tests;

pub use reflector::{
    BURST, MAX_HOSTS, MAX_OUTPUT, MAX_SERVICES, Config, DUP_WINDOW_MS, Net, NetId, Output, RATE_PER_SEC, Reflector, Rule,
    ServiceType, Stats,
};
pub use wire::{GROUP_V4, GROUP_V6, PORT};
