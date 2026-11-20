//! DHCP: DHCPv4 server (done), IPv6 router advertisements ([`v6::ra`],
//! done); DHCPv6-PD client (planned: docs/ipv6.md step 3).
//!
//! Design rules (see `docs/architecture.md`):
//! - `#![no_std]` + `alloc`: the same code runs in the bare-metal kernel and
//!   in host tests.
//! - Sans-IO: no sockets, no clocks, no async runtime. Callers feed in bytes
//!   and the current time, and get back bytes to send and events.
//!
//! See `docs/soho-features.md#dhcp`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod v4;
pub mod v6;
