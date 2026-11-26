//! DHCP: DHCPv4 server ([`v4::server`]) and client ([`v4::client`]),
//! IPv6 router advertisements ([`v6::ra`]), DHCPv6-PD client ([`v6::pd`]).
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
