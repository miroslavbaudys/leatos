//! DHCP: DHCPv4 server and client, DHCPv6-PD client, IPv6 router advertisements.
//!
//! Planned modules: `v4::codec`, `v4::server` (pools, static leases, lease
//! store), `v4::client`, `v6::pd_client`, `ra` (SLAAC + RDNSS).
//! See `docs/soho-features.md#dhcp`.
//!
//! Design rules (see `docs/architecture.md`):
//! - `#![no_std]` + `alloc`: the same code runs in the bare-metal kernel and
//!   in host tests.
//! - Sans-IO: no sockets, no clocks, no async runtime. Callers feed in bytes
//!   and the current time, and get back bytes to send and events.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {}
}
