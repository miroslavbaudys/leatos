//! DNS: forwarder with cache, local .lan zone fed by DHCP leases, rebind protection.
//!
//! Planned modules: `codec`, `cache` (TTL + negative caching), `zone`
//! (static hosts + DHCP hostnames, PTR), `forwarder` (upstream selection).
//! See `docs/soho-features.md#dns`.
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
