//! PPPoE client: discovery (PADI/PADO/PADR/PADS/PADT), LCP, PAP/CHAP, IPCP, IPv6CP.
//!
//! Planned modules: `discovery`, `lcp`, `auth`, `ipcp`, `ipv6cp`, and a
//! `Session` state machine emitting `WanUp { addr, peer, dns }` / `WanDown`.
//! See `docs/soho-features.md#pppoe`.
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
