//! DNS for the LAN: forwarder with cache, local `.lan` zone fed by DHCP
//! leases, rebind protection.
//!
//! - [`wire`]: message parsing/building (bounds-checked, fuzz-tested)
//! - [`zone`]: local authoritative names + reverse records
//! - [`cache`]: bounded TTL cache with in-place TTL aging
//! - [`resolver`]: zone → cache → upstream, with retries and merging
//!
//! Design rules (see `docs/architecture.md`): `#![no_std]` + `alloc`,
//! sans-IO (bytes and `now_ms` in, [`resolver::Action`]s out).
//! See `docs/soho-features.md#dns`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cache;
pub mod resolver;
pub mod wire;
pub mod zone;
