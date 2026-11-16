//! DNS over TLS (RFC 7858, strict profile of RFC 8310) for the router's
//! forwarder: TLS client connections to upstream resolvers, port 853.
//!
//! - [`provider`]: a rustls crypto provider on RustCrypto (pure Rust)
//! - [`verify`]: webpki with Mozilla's roots, and what to do before the
//!   clock is set
//! - [`Conn`]: one connection, sans-IO (TCP bytes and DNS messages in and
//!   out)
//!
//! rustls runs without `std` through its unbuffered API. Design rules
//! (`docs/architecture.md`): `#![no_std]` + `alloc`, sans-IO; the kernel
//! supplies randomness ([`rustls::crypto::SecureRandom`]), the clock
//! ([`Clock`]) and the TCP connection.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod conn;
pub mod provider;
pub mod verify;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

pub use conn::{Conn, State};
pub use rustls;
pub use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
pub use verify::{Clock, Dates};

use alloc::collections::VecDeque;
use rustls::client::{ClientSessionStore, Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue, WebPkiServerVerifier};
use rustls::crypto::SecureRandom;
use rustls::{ClientConfig, Error, NamedGroup, RootCertStore};

/// The port of DNS over TLS (RFC 7858 §3.1).
pub const PORT: u16 = 853;

/// Shared by all connections: the TLS settings, trust anchors and
/// session tickets (resumption saves a round trip and the certificate
/// check when a connection is reopened).
pub struct Config {
    tls: Arc<ClientConfig>,
    clock: Arc<dyn Clock>,
    verifier: Arc<verify::DotVerifier>,
    roots: usize,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config").field("roots", &self.roots).finish_non_exhaustive()
    }
}

impl Config {
    /// TLS 1.3 and 1.2 with [`provider::provider`]`(rng)`, Mozilla's
    /// roots plus `extra_roots`; `floor` (Unix seconds, the kernel's build
    /// time) bounds certificate dates while `clock` is unknown.
    pub fn new(
        rng: &'static dyn SecureRandom,
        clock: Arc<dyn Clock>,
        floor: u64,
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Self, Error> {
        let provider = Arc::new(provider::provider(rng));
        let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        for r in extra_roots {
            roots.add(r.clone())?;
        }
        let n = roots.len();
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| Error::General(alloc::format!("trust anchors: {e}")))?;
        let floor = UnixTime::since_unix_epoch(Duration::from_secs(floor));
        let time = Arc::new(verify::Time { clock: clock.clone(), floor });
        let verifier = Arc::new(verify::DotVerifier {
            inner,
            clock: clock.clone(),
            floor,
            last: core::sync::atomic::AtomicU8::new(0),
        });
        let mut tls = ClientConfig::builder_with_details(provider, time)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        tls.resumption = Resumption::store(Arc::new(Sessions::default()));
        Ok(Config { tls: Arc::new(tls), clock, verifier, roots: n })
    }

    /// Trust anchors in use (Mozilla's and extra ones).
    pub fn roots(&self) -> usize {
        self.roots
    }
}

/// Certificates from PEM text (`-----BEGIN CERTIFICATE-----` blocks).
pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::General(alloc::format!("PEM: {e:?}")))
}

/// Resumption state per server: a few, so a bounded list. A spin lock
/// because the kernel's tasks may move between cores.
#[derive(Default)]
struct Sessions(spin::Mutex<Vec<Session>>);

struct Session {
    name: ServerName<'static>,
    kx: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    tls13: VecDeque<Tls13ClientSessionValue>,
}

/// Servers remembered, and TLS 1.3 tickets per server.
const MAX_SESSIONS: usize = 16;
const MAX_TICKETS: usize = 4;

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sessions")
    }
}

impl Sessions {
    fn with<R>(&self, name: &ServerName<'_>, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        self.0.lock().iter_mut().find(|s| s.name == *name).map(f)
    }

    fn entry(&self, name: ServerName<'static>, f: impl FnOnce(&mut Session)) {
        let mut v = self.0.lock();
        let i = match v.iter().position(|s| s.name == name) {
            Some(i) => i,
            None => {
                if v.len() >= MAX_SESSIONS {
                    v.remove(0);
                }
                v.push(Session { name, kx: None, tls12: None, tls13: VecDeque::new() });
                v.len() - 1
            }
        };
        f(&mut v[i]);
    }
}

impl ClientSessionStore for Sessions {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        self.entry(name, |s| s.kx = Some(group));
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        self.with(name, |s| s.kx).flatten()
    }
    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.entry(name, |s| s.tls12 = Some(value));
    }
    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.with(name, |s| s.tls12.clone()).flatten()
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.with(name, |s| s.tls12 = None);
    }
    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.entry(name, |s| {
            if s.tls13.len() >= MAX_TICKETS {
                s.tls13.pop_front();
            }
            s.tls13.push_back(value);
        });
    }
    /// Each ticket once (RFC 8446 §C.4).
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.with(name, |s| s.tls13.pop_back()).flatten()
    }
}

#[cfg(test)]
mod tests;
