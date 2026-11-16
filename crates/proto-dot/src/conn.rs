//! One DNS-over-TLS connection (RFC 7858), sans-IO: TCP bytes in and out,
//! DNS messages in and out.
//!
//! Queries are framed with their two-byte length (RFC 1035 §4.2.2), held
//! until the handshake is done, then sent pipelined; responses come back
//! in any order (RFC 7766 §6.2.1.1) and the resolver matches them by ID.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::{AppDataRecord, ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use rustls::Error;

use crate::Clock;

/// TLS bytes waiting to be processed: a record is at most 16 KiB plus
/// overhead, so more than this means a peer that never completes one.
const MAX_INCOMING: usize = 64 * 1024;
/// Queries waiting for the handshake.
const MAX_QUEUED: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    /// TCP is up (or coming up), the TLS handshake runs.
    Handshaking,
    /// Queries go out as soon as they are sent.
    Open,
    /// Closed by either side; no more queries.
    Closed,
    /// The handshake or the connection failed (a bad certificate, a
    /// protocol error): close the TCP connection.
    Failed(Error),
}

pub struct Conn {
    tls: UnbufferedClientConnection,
    clock: Arc<dyn Clock>,
    verifier: Arc<crate::verify::DotVerifier>,
    dates: Option<crate::Dates>,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    queued: Vec<u8>,
    plain: Vec<u8>,
    responses: VecDeque<Vec<u8>>,
    state: State,
    without_time: bool,
}

/// What one round of rustls' state machine asked for.
enum Step {
    Again,
    Stop,
    Open,
    Closed,
    Fail(Error),
}

impl Conn {
    /// A connection to `name` (a host name or an IP address, checked
    /// against the certificate). The TCP connection is the caller's.
    pub fn new(config: &crate::Config, name: ServerName<'static>) -> Result<Self, Error> {
        let tls = UnbufferedClientConnection::new(config.tls.clone(), name)?;
        let mut c = Conn {
            tls,
            clock: config.clock.clone(),
            verifier: config.verifier.clone(),
            dates: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            queued: Vec::new(),
            plain: Vec::new(),
            responses: VecDeque::new(),
            state: State::Handshaking,
            without_time: false,
        };
        c.drive(); // the ClientHello
        Ok(c)
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Accepting queries (open, or still in the handshake).
    pub fn usable(&self) -> bool {
        matches!(self.state, State::Handshaking | State::Open)
    }

    /// The negotiated protocol and cipher suite, once open
    /// (`TLSv1_3 TLS13_AES_128_GCM_SHA256`), and whether the session was
    /// resumed.
    pub fn tls_info(&self) -> Option<alloc::string::String> {
        let v = self.tls.protocol_version()?;
        let s = self.tls.negotiated_cipher_suite()?;
        let resumed = self.tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
        Some(alloc::format!("{v:?} {:?}{}", s.suite(), if resumed { ", resumed" } else { "" }))
    }

    /// What the certificate's dates were checked against (`None`: a
    /// resumed session, checked when it began).
    pub fn dates(&self) -> Option<crate::Dates> {
        self.dates
    }

    /// The certificate was checked while the clock was unknown
    /// ([`crate::verify`]): reconnect once it is known.
    pub fn opened_without_time(&self) -> bool {
        self.without_time
    }

    /// Queue a DNS message (sent once the handshake is done).
    pub fn send(&mut self, msg: &[u8]) {
        let Ok(len) = u16::try_from(msg.len()) else { return };
        if !self.usable() || self.queued.len() + msg.len() + 2 > MAX_QUEUED {
            return;
        }
        self.queued.extend_from_slice(&len.to_be_bytes());
        self.queued.extend_from_slice(msg);
        self.drive();
    }

    /// Bytes read from the TCP connection.
    pub fn receive(&mut self, tcp: &[u8]) {
        if self.incoming.len() + tcp.len() > MAX_INCOMING {
            self.state = State::Failed(Error::General("DNS over TLS: oversized record".into()));
            return;
        }
        self.incoming.extend_from_slice(tcp);
        self.drive();
    }

    /// The TCP connection ended (reset, closed, timed out).
    pub fn tcp_closed(&mut self) {
        if self.usable() {
            self.state = State::Closed;
        }
    }

    /// TLS bytes to write to the TCP connection; [`Self::consume`] what
    /// was written.
    pub fn outgoing(&self) -> &[u8] {
        &self.outgoing
    }

    pub fn consume(&mut self, n: usize) {
        self.outgoing.drain(..n.min(self.outgoing.len()));
    }

    /// The next complete DNS response.
    pub fn pop_response(&mut self) -> Option<Vec<u8>> {
        self.responses.pop_front()
    }

    /// Close cleanly: a close_notify goes out (write it, then close TCP).
    pub fn close(&mut self) {
        if self.state == State::Open {
            self.queued.clear();
            self.close_notify();
        }
        if self.usable() {
            self.state = State::Closed;
        }
    }

    fn close_notify(&mut self) {
        let UnbufferedStatus { state, .. } = self.tls.process_tls_records(&mut []);
        if let Ok(ConnectionState::WriteTraffic(mut w)) = state {
            let _ = grow(&mut self.outgoing, |buf| w.queue_close_notify(buf).map_err(Grow::from));
        }
    }

    /// Run rustls until it needs more bytes from the server.
    fn drive(&mut self) {
        while self.usable() {
            let step = self.step();
            match step {
                Step::Again => continue,
                Step::Stop => break,
                Step::Open => {
                    if self.state == State::Handshaking {
                        self.without_time = self.clock.now().is_none();
                        // A resumed session skipped the certificate check.
                        let full = self.tls.handshake_kind() != Some(rustls::HandshakeKind::Resumed);
                        self.dates = if full { self.verifier.last_dates() } else { None };
                        self.state = State::Open;
                    }
                    break;
                }
                Step::Closed => {
                    self.state = State::Closed;
                    break;
                }
                Step::Fail(e) => {
                    self.state = State::Failed(e);
                    break;
                }
            }
        }
        self.deframe();
    }

    fn step(&mut self) -> Step {
        let UnbufferedStatus { mut discard, state } = self.tls.process_tls_records(&mut self.incoming);
        let step = match state {
            Err(e) => Step::Fail(e),
            Ok(ConnectionState::ReadTraffic(mut r)) => {
                let mut step = Step::Again;
                while let Some(rec) = r.next_record() {
                    match rec {
                        Ok(AppDataRecord { discard: d, payload }) => {
                            discard += d;
                            self.plain.extend_from_slice(payload);
                        }
                        Err(e) => {
                            step = Step::Fail(e);
                            break;
                        }
                    }
                }
                step
            }
            Ok(ConnectionState::EncodeTlsData(mut e)) => {
                match grow(&mut self.outgoing, |buf| e.encode(buf).map_err(Grow::from)) {
                    Ok(()) => Step::Again,
                    Err(e) => Step::Fail(e),
                }
            }
            // The bytes stay in `outgoing` until the caller writes them.
            Ok(ConnectionState::TransmitTlsData(t)) => {
                t.done();
                Step::Again
            }
            Ok(ConnectionState::BlockedHandshake) => Step::Stop,
            Ok(ConnectionState::WriteTraffic(mut w)) => {
                if self.queued.is_empty() {
                    Step::Open
                } else {
                    let q = &self.queued;
                    match grow(&mut self.outgoing, |buf| w.encrypt(q, buf).map_err(Grow::from)) {
                        Ok(()) => {
                            self.queued.clear();
                            Step::Open
                        }
                        Err(e) => Step::Fail(e),
                    }
                }
            }
            Ok(ConnectionState::PeerClosed | ConnectionState::Closed) => Step::Closed,
            Ok(_) => Step::Stop,
        };
        self.incoming.drain(..discard.min(self.incoming.len()));
        step
    }

    fn deframe(&mut self) {
        while self.plain.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([self.plain[0], self.plain[1]]));
            if self.plain.len() < 2 + len {
                break;
            }
            self.responses.push_back(self.plain[2..2 + len].to_vec());
            self.plain.drain(..2 + len);
        }
    }
}

/// Why an encode or encrypt into the outgoing buffer stopped.
enum Grow {
    Need(usize),
    Fail(Error),
}

impl From<EncodeError> for Grow {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::InsufficientSize(s) => Grow::Need(s.required_size),
            other => Grow::Fail(Error::General(alloc::format!("TLS encode: {other}"))),
        }
    }
}

impl From<EncryptError> for Grow {
    fn from(e: EncryptError) -> Self {
        match e {
            EncryptError::InsufficientSize(s) => Grow::Need(s.required_size),
            other => Grow::Fail(Error::General(alloc::format!("TLS encrypt: {other}"))),
        }
    }
}

/// Append what `f` writes to `out`, growing the space until it fits.
fn grow(out: &mut Vec<u8>, mut f: impl FnMut(&mut [u8]) -> Result<usize, Grow>) -> Result<(), Error> {
    let start = out.len();
    let mut room = 1024;
    loop {
        out.resize(start + room, 0);
        match f(&mut out[start..]) {
            Ok(n) => {
                out.truncate(start + n);
                return Ok(());
            }
            Err(Grow::Need(n)) if n > room => room = n,
            Err(Grow::Need(_)) => {
                out.truncate(start);
                return Err(Error::General("TLS: buffer size".into()));
            }
            Err(Grow::Fail(e)) => {
                out.truncate(start);
                return Err(e);
            }
        }
    }
}
