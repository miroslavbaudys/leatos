//! Server certificates: webpki against the trust anchors (Mozilla's, plus
//! any the config adds), with one change for a router that has no clock
//! at boot.
//!
//! The wall clock comes from SNTP, and SNTP's server names are resolved
//! through this resolver: before the first sync there is no time to check
//! certificate dates against. Until then a chain is checked at the moment
//! its leaf certificate became valid (its `notBefore`), but never earlier
//! than `floor` (the kernel's build time): signatures, names and the
//! chain are checked as always, and a certificate that expired before the
//! kernel was built still fails. The caller reconnects once the clock is
//! set ([`crate::Conn::opened_without_time`]), which checks the dates for
//! real. SNTP itself is unauthenticated, so this gives up
//! nothing the clock did not already depend on.
//!
//! A battery-backed RTC ([`Clock::hint`]) narrows this: if it is no
//! earlier than `floor` and the leaf has not expired by it, the chain is
//! checked at the RTC's time (or the leaf's `notBefore`, if the RTC is
//! behind that). If the leaf has expired by the RTC, the RTC may be the
//! one that is wrong, and refusing would leave DNS (and so SNTP, which
//! needs it) dead for good: the issue-time rule applies and the caller is
//! told ([`Dates::RtcSaysExpired`]), so it can log it. Either way the
//! reconnect after SNTP checks the real dates.

use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};
use core::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// The wall clock, `None` until it is known.
pub trait Clock: Send + Sync + fmt::Debug {
    fn now(&self) -> Option<UnixTime>;
    /// An unverified time (a battery-backed RTC), used only before
    /// [`Self::now`] is known.
    fn hint(&self) -> Option<UnixTime> {
        None
    }
}

/// What a certificate's dates were checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dates {
    /// The wall clock (SNTP).
    Clock = 1,
    /// The RTC, before SNTP.
    Rtc = 2,
    /// The leaf's issue time (≥ the build time): no usable RTC.
    IssueTime = 3,
    /// The issue time, because the leaf had expired by the RTC.
    RtcSaysExpired = 4,
}

impl Dates {
    fn from_u8(v: u8) -> Option<Self> {
        [Dates::Clock, Dates::Rtc, Dates::IssueTime, Dates::RtcSaysExpired].into_iter().find(|d| *d as u8 == v)
    }
}

impl fmt::Display for Dates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Dates::Clock => "dates checked",
            Dates::Rtc => "dates checked against the RTC until SNTP",
            Dates::IssueTime => "dates checked at issue time until SNTP (no usable RTC)",
            Dates::RtcSaysExpired => "expired by the RTC: accepted until SNTP checks the dates",
        })
    }
}

/// When to check a chain while the clock is unknown, and how that was
/// chosen: `validity` is the leaf's (`notBefore`, `notAfter`), `hint` the
/// RTC's time, `floor` the build time (Unix seconds).
pub fn unknown_clock_time(validity: Option<(u64, u64)>, hint: Option<u64>, floor: u64) -> (u64, Dates) {
    let (nb, na) = validity.unwrap_or((0, u64::MAX));
    let issued = nb.saturating_add(1).max(floor);
    match hint {
        Some(h) if h >= floor && h < na && h > nb => (h, Dates::Rtc),
        Some(h) if h >= floor && h >= na => (issued, Dates::RtcSaysExpired),
        _ => (issued, Dates::IssueTime),
    }
}

/// rustls' time source: the clock, or `floor` while it is unknown.
#[derive(Debug)]
pub(crate) struct Time {
    pub clock: Arc<dyn Clock>,
    pub floor: UnixTime,
}

impl rustls::time_provider::TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.clock.now().unwrap_or(self.floor))
    }
}

pub(crate) struct DotVerifier {
    pub inner: Arc<WebPkiServerVerifier>,
    pub clock: Arc<dyn Clock>,
    pub floor: UnixTime,
    /// The last check's [`Dates`] (connections are handshaken one at a
    /// time by one task; [`crate::Conn`] reads it when it opens).
    pub last: AtomicU8,
}

impl DotVerifier {
    pub(crate) fn last_dates(&self) -> Option<Dates> {
        Dates::from_u8(self.last.load(Ordering::Relaxed))
    }
}

impl fmt::Debug for DotVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DotVerifier").field("floor", &self.floor).finish_non_exhaustive()
    }
}

impl ServerCertVerifier for DotVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (at, dates) = match self.clock.now() {
            Some(_) => (now, Dates::Clock),
            None => {
                let hint = self.clock.hint().map(|t| t.as_secs());
                let (at, d) = unknown_clock_time(validity(end_entity), hint, self.floor.as_secs());
                (UnixTime::since_unix_epoch(Duration::from_secs(at)), d)
            }
        };
        self.last.store(dates as u8, Ordering::Relaxed);
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, at)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> alloc::vec::Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---- just enough DER for `notBefore` -----------------------------------------

/// One DER TLV at the start of `b`: (tag, contents, rest).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, mut b) = b.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 || b.len() < n {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |a, &x| (a << 8) | usize::from(x));
        b = &b[n..];
        len
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// The leaf's (`notBefore`, `notAfter`) in Unix seconds: Certificate →
/// TBSCertificate → [0] version (optional), serial, signature algorithm,
/// issuer, validity.
pub fn validity(cert: &[u8]) -> Option<(u64, u64)> {
    let (0x30, c, _) = tlv(cert)? else { return None };
    let (0x30, mut tbs, _) = tlv(c)? else { return None };
    if tbs.first() == Some(&0xa0) {
        tbs = tlv(tbs)?.2;
    }
    let (_serial, _, tbs) = tlv(tbs)?;
    let (_alg, _, tbs) = tlv(tbs)?;
    let (_issuer, _, tbs) = tlv(tbs)?;
    let (0x30, validity, _) = tlv(tbs)? else { return None };
    let (tag, t, rest) = tlv(validity)?;
    let (tag2, t2, _) = tlv(rest)?;
    Some((der_time(tag, t)?, der_time(tag2, t2)?))
}

/// UTCTime (`YYMMDDHHMMSSZ`, years 1950–2049) or GeneralizedTime
/// (`YYYYMMDDHHMMSSZ`) to Unix seconds.
fn der_time(tag: u8, t: &[u8]) -> Option<u64> {
    let digits = |s: &[u8]| -> Option<u64> {
        s.iter().try_fold(0u64, |a, &d| d.is_ascii_digit().then(|| a * 10 + u64::from(d - b'0')))
    };
    let (year, rest) = match (tag, t.len()) {
        (0x17, 13) => {
            let y = digits(&t[..2])?;
            (if y < 50 { 2000 + y } else { 1900 + y }, &t[2..])
        }
        (0x18, 15) => (digits(&t[..4])?, &t[4..]),
        _ => return None,
    };
    if rest[10] != b'Z' {
        return None;
    }
    let f = |i: usize| digits(&rest[i..i + 2]);
    let (mo, d, h, mi, s) = (f(0)?, f(2)?, f(4)?, f(6)?, f(8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 || year < 1970 {
        return None;
    }
    // Days from civil (H. Hinnant), years from 1970.
    let (y, m) = if mo <= 2 { (year - 1, mo + 9) } else { (year, mo - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_times() {
        assert_eq!(der_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(der_time(0x17, b"261116120000Z"), Some(1_794_830_400));
        assert_eq!(der_time(0x18, b"20261116120000Z"), Some(1_794_830_400));
        assert_eq!(der_time(0x18, b"20000229235959Z"), Some(951_868_799));
        assert_eq!(der_time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(der_time(0x17, b"261316120000Z"), None, "month 13");
        assert_eq!(der_time(0x17, b"2611161200000"), None, "no Z");
        assert_eq!(der_time(0x17, b"26111612000Z"), None, "short");
        assert_eq!(der_time(0x04, b"261116120000Z"), None, "not a time");
    }

    #[test]
    fn rtc_rule() {
        let (nb, na, floor) = (1_000, 5_000, 500);
        let v = Some((nb, na));
        // A plausible RTC within the leaf's validity: its time.
        assert_eq!(unknown_clock_time(v, Some(3_000), floor), (3_000, Dates::Rtc));
        // Behind the leaf's issue (or right at it): the issue time.
        assert_eq!(unknown_clock_time(v, Some(900), floor), (1_001, Dates::IssueTime));
        assert_eq!(unknown_clock_time(v, Some(1_000), floor), (1_001, Dates::IssueTime));
        // Before the build time (a reset RTC): ignored.
        assert_eq!(unknown_clock_time(v, Some(100), floor), (1_001, Dates::IssueTime));
        // Expired by the RTC: never refused on its word alone.
        assert_eq!(unknown_clock_time(v, Some(5_000), floor), (1_001, Dates::RtcSaysExpired));
        assert_eq!(unknown_clock_time(v, Some(9_000), floor), (1_001, Dates::RtcSaysExpired));
        // No RTC; the build time above the issue time.
        assert_eq!(unknown_clock_time(v, None, floor), (1_001, Dates::IssueTime));
        assert_eq!(unknown_clock_time(v, None, 2_000), (2_000, Dates::IssueTime));
        // Unparsable validity: the build time, RTC as it says.
        assert_eq!(unknown_clock_time(None, Some(3_000), floor), (3_000, Dates::Rtc));
        assert_eq!(unknown_clock_time(None, None, floor), (500, Dates::IssueTime));
    }

    #[test]
    fn truncated_der_is_rejected() {
        assert_eq!(tlv(&[0x30]), None);
        assert_eq!(tlv(&[0x30, 0x82, 0x01]), None);
        assert_eq!(tlv(&[0x30, 0x05, 1, 2]), None);
        assert_eq!(validity(&[]), None);
        assert_eq!(validity(&[0x30, 0x02, 0x30, 0x00]), None);
    }
}
