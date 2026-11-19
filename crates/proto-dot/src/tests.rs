//! Handshakes and DNS round trips against a real TLS server (rustls with
//! ring, certificates from rcgen), for every cipher suite, key exchange
//! group and certificate type the provider offers, and the certificate
//! checks that must fail.

extern crate std;

use super::*;
use alloc::string::{String, ToString};
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SignatureAlgorithm};
use rustls::crypto::{CryptoProvider, GetRandomFailed};
use rustls::pki_types::PrivateKeyDer;
use rustls::server::ServerConnection;
use rustls::{CertificateError, HandshakeKind, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion};
use std::io::{Read, Write};

/// Deterministic test randomness (xorshift; never use outside tests).
#[derive(Debug)]
struct TestRng(AtomicU64);

impl SecureRandom for TestRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        for b in buf {
            let mut x = self.0.load(Ordering::Relaxed);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0.store(x, Ordering::Relaxed);
            *b = (x >> 24) as u8;
        }
        Ok(())
    }
}

static RNG: TestRng = TestRng(AtomicU64::new(0x9e37_79b9_7f4a_7c15));

#[derive(Debug)]
struct FixedClock(Option<u64>);

impl Clock for FixedClock {
    fn now(&self) -> Option<UnixTime> {
        self.0.map(|s| UnixTime::since_unix_epoch(Duration::from_secs(s)))
    }
}

/// 2026-11-16 12:00 UTC.
const NOW: u64 = 1_794_830_400;
const YEAR: u64 = 365 * 86_400;

struct Pki {
    ca: rcgen::Certificate,
    issuer: Issuer<'static, KeyPair>,
}

fn pki(alg: &'static SignatureAlgorithm) -> Pki {
    pki_named(alg, "leatos test CA")
}

fn pki_named(alg: &'static SignatureAlgorithm, cn: &str) -> Pki {
    let ca_key = key(alg);
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let ca = p.self_signed(&ca_key).unwrap();
    Pki { ca, issuer: Issuer::new(p, ca_key) }
}

fn key(alg: &'static SignatureAlgorithm) -> KeyPair {
    if alg == &rcgen::PKCS_RSA_SHA256 {
        KeyPair::from_pem_and_sign_algo(include_str!("testdata/rsa2048.pem"), alg).unwrap()
    } else {
        KeyPair::generate_for(alg).unwrap()
    }
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

/// A leaf for `names`, valid from `from` to `to` (Unix seconds).
fn leaf(pki: &Pki, alg: &'static SignatureAlgorithm, names: &[&str], from: u64, to: u64) -> Leaf {
    let k = key(alg);
    let mut p = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name.push(DnType::CommonName, names[0]);
    p.not_before = time::OffsetDateTime::from_unix_timestamp(from as i64).unwrap();
    p.not_after = time::OffsetDateTime::from_unix_timestamp(to as i64).unwrap();
    let cert = p.signed_by(&k, &pki.issuer).unwrap();
    Leaf {
        chain: vec![cert.der().clone()],
        key: PrivateKeyDer::try_from(k.serialize_der()).unwrap(),
    }
}

fn valid_leaf(pki: &Pki, alg: &'static SignatureAlgorithm) -> Leaf {
    leaf(pki, alg, &["dns.test"], NOW - YEAR, NOW + YEAR)
}

struct ServerOpts {
    versions: &'static [&'static SupportedProtocolVersion],
    suites: Option<Vec<SupportedCipherSuite>>,
    kx: Option<&'static str>,
}

static V13: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
static V12: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];

const ANY: ServerOpts = ServerOpts { versions: &[&rustls::version::TLS13, &rustls::version::TLS12], suites: None, kx: None };

fn server_config(l: &Leaf, o: &ServerOpts) -> Arc<ServerConfig> {
    let mut p: CryptoProvider = rustls::crypto::ring::default_provider();
    if let Some(s) = &o.suites {
        p.cipher_suites = s.clone();
    }
    if let Some(name) = o.kx {
        p.kx_groups.retain(|g| alloc::format!("{:?}", g.name()) == name);
        assert_eq!(p.kx_groups.len(), 1, "{name}");
    }
    let c = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(o.versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(l.chain.clone(), l.key.clone_key())
        .unwrap();
    Arc::new(c)
}

fn client_config(pki: &Pki, clock: Option<u64>, floor: u64) -> Config {
    Config::new(&RNG, Arc::new(FixedClock(clock)), floor, &[pki.ca.der().clone()]).unwrap()
}

/// The test's DNS server: answers each framed query with the same bytes,
/// QR bit set.
struct Server {
    tls: ServerConnection,
    plain: Vec<u8>,
    error: Option<Error>,
}

impl Server {
    fn new(cfg: Arc<ServerConfig>) -> Self {
        Server { tls: ServerConnection::new(cfg).unwrap(), plain: Vec::new(), error: None }
    }

    fn answer(&mut self) {
        let mut buf = [0u8; 4096];
        while let Ok(n) = self.tls.reader().read(&mut buf) {
            if n == 0 {
                break;
            }
            self.plain.extend_from_slice(&buf[..n]);
        }
        while self.plain.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([self.plain[0], self.plain[1]]));
            if self.plain.len() < 2 + len {
                break;
            }
            let mut msg: Vec<u8> = self.plain.drain(..2 + len).collect();
            msg[4] |= 0x80; // QR
            self.tls.writer().write_all(&msg).unwrap();
        }
    }
}

/// Move bytes both ways until neither side has anything to say.
fn pump(c: &mut Conn, s: &mut Server) {
    for _ in 0..100 {
        let out = c.outgoing().to_vec();
        c.consume(out.len());
        if !out.is_empty() && s.error.is_none() {
            let mut r = &out[..];
            while !r.is_empty() {
                s.tls.read_tls(&mut r).unwrap();
            }
            match s.tls.process_new_packets() {
                Ok(_) => s.answer(),
                Err(e) => s.error = Some(e),
            }
        }
        let mut back = Vec::new();
        while s.tls.wants_write() {
            s.tls.write_tls(&mut back).unwrap();
        }
        if !back.is_empty() {
            c.receive(&back);
        }
        if out.is_empty() && back.is_empty() {
            return;
        }
    }
    panic!("no quiescence");
}

/// A query: ID, flags, one question.
fn query(id: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1]);
    q
}

/// Connect, send two pipelined queries (one before the handshake ends)
/// and check both answers.
fn round_trip(c: &mut Conn, s: &mut Server) {
    c.send(&query(0x1234));
    pump(c, s);
    assert_eq!(c.state(), &State::Open, "server: {:?}", s.error);
    c.send(&query(0x5678));
    pump(c, s);
    let a = c.pop_response().expect("first answer");
    let b = c.pop_response().expect("second answer");
    assert_eq!((&a[..2], a[2] & 0x80), (&[0x12, 0x34][..], 0x80));
    assert_eq!(&b[..2], &[0x56, 0x78]);
    assert!(c.pop_response().is_none());
}

fn connect(cfg: &Config, name: &str, server: Arc<ServerConfig>) -> (Conn, Server) {
    let c = Conn::new(cfg, ServerName::try_from(name.to_string()).unwrap()).unwrap();
    (c, Server::new(server))
}

fn cert_error(c: &Conn) -> CertificateError {
    match c.state() {
        State::Failed(Error::InvalidCertificate(e)) => e.clone(),
        other => panic!("expected a certificate error, got {other:?}"),
    }
}

#[test]
fn mozilla_roots_are_built_in() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    assert!(cfg.roots() > 100, "{}", cfg.roots());
}

#[test]
fn every_tls13_suite() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    use rustls::crypto::ring::cipher_suite as cs;
    for suite in [cs::TLS13_AES_128_GCM_SHA256, cs::TLS13_AES_256_GCM_SHA384, cs::TLS13_CHACHA20_POLY1305_SHA256] {
        let o = ServerOpts { versions: V13, suites: Some(vec![suite]), kx: None };
        let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &o));
        round_trip(&mut c, &mut s);
        assert_eq!(s.tls.negotiated_cipher_suite(), Some(suite));
    }
}

#[test]
fn every_tls12_suite() {
    use rustls::crypto::ring::cipher_suite as cs;
    let ecdsa = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let ecdsa_leaf = valid_leaf(&ecdsa, &rcgen::PKCS_ECDSA_P256_SHA256);
    let rsa = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let rsa_leaf = valid_leaf(&rsa, &rcgen::PKCS_RSA_SHA256);
    let cases = [
        (&ecdsa, &ecdsa_leaf, cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        (&ecdsa, &ecdsa_leaf, cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        (&ecdsa, &ecdsa_leaf, cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
        (&rsa, &rsa_leaf, cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        (&rsa, &rsa_leaf, cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        (&rsa, &rsa_leaf, cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    ];
    for (p, l, suite) in cases {
        let cfg = client_config(p, Some(NOW), 0);
        let o = ServerOpts { versions: V12, suites: Some(vec![suite]), kx: None };
        let (mut c, mut s) = connect(&cfg, "dns.test", server_config(l, &o));
        round_trip(&mut c, &mut s);
        assert_eq!(s.tls.negotiated_cipher_suite(), Some(suite));
        assert_eq!(s.tls.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    }
}

#[test]
fn every_key_exchange_group() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    for versions in [V13, V12] {
        for kx in ["X25519", "secp256r1", "secp384r1"] {
            let o = ServerOpts { versions, suites: None, kx: Some(kx) };
            let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &o));
            round_trip(&mut c, &mut s);
            assert_eq!(s.tls.negotiated_key_exchange_group().map(|g| alloc::format!("{:?}", g.name())), Some(kx.into()));
        }
    }
}

#[test]
fn every_certificate_type() {
    let algs: [&'static SignatureAlgorithm; 4] = [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
        &rcgen::PKCS_RSA_SHA256,
    ];
    // Every CA type signing every leaf type: chain signatures (ECDSA,
    // Ed25519, RSA PKCS#1) and handshake signatures (ECDSA, Ed25519,
    // RSA-PSS in TLS 1.3, PKCS#1 or PSS in 1.2).
    for ca in algs {
        let p = pki(ca);
        let cfg = client_config(&p, Some(NOW), 0);
        for alg in algs {
            for versions in [V13, V12] {
                let l = valid_leaf(&p, alg);
                let o = ServerOpts { versions, suites: None, kx: None };
                let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &o));
                round_trip(&mut c, &mut s);
            }
        }
    }
}

#[test]
fn ip_address_names_are_checked_too() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256, &["dns.test", "192.0.2.53"], NOW - YEAR, NOW + YEAR);
    let cfg = client_config(&p, Some(NOW), 0);
    let (mut c, mut s) = connect(&cfg, "192.0.2.53", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    let (mut c, mut s) = connect(&cfg, "192.0.2.54", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert!(matches!(cert_error(&c), CertificateError::NotValidForNameContext { .. }));
}

#[test]
fn wrong_name_fails() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    let (mut c, mut s) = connect(&cfg, "other.test", server_config(&l, &ANY));
    c.send(&query(1));
    pump(&mut c, &mut s);
    assert!(matches!(cert_error(&c), CertificateError::NotValidForNameContext { .. }));
    assert!(!c.usable());
    assert!(c.pop_response().is_none(), "nothing reaches a server that failed the check");
}

#[test]
fn unknown_issuer_fails() {
    let trusted = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let other = pki_named(&rcgen::PKCS_ECDSA_P256_SHA256, "someone else's CA");
    let l = valid_leaf(&other, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&trusted, Some(NOW), 0);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert_eq!(cert_error(&c), CertificateError::UnknownIssuer);
    // A forged CA with the trusted one's name: the signature fails.
    let forged = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&forged, &rcgen::PKCS_ECDSA_P256_SHA256);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert_eq!(cert_error(&c), CertificateError::BadSignature);
    // Mozilla's roots alone do not know the test CA either.
    let cfg = Config::new(&RNG, Arc::new(FixedClock(Some(NOW))), 0, &[]).unwrap();
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert_eq!(cert_error(&c), CertificateError::UnknownIssuer);
}

#[test]
fn dates_are_checked_once_the_clock_is_known() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let expired = leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256, &["dns.test"], NOW - 2 * YEAR, NOW - YEAR);
    let future = leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256, &["dns.test"], NOW + YEAR, NOW + 2 * YEAR);
    let cfg = client_config(&p, Some(NOW), 0);
    for (l, what) in [(&expired, "expired"), (&future, "not yet valid")] {
        let (mut c, mut s) = connect(&cfg, "dns.test", server_config(l, &ANY));
        pump(&mut c, &mut s);
        let e = cert_error(&c);
        assert!(
            matches!(e, CertificateError::ExpiredContext { .. } | CertificateError::NotValidYetContext { .. }),
            "{what}: {e:?}"
        );
    }
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256), &ANY));
    round_trip(&mut c, &mut s);
    assert!(!c.opened_without_time());
    assert_eq!(c.dates(), Some(Dates::Clock));
}

#[test]
fn without_a_clock_the_leaf_is_checked_at_its_issue_time_but_not_before_the_floor() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256, &["dns.test"], NOW - 30 * 86_400, NOW + 60 * 86_400);
    // Built (floor) before the certificate was issued: fine.
    let cfg = client_config(&p, None, NOW - YEAR);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    assert!(c.opened_without_time(), "reconnect once the clock is known");
    // Built after it was issued, before it expires: fine.
    let cfg = client_config(&p, None, NOW);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    // Expired before the kernel was built: refused even without a clock.
    let cfg = client_config(&p, None, NOW + YEAR);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert!(matches!(cert_error(&c), CertificateError::ExpiredContext { .. }));
    // The name and the issuer are checked as always.
    let cfg = client_config(&p, None, 0);
    let (mut c, mut s) = connect(&cfg, "other.test", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert!(matches!(cert_error(&c), CertificateError::NotValidForNameContext { .. }));
}

/// No wall clock yet, an RTC saying `rtc`.
#[derive(Debug)]
struct RtcOnly(u64);

impl Clock for RtcOnly {
    fn now(&self) -> Option<UnixTime> {
        None
    }
    fn hint(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn rtc_config(pki: &Pki, rtc: u64, floor: u64) -> Config {
    Config::new(&RNG, Arc::new(RtcOnly(rtc)), floor, &[pki.ca.der().clone()]).unwrap()
}

#[test]
fn before_sntp_the_rtc_dates_the_check_where_it_cannot_lock_dns_out() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256, &["dns.test"], NOW - 30 * 86_400, NOW + 60 * 86_400);
    // A plausible RTC inside the leaf's validity: checked at its time.
    let (mut c, mut s) = connect(&rtc_config(&p, NOW, NOW - YEAR), "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    assert_eq!(c.dates(), Some(Dates::Rtc));
    assert!(c.opened_without_time(), "still rechecked after SNTP");
    // An RTC reset to before the build: ignored, issue time.
    let (mut c, mut s) = connect(&rtc_config(&p, 946_684_800, NOW - YEAR), "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    assert_eq!(c.dates(), Some(Dates::IssueTime));
    // An RTC far ahead (the leaf expired by it): accepted, but said so.
    let (mut c, mut s) = connect(&rtc_config(&p, NOW + 5 * YEAR, NOW - YEAR), "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    assert_eq!(c.dates(), Some(Dates::RtcSaysExpired));
    // What the RTC adds: the rest of the chain at a real time. An
    // intermediate that expired before the RTC's time (the leaf still
    // valid) fails. (Trust anchors' own dates are not checked by webpki.)
    let (ik, ic) = {
        let k = key(&rcgen::PKCS_ECDSA_P256_SHA256);
        let mut cp = CertificateParams::new(Vec::<String>::new()).unwrap();
        cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        cp.distinguished_name.push(DnType::CommonName, "expired intermediate");
        cp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        cp.not_before = time::OffsetDateTime::from_unix_timestamp((NOW - YEAR) as i64).unwrap();
        cp.not_after = time::OffsetDateTime::from_unix_timestamp((NOW - 10 * 86_400) as i64).unwrap();
        let c = cp.signed_by(&k, &p.issuer).unwrap();
        (Issuer::new(cp, k), c)
    };
    let lk = key(&rcgen::PKCS_ECDSA_P256_SHA256);
    let mut lp = CertificateParams::new(vec![String::from("dns.test")]).unwrap();
    lp.not_before = time::OffsetDateTime::from_unix_timestamp((NOW - 30 * 86_400) as i64).unwrap();
    lp.not_after = time::OffsetDateTime::from_unix_timestamp((NOW + 60 * 86_400) as i64).unwrap();
    let lc = lp.signed_by(&lk, &ik).unwrap();
    let l = Leaf { chain: vec![lc.der().clone(), ic.der().clone()], key: PrivateKeyDer::try_from(lk.serialize_der()).unwrap() };
    let (mut c, mut s) = connect(&rtc_config(&p, NOW, NOW - YEAR), "dns.test", server_config(&l, &ANY));
    pump(&mut c, &mut s);
    assert!(matches!(cert_error(&c), CertificateError::ExpiredContext { .. } | CertificateError::Expired), "{:?}", c.state());
    // Without the RTC the same chain passes (checked at the leaf's issue).
    let (mut c, mut s) = connect(&client_config(&p, None, NOW - YEAR), "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    assert_eq!(c.dates(), Some(Dates::IssueTime));
}

#[test]
fn reconnects_resume_the_session() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    let server = server_config(&l, &ANY);
    let (mut c, mut s) = connect(&cfg, "dns.test", server.clone());
    round_trip(&mut c, &mut s);
    assert_eq!(s.tls.handshake_kind(), Some(HandshakeKind::Full));
    let (mut c, mut s) = connect(&cfg, "dns.test", server);
    round_trip(&mut c, &mut s);
    assert_eq!(s.tls.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(c.dates(), None, "a resumed session skipped the check");
}

#[test]
fn responses_split_across_reads_and_records() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    // A 3000-byte response written in two pieces, delivered byte by byte.
    let mut big = query(0x4242);
    big.resize(3000, 0xab);
    let framed = [&(big.len() as u16).to_be_bytes()[..], &big].concat();
    s.tls.writer().write_all(&framed[..1500]).unwrap();
    let mut wire = Vec::new();
    while s.tls.wants_write() {
        s.tls.write_tls(&mut wire).unwrap();
    }
    s.tls.writer().write_all(&framed[1500..]).unwrap();
    while s.tls.wants_write() {
        s.tls.write_tls(&mut wire).unwrap();
    }
    for b in &wire[..wire.len() - 1] {
        c.receive(core::slice::from_ref(b));
    }
    assert!(c.pop_response().is_none(), "incomplete");
    c.receive(&wire[wire.len() - 1..]);
    assert_eq!(c.pop_response(), Some(big));
}

#[test]
fn close_sends_close_notify() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let l = valid_leaf(&p, &rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    let (mut c, mut s) = connect(&cfg, "dns.test", server_config(&l, &ANY));
    round_trip(&mut c, &mut s);
    c.close();
    assert_eq!(c.state(), &State::Closed);
    let out = c.outgoing().to_vec();
    assert!(!out.is_empty());
    s.tls.read_tls(&mut &out[..]).unwrap();
    let st = s.tls.process_new_packets().unwrap();
    assert!(st.peer_has_closed());
    c.send(&query(9));
    assert!(c.outgoing().len() == out.len(), "nothing after close");
}

#[test]
fn garbage_from_the_server_fails_the_connection() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let cfg = client_config(&p, Some(NOW), 0);
    let mut c = Conn::new(&cfg, ServerName::try_from("dns.test").unwrap()).unwrap();
    assert!(!c.outgoing().is_empty(), "ClientHello");
    c.receive(b"HTTP/1.1 400 Bad Request\r\n\r\n");
    assert!(matches!(c.state(), State::Failed(_)), "{:?}", c.state());
    // Oversized input fails rather than growing without bound.
    let mut c = Conn::new(&cfg, ServerName::try_from("dns.test").unwrap()).unwrap();
    c.receive(&[0x16, 0x03, 0x03, 0xff, 0xff]);
    for _ in 0..20 {
        c.receive(&[0u8; 4096]);
    }
    assert!(matches!(c.state(), State::Failed(_)), "{:?}", c.state());
}

#[test]
fn pem_certificates() {
    let p = pki(&rcgen::PKCS_ECDSA_P256_SHA256);
    let pem = p.ca.pem();
    let certs = certs_from_pem(&alloc::format!("{pem}\n{pem}")).unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0], *p.ca.der());
    assert!(certs_from_pem("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n").is_err());
}
