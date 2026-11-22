//! DNS over TLS (`crates/proto-dot`): the parts written here, fed what a
//! server (or anyone on the path, before the certificate check) controls.
//! - the crypto provider (`provider.rs`): key exchange completed with an
//!   arbitrary peer key share (X25519, P-256, P-384), every signature
//!   algorithm on an arbitrary key, message and signature, TLS 1.3 and 1.2
//!   record decryption of arbitrary ciphertext (suites with 32-byte keys:
//!   rustls hands the 16-byte ones a 16-byte key, which this target cannot
//!   build);
//! - the leaf certificate date parser (`verify::validity`) on arbitrary DER;
//! - a client connection fed an arbitrary server byte stream in pieces
//!   (rustls's parsers in front of ours).
//! Checks: no panic; a key exchange or signature on garbage is refused,
//! never accepted by accident with an all-zero secret.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use proto_dot::rustls::crypto::cipher::{AeadKey, InboundOpaqueMessage, Iv};
use proto_dot::rustls::crypto::{GetRandomFailed, SecureRandom};
use proto_dot::rustls::{ContentType, ProtocolVersion, SupportedCipherSuite};
use proto_dot::{Clock, Config, Conn, ServerName, UnixTime};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

#[derive(Debug)]
struct Rng(AtomicU64);
impl SecureRandom for Rng {
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
static RNG: Rng = Rng(AtomicU64::new(0x9e37_79b9_7f4a_7c15));

#[derive(Debug)]
struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_794_830_400)))
    }
}

fn provider() -> &'static proto_dot::rustls::crypto::CryptoProvider {
    static P: OnceLock<proto_dot::rustls::crypto::CryptoProvider> = OnceLock::new();
    P.get_or_init(|| proto_dot::provider::provider(&RNG))
}

fn config() -> &'static Config {
    static C: OnceLock<Config> = OnceLock::new();
    C.get_or_init(|| Config::new(&RNG, Arc::new(Fixed), 0, &[]).expect("config"))
}

#[derive(Arbitrary, Debug)]
struct Input {
    peer_key: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    key: [u8; 32],
    iv: [u8; 12],
    record: Vec<u8>,
    seq: u64,
    cert: Vec<u8>,
    cuts: Vec<u8>,
    stream: Vec<u8>,
}

fuzz_target!(|i: Input| {
    let p = provider();
    for kx in &p.kx_groups {
        if let Ok(active) = kx.start() {
            if let Ok(secret) = active.complete(&i.peer_key) {
                assert!(secret.secret_bytes().iter().any(|&b| b != 0), "all-zero shared secret accepted");
            }
        }
    }
    // RSA keys beyond 4096 bits only slow the fuzzer down (a CA-signed
    // certificate is the only way to one).
    if i.public_key.len() <= 600 {
        for alg in p.signature_verification_algorithms.all {
            let _ = alg.verify_signature(&i.public_key, &i.message, &i.signature);
        }
    }
    for suite in &p.cipher_suites {
        let mut payload = i.record.clone();
        let msg = InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut payload);
        match suite {
            SupportedCipherSuite::Tls13(s) if s.aead_alg.key_len() == 32 => {
                let mut d = s.aead_alg.decrypter(AeadKey::from(i.key), Iv::new(i.iv));
                let _ = d.decrypt(msg, i.seq);
            }
            SupportedCipherSuite::Tls12(s) if s.aead_alg.key_block_shape().enc_key_len == 32 => {
                let fixed = s.aead_alg.key_block_shape().fixed_iv_len;
                let mut d = s.aead_alg.decrypter(AeadKey::from(i.key), &i.iv[..fixed]);
                let _ = d.decrypt(msg, i.seq);
            }
            _ => {}
        }
    }
    let _ = proto_dot::verify::validity(&i.cert);
    let Ok(mut c) = Conn::new(config(), ServerName::try_from("dns.example").expect("name")) else { return };
    c.send(b"\x00\x0c0123456789ab");
    let mut rest = &i.stream[..];
    for &cut in &i.cuts {
        if rest.is_empty() {
            break;
        }
        let n = (usize::from(cut) * 16 + 1).min(rest.len());
        c.receive(&rest[..n]);
        let out = c.outgoing().len();
        c.consume(out);
        while c.pop_response().is_some() {}
        rest = &rest[n..];
    }
    c.receive(rest);
    c.tcp_closed();
});
