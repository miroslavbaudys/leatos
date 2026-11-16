//! A rustls `CryptoProvider` on RustCrypto (pure Rust, no_std, no C or
//! assembly to cross-compile): what a DNS-over-TLS client needs and no
//! more.
//!
//! - TLS 1.3: AES-128-GCM-SHA256, AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256
//! - TLS 1.2 (servers that have no 1.3): ECDHE with ECDSA or RSA, AES-GCM
//!   or ChaCha20-Poly1305 (forward secrecy and AEAD only: no CBC, no RSA
//!   key exchange)
//! - Key exchange: X25519, secp256r1, secp384r1
//! - Signatures (certificates and handshakes): ECDSA P-256/P-384 with
//!   SHA-256/384, Ed25519, RSA PKCS#1 v1.5 and PSS with SHA-256/384/512
//!   (2048–8192-bit keys)
//!
//! Randomness comes from the caller ([`provider`]): the kernel's entropy
//! pool. Client certificates are not supported (no signing keys).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use aes_gcm::aead::{self as aead_api, AeadInPlace, KeyInit};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter,
    NONCE_LEN, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm,
    Tls13AeadAlgorithm, UnsupportedOperationError, make_tls12_aad, make_tls13_aad,
};
use rustls::crypto::hash::HashAlgorithm;
use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyExchangeAlgorithm, KeyProvider,
    SecureRandom, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms, hash, hmac,
};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, alg_id};
use rustls::sign::SigningKey;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The provider, with `rng` for key shares and handshake randoms. Leaks
/// three small key-exchange objects (rustls wants `'static` ones): call
/// it once.
pub fn provider(rng: &'static dyn SecureRandom) -> CryptoProvider {
    let x25519: &'static X25519 = Box::leak(Box::new(X25519(rng)));
    let p256: &'static P256 = Box::leak(Box::new(P256(rng)));
    let p384: &'static P384 = Box::leak(Box::new(P384(rng)));
    CryptoProvider {
        cipher_suites: alloc::vec![
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: alloc::vec![x25519, p256, p384],
        signature_verification_algorithms: SIGNATURE_ALGORITHMS,
        secure_random: rng,
        key_provider: &NoKeys,
    }
}

// ---- hashes and HMAC --------------------------------------------------------

struct Hash<D>(HashAlgorithm, PhantomData<fn() -> D>);

static SHA256: Hash<Sha256> = Hash(HashAlgorithm::SHA256, PhantomData);
static SHA384: Hash<Sha384> = Hash(HashAlgorithm::SHA384, PhantomData);

impl<D: Digest + Clone + Send + Sync + 'static> hash::Hash for Hash<D> {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(D::new()))
    }
    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(data))
    }
    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }
}

struct HashContext<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> hash::Context for HashContext<D> {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }
    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashContext(self.0.clone()))
    }
    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

struct Hmac<D>(PhantomData<fn() -> D>);

static HMAC_SHA256: Hmac<Sha256> = Hmac(PhantomData);
static HMAC_SHA384: Hmac<Sha384> = Hmac(PhantomData);

impl<D> hmac::Hmac for Hmac<D>
where
    D: Digest + digest::core_api::BlockSizeUser + Clone + Send + Sync + 'static,
    ::hmac::SimpleHmac<D>: Send + Sync,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        // HMAC takes keys of any length.
        Box::new(HmacKey(<::hmac::SimpleHmac<D> as KeyInit>::new_from_slice(key).expect("any key length")))
    }
    fn hash_output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct HmacKey<D: Digest + digest::core_api::BlockSizeUser>(::hmac::SimpleHmac<D>);

impl<D> hmac::Key for HmacKey<D>
where
    D: Digest + digest::core_api::BlockSizeUser + Clone + Send + Sync + 'static,
    ::hmac::SimpleHmac<D>: Send + Sync,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        use ::hmac::Mac;
        let mut m = self.0.clone();
        m.update(first);
        for d in middle {
            m.update(d);
        }
        m.update(last);
        hmac::Tag::new(&m.finalize().into_bytes())
    }
    fn tag_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

// ---- AEADs -----------------------------------------------------------------

const TAG_LEN: usize = 16;
/// Largest plaintext in one TLS record (RFC 8446 §5.1).
const MAX_FRAGMENT_LEN: usize = 16_384;

type Aes128Gcm = aes_gcm::Aes128Gcm;
type Aes256Gcm = aes_gcm::Aes256Gcm;
type ChaCha = chacha20poly1305::ChaCha20Poly1305;

/// An AEAD with a 12-byte nonce and a 16-byte tag (all three here).
trait Aead: AeadInPlace + KeyInit + Send + Sync + 'static {
    const KEY_LEN: usize;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

impl Aead for Aes128Gcm {
    const KEY_LEN: usize = 16;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
    }
}

impl Aead for Aes256Gcm {
    const KEY_LEN: usize = 32;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes256Gcm { key, iv }
    }
}

impl Aead for ChaCha {
    const KEY_LEN: usize = 32;
    fn secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

fn new_aead<A: Aead>(key: &AeadKey) -> A {
    // rustls hands over keys of `key_len()` bytes.
    A::new_from_slice(key.as_ref()).expect("AEAD key length")
}

fn seal<A: Aead>(aead: &A, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
    let tag = aead
        .encrypt_in_place_detached(aead_api::Nonce::<A>::from_slice(nonce), aad, data)
        .map_err(|_| Error::EncryptError)?;
    let mut t = [0; TAG_LEN];
    t.copy_from_slice(&tag);
    Ok(t)
}

fn open<A: Aead>(aead: &A, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8], tag: &[u8]) -> Result<(), Error> {
    // All three AEADs: 12-byte nonces, 16-byte tags (callers split them off).
    aead.decrypt_in_place_detached(aead_api::Nonce::<A>::from_slice(nonce), aad, data, aead_api::Tag::<A>::from_slice(tag))
        .map_err(|_| Error::DecryptError)
}

/// TLS 1.3 record protection (RFC 8446 §5.2): the per-record nonce is the
/// IV XOR the sequence number; the inner content type trails the data.
struct Tls13Aead<A>(PhantomData<fn() -> A>);

impl<A: Aead> Tls13AeadAlgorithm for Tls13Aead<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher { aead: new_aead::<A>(&key), iv })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher { aead: new_aead::<A>(&key), iv })
    }
    fn key_len(&self) -> usize {
        A::KEY_LEN
    }
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(A::secrets(key, iv))
    }
}

struct Tls13Cipher<A> {
    aead: A,
    iv: Iv,
}

impl<A: Aead> MessageEncrypter for Tls13Cipher<A> {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).0;
        let tag = seal(&self.aead, &nonce, &make_tls13_aad(total_len), payload.as_mut())?;
        payload.extend_from_slice(&tag);
        // TLS 1.3 records carry the legacy version 0x0303 (RFC 8446 §5.1).
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<A: Aead> MessageDecrypter for Tls13Cipher<A> {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let Some(n) = payload.len().checked_sub(TAG_LEN) else {
            return Err(Error::DecryptError);
        };
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(payload.len());
        let (data, tag) = payload.split_at_mut(n);
        open(&self.aead, &nonce, &aad, data, tag)?;
        payload.truncate(n);
        msg.into_tls13_unpadded_message()
    }
}

/// TLS 1.2 AES-GCM (RFC 5288): 4-byte salt from the key block, 8-byte
/// explicit nonce in front of each record.
struct Tls12Gcm<A>(PhantomData<fn() -> A>);

const GCM_EXPLICIT_NONCE_LEN: usize = 8;

impl<A: Aead> Tls12AeadAlgorithm for Tls12Gcm<A> {
    fn encrypter(&self, key: AeadKey, iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12GcmCipher { aead: new_aead::<A>(&key), iv: gcm_iv(iv, explicit) })
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        // Only the salt matters when decrypting: the rest of the nonce is
        // in each record.
        Box::new(Tls12GcmCipher { aead: new_aead::<A>(&key), iv: gcm_iv(iv, &[0; 8]) })
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: A::KEY_LEN, fixed_iv_len: 4, explicit_nonce_len: GCM_EXPLICIT_NONCE_LEN }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(A::secrets(key, gcm_iv(iv, explicit)))
    }
}

fn gcm_iv(salt: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0; NONCE_LEN];
    iv[..4].copy_from_slice(&salt[..4]);
    iv[4..].copy_from_slice(&explicit[..8]);
    Iv::new(iv)
}

struct Tls12GcmCipher<A> {
    aead: A,
    iv: Iv,
}

impl<A: Aead> MessageEncrypter for Tls12GcmCipher<A> {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_slice(&nonce[4..]);
        payload.extend_from_chunks(&msg.payload);
        let tag = seal(&self.aead, &nonce, &aad, &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..])?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + TAG_LEN
    }
}

impl<A: Aead> MessageDecrypter for Tls12GcmCipher<A> {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let Some(plain_len) = payload.len().checked_sub(GCM_EXPLICIT_NONCE_LEN + TAG_LEN) else {
            return Err(Error::DecryptError);
        };
        let mut nonce = [0; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.iv.as_ref()[..4]);
        nonce[4..].copy_from_slice(&payload[..GCM_EXPLICIT_NONCE_LEN]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let end = GCM_EXPLICIT_NONCE_LEN + plain_len;
        let (data, tag) = payload.split_at_mut(end);
        open(&self.aead, &nonce, &aad, &mut data[GCM_EXPLICIT_NONCE_LEN..], tag)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.copy_within(GCM_EXPLICIT_NONCE_LEN..end, 0);
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

/// TLS 1.2 ChaCha20-Poly1305 (RFC 7905): nonce = IV XOR sequence number.
struct Tls12ChaCha;

impl Tls12AeadAlgorithm for Tls12ChaCha {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12ChaChaCipher { aead: new_aead::<ChaCha>(&key), iv: Iv::copy(iv) })
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12ChaChaCipher { aead: new_aead::<ChaCha>(&key), iv: Iv::copy(iv) })
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: 32, fixed_iv_len: NONCE_LEN, explicit_nonce_len: 0 }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ChaCha::secrets(key, Iv::copy(iv)))
    }
}

struct Tls12ChaChaCipher {
    aead: ChaCha,
    iv: Iv,
}

impl MessageEncrypter for Tls12ChaChaCipher {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_chunks(&msg.payload);
        let tag = seal(&self.aead, &nonce, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl MessageDecrypter for Tls12ChaChaCipher {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let Some(plain_len) = payload.len().checked_sub(TAG_LEN) else {
            return Err(Error::DecryptError);
        };
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let (data, tag) = payload.split_at_mut(plain_len);
        open(&self.aead, &nonce, &aad, data, tag)?;
        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }
        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

// ---- cipher suites ---------------------------------------------------------

static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &Tls13Aead::<Aes128Gcm>(PhantomData),
    quic: None,
});

static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &SHA384,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HkdfUsingHmac(&HMAC_SHA384),
    aead_alg: &Tls13Aead::<Aes256Gcm>(PhantomData),
    quic: None,
});

static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &Tls13Aead::<ChaCha>(PhantomData),
    quic: None,
});

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

macro_rules! tls12_suite {
    ($name:ident, $suite:ident, $hash:ident, $hmac:ident, $sign:ident, $aead:expr, $limit:expr) => {
        static $name: SupportedCipherSuite = SupportedCipherSuite::Tls12(&Tls12CipherSuite {
            common: CipherSuiteCommon { suite: CipherSuite::$suite, hash_provider: &$hash, confidentiality_limit: $limit },
            kx: KeyExchangeAlgorithm::ECDHE,
            sign: $sign,
            aead_alg: $aead,
            prf_provider: &PrfUsingHmac(&$hmac),
        });
    };
}

tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    &Tls12Gcm::<Aes128Gcm>(PhantomData),
    1 << 24
);
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_ECDSA_SCHEMES,
    &Tls12Gcm::<Aes256Gcm>(PhantomData),
    1 << 24
);
tls12_suite!(
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_ECDSA_SCHEMES,
    &Tls12ChaCha,
    u64::MAX
);
tls12_suite!(
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    &Tls12Gcm::<Aes128Gcm>(PhantomData),
    1 << 24
);
tls12_suite!(
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC_SHA384,
    TLS12_RSA_SCHEMES,
    &Tls12Gcm::<Aes256Gcm>(PhantomData),
    1 << 24
);
tls12_suite!(
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC_SHA256,
    TLS12_RSA_SCHEMES,
    &Tls12ChaCha,
    u64::MAX
);

// ---- key exchange ----------------------------------------------------------

fn random<const N: usize>(rng: &dyn SecureRandom) -> Result<[u8; N], GetRandomFailed> {
    let mut b = [0; N];
    rng.fill(&mut b)?;
    Ok(b)
}

struct X25519(&'static dyn SecureRandom);

impl fmt::Debug for X25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519")
    }
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = x25519_dalek::StaticSecret::from(random::<32>(self.0)?);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ok(Box::new(X25519Kx { secret, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Kx {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Kx {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // An all-zero result means a low-order point (RFC 7748 §6.1).
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

macro_rules! nist_group {
    ($group:ident, $kx:ident, $curve:ident, $named:ident, $len:literal) => {
        struct $group(&'static dyn SecureRandom);

        impl fmt::Debug for $group {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($named))
            }
        }

        impl SupportedKxGroup for $group {
            fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                // Rejection sampling: zero and values ≥ n are not keys.
                let secret = loop {
                    if let Ok(s) = $curve::SecretKey::from_slice(&random::<$len>(self.0)?) {
                        break s;
                    }
                };
                use $curve::elliptic_curve::sec1::ToEncodedPoint;
                let public = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
                Ok(Box::new($kx { secret, public }))
            }
            fn name(&self) -> NamedGroup {
                NamedGroup::$named
            }
        }

        struct $kx {
            secret: $curve::SecretKey,
            public: Vec<u8>,
        }

        impl ActiveKeyExchange for $kx {
            fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
                // TLS sends uncompressed points only (RFC 8446 §4.2.8.2).
                if peer.first() != Some(&4) {
                    return Err(PeerMisbehaved::InvalidKeyShare.into());
                }
                let peer = $curve::PublicKey::from_sec1_bytes(peer).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
                let shared = $curve::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
                Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
            }
            fn pub_key(&self) -> &[u8] {
                &self.public
            }
            fn group(&self) -> NamedGroup {
                NamedGroup::$named
            }
        }
    };
}

nist_group!(P256, P256Kx, p256, secp256r1, 32);
nist_group!(P384, P384Kx, p384, secp384r1, 48);

// ---- signature verification ------------------------------------------------

#[derive(Debug)]
enum Ecdsa {
    P256Sha256,
    P256Sha384,
    P384Sha256,
    P384Sha384,
}

impl SignatureVerificationAlgorithm for Ecdsa {
    fn verify_signature(&self, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), InvalidSignature> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        let digest = match self {
            Ecdsa::P256Sha256 | Ecdsa::P384Sha256 => Sha256::digest(msg).to_vec(),
            Ecdsa::P256Sha384 | Ecdsa::P384Sha384 => Sha384::digest(msg).to_vec(),
        };
        match self {
            Ecdsa::P256Sha256 | Ecdsa::P256Sha384 => {
                let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| InvalidSignature)?;
                let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| InvalidSignature)?;
                k.verify_prehash(&digest, &s).map_err(|_| InvalidSignature)
            }
            Ecdsa::P384Sha256 | Ecdsa::P384Sha384 => {
                let k = p384::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| InvalidSignature)?;
                let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| InvalidSignature)?;
                k.verify_prehash(&digest, &s).map_err(|_| InvalidSignature)
            }
        }
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Ecdsa::P256Sha256 | Ecdsa::P256Sha384 => alg_id::ECDSA_P256,
            Ecdsa::P384Sha256 | Ecdsa::P384Sha384 => alg_id::ECDSA_P384,
        }
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Ecdsa::P256Sha256 | Ecdsa::P384Sha256 => alg_id::ECDSA_SHA256,
            Ecdsa::P256Sha384 | Ecdsa::P384Sha384 => alg_id::ECDSA_SHA384,
        }
    }
}

#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(&self, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), InvalidSignature> {
        let key: &[u8; 32] = key.try_into().map_err(|_| InvalidSignature)?;
        let k = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| InvalidSignature)?;
        let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| InvalidSignature)?;
        k.verify_strict(msg, &s).map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

#[derive(Clone, Copy, Debug)]
enum RsaHash {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug)]
struct RsaPkcs1(RsaHash);

#[derive(Debug)]
struct RsaPss(RsaHash);

/// An RSA public key from a certificate (PKCS#1 `RSAPublicKey`), 2048 to
/// 8192 bits as webpki's other providers accept.
fn rsa_key(der: &[u8]) -> Result<rsa::RsaPublicKey, InvalidSignature> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;
    let k = rsa::RsaPublicKey::from_pkcs1_der(der).map_err(|_| InvalidSignature)?;
    if !(2048..=8192).contains(&(k.n().bits())) {
        return Err(InvalidSignature);
    }
    Ok(k)
}

fn rsa_verify<V, S>(v: V, msg: &[u8], sig: &[u8]) -> Result<(), InvalidSignature>
where
    V: signature::Verifier<S>,
    S: for<'a> TryFrom<&'a [u8]>,
{
    let s = S::try_from(sig).map_err(|_| InvalidSignature)?;
    v.verify(msg, &s).map_err(|_| InvalidSignature)
}

impl SignatureVerificationAlgorithm for RsaPkcs1 {
    fn verify_signature(&self, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), InvalidSignature> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        let k = rsa_key(key)?;
        match self.0 {
            RsaHash::Sha256 => rsa_verify::<_, Signature>(VerifyingKey::<Sha256>::new(k), msg, sig),
            RsaHash::Sha384 => rsa_verify::<_, Signature>(VerifyingKey::<Sha384>::new(k), msg, sig),
            RsaHash::Sha512 => rsa_verify::<_, Signature>(VerifyingKey::<Sha512>::new(k), msg, sig),
        }
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            RsaHash::Sha256 => alg_id::RSA_PKCS1_SHA256,
            RsaHash::Sha384 => alg_id::RSA_PKCS1_SHA384,
            RsaHash::Sha512 => alg_id::RSA_PKCS1_SHA512,
        }
    }
}

impl SignatureVerificationAlgorithm for RsaPss {
    fn verify_signature(&self, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), InvalidSignature> {
        use rsa::pss::{Signature, VerifyingKey};
        let k = rsa_key(key)?;
        match self.0 {
            RsaHash::Sha256 => rsa_verify::<_, Signature>(VerifyingKey::<Sha256>::new(k), msg, sig),
            RsaHash::Sha384 => rsa_verify::<_, Signature>(VerifyingKey::<Sha384>::new(k), msg, sig),
            RsaHash::Sha512 => rsa_verify::<_, Signature>(VerifyingKey::<Sha512>::new(k), msg, sig),
        }
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            RsaHash::Sha256 => alg_id::RSA_PSS_SHA256,
            RsaHash::Sha384 => alg_id::RSA_PSS_SHA384,
            RsaHash::Sha512 => alg_id::RSA_PSS_SHA512,
        }
    }
}

static ECDSA_P256_SHA256: Ecdsa = Ecdsa::P256Sha256;
static ECDSA_P256_SHA384: Ecdsa = Ecdsa::P256Sha384;
static ECDSA_P384_SHA256: Ecdsa = Ecdsa::P384Sha256;
static ECDSA_P384_SHA384: Ecdsa = Ecdsa::P384Sha384;
static ED25519: Ed25519 = Ed25519;
static RSA_PKCS1_SHA256: RsaPkcs1 = RsaPkcs1(RsaHash::Sha256);
static RSA_PKCS1_SHA384: RsaPkcs1 = RsaPkcs1(RsaHash::Sha384);
static RSA_PKCS1_SHA512: RsaPkcs1 = RsaPkcs1(RsaHash::Sha512);
static RSA_PSS_SHA256: RsaPss = RsaPss(RsaHash::Sha256);
static RSA_PSS_SHA384: RsaPss = RsaPss(RsaHash::Sha384);
static RSA_PSS_SHA512: RsaPss = RsaPss(RsaHash::Sha512);

/// Certificate chains use all of them; TLS signature schemes map onto
/// them as with rustls' own providers.
static SIGNATURE_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &ECDSA_P256_SHA256,
        &ECDSA_P256_SHA384,
        &ECDSA_P384_SHA256,
        &ECDSA_P384_SHA384,
        &ED25519,
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
        &RSA_PSS_SHA256,
        &RSA_PSS_SHA384,
        &RSA_PSS_SHA512,
    ],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[&ECDSA_P384_SHA384, &ECDSA_P256_SHA384]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[&ECDSA_P256_SHA256, &ECDSA_P384_SHA256]),
        (SignatureScheme::ED25519, &[&ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA_PKCS1_SHA256]),
    ],
};

// ---- no client keys --------------------------------------------------------

#[derive(Debug)]
struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(&self, _: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General("no private keys: a DNS-over-TLS client needs none".into()))
    }
}
