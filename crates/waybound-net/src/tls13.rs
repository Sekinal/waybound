//! Pure-Rust passive TLS 1.3 record decryptor (RFC 8446).
//!
//! Observes unmodified ciphertext bytes from both directions of a TCP connection,
//! extracts `client_random` from `ClientHello` and `cipher_suite` from `ServerHello`,
//! derives traffic keys from `SSLKEYLOGFILE` via `HKDF-Expand-Label`, and yields
//! decrypted application-data plaintext streams without any MITM or certificate injection.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

use crate::fingerprint::{FingerprintRecorder, parse_client_hello};
use crate::keylog::KeyLogStore;

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_KEY_UPDATE: u8 = 24;

/// Maximum single TLS record payload size (RFC 8446 §5.2 allows up to 16384 + 256).
const MAX_TLS_RECORD_LEN: usize = 18_432;
/// Cap buffered ciphertext waiting for keylog secrets so memory stays bounded.
const MAX_PENDING_CIPHERTEXT: usize = 256 * 1024;

/// Supported TLS 1.3 AEAD cipher suites (covers >99.9% of Chrome/Chromium HTTPS traffic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13CipherSuite {
    /// `0x1301` — `TLS_AES_128_GCM_SHA256`
    Aes128GcmSha256,
    /// `0x1302` — `TLS_AES_256_GCM_SHA384`
    Aes256GcmSha384,
    /// `0x1303` — `TLS_CHACHA20_POLY1305_SHA256`
    ChaCha20Poly1305Sha256,
}

impl Tls13CipherSuite {
    /// Parses a 16-bit TLS cipher suite identifier.
    #[must_use]
    pub const fn from_u16(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    const fn hash_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => 32,
            Self::Aes256GcmSha384 => 48,
        }
    }
}

/// Direction of a TLS record stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Browser -> Origin server.
    ClientToServer,
    /// Origin server -> Browser.
    ServerToClient,
}

impl Direction {
    /// Returns the other direction of the same connection.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

#[derive(Debug, Clone)]
struct TrafficKeyState {
    suite: Tls13CipherSuite,
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    seq: u64,
}

impl TrafficKeyState {
    fn from_secret(suite: Tls13CipherSuite, secret: Vec<u8>) -> Option<Self> {
        let key = hkdf_expand_label(suite, &secret, b"key", b"", suite.key_len())?;
        let iv_vec = hkdf_expand_label(suite, &secret, b"iv", b"", 12)?;
        let iv = <[u8; 12]>::try_from(iv_vec).ok()?;
        Some(Self {
            suite,
            secret,
            key,
            iv,
            seq: 0,
        })
    }

    fn key_update(&mut self) {
        if let Some(next_secret) = hkdf_expand_label(
            self.suite,
            &self.secret,
            b"traffic upd",
            b"",
            self.suite.hash_len(),
        ) && let Some(next_state) = Self::from_secret(self.suite, next_secret)
        {
            *self = next_state;
        }
    }

    fn decrypt_record(&mut self, header: [u8; 5], ciphertext: &[u8]) -> Option<(u8, Vec<u8>)> {
        let nonce_bytes = xor_nonce(self.iv, self.seq);
        let payload = Payload {
            msg: ciphertext,
            aad: &header,
        };
        let plaintext = match self.suite {
            Tls13CipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).ok()?;
                cipher
                    .decrypt(Nonce::from_slice(&nonce_bytes), payload)
                    .ok()?
            }
            Tls13CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
                cipher
                    .decrypt(Nonce::from_slice(&nonce_bytes), payload)
                    .ok()?
            }
            Tls13CipherSuite::ChaCha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).ok()?;
                cipher
                    .decrypt(Nonce::from_slice(&nonce_bytes), payload)
                    .ok()?
            }
        };
        self.seq = self.seq.saturating_add(1);
        strip_tls13_inner_plaintext(plaintext)
    }
}

/// Strips RFC 8446 §5.4 trailing zero padding and extracts `(inner_content_type, content)`.
fn strip_tls13_inner_plaintext(mut plaintext: Vec<u8>) -> Option<(u8, Vec<u8>)> {
    while plaintext.last() == Some(&0) {
        let _ = plaintext.pop();
    }
    let content_type = plaintext.pop()?;
    Some((content_type, plaintext))
}

fn xor_nonce(mut iv: [u8; 12], seq: u64) -> [u8; 12] {
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        iv[4 + i] ^= seq_bytes[i];
    }
    iv
}

/// RFC 8446 §7.1 `HKDF-Expand-Label(Secret, Label, Context, Length)`.
#[must_use]
pub fn hkdf_expand_label(
    suite: Tls13CipherSuite,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Option<Vec<u8>> {
    let full_label_len = 6usize.checked_add(label.len())?;
    let len_u16 = u16::try_from(length).ok()?;
    let label_u8 = u8::try_from(full_label_len).ok()?;
    let ctx_u8 = u8::try_from(context.len()).ok()?;

    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    hkdf_label.extend_from_slice(&len_u16.to_be_bytes());
    hkdf_label.push(label_u8);
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(ctx_u8);
    hkdf_label.extend_from_slice(context);

    let mut okm = vec![0u8; length];
    match suite {
        Tls13CipherSuite::Aes128GcmSha256 | Tls13CipherSuite::ChaCha20Poly1305Sha256 => {
            let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
            hk.expand(&hkdf_label, &mut okm).ok()?;
        }
        Tls13CipherSuite::Aes256GcmSha384 => {
            let hk = Hkdf::<Sha384>::from_prk(secret).ok()?;
            hk.expand(&hkdf_label, &mut okm).ok()?;
        }
    }
    Some(okm)
}

#[derive(Debug, Default)]
struct DirBuffer {
    raw: Vec<u8>,
    key_state: Option<TrafficKeyState>,
    /// `ApplicationData` records seen before keys were ready (or handshake encrypted records).
    pending_app_records: Vec<([u8; 5], Vec<u8>)>,
    /// True once we've successfully decrypted our first application-data record.
    synced: bool,
    /// Number of skipped encrypted handshake records before application traffic keys took effect.
    skipped_handshake_records: usize,
}

/// Passive bidirectional TLS 1.3 decryptor for a single TCP connection.
#[derive(Debug)]
pub struct PassiveTls13Decoder {
    keylog: KeyLogStore,
    fingerprint: Option<FingerprintRecorder>,
    client_random: Option<[u8; 32]>,
    cipher_suite: Option<Tls13CipherSuite>,
    c2s: DirBuffer,
    s2c: DirBuffer,
}

impl PassiveTls13Decoder {
    /// Creates a new passive TLS 1.3 decoder using `keylog` for secret lookups.
    #[must_use]
    pub fn new(keylog: KeyLogStore) -> Self {
        Self::with_fingerprint(keylog, None)
    }

    /// Creates a new passive TLS 1.3 decoder that also records `ClientHello` fingerprints.
    #[must_use]
    pub fn with_fingerprint(keylog: KeyLogStore, fingerprint: Option<FingerprintRecorder>) -> Self {
        Self {
            keylog,
            fingerprint,
            client_random: None,
            cipher_suite: None,
            c2s: DirBuffer::default(),
            s2c: DirBuffer::default(),
        }
    }

    /// Feeds raw ciphertext bytes for `dir` and returns any decrypted application-data plaintext.
    pub fn feed(&mut self, dir: Direction, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let buf = match dir {
                Direction::ClientToServer => &mut self.c2s,
                Direction::ServerToClient => &mut self.s2c,
            };
            if buf.raw.len().saturating_add(data.len()) > MAX_PENDING_CIPHERTEXT * 2 {
                // Prevent unbounded growth on non-TLS or unsupported streams.
                buf.raw.clear();
                return out;
            }
            buf.raw.extend_from_slice(data);
        }

        self.drain_records(dir, &mut out);
        out
    }

    fn drain_records(&mut self, dir: Direction, out: &mut Vec<u8>) {
        loop {
            let record = {
                let buf = match dir {
                    Direction::ClientToServer => &mut self.c2s,
                    Direction::ServerToClient => &mut self.s2c,
                };
                if buf.raw.len() < 5 {
                    break;
                }
                let header = [buf.raw[0], buf.raw[1], buf.raw[2], buf.raw[3], buf.raw[4]];
                let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
                if len > MAX_TLS_RECORD_LEN {
                    // Not valid TLS framing; drop buffer to avoid stalling.
                    buf.raw.clear();
                    break;
                }
                if buf.raw.len() < 5 + len {
                    break;
                }
                let payload = buf.raw[5..5 + len].to_vec();
                let _ = buf.raw.drain(..5 + len);
                (header, payload)
            };

            let (header, payload) = record;
            match header[0] {
                CONTENT_TYPE_HANDSHAKE => {
                    self.inspect_plaintext_handshake(dir, &payload);
                }
                CONTENT_TYPE_APPLICATION_DATA => {
                    self.handle_app_record(dir, header, payload, out);
                }
                _ => {}
            }
        }
    }

    fn inspect_plaintext_handshake(&mut self, dir: Direction, payload: &[u8]) {
        if payload.len() < 38 {
            return;
        }
        let hs_type = payload[0];
        if dir == Direction::ClientToServer
            && hs_type == HANDSHAKE_CLIENT_HELLO
            && self.client_random.is_none()
            && let Ok(rand) = <[u8; 32]>::try_from(&payload[6..38])
        {
            self.client_random = Some(rand);
            if let Some(ref rec) = self.fingerprint
                && let Some(fp) = parse_client_hello(payload)
            {
                rec.record_tls(fp);
            }
        } else if dir == Direction::ServerToClient
            && hs_type == HANDSHAKE_SERVER_HELLO
            && self.cipher_suite.is_none()
            && let Some(suite) = parse_server_hello_cipher_suite(payload)
        {
            self.cipher_suite = Some(suite);
        }
    }

    fn ensure_keys(&mut self, dir: Direction) -> bool {
        let has_key = match dir {
            Direction::ClientToServer => self.c2s.key_state.is_some(),
            Direction::ServerToClient => self.s2c.key_state.is_some(),
        };
        if has_key {
            return true;
        }
        let (Some(client_random), Some(suite)) = (self.client_random, self.cipher_suite) else {
            return false;
        };
        let Some(secrets) = self.keylog.lookup(&client_random) else {
            return false;
        };
        if self.c2s.key_state.is_none()
            && let Some(sec) = secrets.client_traffic_secret_0
        {
            self.c2s.key_state = TrafficKeyState::from_secret(suite, sec);
        }
        if self.s2c.key_state.is_none()
            && let Some(sec) = secrets.server_traffic_secret_0
        {
            self.s2c.key_state = TrafficKeyState::from_secret(suite, sec);
        }
        match dir {
            Direction::ClientToServer => self.c2s.key_state.is_some(),
            Direction::ServerToClient => self.s2c.key_state.is_some(),
        }
    }

    fn handle_app_record(
        &mut self,
        dir: Direction,
        header: [u8; 5],
        payload: Vec<u8>,
        out: &mut Vec<u8>,
    ) {
        let keys_ready = self.ensure_keys(dir);
        let buf = match dir {
            Direction::ClientToServer => &mut self.c2s,
            Direction::ServerToClient => &mut self.s2c,
        };

        if !keys_ready {
            if buf.pending_app_records.len() < 32 {
                buf.pending_app_records.push((header, payload));
            }
            return;
        }

        // First flush any queued records that arrived right before keylog became visible.
        let mut records = std::mem::take(&mut buf.pending_app_records);
        records.push((header, payload));

        for (hdr, ct) in records {
            if let Some(ks) = buf.key_state.as_mut() {
                if let Some((inner_ct, plain)) = ks.decrypt_record(hdr, &ct) {
                    buf.synced = true;
                    if inner_ct == CONTENT_TYPE_APPLICATION_DATA {
                        out.extend_from_slice(&plain);
                    } else if inner_ct == CONTENT_TYPE_HANDSHAKE
                        && plain.first() == Some(&HANDSHAKE_KEY_UPDATE)
                    {
                        ks.key_update();
                    }
                } else if !buf.synced && buf.skipped_handshake_records < 16 {
                    // Initial TLS 1.3 encrypted handshake records (EncryptedExtensions,
                    // Certificate, CertificateVerify, Finished) use handshake traffic keys,
                    // not application traffic keys; skip them until seq 0 decrypts cleanly.
                    buf.skipped_handshake_records += 1;
                }
            }
        }
    }
}

/// Extracts the negotiated TLS 1.3 cipher suite from a `ServerHello` handshake message.
fn parse_server_hello_cipher_suite(payload: &[u8]) -> Option<Tls13CipherSuite> {
    // 4-byte handshake header + 2-byte legacy_version + 32-byte random + 1-byte session_id_len
    if payload.len() < 39 {
        return None;
    }
    let sid_len = usize::from(payload[38]);
    let cs_offset = 39usize.checked_add(sid_len)?;
    let hi = *payload.get(cs_offset)?;
    let lo = *payload.get(cs_offset + 1)?;
    Tls13CipherSuite::from_u16(u16::from_be_bytes([hi, lo]))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use waybound_core::CapturedResponse;

    use super::*;
    use crate::{HttpConnectionCorrelator, InflightCounter, PassiveConnectionTap};

    const fn suite_id(suite: Tls13CipherSuite) -> u16 {
        match suite {
            Tls13CipherSuite::Aes128GcmSha256 => 0x1301,
            Tls13CipherSuite::Aes256GcmSha384 => 0x1302,
            Tls13CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    fn build_client_hello(client_random: &[u8; 32]) -> Vec<u8> {
        let mut ch = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01, 0x00, 38];
        ch.extend_from_slice(&[HANDSHAKE_CLIENT_HELLO, 0, 0, 34, 0x03, 0x03]);
        ch.extend_from_slice(client_random);
        ch
    }

    fn build_server_hello(suite: Tls13CipherSuite) -> Vec<u8> {
        // ServerHello body: legacy_version (2) + random (32) + sid_len (1) +
        // cipher_suite (2) + compression (1) + extensions_len (2) + supported_versions ext (6).
        let mut body = Vec::with_capacity(46);
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x99u8; 32]);
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&suite_id(suite).to_be_bytes());
        body.push(0); // legacy_compression_method = 0
        // extensions: supported_versions (0x002b), len 2, version 0x0304 (TLS 1.3)
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

        let body_len = u8::try_from(body.len()).unwrap_or(0);
        let rec_len = u16::try_from(4 + body.len()).unwrap_or(0);
        let mut sh = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x03];
        sh.extend_from_slice(&rec_len.to_be_bytes());
        sh.extend_from_slice(&[HANDSHAKE_SERVER_HELLO, 0, 0, body_len]);
        sh.extend_from_slice(&body);
        sh
    }

    fn seal_record(
        ks: &TrafficKeyState,
        seq: u64,
        inner_ct: u8,
        plaintext: &[u8],
        padding: usize,
    ) -> Option<Vec<u8>> {
        let mut inner = Vec::with_capacity(plaintext.len() + 1 + padding);
        inner.extend_from_slice(plaintext);
        inner.push(inner_ct);
        inner.resize(inner.len() + padding, 0);

        let ct_len = u16::try_from(inner.len() + 16).ok()?;
        let [len_hi, len_lo] = ct_len.to_be_bytes();
        let header = [CONTENT_TYPE_APPLICATION_DATA, 0x03, 0x03, len_hi, len_lo];
        let nonce = xor_nonce(ks.iv, seq);
        let payload = Payload {
            msg: &inner,
            aad: &header,
        };
        let ct = match ks.suite {
            Tls13CipherSuite::Aes128GcmSha256 => {
                let cipher = Aes128Gcm::new_from_slice(&ks.key).ok()?;
                cipher.encrypt(Nonce::from_slice(&nonce), payload).ok()?
            }
            Tls13CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(&ks.key).ok()?;
                cipher.encrypt(Nonce::from_slice(&nonce), payload).ok()?
            }
            Tls13CipherSuite::ChaCha20Poly1305Sha256 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&ks.key).ok()?;
                cipher.encrypt(Nonce::from_slice(&nonce), payload).ok()?
            }
        };

        let mut rec = Vec::with_capacity(5 + ct.len());
        rec.extend_from_slice(&header);
        rec.extend_from_slice(&ct);
        Some(rec)
    }

    #[test]
    fn decrypts_all_three_supported_cipher_suites() {
        let suites = [
            Tls13CipherSuite::Aes128GcmSha256,
            Tls13CipherSuite::Aes256GcmSha384,
            Tls13CipherSuite::ChaCha20Poly1305Sha256,
        ];

        for (idx, suite) in suites.into_iter().enumerate() {
            let tag = u8::try_from(idx + 1).unwrap_or(1);
            let client_random = [0x40u8.wrapping_add(tag); 32];
            let server_secret = vec![0x10u8.wrapping_add(tag); suite.hash_len()];
            let client_secret = vec![0x20u8.wrapping_add(tag); suite.hash_len()];

            let ks = TrafficKeyState::from_secret(suite, server_secret.clone());
            assert!(ks.is_some());
            let Some(ks) = ks else {
                return;
            };

            let expected = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
            let rec = seal_record(&ks, 0, CONTENT_TYPE_APPLICATION_DATA, expected, 2);
            assert!(rec.is_some());
            let Some(rec) = rec else {
                return;
            };

            let store = KeyLogStore::new("/nonexistent/test.keylog");
            store.insert_for_test(client_random, client_secret, server_secret);
            let mut dec = PassiveTls13Decoder::new(store);

            assert_eq!(
                dec.feed(
                    Direction::ClientToServer,
                    &build_client_hello(&client_random)
                ),
                Vec::<u8>::new()
            );
            assert_eq!(
                dec.feed(Direction::ServerToClient, &build_server_hello(suite)),
                Vec::<u8>::new()
            );

            // Include a bogus encrypted handshake record to verify it is skipped while seq stays 0.
            let mut s2c = vec![CONTENT_TYPE_APPLICATION_DATA, 0x03, 0x03, 0x00, 20];
            s2c.extend_from_slice(&[0xABu8; 20]);
            s2c.extend_from_slice(&rec);

            let plain = dec.feed(Direction::ServerToClient, &s2c);
            assert_eq!(plain, expected, "suite {suite:?}");
        }
    }

    #[test]
    fn handles_key_update_mid_stream() {
        let suite = Tls13CipherSuite::Aes256GcmSha384;
        let client_random = [0x55u8; 32];
        let server_secret = vec![0x33u8; suite.hash_len()];
        let client_secret = vec![0x44u8; suite.hash_len()];

        let ks0 = TrafficKeyState::from_secret(suite, server_secret.clone());
        assert!(ks0.is_some());
        let Some(mut ks) = ks0 else {
            return;
        };

        let r0 = seal_record(&ks, 0, CONTENT_TYPE_APPLICATION_DATA, b"before-", 0);
        // RFC 8446 §4.6.3 KeyUpdate handshake message: type=24, length=1, request_update=0.
        let ku = seal_record(
            &ks,
            1,
            CONTENT_TYPE_HANDSHAKE,
            &[HANDSHAKE_KEY_UPDATE, 0, 0, 1, 0],
            0,
        );
        ks.key_update();
        let r1 = seal_record(&ks, 0, CONTENT_TYPE_APPLICATION_DATA, b"after-update", 1);
        let r2 = seal_record(&ks, 1, CONTENT_TYPE_APPLICATION_DATA, b"-and-more", 0);

        assert!(r0.is_some());
        assert!(ku.is_some());
        assert!(r1.is_some());
        assert!(r2.is_some());
        let (Some(r0), Some(ku), Some(r1), Some(r2)) = (r0, ku, r1, r2) else {
            return;
        };

        let store = KeyLogStore::new("/nonexistent/test.keylog");
        store.insert_for_test(client_random, client_secret, server_secret);
        let mut dec = PassiveTls13Decoder::new(store);

        let _ = dec.feed(
            Direction::ClientToServer,
            &build_client_hello(&client_random),
        );
        let _ = dec.feed(Direction::ServerToClient, &build_server_hello(suite));

        let mut stream = Vec::new();
        stream.extend_from_slice(&r0);
        stream.extend_from_slice(&ku);
        stream.extend_from_slice(&r1);
        stream.extend_from_slice(&r2);

        let plain = dec.feed(Direction::ServerToClient, &stream);
        assert_eq!(plain, b"before-after-update-and-more");
    }

    #[test]
    fn handles_byte_by_byte_fragmented_tcp_feeds() {
        let suite = Tls13CipherSuite::ChaCha20Poly1305Sha256;
        let client_random = [0x66u8; 32];
        let server_secret = vec![0x77u8; suite.hash_len()];
        let client_secret = vec![0x88u8; suite.hash_len()];

        let ks = TrafficKeyState::from_secret(suite, server_secret.clone());
        assert!(ks.is_some());
        let Some(ks) = ks else {
            return;
        };

        let r0 = seal_record(&ks, 0, CONTENT_TYPE_APPLICATION_DATA, b"chunk-one:", 0);
        let r1 = seal_record(&ks, 1, CONTENT_TYPE_APPLICATION_DATA, b"chunk-two", 3);
        assert!(r0.is_some());
        assert!(r1.is_some());
        let (Some(r0), Some(r1)) = (r0, r1) else {
            return;
        };

        let store = KeyLogStore::new("/nonexistent/test.keylog");
        store.insert_for_test(client_random, client_secret, server_secret);
        let mut dec = PassiveTls13Decoder::new(store);

        let ch = build_client_hello(&client_random);
        for byte in &ch {
            assert!(dec.feed(Direction::ClientToServer, &[*byte]).is_empty());
        }

        let mut s2c = build_server_hello(suite);
        s2c.extend_from_slice(&r0);
        s2c.extend_from_slice(&r1);

        let mut out = Vec::new();
        for byte in &s2c {
            out.extend_from_slice(&dec.feed(Direction::ServerToClient, &[*byte]));
        }
        assert_eq!(out, b"chunk-one:chunk-two");
    }

    #[test]
    fn progresses_sequence_numbers_and_queues_records_until_late_keylog() {
        let suite = Tls13CipherSuite::Aes128GcmSha256;
        let client_random = [0x71u8; 32];
        let server_secret = vec![0x91u8; suite.hash_len()];
        let client_secret = vec![0xA1u8; suite.hash_len()];

        let ks = TrafficKeyState::from_secret(suite, server_secret.clone());
        assert!(ks.is_some());
        let Some(ks) = ks else {
            return;
        };

        let r0 = seal_record(&ks, 0, CONTENT_TYPE_APPLICATION_DATA, b"rec0-", 0);
        let r1 = seal_record(&ks, 1, CONTENT_TYPE_APPLICATION_DATA, b"rec1-", 0);
        let r2 = seal_record(&ks, 2, CONTENT_TYPE_APPLICATION_DATA, b"rec2", 0);
        assert!(r0.is_some());
        assert!(r1.is_some());
        assert!(r2.is_some());
        let (Some(r0), Some(r1), Some(r2)) = (r0, r1, r2) else {
            return;
        };

        // Start with an empty keylog store; secrets arrive late.
        let store = KeyLogStore::new("/nonexistent/test.keylog");
        let mut dec = PassiveTls13Decoder::new(store.clone());

        let _ = dec.feed(
            Direction::ClientToServer,
            &build_client_hello(&client_random),
        );
        let _ = dec.feed(Direction::ServerToClient, &build_server_hello(suite));

        // Feed seq 0 and seq 1 before keylog is populated — both must be queued.
        assert!(dec.feed(Direction::ServerToClient, &r0).is_empty());
        assert!(dec.feed(Direction::ServerToClient, &r1).is_empty());

        // Now populate the keylog and feed seq 2; all three records flush in order.
        store.insert_for_test(client_random, client_secret, server_secret);
        let flushed = dec.feed(Direction::ServerToClient, &r2);
        assert_eq!(flushed, b"rec0-rec1-rec2");
    }

    #[test]
    fn correlates_bidirectional_http_over_passive_tls13_tap() {
        let suite = Tls13CipherSuite::Aes128GcmSha256;
        let client_random = [0x99u8; 32];
        let client_secret = vec![0xB1u8; suite.hash_len()];
        let server_secret = vec![0xC2u8; suite.hash_len()];

        let c_ks = TrafficKeyState::from_secret(suite, client_secret.clone());
        let s_ks = TrafficKeyState::from_secret(suite, server_secret.clone());
        assert!(c_ks.is_some());
        assert!(s_ks.is_some());
        let (Some(c_ks), Some(s_ks)) = (c_ks, s_ks) else {
            return;
        };

        let http_req = b"GET /api/items HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let http_resp =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";

        let req_rec = seal_record(&c_ks, 0, CONTENT_TYPE_APPLICATION_DATA, http_req, 0);
        let resp_rec = seal_record(&s_ks, 0, CONTENT_TYPE_APPLICATION_DATA, http_resp, 0);
        assert!(req_rec.is_some());
        assert!(resp_rec.is_some());
        let (Some(req_rec), Some(resp_rec)) = (req_rec, resp_rec) else {
            return;
        };

        // 1. Direct PassiveTls13Decoder + HttpConnectionCorrelator correlation.
        let store = KeyLogStore::new("/nonexistent/test.keylog");
        store.insert_for_test(client_random, client_secret, server_secret);
        let mut dec = PassiveTls13Decoder::new(store.clone());

        let captured: Arc<Mutex<Vec<CapturedResponse>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);
        let mut http = HttpConnectionCorrelator::new(
            "example.test".to_owned(),
            1,
            InflightCounter::default(),
            Arc::new(move |_seq, resp| {
                if let Ok(mut guard) = sink.lock() {
                    guard.push(resp);
                }
            }),
        );

        let _ = dec.feed(
            Direction::ClientToServer,
            &build_client_hello(&client_random),
        );
        let _ = dec.feed(Direction::ServerToClient, &build_server_hello(suite));

        let c2s_plain = dec.feed(Direction::ClientToServer, &req_rec);
        assert_eq!(c2s_plain, http_req);
        http.feed_client(&c2s_plain);

        let s2c_plain = dec.feed(Direction::ServerToClient, &resp_rec);
        assert_eq!(s2c_plain, http_resp);
        http.feed_server(&s2c_plain);

        let responses = captured.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(responses.len(), 1);
        if let Some(resp) = responses.first() {
            assert_eq!(resp.url, "https://example.test/api/items");
            assert_eq!(resp.status, 200);
            assert_eq!(resp.body.as_deref(), Some("{\"ok\":true}"));
        }

        // 2. Full PassiveConnectionTap end-to-end (version detection -> TLS 1.3 -> HTTP).
        let tap_captured: Arc<Mutex<Vec<CapturedResponse>>> = Arc::new(Mutex::new(Vec::new()));
        let tap_sink = Arc::clone(&tap_captured);
        let tap = PassiveConnectionTap::new(
            "example.test".to_owned(),
            store,
            InflightCounter::default(),
            Arc::new(move |_seq, resp| {
                if let Ok(mut guard) = tap_sink.lock() {
                    guard.push(resp);
                }
            }),
        );

        tap.observe(
            Direction::ClientToServer,
            &build_client_hello(&client_random),
        );
        tap.observe(Direction::ServerToClient, &build_server_hello(suite));
        tap.observe(Direction::ClientToServer, &req_rec);
        tap.observe(Direction::ServerToClient, &resp_rec);

        let tap_responses = tap_captured.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(tap_responses.len(), 1);
        if let Some(resp) = tap_responses.first() {
            assert_eq!(resp.url, "https://example.test/api/items");
            assert_eq!(resp.status, 200);
            assert_eq!(resp.body.as_deref(), Some("{\"ok\":true}"));
        }
    }
}
