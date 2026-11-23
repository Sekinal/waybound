//! Pure-Rust passive TLS 1.2 AEAD record decryptor (RFC 5246, RFC 5288, RFC 7905).
//!
//! Extracts `client_random` from the `ClientHello` and `server_random` + `cipher_suite`
//! from the `ServerHello`, looks up the `CLIENT_RANDOM` master secret in `SSLKEYLOGFILE`,
//! derives the key block with the RFC 5246 §5 PRF, and decrypts every record that follows
//! `ChangeCipherSpec` in each direction. Only AEAD suites are supported (no CBC).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use crate::keylog::KeyLogStore;
use crate::tls::ServerHello;
use crate::tls13::Direction;

const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// Maximum TLS 1.2 record payload (RFC 5246 §6.2.3: 2^14 + 2048).
const MAX_TLS_RECORD_LEN: usize = 18_432;
/// Cap on protected records queued per direction while the master secret is unknown.
const MAX_PENDING_RECORDS: usize = 32;
/// Cap buffered ciphertext waiting for keylog secrets so memory stays bounded. Sized so
/// that [`MAX_PENDING_RECORDS`] full-size records fit, matching the TLS 1.3 decoder's
/// tolerance for a late keylog line during a large transfer.
const MAX_PENDING_CIPHERTEXT: usize = MAX_PENDING_RECORDS * MAX_TLS_RECORD_LEN;
/// RFC 5288 §3: `GenericAEADCipher.nonce_explicit` length for AES-GCM.
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const AEAD_TAG_LEN: usize = 16;
/// RFC 5246 master secret length.
const MASTER_SECRET_LEN: usize = 48;

/// Supported TLS 1.2 AEAD cipher suites (the ones Chrome offers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12CipherSuite {
    /// `0xC02B` / `0xC02F` / `0x009C` — `TLS_{ECDHE_ECDSA,ECDHE_RSA,RSA}_WITH_AES_128_GCM_SHA256`
    Aes128GcmSha256,
    /// `0xC02C` / `0xC030` / `0x009D` — `TLS_{ECDHE_ECDSA,ECDHE_RSA,RSA}_WITH_AES_256_GCM_SHA384`
    Aes256GcmSha384,
    /// `0xCCA9` / `0xCCA8` — `TLS_ECDHE_{ECDSA,RSA}_WITH_CHACHA20_POLY1305_SHA256`
    ChaCha20Poly1305Sha256,
}

/// Hash function underlying the TLS 1.2 PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfHash {
    /// `P_SHA256`
    Sha256,
    /// `P_SHA384`
    Sha384,
}

impl Tls12CipherSuite {
    /// Parses a 16-bit TLS cipher suite identifier.
    #[must_use]
    pub const fn from_u16(id: u16) -> Option<Self> {
        match id {
            0xc02b | 0xc02f | 0x009c => Some(Self::Aes128GcmSha256),
            0xc02c | 0xc030 | 0x009d => Some(Self::Aes256GcmSha384),
            0xcca8 | 0xcca9 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// `SecurityParameters.fixed_iv_length`: 4 for GCM (RFC 5288), 12 for `ChaCha20` (RFC 7905).
    const fn fixed_iv_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 | Self::Aes256GcmSha384 => 4,
            Self::ChaCha20Poly1305Sha256 => 12,
        }
    }

    /// PRF hash: SHA-384 for `*_SHA384` suites, SHA-256 otherwise (RFC 5288 §3, RFC 7905 §2).
    #[must_use]
    pub const fn prf_hash(self) -> PrfHash {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => PrfHash::Sha256,
            Self::Aes256GcmSha384 => PrfHash::Sha384,
        }
    }
}

/// RFC 5246 §5 `PRF(secret, label, seed)` truncated to `length` bytes.
#[must_use]
pub fn prf(
    hash: PrfHash,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Option<Vec<u8>> {
    let mut label_seed = Vec::with_capacity(label.len().saturating_add(seed.len()));
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    let mut out = vec![0u8; length];
    match hash {
        PrfHash::Sha256 => p_hash::<Hmac<Sha256>>(secret, &label_seed, &mut out)?,
        PrfHash::Sha384 => p_hash::<Hmac<Sha384>>(secret, &label_seed, &mut out)?,
    }
    Some(out)
}

/// RFC 5246 §5 `P_hash`: `HMAC(secret, A(i) + seed)` with `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`.
fn p_hash<M: Mac + KeyInit + Clone>(secret: &[u8], seed: &[u8], out: &mut [u8]) -> Option<()> {
    let base = <M as KeyInit>::new_from_slice(secret).ok()?;
    let mut a = {
        let mut mac = base.clone();
        mac.update(seed);
        mac.finalize().into_bytes()
    };
    let mut filled = 0usize;
    while filled < out.len() {
        let mut mac = base.clone();
        mac.update(&a);
        mac.update(seed);
        let block = mac.finalize().into_bytes();
        let take = block.len().min(out.len() - filled);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;

        let mut mac = base.clone();
        mac.update(&a);
        a = mac.finalize().into_bytes();
    }
    Some(())
}

/// Per-direction AEAD write key and fixed IV taken from the TLS 1.2 key block.
#[derive(Debug, Clone)]
struct RecordKeys {
    suite: Tls12CipherSuite,
    key: Vec<u8>,
    iv: Vec<u8>,
}

/// Client and server write keys derived from one master secret.
#[derive(Debug, Clone)]
struct KeyBlock {
    client: RecordKeys,
    server: RecordKeys,
}

impl KeyBlock {
    /// RFC 5246 §6.3: `key_block = PRF(master_secret, "key expansion", server_random + client_random)`,
    /// partitioned as client/server MAC keys (empty for AEAD), write keys, then fixed IVs.
    fn derive(
        suite: Tls12CipherSuite,
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Option<Self> {
        if master_secret.len() != MASTER_SECRET_LEN {
            return None;
        }
        let key_len = suite.key_len();
        let iv_len = suite.fixed_iv_len();
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);
        let block = prf(
            suite.prf_hash(),
            master_secret,
            b"key expansion",
            &seed,
            2 * key_len + 2 * iv_len,
        )?;
        let (client_key, rest) = block.split_at_checked(key_len)?;
        let (server_key, rest) = rest.split_at_checked(key_len)?;
        let (client_iv, server_iv) = rest.split_at_checked(iv_len)?;
        Some(Self {
            client: RecordKeys {
                suite,
                key: client_key.to_vec(),
                iv: client_iv.to_vec(),
            },
            server: RecordKeys {
                suite,
                key: server_key.to_vec(),
                iv: server_iv.to_vec(),
            },
        })
    }
}

impl RecordKeys {
    /// Decrypts one protected record whose sequence number is `seq`.
    fn decrypt(&self, seq: u64, header: [u8; 5], payload: &[u8]) -> Option<Vec<u8>> {
        let (nonce, ciphertext) = match self.suite {
            Tls12CipherSuite::Aes128GcmSha256 | Tls12CipherSuite::Aes256GcmSha384 => {
                // RFC 5288 §3: nonce = salt (fixed IV, 4 bytes) || nonce_explicit (8 bytes).
                let (explicit, rest) = payload.split_at_checked(GCM_EXPLICIT_NONCE_LEN)?;
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(self.iv.get(..4)?);
                nonce[4..].copy_from_slice(explicit);
                (nonce, rest)
            }
            Tls12CipherSuite::ChaCha20Poly1305Sha256 => {
                // RFC 7905 §2: nonce = fixed IV XOR (64-bit seq left-padded to 96 bits).
                let mut nonce = <[u8; 12]>::try_from(self.iv.as_slice()).ok()?;
                for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
                    *n ^= s;
                }
                (nonce, payload)
            }
        };
        let plaintext_len = ciphertext.len().checked_sub(AEAD_TAG_LEN)?;
        // RFC 5246 §6.2.3.3: additional_data = seq_num + type + version + length (13 bytes).
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8..11].copy_from_slice(&header[..3]);
        aad[11..].copy_from_slice(&u16::try_from(plaintext_len).ok()?.to_be_bytes());
        let msg = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let nonce = Nonce::from_slice(&nonce);
        match self.suite {
            Tls12CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(&self.key)
                .ok()?
                .decrypt(nonce, msg)
                .ok(),
            Tls12CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(&self.key)
                .ok()?
                .decrypt(nonce, msg)
                .ok(),
            Tls12CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(&self.key)
                .ok()?
                .decrypt(nonce, msg)
                .ok(),
        }
    }
}

#[derive(Debug)]
struct PendingRecord {
    seq: u64,
    header: [u8; 5],
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct DirState {
    raw: Vec<u8>,
    /// True once this direction has sent `ChangeCipherSpec`; later records are protected.
    encrypted: bool,
    /// Sequence number of the next protected record (reset to 0 by `ChangeCipherSpec`).
    next_seq: u64,
    keys: Option<RecordKeys>,
    /// Protected records seen before the master secret was available.
    pending: Vec<PendingRecord>,
    pending_bytes: usize,
}

impl DirState {
    /// Decrypts all queued records in sequence order, appending application data to `out`.
    fn decrypt_pending(&mut self, out: &mut Vec<u8>) {
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        for record in self.pending.drain(..) {
            // TLS 1.2 has no inner content type: the outer type is authenticated via the AAD.
            if let Some(plain) = keys.decrypt(record.seq, record.header, &record.payload)
                && record.header[0] == CONTENT_TYPE_APPLICATION_DATA
            {
                out.extend_from_slice(&plain);
            }
        }
        self.pending_bytes = 0;
    }
}

/// Passive bidirectional TLS 1.2 AEAD decryptor for a single TCP connection.
#[derive(Debug)]
pub struct PassiveTls12Decoder {
    keylog: KeyLogStore,
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    cipher_suite: Option<Tls12CipherSuite>,
    /// Keylog generation at the last `CLIENT_RANDOM` miss (skips re-searching unchanged data).
    last_keylog_miss: Option<u64>,
    /// Set when the connection cannot be decrypted (unsupported suite or queue overflow);
    /// all buffers are released and later bytes are ignored.
    abandoned: bool,
    c2s: DirState,
    s2c: DirState,
}

impl PassiveTls12Decoder {
    /// Creates a new passive TLS 1.2 decoder using `keylog` for `CLIENT_RANDOM` lookups.
    #[must_use]
    pub fn new(keylog: KeyLogStore) -> Self {
        Self {
            keylog,
            client_random: None,
            server_random: None,
            cipher_suite: None,
            last_keylog_miss: None,
            abandoned: false,
            c2s: DirState::default(),
            s2c: DirState::default(),
        }
    }

    const fn dir_mut(&mut self, dir: Direction) -> &mut DirState {
        match dir {
            Direction::ClientToServer => &mut self.c2s,
            Direction::ServerToClient => &mut self.s2c,
        }
    }

    /// Stops decrypting this connection and frees everything buffered for it.
    fn abandon(&mut self) {
        self.abandoned = true;
        self.c2s = DirState::default();
        self.s2c = DirState::default();
    }

    /// Feeds raw ciphertext bytes for `dir` and returns any decrypted application-data plaintext.
    pub fn feed(&mut self, dir: Direction, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.abandoned {
            return out;
        }
        let buf = self.dir_mut(dir);
        if buf.raw.len().saturating_add(data.len()) > MAX_PENDING_CIPHERTEXT * 2 {
            // Prevent unbounded growth on non-TLS or unsupported streams.
            buf.raw.clear();
            return out;
        }
        buf.raw.extend_from_slice(data);
        self.drain_records(dir, &mut out);
        out
    }

    fn drain_records(&mut self, dir: Direction, out: &mut Vec<u8>) {
        // Walk complete records with a cursor and compact the buffer once at the end.
        let mut pos = 0usize;
        loop {
            let buf = self.dir_mut(dir);
            let Some(header) = buf
                .raw
                .get(pos..)
                .and_then(<[u8]>::first_chunk::<5>)
                .copied()
            else {
                break;
            };
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if len > MAX_TLS_RECORD_LEN {
                // Not valid TLS framing; drop buffer to avoid stalling.
                buf.raw.clear();
                return;
            }
            let start = pos + 5;
            let Some(payload) = buf.raw.get(start..start + len).map(<[u8]>::to_vec) else {
                break;
            };
            pos = start + len;

            if buf.encrypted {
                let seq = buf.next_seq;
                buf.next_seq = buf.next_seq.wrapping_add(1);
                self.handle_protected(dir, seq, header, payload, out);
            } else if header[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                buf.encrypted = true;
                buf.next_seq = 0;
            } else if header[0] == CONTENT_TYPE_HANDSHAKE {
                self.inspect_plaintext_handshake(dir, &payload);
            }
            if self.abandoned {
                return;
            }
        }
        let buf = self.dir_mut(dir);
        let consumed = pos.min(buf.raw.len());
        let _ = buf.raw.drain(..consumed);
    }

    fn inspect_plaintext_handshake(&mut self, dir: Direction, payload: &[u8]) {
        match dir {
            Direction::ClientToServer => {
                if self.client_random.is_none()
                    && payload.first() == Some(&HANDSHAKE_CLIENT_HELLO)
                    && let Some(rand) = payload.get(6..38)
                    && let Ok(rand) = <[u8; 32]>::try_from(rand)
                {
                    self.client_random = Some(rand);
                }
            }
            Direction::ServerToClient => {
                if self.server_random.is_none()
                    && let Some(hello) = ServerHello::parse(payload)
                {
                    self.server_random = Some(hello.random);
                    self.cipher_suite = Tls12CipherSuite::from_u16(hello.cipher_suite);
                    if self.cipher_suite.is_none() {
                        // CBC or another suite we cannot decrypt: never queue anything.
                        self.abandon();
                    }
                }
            }
        }
    }

    fn ensure_keys(&mut self, dir: Direction) -> bool {
        if self.dir_mut(dir).keys.is_some() {
            return true;
        }
        let (Some(client_random), Some(server_random), Some(suite)) =
            (self.client_random, self.server_random, self.cipher_suite)
        else {
            return false;
        };
        let Some(master_secret) = self
            .keylog
            .lookup_if_changed(&client_random, &mut self.last_keylog_miss)
            .and_then(|secrets| secrets.master_secret)
        else {
            return false;
        };
        let Some(block) = KeyBlock::derive(suite, &master_secret, &client_random, &server_random)
        else {
            return false;
        };
        self.c2s.keys = Some(block.client);
        self.s2c.keys = Some(block.server);
        true
    }

    fn handle_protected(
        &mut self,
        dir: Direction,
        seq: u64,
        header: [u8; 5],
        payload: Vec<u8>,
        out: &mut Vec<u8>,
    ) {
        let keys_ready = self.ensure_keys(dir);
        let buf = self.dir_mut(dir);
        let record = PendingRecord {
            seq,
            header,
            payload,
        };
        if keys_ready {
            buf.pending.push(record);
            buf.decrypt_pending(out);
            return;
        }
        // Keep the record with its sequence number so it decrypts once the keylog catches up.
        let bytes = buf.pending_bytes.saturating_add(record.payload.len());
        if buf.pending.len() >= MAX_PENDING_RECORDS || bytes > MAX_PENDING_CIPHERTEXT {
            // The keylog line is not coming in time; a gap would desync the HTTP stream anyway.
            self.abandon();
            return;
        }
        buf.pending_bytes = bytes;
        buf.pending.push(record);
    }

    /// Decrypts records of `dir` that were queued while the master secret was unavailable.
    ///
    /// Keys can become available while processing the *other* direction (for example the
    /// `ServerHello` or the keylog line arriving after the client already sent its request),
    /// so callers should flush the opposite direction after each feed.
    pub fn flush(&mut self, dir: Direction) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.dir_mut(dir).pending.is_empty() && self.ensure_keys(dir) {
            self.dir_mut(dir).decrypt_pending(&mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::tls::{PassiveTlsDecoder, Plaintext, TlsVersion};
    use waybound_core::CapturedResponse;

    use crate::{InflightCounter, PassiveConnectionTap};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect()
    }

    /// Published TLS 1.2 PRF test vector (SHA-256), 100 bytes of output.
    #[test]
    fn prf_sha256_known_answer() {
        let out = prf(
            PrfHash::Sha256,
            &hex("9bbe436ba940f017b17652849a71db35"),
            b"test label",
            &hex("a0ba9f936cda311827a6f796ffd5198c"),
            100,
        );
        let expected = hex(concat!(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a",
            "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab",
            "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701",
            "87347b66"
        ));
        assert_eq!(out, Some(expected));
    }

    /// Published TLS 1.2 PRF test vector (SHA-384), 148 bytes of output.
    #[test]
    fn prf_sha384_known_answer() {
        let out = prf(
            PrfHash::Sha384,
            &hex("b80b733d6ceefcdc71566ea48e5567df"),
            b"test label",
            &hex("cd665cf6a8447dd6ff8b27555edb7465"),
            148,
        );
        let expected = hex(concat!(
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd",
            "e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd",
            "8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425",
            "9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6",
            "91c8f3a26854308d5eaa3be85e0990703d73e56f"
        ));
        assert_eq!(out, Some(expected));
    }

    const CLIENT_RANDOM: [u8; 32] = [0x11; 32];
    const SERVER_RANDOM: [u8; 32] = [0x22; 32];

    fn master_secret() -> Vec<u8> {
        (0x30u8..0x60).collect()
    }

    /// Key material for [`master_secret`], [`CLIENT_RANDOM`], [`SERVER_RANDOM`], computed
    /// independently (Python `hmac` stdlib implementation of RFC 5246 §5/§6.3).
    struct ExpectedKeys {
        suite_id: u16,
        client_key: &'static str,
        server_key: &'static str,
        client_iv: &'static str,
        server_iv: &'static str,
    }

    const AES128: ExpectedKeys = ExpectedKeys {
        suite_id: 0xc02f,
        client_key: "d297e8f315ba5aa3bfd54449c1d6f35e",
        server_key: "7bcf5220f2bb57abfc850dbc3e810d7e",
        client_iv: "077677e7",
        server_iv: "51aeab4c",
    };
    const AES256: ExpectedKeys = ExpectedKeys {
        suite_id: 0xc02c,
        client_key: "2cc1f308a27ca44ac28fa1ce2a1b8faffe65aa7536e7edd34748a9c1ba1d16ab",
        server_key: "9bc7c4542df709016d6553b82b6a4884ff43a809682ce6638357241a635b225b",
        client_iv: "3c9435f0",
        server_iv: "d4f89ce4",
    };
    const CHACHA: ExpectedKeys = ExpectedKeys {
        suite_id: 0xcca8,
        client_key: "d297e8f315ba5aa3bfd54449c1d6f35e7bcf5220f2bb57abfc850dbc3e810d7e",
        server_key: "077677e751aeab4c030a7f236ac38c3d582ba9b2e455689f386d9182dc9a719b",
        client_iv: "536f9d36121feaac767eac1f",
        server_iv: "598b5beba0f45643e78eacb5",
    };

    #[test]
    fn key_block_matches_independent_derivation() {
        for exp in [AES128, AES256, CHACHA] {
            let suite = Tls12CipherSuite::from_u16(exp.suite_id);
            assert!(suite.is_some());
            let Some(suite) = suite else { return };
            let block = KeyBlock::derive(suite, &master_secret(), &CLIENT_RANDOM, &SERVER_RANDOM);
            assert!(block.is_some());
            let Some(block) = block else { return };
            assert_eq!(block.client.key, hex(exp.client_key));
            assert_eq!(block.server.key, hex(exp.server_key));
            assert_eq!(block.client.iv, hex(exp.client_iv));
            assert_eq!(block.server.iv, hex(exp.server_iv));
        }
        // Wrong-length master secret is rejected rather than silently used.
        assert!(
            KeyBlock::derive(
                Tls12CipherSuite::Aes128GcmSha256,
                &[0u8; 47],
                &CLIENT_RANDOM,
                &SERVER_RANDOM
            )
            .is_none()
        );
    }

    /// Independent TLS 1.2 AEAD record encryptor used only to build test ciphertext.
    fn seal_record(exp: &ExpectedKeys, client: bool, seq: u64, ct: u8, plain: &[u8]) -> Vec<u8> {
        let (key, iv) = if client {
            (hex(exp.client_key), hex(exp.client_iv))
        } else {
            (hex(exp.server_key), hex(exp.server_iv))
        };
        let mut aad = seq.to_be_bytes().to_vec();
        aad.extend_from_slice(&[ct, 0x03, 0x03]);
        aad.extend_from_slice(&u16::try_from(plain.len()).unwrap_or(0).to_be_bytes());
        let payload = Payload {
            msg: plain,
            aad: &aad,
        };
        let mut body = Vec::new();
        let sealed = if exp.suite_id == 0xcca8 {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&seq.to_be_bytes());
            for (n, v) in nonce.iter_mut().zip(&iv) {
                *n ^= v;
            }
            ChaCha20Poly1305::new_from_slice(&key)
                .ok()
                .and_then(|c| c.encrypt(Nonce::from_slice(&nonce), payload).ok())
        } else {
            // Explicit nonce deliberately unrelated to `seq` to prove it is read from the wire.
            let explicit = (seq ^ 0xa5a5_0000_0000_5a5a).to_be_bytes();
            body.extend_from_slice(&explicit);
            let mut nonce = iv;
            nonce.extend_from_slice(&explicit);
            let n = Nonce::from_slice(&nonce);
            if key.len() == 16 {
                Aes128Gcm::new_from_slice(&key)
                    .ok()
                    .and_then(|c| c.encrypt(n, payload).ok())
            } else {
                Aes256Gcm::new_from_slice(&key)
                    .ok()
                    .and_then(|c| c.encrypt(n, payload).ok())
            }
        };
        assert!(sealed.is_some());
        body.extend_from_slice(&sealed.unwrap_or_default());
        record(ct, &body)
    }

    fn record(ct: u8, body: &[u8]) -> Vec<u8> {
        let mut rec = vec![ct, 0x03, 0x03];
        rec.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
        rec.extend_from_slice(body);
        rec
    }

    fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
        let mut hs = vec![msg_type, len[1], len[2], len[3]];
        hs.extend_from_slice(body);
        hs
    }

    fn client_hello() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&CLIENT_RANDOM);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2f, 0xcc, 0xa8]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods
        record(
            CONTENT_TYPE_HANDSHAKE,
            &handshake(HANDSHAKE_CLIENT_HELLO, &body),
        )
    }

    /// `ServerHello` (no `supported_versions`) + a fake `Certificate` in the same record.
    fn server_hello(suite_id: u16) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&SERVER_RANDOM);
        body.push(32);
        body.extend_from_slice(&[0x5e; 32]); // session id
        body.extend_from_slice(&suite_id.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00]); // renegotiation_info
        let mut flight = handshake(2, &body);
        flight.extend_from_slice(&handshake(11, &[0u8; 40]));
        record(CONTENT_TYPE_HANDSHAKE, &flight)
    }

    const CCS: [u8; 6] = [
        CONTENT_TYPE_CHANGE_CIPHER_SPEC,
        0x03,
        0x03,
        0x00,
        0x01,
        0x01,
    ];
    const REQUEST: &[u8] = b"GET /legacy HTTP/1.1\r\nHost: old.example.com\r\n\r\n";
    const RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";

    /// Full synthetic client->server and server->client byte streams for one connection.
    fn transcript(exp: &ExpectedKeys) -> (Vec<u8>, Vec<u8>) {
        let finished = handshake(20, &[0x99; 12]);
        let mut c2s = client_hello();
        c2s.extend_from_slice(&record(CONTENT_TYPE_HANDSHAKE, &handshake(16, &[0x04; 33])));
        c2s.extend_from_slice(&CCS);
        c2s.extend_from_slice(&seal_record(
            exp,
            true,
            0,
            CONTENT_TYPE_HANDSHAKE,
            &finished,
        ));
        c2s.extend_from_slice(&seal_record(
            exp,
            true,
            1,
            CONTENT_TYPE_APPLICATION_DATA,
            REQUEST,
        ));

        let mut s2c = server_hello(exp.suite_id);
        s2c.extend_from_slice(&CCS);
        s2c.extend_from_slice(&seal_record(
            exp,
            false,
            0,
            CONTENT_TYPE_HANDSHAKE,
            &finished,
        ));
        let (head, tail) = RESPONSE.split_at(20);
        s2c.extend_from_slice(&seal_record(
            exp,
            false,
            1,
            CONTENT_TYPE_APPLICATION_DATA,
            head,
        ));
        s2c.extend_from_slice(&seal_record(
            exp,
            false,
            2,
            CONTENT_TYPE_APPLICATION_DATA,
            tail,
        ));
        // close_notify alert is protected too and must not leak into the plaintext.
        s2c.extend_from_slice(&seal_record(exp, false, 3, 21, &[1, 0]));
        (c2s, s2c)
    }

    fn keylog_with(master: Vec<u8>) -> KeyLogStore {
        let store = KeyLogStore::new("/nonexistent/test.keylog");
        store.insert_master_secret_for_test(CLIENT_RANDOM, master);
        store
    }

    #[test]
    fn decrypts_each_aead_suite_end_to_end() {
        for exp in [AES128, AES256, CHACHA] {
            let (c2s, s2c) = transcript(&exp);
            let mut dec = PassiveTlsDecoder::new(keylog_with(master_secret()));
            // No ServerHello yet, so nothing can be decrypted.
            assert_eq!(
                dec.feed(Direction::ClientToServer, &c2s),
                Plaintext::default()
            );
            // The ServerHello reveals TLS 1.2; buffered client bytes are replayed too.
            let plain = dec.feed(Direction::ServerToClient, &s2c);
            assert_eq!(dec.version(), Some(TlsVersion::Tls12));
            assert_eq!(plain.client_to_server, REQUEST);
            assert_eq!(plain.server_to_client, RESPONSE);
        }
    }

    #[test]
    fn decrypts_records_split_across_feed_boundaries() {
        for exp in [AES128, AES256, CHACHA] {
            let (c2s, s2c) = transcript(&exp);
            let mut dec = PassiveTlsDecoder::new(keylog_with(master_secret()));
            let mut client_out = Vec::new();
            let mut server_out = Vec::new();
            // Interleave small, odd-sized chunks from both directions.
            let mut c_chunks = c2s.chunks(7);
            let mut s_chunks = s2c.chunks(5);
            loop {
                let c = c_chunks.next();
                let s = s_chunks.next();
                if c.is_none() && s.is_none() {
                    break;
                }
                for (dir, chunk) in [
                    (Direction::ClientToServer, c),
                    (Direction::ServerToClient, s),
                ] {
                    if let Some(chunk) = chunk {
                        let plain = dec.feed(dir, chunk);
                        client_out.extend_from_slice(&plain.client_to_server);
                        server_out.extend_from_slice(&plain.server_to_client);
                    }
                }
            }
            assert_eq!(client_out, REQUEST);
            assert_eq!(server_out, RESPONSE);
        }
    }

    #[test]
    fn queues_records_until_keylog_entry_appears() {
        let (c2s, s2c) = transcript(&AES128);
        let store = KeyLogStore::new("/nonexistent/test.keylog");
        let mut dec = PassiveTls12Decoder::new(store.clone());
        assert_eq!(dec.feed(Direction::ClientToServer, &c2s), Vec::<u8>::new());
        let (early, late) = s2c.split_at(s2c.len() - 30);
        assert_eq!(dec.feed(Direction::ServerToClient, early), Vec::<u8>::new());
        // A repeated miss with an unchanged keylog does not search again.
        let miss = dec.last_keylog_miss;
        assert_ne!(miss, None);
        assert_eq!(dec.flush(Direction::ClientToServer), Vec::<u8>::new());
        assert_eq!(dec.last_keylog_miss, miss);

        store.insert_master_secret_for_test(CLIENT_RANDOM, master_secret());
        assert_eq!(dec.feed(Direction::ServerToClient, late), RESPONSE);
        // The client side still has its queued request; an explicit flush releases it.
        assert_eq!(dec.flush(Direction::ClientToServer), REQUEST);
        assert_eq!(dec.flush(Direction::ClientToServer), Vec::<u8>::new());
        // Later records keep the sequence numbering intact.
        let next = seal_record(&AES128, true, 2, CONTENT_TYPE_APPLICATION_DATA, b"!");
        assert_eq!(dec.feed(Direction::ClientToServer, &next), b"!");
    }

    #[test]
    fn queue_overflow_and_unsupported_suite_release_buffers() {
        let store = KeyLogStore::new("/nonexistent/test.keylog");
        let mut dec = PassiveTls12Decoder::new(store.clone());
        let _ = dec.feed(Direction::ClientToServer, &client_hello());
        let _ = dec.feed(Direction::ServerToClient, &server_hello(AES128.suite_id));
        let _ = dec.feed(Direction::ServerToClient, &CCS);
        for seq in 0..u64::try_from(MAX_PENDING_RECORDS).unwrap_or(0) {
            let rec = seal_record(&AES128, false, seq, CONTENT_TYPE_APPLICATION_DATA, b"x");
            assert_eq!(dec.feed(Direction::ServerToClient, &rec), Vec::<u8>::new());
        }
        assert_eq!(dec.s2c.pending.len(), MAX_PENDING_RECORDS);
        let rec = seal_record(&AES128, false, 32, CONTENT_TYPE_APPLICATION_DATA, b"x");
        assert_eq!(dec.feed(Direction::ServerToClient, &rec), Vec::<u8>::new());
        assert!(dec.abandoned);
        assert_eq!(dec.s2c.pending.len(), 0);
        assert_eq!(dec.s2c.raw.capacity(), 0);
        // Even once the key shows up, the gapped connection stays abandoned.
        store.insert_master_secret_for_test(CLIENT_RANDOM, master_secret());
        let rec = seal_record(&AES128, false, 33, CONTENT_TYPE_APPLICATION_DATA, b"y");
        assert_eq!(dec.feed(Direction::ServerToClient, &rec), Vec::<u8>::new());

        // A CBC ServerHello abandons immediately: nothing is queued afterwards.
        let mut dec = PassiveTls12Decoder::new(keylog_with(master_secret()));
        let _ = dec.feed(Direction::ClientToServer, &client_hello());
        let _ = dec.feed(Direction::ServerToClient, &server_hello(0xc013));
        assert!(dec.abandoned);
        let _ = dec.feed(Direction::ServerToClient, &CCS);
        assert_eq!(
            dec.feed(Direction::ServerToClient, &record(23, &[0u8; 64])),
            Vec::<u8>::new()
        );
        assert_eq!(dec.s2c.pending.len(), 0);
        assert_eq!(dec.s2c.raw.len(), 0);
    }

    #[test]
    fn wrong_key_and_garbage_do_not_panic() {
        let (c2s, s2c) = transcript(&CHACHA);
        let mut wrong = master_secret();
        wrong[0] ^= 1;
        let mut dec = PassiveTlsDecoder::new(keylog_with(wrong));
        assert_eq!(
            dec.feed(Direction::ClientToServer, &c2s),
            Plaintext::default()
        );
        assert_eq!(
            dec.feed(Direction::ServerToClient, &s2c),
            Plaintext::default()
        );

        // Protected records that are too short, oversized framing, and random bytes.
        for exp in [AES128, CHACHA] {
            let mut dec = PassiveTls12Decoder::new(keylog_with(master_secret()));
            let _ = dec.feed(Direction::ClientToServer, &client_hello());
            let _ = dec.feed(Direction::ServerToClient, &server_hello(exp.suite_id));
            let _ = dec.feed(Direction::ServerToClient, &CCS);
            for len in 0..40 {
                let body: Vec<u8> = (0..len).map(|i| u8::try_from(i).unwrap_or(0)).collect();
                assert_eq!(
                    dec.feed(Direction::ServerToClient, &record(23, &body)),
                    Vec::<u8>::new()
                );
            }
            assert_eq!(
                dec.feed(Direction::ServerToClient, &[23, 3, 3, 0xff, 0xff, 0]),
                Vec::<u8>::new()
            );
            let junk: Vec<u8> = (0u32..4096)
                .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).unwrap_or(0))
                .collect();
            assert_eq!(dec.feed(Direction::ClientToServer, &junk), Vec::<u8>::new());
        }
    }

    type Captured = Arc<Mutex<Vec<CapturedResponse>>>;

    fn tap_with(store: KeyLogStore) -> (PassiveConnectionTap, Captured, InflightCounter) {
        let captured: Captured = Arc::new(Mutex::new(Vec::new()));
        let cap_clone = Arc::clone(&captured);
        let inflight = InflightCounter::default();
        let tap = PassiveConnectionTap::new(
            "old.example.com".to_owned(),
            store,
            inflight.clone(),
            Arc::new(move |_, resp| {
                if let Ok(mut g) = cap_clone.lock() {
                    g.push(resp);
                }
            }),
        );
        (tap, captured, inflight)
    }

    fn assert_single_legacy_response(captured: &Captured, inflight: &InflightCounter) {
        let list = captured.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].url, "https://old.example.com/legacy");
        assert_eq!(list[0].status, 200);
        assert_eq!(list[0].body.as_deref(), Some("hello"));
        assert_eq!(inflight.get(), 0);
    }

    #[test]
    fn passive_tap_correlates_tls12_http_exchange() {
        let (tap, captured, inflight) = tap_with(keylog_with(master_secret()));
        let (c2s, s2c) = transcript(&AES256);
        tap.observe(Direction::ClientToServer, &c2s);
        // The request is replayed when the ServerHello reveals TLS 1.2 and must reach the
        // correlator before the response decrypted in the same call.
        tap.observe(Direction::ServerToClient, &s2c);
        assert_single_legacy_response(&captured, &inflight);
    }

    /// Regression: with the keylog line late, both directions are queued; whichever direction
    /// next delivers a record releases both queues, and the request must still go first.
    #[test]
    fn passive_tap_orders_request_first_when_keylog_arrives_late() {
        for trigger in [Direction::ClientToServer, Direction::ServerToClient] {
            let store = KeyLogStore::new("/nonexistent/test.keylog");
            let (tap, captured, inflight) = tap_with(store.clone());
            let (c2s, s2c) = transcript(&CHACHA);
            tap.observe(Direction::ClientToServer, &c2s);
            tap.observe(Direction::ServerToClient, &s2c);
            assert_eq!(captured.lock().map_or(1, |g| g.len()), 0);

            store.insert_master_secret_for_test(CLIENT_RANDOM, master_secret());
            // An encrypted alert carries no plaintext but releases the queued records.
            let alert = match trigger {
                Direction::ClientToServer => seal_record(&CHACHA, true, 2, 21, &[1, 0]),
                Direction::ServerToClient => seal_record(&CHACHA, false, 4, 21, &[1, 0]),
            };
            tap.observe(trigger, &alert);
            assert_single_legacy_response(&captured, &inflight);
        }
    }
}
