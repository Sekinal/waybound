//! Version-dispatching passive TLS decoder.
//!
//! Buffers both directions of a connection until the server's first handshake record
//! (the `ServerHello`) is complete, then picks [`PassiveTls13Decoder`] or
//! [`PassiveTls12Decoder`] and replays the buffered ciphertext into it. A TLS 1.3
//! `ServerHello` carries a `supported_versions` extension selecting `0x0304` (and always
//! negotiates a `0x13xx` cipher suite); a TLS 1.2 `ServerHello` does neither.

use crate::keylog::KeyLogStore;
use crate::tls12::PassiveTls12Decoder;
use crate::tls13::{Direction, PassiveTls13Decoder};

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
const VERSION_TLS13: u16 = 0x0304;
/// Maximum single TLS record payload size (RFC 8446 §5.2 allows up to 16384 + 256).
const MAX_TLS_RECORD_LEN: usize = 18_432;
/// Cap on ciphertext buffered per direction while the version is still unknown.
const MAX_DETECT_BUFFER: usize = 512 * 1024;

/// TLS protocol version negotiated on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2 (RFC 5246), decrypted with `CLIENT_RANDOM` master secrets.
    Tls12,
    /// TLS 1.3 (RFC 8446), decrypted with traffic secrets.
    Tls13,
}

/// Fields of a plaintext `ServerHello` handshake message relevant to passive decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerHello {
    pub(crate) random: [u8; 32],
    pub(crate) cipher_suite: u16,
    /// Version selected through the `supported_versions` extension, if present.
    pub(crate) selected_version: Option<u16>,
}

impl ServerHello {
    /// Parses a `ServerHello` from the start of a plaintext handshake record payload.
    pub(crate) fn parse(payload: &[u8]) -> Option<Self> {
        if *payload.first()? != HANDSHAKE_SERVER_HELLO {
            return None;
        }
        let msg_len = usize::from(*payload.get(1)?) << 16
            | usize::from(*payload.get(2)?) << 8
            | usize::from(*payload.get(3)?);
        let end = 4usize.saturating_add(msg_len).min(payload.len());
        let body = payload.get(4..end)?;

        // legacy_version (2) + random (32) + legacy_session_id_echo (1 + n)
        let random = <[u8; 32]>::try_from(body.get(2..34)?).ok()?;
        let sid_len = usize::from(*body.get(34)?);
        let cs_offset = 35usize.checked_add(sid_len)?;
        let cipher_suite = u16::from_be_bytes([*body.get(cs_offset)?, *body.get(cs_offset + 1)?]);
        // cipher_suite (2) + legacy_compression_method (1)
        let ext_offset = cs_offset.checked_add(3)?;
        let selected_version = body.get(ext_offset..).and_then(find_supported_version);
        Some(Self {
            random,
            cipher_suite,
            selected_version,
        })
    }

    /// Returns the protocol version this `ServerHello` negotiates.
    pub(crate) const fn version(&self) -> TlsVersion {
        let selects_tls13 = matches!(self.selected_version, Some(VERSION_TLS13));
        // TLS 1.3 cipher suites (0x1301..=0x1305) cannot be negotiated by TLS 1.2.
        if selects_tls13 || self.cipher_suite >> 8 == 0x13 {
            TlsVersion::Tls13
        } else {
            TlsVersion::Tls12
        }
    }
}

/// Scans a `ServerHello` extensions block (`u16` length + extensions) for `supported_versions`.
fn find_supported_version(block: &[u8]) -> Option<u16> {
    let total = usize::from(u16::from_be_bytes([*block.first()?, *block.get(1)?]));
    let mut exts = block.get(2..2usize.checked_add(total)?)?;
    while exts.len() >= 4 {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let ext_len = usize::from(u16::from_be_bytes([exts[2], exts[3]]));
        let data = exts.get(4..4usize.checked_add(ext_len)?)?;
        if ext_type == EXTENSION_SUPPORTED_VERSIONS && data.len() == 2 {
            return Some(u16::from_be_bytes([data[0], data[1]]));
        }
        exts = exts.get(4 + ext_len..)?;
    }
    None
}

/// Inspects the start of the server->client byte stream and decides the protocol version.
///
/// Returns `None` while the first record is still incomplete. Anything that is not a
/// parseable TLS 1.2 `ServerHello` falls back to the TLS 1.3 decoder.
fn detect_version(s2c: &[u8]) -> Option<TlsVersion> {
    let header = s2c.get(..5)?;
    if header[0] != CONTENT_TYPE_HANDSHAKE {
        return Some(TlsVersion::Tls13);
    }
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len > MAX_TLS_RECORD_LEN {
        return Some(TlsVersion::Tls13);
    }
    let payload = s2c.get(5..5 + len)?;
    Some(ServerHello::parse(payload).map_or(TlsVersion::Tls13, |hello| hello.version()))
}

#[derive(Debug)]
enum DecoderState {
    Detecting { c2s: Vec<u8>, s2c: Vec<u8> },
    Tls12(Box<PassiveTls12Decoder>),
    Tls13(Box<PassiveTls13Decoder>),
}

/// Passive bidirectional TLS 1.2 / 1.3 decryptor for a single TCP connection.
#[derive(Debug)]
pub struct PassiveTlsDecoder {
    keylog: KeyLogStore,
    state: DecoderState,
    /// Plaintext produced for the opposite direction while replaying buffered bytes.
    carry_c2s: Vec<u8>,
    carry_s2c: Vec<u8>,
}

impl PassiveTlsDecoder {
    /// Creates a new version-dispatching passive decoder using `keylog` for secret lookups.
    #[must_use]
    pub const fn new(keylog: KeyLogStore) -> Self {
        Self {
            keylog,
            state: DecoderState::Detecting {
                c2s: Vec::new(),
                s2c: Vec::new(),
            },
            carry_c2s: Vec::new(),
            carry_s2c: Vec::new(),
        }
    }

    /// Returns the negotiated protocol version once the `ServerHello` has been observed.
    #[must_use]
    pub const fn version(&self) -> Option<TlsVersion> {
        match self.state {
            DecoderState::Detecting { .. } => None,
            DecoderState::Tls12(_) => Some(TlsVersion::Tls12),
            DecoderState::Tls13(_) => Some(TlsVersion::Tls13),
        }
    }

    /// Takes plaintext for `dir` that was decrypted while replaying buffered ciphertext
    /// during a [`Self::feed`] call for the opposite direction.
    ///
    /// [`Self::feed`] also returns this data on the next call for `dir`; callers that
    /// care about cross-direction ordering (request before response) drain it right after
    /// each feed.
    pub fn take_carried(&mut self, dir: Direction) -> Vec<u8> {
        std::mem::take(match dir {
            Direction::ClientToServer => &mut self.carry_c2s,
            Direction::ServerToClient => &mut self.carry_s2c,
        })
    }

    /// Feeds raw ciphertext bytes for `dir` and returns any decrypted application-data plaintext.
    pub fn feed(&mut self, dir: Direction, data: &[u8]) -> Vec<u8> {
        let mut out = self.take_carried(dir);
        let detected = match &mut self.state {
            DecoderState::Tls12(dec) => {
                out.extend_from_slice(&dec.feed(dir, data));
                // Keys may have just become available for records queued on the other side.
                let flushed = dec.flush(dir.opposite());
                match dir {
                    Direction::ClientToServer => self.carry_s2c.extend_from_slice(&flushed),
                    Direction::ServerToClient => self.carry_c2s.extend_from_slice(&flushed),
                }
                return out;
            }
            DecoderState::Tls13(dec) => {
                out.extend_from_slice(&dec.feed(dir, data));
                return out;
            }
            DecoderState::Detecting { c2s, s2c } => {
                let buf = match dir {
                    Direction::ClientToServer => &mut *c2s,
                    Direction::ServerToClient => &mut *s2c,
                };
                if buf.len().saturating_add(data.len()) > MAX_DETECT_BUFFER {
                    // Not TLS (or a ServerHello that never completes); stay bounded.
                    buf.clear();
                    return out;
                }
                buf.extend_from_slice(data);
                detect_version(s2c)
            }
        };
        if let Some(version) = detected {
            self.switch_to(version, dir, &mut out);
        }
        out
    }

    fn switch_to(&mut self, version: TlsVersion, dir: Direction, out: &mut Vec<u8>) {
        let placeholder = DecoderState::Detecting {
            c2s: Vec::new(),
            s2c: Vec::new(),
        };
        let DecoderState::Detecting { c2s, s2c } = std::mem::replace(&mut self.state, placeholder)
        else {
            return;
        };
        let keylog = self.keylog.clone();
        // Replay the client side first so `client_random` is known before the ServerHello.
        let (plain_c2s, plain_s2c) = match version {
            TlsVersion::Tls12 => {
                let mut dec = Box::new(PassiveTls12Decoder::new(keylog));
                let mut c = dec.feed(Direction::ClientToServer, &c2s);
                let s = dec.feed(Direction::ServerToClient, &s2c);
                // Client records queued before the ServerHello supplied `server_random`.
                c.extend_from_slice(&dec.flush(Direction::ClientToServer));
                self.state = DecoderState::Tls12(dec);
                (c, s)
            }
            TlsVersion::Tls13 => {
                let mut dec = Box::new(PassiveTls13Decoder::new(keylog));
                let c = dec.feed(Direction::ClientToServer, &c2s);
                let s = dec.feed(Direction::ServerToClient, &s2c);
                self.state = DecoderState::Tls13(dec);
                (c, s)
            }
        };
        let (same, other, other_carry) = match dir {
            Direction::ClientToServer => (plain_c2s, plain_s2c, &mut self.carry_s2c),
            Direction::ServerToClient => (plain_s2c, plain_c2s, &mut self.carry_c2s),
        };
        out.extend_from_slice(&same);
        other_carry.extend_from_slice(&other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello_record(suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x77u8; 32]);
        body.push(0); // session id length
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0); // compression
        if !extensions.is_empty() {
            body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
            body.extend_from_slice(extensions);
        }
        let mut hs = vec![HANDSHAKE_SERVER_HELLO, 0];
        hs.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x03];
        rec.extend_from_slice(&u16::try_from(hs.len()).unwrap_or(0).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn detects_tls13_from_supported_versions_and_tls12_without_it() {
        // renegotiation_info (empty) + supported_versions = 0x0304
        let tls13_ext = [
            0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        ];
        let rec13 = server_hello_record(0x1301, &tls13_ext);
        assert_eq!(detect_version(&rec13), Some(TlsVersion::Tls13));

        let rec12 = server_hello_record(0xc02f, &[0xff, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(detect_version(&rec12), Some(TlsVersion::Tls12));
        let parsed = ServerHello::parse(&rec12[5..]);
        assert_eq!(
            parsed,
            Some(ServerHello {
                random: [0x77; 32],
                cipher_suite: 0xc02f,
                selected_version: None,
            })
        );

        // A 1.3 suite without extensions (as in minimal synthetic hellos) still means 1.3.
        let bare13 = server_hello_record(0x1302, &[]);
        assert_eq!(detect_version(&bare13), Some(TlsVersion::Tls13));

        // Incomplete record: wait for more bytes.
        assert_eq!(detect_version(&rec12[..rec12.len() - 1]), None);
        // Non-handshake first record: legacy TLS 1.3 path.
        assert_eq!(
            detect_version(&[23, 3, 3, 0, 1, 0]),
            Some(TlsVersion::Tls13)
        );
    }

    #[test]
    fn dispatcher_waits_for_server_hello_then_selects_version() {
        let store = KeyLogStore::new("/nonexistent/test.keylog");
        let mut dec = PassiveTlsDecoder::new(store);
        let rec12 = server_hello_record(0xc02b, &[]);
        let (first, rest) = rec12.split_at(10);
        assert!(dec.feed(Direction::ServerToClient, first).is_empty());
        assert_eq!(dec.version(), None);
        assert!(dec.feed(Direction::ServerToClient, rest).is_empty());
        assert_eq!(dec.version(), Some(TlsVersion::Tls12));
    }

    #[test]
    fn garbage_server_hello_does_not_panic() {
        for len in 0..48 {
            let junk: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 37 % 251).unwrap_or(0))
                .collect();
            let _ = ServerHello::parse(&junk);
            let mut with_type = vec![HANDSHAKE_SERVER_HELLO, 0xff, 0xff, 0xff];
            with_type.extend_from_slice(&junk);
            let _ = ServerHello::parse(&with_type);
        }
        let _ = find_supported_version(&[0x00, 0x08, 0x00, 0x2b, 0xff, 0xff]);
    }
}
