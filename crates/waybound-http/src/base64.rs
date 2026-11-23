//! Minimal, zero-dependency RFC 4648 standard Base64 encoder and decoder.
//!
//! Used by `waybound-http` and `waybound-daemon --replay` to transport arbitrary
//! binary HTTP request and response bodies losslessly over JSON-RPC.

use std::fmt;

const ENCODE_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Error returned when decoding an invalid RFC 4648 Base64 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base64DecodeError {
    /// Input length is not a multiple of 4.
    InvalidLength(usize),
    /// Input contains a byte outside the standard Base64 alphabet or misplaced padding.
    InvalidByte {
        /// Zero-based byte offset in the input string.
        offset: usize,
        /// The offending byte value.
        byte: u8,
    },
    /// Non-zero trailing bits in the final padded quantum.
    NonCanonicalPadding,
}

impl fmt::Display for Base64DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(f, "invalid base64 length {len}: must be a multiple of 4")
            }
            Self::InvalidByte { offset, byte } => {
                write!(f, "invalid base64 byte 0x{byte:02x} at offset {offset}")
            }
            Self::NonCanonicalPadding => write!(f, "non-zero trailing bits before base64 padding"),
        }
    }
}

impl std::error::Error for Base64DecodeError {}

const fn decode_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Encodes `input` into a standard RFC 4648 Base64 string with `=` padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let out_len = input.len().div_ceil(3).saturating_mul(4);
    let mut out = Vec::with_capacity(out_len);

    let (chunks, remainder) = input.as_chunks::<3>();
    for &[b0, b1, b2] in chunks {
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ENCODE_TABLE[((n >> 18) & 0x3f) as usize]);
        out.push(ENCODE_TABLE[((n >> 12) & 0x3f) as usize]);
        out.push(ENCODE_TABLE[((n >> 6) & 0x3f) as usize]);
        out.push(ENCODE_TABLE[(n & 0x3f) as usize]);
    }

    match remainder {
        [b0] => {
            let n = u32::from(*b0) << 16;
            out.push(ENCODE_TABLE[((n >> 18) & 0x3f) as usize]);
            out.push(ENCODE_TABLE[((n >> 12) & 0x3f) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        [b0, b1] => {
            let n = (u32::from(*b0) << 16) | (u32::from(*b1) << 8);
            out.push(ENCODE_TABLE[((n >> 18) & 0x3f) as usize]);
            out.push(ENCODE_TABLE[((n >> 12) & 0x3f) as usize]);
            out.push(ENCODE_TABLE[((n >> 6) & 0x3f) as usize]);
            out.push(b'=');
        }
        _ => {}
    }

    // All bytes pushed are ASCII from ENCODE_TABLE or b'='.
    String::from_utf8(out).unwrap_or_default()
}

/// Decodes a standard RFC 4648 Base64 string (with `=` padding) into raw bytes.
///
/// # Errors
///
/// Returns [`Base64DecodeError`] if `input` has an invalid length, contains
/// non-Base64 characters, has misplaced `=` padding, or has non-zero trailing
/// bits before padding.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64DecodeError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(Base64DecodeError::InvalidLength(bytes.len()));
    }

    let (chunks, _) = bytes.as_chunks::<4>();
    let total_chunks = chunks.len();
    let mut out = Vec::with_capacity(total_chunks * 3);

    for (chunk_idx, &[c0, c1, c2, c3]) in chunks.iter().enumerate() {
        let base_offset = chunk_idx * 4;
        let is_last = chunk_idx + 1 == total_chunks;

        let s0 = decode_sextet(c0).ok_or(Base64DecodeError::InvalidByte {
            offset: base_offset,
            byte: c0,
        })?;
        let s1 = decode_sextet(c1).ok_or(Base64DecodeError::InvalidByte {
            offset: base_offset + 1,
            byte: c1,
        })?;

        if c2 == b'=' {
            if !is_last || c3 != b'=' {
                return Err(Base64DecodeError::InvalidByte {
                    offset: base_offset + 2,
                    byte: c2,
                });
            }
            if (s1 & 0x0f) != 0 {
                return Err(Base64DecodeError::NonCanonicalPadding);
            }
            out.push((s0 << 2) | (s1 >> 4));
            continue;
        }

        let s2 = decode_sextet(c2).ok_or(Base64DecodeError::InvalidByte {
            offset: base_offset + 2,
            byte: c2,
        })?;

        if c3 == b'=' {
            if !is_last {
                return Err(Base64DecodeError::InvalidByte {
                    offset: base_offset + 3,
                    byte: c3,
                });
            }
            if (s2 & 0x03) != 0 {
                return Err(Base64DecodeError::NonCanonicalPadding);
            }
            out.push((s0 << 2) | (s1 >> 4));
            out.push((s1 << 4) | (s2 >> 2));
            continue;
        }

        let s3 = decode_sextet(c3).ok_or(Base64DecodeError::InvalidByte {
            offset: base_offset + 3,
            byte: c3,
        })?;

        out.push((s0 << 2) | (s1 >> 4));
        out.push((s1 << 4) | (s2 >> 2));
        out.push((s2 << 6) | s3);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_roundtrip() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];

        for &(raw, expected_b64) in vectors {
            assert_eq!(encode(raw), expected_b64);
            assert_eq!(decode(expected_b64), Ok(raw.to_vec()));
        }
    }

    #[test]
    fn all_256_bytes_roundtrip_losslessly() {
        let all_bytes: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = encode(&all_bytes);
        assert_eq!(decode(&encoded), Ok(all_bytes));
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert_eq!(decode("abc"), Err(Base64DecodeError::InvalidLength(3)));
        assert_eq!(
            decode("Zm9*"),
            Err(Base64DecodeError::InvalidByte {
                offset: 3,
                byte: b'*'
            })
        );
        // Padding in non-final chunk
        assert_eq!(
            decode("Zg==Zg=="),
            Err(Base64DecodeError::InvalidByte {
                offset: 2,
                byte: b'='
            })
        );
        // Non-canonical trailing bits
        assert_eq!(decode("Zh=="), Err(Base64DecodeError::NonCanonicalPadding));
        assert_eq!(decode("Zm9="), Err(Base64DecodeError::NonCanonicalPadding));
    }
}
