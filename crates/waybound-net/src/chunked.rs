//! Incremental HTTP/1.1 `Transfer-Encoding: chunked` decoder (RFC 9112 section 7.1).
//!
//! Consumes input as it arrives (so a body never has to sit in a buffer and be
//! re-parsed from the start), accepts chunk extensions, skips the trailer section up to
//! its terminating empty line, and retains at most a caller-chosen number of bytes.

/// Longest accepted chunk-size, CRLF or trailer line (bytes).
const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading a `chunk-size [; ext]` line.
    Size,
    /// Copying chunk data; the value is the number of bytes still expected.
    Data(usize),
    /// Expecting the CRLF that ends a chunk's data.
    DataEnd,
    /// Skipping trailer fields until the empty line.
    Trailer,
    /// The terminating empty line has been consumed.
    Done,
}

/// Result of feeding bytes into a [`ChunkedDecoder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkStatus {
    /// All input was consumed and more is needed.
    NeedMore,
    /// The body (including any trailer section) ended; later bytes belong to the next message.
    Done,
    /// The framing is malformed; the caller should stop treating bytes as this body.
    Invalid,
}

/// Incremental chunked-body decoder.
#[derive(Debug, Clone)]
pub struct ChunkedDecoder {
    phase: Phase,
    line: Vec<u8>,
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedDecoder {
    /// Creates a decoder positioned at the first chunk-size line.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: Phase::Size,
            line: Vec::new(),
        }
    }

    /// Decodes as much of `input` as possible, appending chunk data to `out` while
    /// `out` is shorter than `cap`. Returns the number of input bytes consumed and the
    /// resulting status; on [`ChunkStatus::Done`] the remaining input is not consumed.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>, cap: usize) -> (usize, ChunkStatus) {
        let mut pos = 0;
        loop {
            match self.phase {
                Phase::Done => return (pos, ChunkStatus::Done),
                Phase::Data(0) => self.phase = Phase::DataEnd,
                Phase::Data(remaining) => {
                    let avail = input.len() - pos;
                    if avail == 0 {
                        return (pos, ChunkStatus::NeedMore);
                    }
                    let take = remaining.min(avail);
                    let room = cap.saturating_sub(out.len()).min(take);
                    out.extend_from_slice(&input[pos..pos + room]);
                    pos += take;
                    self.phase = Phase::Data(remaining - take);
                }
                Phase::Size | Phase::DataEnd | Phase::Trailer => {
                    let rest = &input[pos..];
                    let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
                        if self.line.len() + rest.len() > MAX_CHUNK_LINE_BYTES {
                            return (input.len(), ChunkStatus::Invalid);
                        }
                        self.line.extend_from_slice(rest);
                        return (input.len(), ChunkStatus::NeedMore);
                    };
                    self.line.extend_from_slice(&rest[..nl]);
                    pos += nl + 1;
                    if self.line.len() > MAX_CHUNK_LINE_BYTES {
                        return (pos, ChunkStatus::Invalid);
                    }
                    let line = std::mem::take(&mut self.line);
                    let text = line.strip_suffix(b"\r").unwrap_or(&line);
                    if !self.accept_line(text) {
                        return (pos, ChunkStatus::Invalid);
                    }
                }
            }
        }
    }

    /// Applies one complete line (without its line ending) to the state machine.
    fn accept_line(&mut self, text: &[u8]) -> bool {
        match self.phase {
            Phase::Size => {
                let size_part = text.split(|&b| b == b';').next().unwrap_or(&[]);
                // Only hex digits: `from_str_radix` alone would also accept a leading `+`.
                let Some(size) = std::str::from_utf8(size_part)
                    .ok()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    .and_then(|s| usize::from_str_radix(s, 16).ok())
                else {
                    return false;
                };
                self.phase = if size == 0 {
                    Phase::Trailer
                } else {
                    Phase::Data(size)
                };
                true
            }
            Phase::DataEnd => {
                self.phase = Phase::Size;
                text.is_empty()
            }
            Phase::Trailer => {
                if text.is_empty() {
                    self.phase = Phase::Done;
                }
                true
            }
            Phase::Data(_) | Phase::Done => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(input: &[u8], cap: usize) -> (Vec<u8>, usize, ChunkStatus) {
        let mut out = Vec::new();
        let (used, status) = ChunkedDecoder::new().feed(input, &mut out, cap);
        (out, used, status)
    }

    #[test]
    fn decodes_with_extensions_and_trailers() {
        let input =
            b"4;name=val\r\nWiki\r\n5 ; x\r\npedia\r\n0\r\nX-Sum: 1\r\nX-Other: 2\r\n\r\nNEXT";
        let (out, used, status) = decode_all(input, usize::MAX);
        assert_eq!(status, ChunkStatus::Done);
        assert_eq!(out, b"Wikipedia");
        assert_eq!(&input[used..], b"NEXT");
    }

    #[test]
    fn split_at_every_point_gives_same_result() {
        let input = b"3\r\nabc\r\n10\r\n0123456789abcdef\r\n0\r\nT: 1\r\n\r\n";
        for cut in 0..=input.len() {
            let mut dec = ChunkedDecoder::new();
            let mut out = Vec::new();
            let (a, s1) = dec.feed(&input[..cut], &mut out, usize::MAX);
            if cut < input.len() {
                assert_eq!(s1, ChunkStatus::NeedMore, "cut {cut}");
                assert_eq!(a, cut);
            }
            let (b, s2) = dec.feed(&input[cut..], &mut out, usize::MAX);
            assert_eq!(s2, ChunkStatus::Done, "cut {cut}");
            assert_eq!(a + b, input.len());
            assert_eq!(out, b"abc0123456789abcdef");
        }
    }

    #[test]
    fn caps_retained_bytes_but_consumes_everything() {
        let input = b"a\r\n0123456789\r\n0\r\n\r\n";
        let (out, used, status) = decode_all(input, 4);
        assert_eq!(status, ChunkStatus::Done);
        assert_eq!(out, b"0123");
        assert_eq!(used, input.len());
    }

    #[test]
    fn rejects_malformed_framing() {
        assert_eq!(decode_all(b"zz\r\n", usize::MAX).2, ChunkStatus::Invalid);
        assert_eq!(
            decode_all(b"+5\r\nhello\r\n", usize::MAX).2,
            ChunkStatus::Invalid
        );
        assert_eq!(decode_all(b"\r\n", usize::MAX).2, ChunkStatus::Invalid);
        assert_eq!(
            decode_all(b"3\r\nabcX\r\n", usize::MAX).2,
            ChunkStatus::Invalid
        );
        let long = vec![b'1'; MAX_CHUNK_LINE_BYTES + 1];
        assert_eq!(decode_all(&long, usize::MAX).2, ChunkStatus::Invalid);
    }
}
