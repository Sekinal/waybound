//! Passive RFC 6455 WebSocket frame parser with RFC 7692 `permessage-deflate` support.
//!
//! Fed with decrypted bytes of an HTTP/1.1 connection after a `101 Switching Protocols`
//! upgrade, one [`WebSocketStream`] per direction. Frames are parsed incrementally, so a
//! frame may be split across any number of feeds and large payloads never need to be
//! buffered in full: only up to [`MAX_WS_PAYLOAD_BYTES`] of each message is retained.
//!
//! Compressed messages (RSV1 set) are inflated with a per-direction raw-DEFLATE
//! decompressor whose sliding window persists across messages (context takeover), unless
//! the server negotiated `*_no_context_takeover` for that direction.

use flate2::{Decompress, FlushDecompress, Status};
use waybound_core::{CapturedWebSocketFrame, WebSocketDirection, WebSocketOpcode};

use crate::http::decode_body_bytes;

/// Maximum retained (unmasked, decompressed) payload bytes per WebSocket message (256 KiB).
pub const MAX_WS_PAYLOAD_BYTES: usize = 256 * 1024;

/// Trailer removed by the sender from every compressed message (RFC 7692 section 7.2.1).
const DEFLATE_TRAILER: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Largest legal control-frame payload (RFC 6455 section 5.5).
const MAX_CONTROL_PAYLOAD: u64 = 125;

/// `permessage-deflate` parameters negotiated in the server's `Sec-WebSocket-Extensions`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerMessageDeflate {
    /// The client resets its compression context after every message.
    pub client_no_context_takeover: bool,
    /// The server resets its compression context after every message.
    pub server_no_context_takeover: bool,
}

impl PerMessageDeflate {
    /// Parses the server's `Sec-WebSocket-Extensions` response header values and returns
    /// the accepted `permessage-deflate` parameters, if that extension was accepted.
    #[must_use]
    pub fn from_extension_headers<'a, I>(values: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a str>,
    {
        for value in values {
            for ext in value.split(',') {
                let mut parts = ext.split(';').map(str::trim);
                if !parts
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("permessage-deflate"))
                {
                    continue;
                }
                let mut cfg = Self::default();
                for param in parts {
                    let key = param.split('=').next().unwrap_or("").trim();
                    if key.eq_ignore_ascii_case("client_no_context_takeover") {
                        cfg.client_no_context_takeover = true;
                    } else if key.eq_ignore_ascii_case("server_no_context_takeover") {
                        cfg.server_no_context_takeover = true;
                    }
                }
                return Some(cfg);
            }
        }
        None
    }
}

/// Raw-DEFLATE inflater for one direction of a `permessage-deflate` connection.
struct Inflater {
    inner: Decompress,
    /// Reset the window after every message (`*_no_context_takeover`).
    reset_after_message: bool,
    /// Set once inflation fails; later messages depend on the lost window and are undecodable.
    failed: bool,
}

impl Inflater {
    fn new(reset_after_message: bool) -> Self {
        Self {
            inner: Decompress::new(false),
            reset_after_message,
            failed: false,
        }
    }

    /// Inflates `input`, handing every produced chunk to `sink`. Returns `false` on error.
    fn inflate(&mut self, mut input: &[u8], sink: &mut MessageBuffer) -> bool {
        if self.failed {
            return false;
        }
        let mut out = vec![0_u8; 16 * 1024];
        loop {
            let in_before = self.inner.total_in();
            let out_before = self.inner.total_out();
            let Ok(status) = self
                .inner
                .decompress(input, &mut out, FlushDecompress::Sync)
            else {
                self.failed = true;
                return false;
            };
            let consumed =
                usize::try_from(self.inner.total_in().saturating_sub(in_before)).unwrap_or(0);
            let produced =
                usize::try_from(self.inner.total_out().saturating_sub(out_before)).unwrap_or(0);
            sink.push(out.get(..produced).unwrap_or(&[]));
            input = input.get(consumed..).unwrap_or(&[]);
            if status == Status::StreamEnd {
                // A final DEFLATE block ends this stream; the next message starts a new one.
                self.inner.reset(false);
                return true;
            }
            if (input.is_empty() && produced < out.len()) || (consumed == 0 && produced == 0) {
                return true;
            }
        }
    }

    fn end_message(&mut self) {
        if self.reset_after_message {
            self.inner.reset(false);
            self.failed = false;
        }
    }
}

/// Bounded accumulator for one (possibly fragmented, possibly compressed) message.
#[derive(Default)]
struct MessageBuffer {
    data: Vec<u8>,
    total_len: u64,
    truncated: bool,
}

impl MessageBuffer {
    fn push(&mut self, chunk: &[u8]) {
        self.total_len = self
            .total_len
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let room = MAX_WS_PAYLOAD_BYTES.saturating_sub(self.data.len());
        if chunk.len() > room {
            self.truncated = true;
        }
        self.data
            .extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or(&[]));
    }
}

struct PendingMessage {
    opcode: WebSocketOpcode,
    compressed: bool,
    undecodable: bool,
    buf: MessageBuffer,
}

struct FrameHeader {
    fin: bool,
    rsv1: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    remaining: u64,
    /// Payload bytes already consumed (for the rolling mask index).
    offset: u64,
}

/// Incremental parser for one direction of a WebSocket connection.
pub struct WebSocketStream {
    url: String,
    direction: WebSocketDirection,
    inflater: Option<Inflater>,
    header_buf: Vec<u8>,
    frame: Option<FrameHeader>,
    control: Vec<u8>,
    message: Option<PendingMessage>,
    /// Set on a protocol violation; the rest of this direction is ignored.
    broken: bool,
}

impl std::fmt::Debug for WebSocketStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketStream")
            .field("url", &self.url)
            .field("direction", &self.direction)
            .field("deflate", &self.inflater.is_some())
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

impl WebSocketStream {
    /// Creates a parser for `direction` of the WebSocket at `url`, with the negotiated
    /// `permessage-deflate` parameters if the extension was accepted.
    #[must_use]
    pub fn new(
        url: String,
        direction: WebSocketDirection,
        deflate: Option<PerMessageDeflate>,
    ) -> Self {
        let inflater = deflate.map(|cfg| {
            Inflater::new(match direction {
                WebSocketDirection::Sent => cfg.client_no_context_takeover,
                WebSocketDirection::Received => cfg.server_no_context_takeover,
            })
        });
        Self {
            url,
            direction,
            inflater,
            header_buf: Vec::with_capacity(14),
            frame: None,
            control: Vec::new(),
            message: None,
            broken: false,
        }
    }

    /// Feeds decrypted bytes for this direction, appending every completed message to `out`.
    pub fn feed(&mut self, mut data: &[u8], out: &mut Vec<CapturedWebSocketFrame>) {
        while !data.is_empty() && !self.broken {
            if self.frame.is_none() {
                data = self.fill_header(data);
                if self.frame.is_none() {
                    return;
                }
            }
            data = self.consume_payload(data);
            if self.frame.as_ref().is_some_and(|f| f.remaining == 0) {
                self.finish_frame(out);
            }
        }
    }

    /// Copies header bytes from `data` until a full frame header is available.
    fn fill_header<'a>(&mut self, mut data: &'a [u8]) -> &'a [u8] {
        loop {
            let need = header_len(&self.header_buf);
            if self.header_buf.len() >= need {
                break;
            }
            if data.is_empty() {
                return data;
            }
            let take = (need - self.header_buf.len()).min(data.len());
            self.header_buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        let parsed = parse_header(&self.header_buf);
        self.header_buf.clear();
        match parsed {
            Some(frame) if self.accept_frame(&frame) => self.frame = Some(frame),
            _ => self.broken = true,
        }
        data
    }

    /// Validates a new frame against the message state and starts a data message if needed.
    fn accept_frame(&mut self, frame: &FrameHeader) -> bool {
        match frame.opcode {
            OP_CLOSE | OP_PING | OP_PONG => {
                self.control.clear();
                // A close payload is empty or starts with a 2-byte status code (section 5.5.1).
                let close_ok = frame.opcode != OP_CLOSE || frame.remaining != 1;
                frame.fin && frame.remaining <= MAX_CONTROL_PAYLOAD && close_ok
            }
            OP_TEXT | OP_BINARY => {
                if self.message.is_some() {
                    return false;
                }
                let opcode = if frame.opcode == OP_TEXT {
                    WebSocketOpcode::Text
                } else {
                    WebSocketOpcode::Binary
                };
                self.message = Some(PendingMessage {
                    opcode,
                    compressed: frame.rsv1,
                    undecodable: frame.rsv1 && self.inflater.as_ref().is_none_or(|inf| inf.failed),
                    buf: MessageBuffer::default(),
                });
                true
            }
            OP_CONTINUATION => self.message.is_some(),
            _ => false,
        }
    }

    fn consume_payload<'a>(&mut self, data: &'a [u8]) -> &'a [u8] {
        let Some(frame) = self.frame.as_mut() else {
            return data;
        };
        let take = usize::try_from(frame.remaining)
            .unwrap_or(usize::MAX)
            .min(data.len());
        if take == 0 {
            return data;
        }
        let mut chunk = data[..take].to_vec();
        if let Some(mask) = frame.mask {
            // Only the low two bits of the offset select the mask byte.
            let start = usize::try_from(frame.offset % 4).unwrap_or(0);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= mask[(start + i) % 4];
            }
        }
        let advanced = u64::try_from(take).unwrap_or(u64::MAX);
        frame.remaining = frame.remaining.saturating_sub(advanced);
        frame.offset = frame.offset.wrapping_add(advanced);
        let is_control = frame.opcode >= OP_CLOSE;

        if is_control {
            self.control.extend_from_slice(&chunk);
        } else if let Some(msg) = self.message.as_mut() {
            if !msg.compressed {
                msg.buf.push(&chunk);
            } else if !msg.undecodable {
                let ok = self
                    .inflater
                    .as_mut()
                    .is_some_and(|inf| inf.inflate(&chunk, &mut msg.buf));
                if !ok {
                    msg.undecodable = true;
                }
            }
        }
        &data[take..]
    }

    fn finish_frame(&mut self, out: &mut Vec<CapturedWebSocketFrame>) {
        let Some(frame) = self.frame.take() else {
            return;
        };
        if frame.opcode >= OP_CLOSE {
            let control = std::mem::take(&mut self.control);
            out.push(self.control_frame(frame.opcode, &control));
            return;
        }
        if !frame.fin {
            return;
        }
        let Some(mut msg) = self.message.take() else {
            return;
        };
        if msg.compressed {
            if !msg.undecodable {
                let ok = self
                    .inflater
                    .as_mut()
                    .is_some_and(|inf| inf.inflate(&DEFLATE_TRAILER, &mut msg.buf));
                if !ok {
                    msg.undecodable = true;
                }
            }
            if let Some(inf) = self.inflater.as_mut() {
                inf.end_message();
            }
        }
        // Binary payloads are not text: a UTF-8 prefix of them would be misleading.
        let payload = if msg.undecodable || msg.opcode == WebSocketOpcode::Binary {
            None
        } else {
            decode_body_bytes(&msg.buf.data, None)
        };
        out.push(CapturedWebSocketFrame {
            url: self.url.clone(),
            direction: self.direction,
            opcode: msg.opcode,
            payload,
            payload_len: if msg.undecodable {
                0
            } else {
                msg.buf.total_len
            },
            compressed: msg.compressed,
            truncated: msg.buf.truncated,
            close_code: None,
        });
    }

    fn control_frame(&self, opcode: u8, payload: &[u8]) -> CapturedWebSocketFrame {
        let (opcode, close_code, text) = match opcode {
            OP_CLOSE => {
                let code = payload.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
                (
                    WebSocketOpcode::Close,
                    code,
                    payload.get(2..).unwrap_or(&[]),
                )
            }
            OP_PING => (WebSocketOpcode::Ping, None, payload),
            _ => (WebSocketOpcode::Pong, None, payload),
        };
        CapturedWebSocketFrame {
            url: self.url.clone(),
            direction: self.direction,
            opcode,
            payload: decode_body_bytes(text, None),
            payload_len: u64::try_from(payload.len()).unwrap_or(0),
            compressed: false,
            truncated: false,
            close_code,
        }
    }
}

/// Number of header bytes required given the bytes seen so far (2 to 14).
fn header_len(seen: &[u8]) -> usize {
    let Some(&b1) = seen.get(1) else {
        return 2;
    };
    let ext = match b1 & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask = if b1 & 0x80 != 0 { 4 } else { 0 };
    2 + ext + mask
}

fn parse_header(h: &[u8]) -> Option<FrameHeader> {
    let (&b0, &b1) = (h.first()?, h.get(1)?);
    let (len, pos) = match b1 & 0x7f {
        126 => (u64::from(u16::from_be_bytes([*h.get(2)?, *h.get(3)?])), 4),
        127 => {
            let bytes: [u8; 8] = h.get(2..10)?.try_into().ok()?;
            let len = u64::from_be_bytes(bytes);
            if len >> 63 != 0 {
                return None;
            }
            (len, 10)
        }
        n => (u64::from(n), 2),
    };
    let mask = if b1 & 0x80 == 0 {
        None
    } else {
        let key: [u8; 4] = h.get(pos..pos + 4)?.try_into().ok()?;
        Some(key)
    };
    Some(FrameHeader {
        fin: b0 & 0x80 != 0,
        rsv1: b0 & 0x40 != 0,
        opcode: b0 & 0x0f,
        mask,
        remaining: len,
        offset: 0,
    })
}

#[cfg(test)]
mod tests {
    use flate2::{Compress, Compression, FlushCompress};

    use super::*;

    const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    fn frame(fin: bool, rsv1: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        let len = payload.len();
        if len < 126 {
            out.push(mask_bit | u8::try_from(len).unwrap_or(0));
        } else if let Ok(short) = u16::try_from(len) {
            out.push(mask_bit | 0x7e);
            out.extend_from_slice(&short.to_be_bytes());
        } else {
            out.push(mask_bit | 0x7f);
            out.extend_from_slice(&u64::try_from(len).unwrap_or(0).to_be_bytes());
        }
        if let Some(key) = mask {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    fn stream(
        direction: WebSocketDirection,
        deflate: Option<PerMessageDeflate>,
    ) -> WebSocketStream {
        WebSocketStream::new("wss://chat.test/ws".to_owned(), direction, deflate)
    }

    fn feed_all(s: &mut WebSocketStream, bytes: &[u8]) -> Vec<CapturedWebSocketFrame> {
        let mut out = Vec::new();
        s.feed(bytes, &mut out);
        out
    }

    fn deflate_message(c: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 128);
        assert!(c.compress_vec(data, &mut out, FlushCompress::Sync).is_ok());
        assert!(out.ends_with(&DEFLATE_TRAILER));
        out.truncate(out.len() - DEFLATE_TRAILER.len());
        out
    }

    #[test]
    fn unmasks_client_text_frame() {
        let mut s = stream(WebSocketDirection::Sent, None);
        let got = feed_all(&mut s, &frame(true, false, OP_TEXT, Some(MASK), b"Hello"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].direction, WebSocketDirection::Sent);
        assert_eq!(got[0].opcode, WebSocketOpcode::Text);
        assert_eq!(got[0].payload.as_deref(), Some("Hello"));
        assert_eq!(got[0].payload_len, 5);
        assert!(!got[0].compressed);
    }

    #[test]
    fn parses_unmasked_server_text_frame() {
        let mut s = stream(WebSocketDirection::Received, None);
        let got = feed_all(&mut s, &frame(true, false, OP_TEXT, None, b"{\"op\":1}"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].direction, WebSocketDirection::Received);
        assert_eq!(got[0].payload.as_deref(), Some("{\"op\":1}"));
    }

    #[test]
    fn reassembles_fragmented_message_with_interleaved_ping() {
        let mut s = stream(WebSocketDirection::Sent, None);
        let mut bytes = frame(false, false, OP_TEXT, Some(MASK), b"Hel");
        bytes.extend(frame(true, false, OP_PING, Some(MASK), b"p"));
        bytes.extend(frame(false, false, OP_CONTINUATION, Some(MASK), b"lo, "));
        bytes.extend(frame(true, false, OP_CONTINUATION, Some(MASK), b"world"));
        let got = feed_all(&mut s, &bytes);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].opcode, WebSocketOpcode::Ping);
        assert_eq!(got[0].payload.as_deref(), Some("p"));
        assert_eq!(got[1].opcode, WebSocketOpcode::Text);
        assert_eq!(got[1].payload.as_deref(), Some("Hello, world"));
        assert_eq!(got[1].payload_len, 12);
    }

    #[test]
    fn handles_16_bit_and_64_bit_lengths() {
        let medium = "a".repeat(300);
        let large = "b".repeat(70_000);
        let mut s = stream(WebSocketDirection::Received, None);
        let mut bytes = frame(true, false, OP_TEXT, None, medium.as_bytes());
        assert_eq!(bytes[1], 126);
        let big = frame(true, false, OP_BINARY, None, large.as_bytes());
        assert_eq!(big[1], 127);
        bytes.extend(big);
        let got = feed_all(&mut s, &bytes);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].payload.as_deref(), Some(medium.as_str()));
        assert_eq!(got[1].opcode, WebSocketOpcode::Binary);
        assert_eq!(got[1].payload_len, 70_000);
        // Binary messages report their size but no text payload.
        assert_eq!(got[1].payload, None);

        let mut masked = stream(WebSocketDirection::Sent, None);
        let got = feed_all(
            &mut masked,
            &frame(true, false, OP_TEXT, Some(MASK), large.as_bytes()),
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload.as_deref(), Some(large.as_str()));
    }

    #[test]
    fn caps_retained_payload_and_flags_truncation() {
        let huge = vec![b'x'; MAX_WS_PAYLOAD_BYTES + 10];
        let mut s = stream(WebSocketDirection::Received, None);
        let got = feed_all(&mut s, &frame(true, false, OP_TEXT, None, &huge));
        assert_eq!(got.len(), 1);
        assert!(got[0].truncated);
        assert_eq!(got[0].payload_len, u64::try_from(huge.len()).unwrap_or(0));
        assert_eq!(
            got[0].payload.as_ref().map(String::len),
            Some(MAX_WS_PAYLOAD_BYTES)
        );
    }

    #[test]
    fn parses_ping_pong_and_close_frames() {
        let mut s = stream(WebSocketDirection::Received, None);
        let mut bytes = frame(true, false, OP_PING, None, b"");
        bytes.extend(frame(true, false, OP_PONG, None, b"hb"));
        let mut close = 1000_u16.to_be_bytes().to_vec();
        close.extend_from_slice(b"bye");
        bytes.extend(frame(true, false, OP_CLOSE, None, &close));
        let got = feed_all(&mut s, &bytes);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].opcode, WebSocketOpcode::Ping);
        assert_eq!(got[0].payload, None);
        assert_eq!(got[1].opcode, WebSocketOpcode::Pong);
        assert_eq!(got[1].payload.as_deref(), Some("hb"));
        assert_eq!(got[2].opcode, WebSocketOpcode::Close);
        assert_eq!(got[2].close_code, Some(1000));
        assert_eq!(got[2].payload.as_deref(), Some("bye"));
    }

    #[test]
    fn reassembles_frames_split_across_feeds() {
        let mut bytes = frame(true, false, OP_TEXT, Some(MASK), b"split payload");
        bytes.extend(frame(true, false, OP_TEXT, Some(MASK), &[b'z'; 200]));
        // Every split point, including inside the header and the extended length.
        for cut in 1..bytes.len() {
            let mut s = stream(WebSocketDirection::Sent, None);
            let mut got = feed_all(&mut s, &bytes[..cut]);
            got.extend(feed_all(&mut s, &bytes[cut..]));
            assert_eq!(got.len(), 2, "cut at {cut}");
            assert_eq!(got[0].payload.as_deref(), Some("split payload"));
            assert_eq!(got[1].payload_len, 200);
        }
        // Byte-by-byte.
        let mut s = stream(WebSocketDirection::Sent, None);
        let mut got = Vec::new();
        for b in &bytes {
            s.feed(std::slice::from_ref(b), &mut got);
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].payload.as_deref(), Some("split payload"));
    }

    #[test]
    fn inflates_permessage_deflate_with_context_takeover() {
        let deflate = PerMessageDeflate::from_extension_headers([
            "permessage-deflate; client_max_window_bits",
        ]);
        assert_eq!(deflate, Some(PerMessageDeflate::default()));
        let mut c = Compress::new(Compression::default(), false);
        let msg = r#"{"type":"price","symbol":"ABC","bid":101.25}"#;
        let first = deflate_message(&mut c, msg.as_bytes());
        // The second identical message is encoded as a back-reference into the first one,
        // so it only decodes with the window retained from the previous message.
        let second = deflate_message(&mut c, msg.as_bytes());
        assert!(second.len() < first.len());

        let mut s = stream(WebSocketDirection::Received, deflate);
        let mut bytes = frame(true, true, OP_TEXT, None, &first);
        // Second message is fragmented: RSV1 only on the first fragment.
        let (a, b) = second.split_at(second.len() / 2);
        bytes.extend(frame(false, true, OP_TEXT, None, a));
        bytes.extend(frame(true, false, OP_CONTINUATION, None, b));
        let got = feed_all(&mut s, &bytes);
        assert_eq!(got.len(), 2);
        for item in &got {
            assert!(item.compressed);
            assert_eq!(item.payload.as_deref(), Some(msg));
            assert_eq!(item.payload_len, u64::try_from(msg.len()).unwrap_or(0));
        }
    }

    #[test]
    fn inflates_masked_client_messages_without_context_takeover() {
        let deflate = PerMessageDeflate::from_extension_headers([
            "x-other, permessage-deflate; client_no_context_takeover; server_max_window_bits=10",
        ]);
        assert_eq!(
            deflate,
            Some(PerMessageDeflate {
                client_no_context_takeover: true,
                server_no_context_takeover: false,
            })
        );
        let mut s = stream(WebSocketDirection::Sent, deflate);
        let mut got = Vec::new();
        for text in ["hello hello hello", "second message"] {
            // A fresh compressor per message, as no_context_takeover requires.
            let mut c = Compress::new(Compression::default(), false);
            s.feed(
                &frame(
                    true,
                    true,
                    OP_TEXT,
                    Some(MASK),
                    &deflate_message(&mut c, text.as_bytes()),
                ),
                &mut got,
            );
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].payload.as_deref(), Some("hello hello hello"));
        assert_eq!(got[1].payload.as_deref(), Some("second message"));
    }

    #[test]
    fn compressed_frame_without_negotiated_deflate_is_flagged_not_decoded() {
        let mut s = stream(WebSocketDirection::Received, None);
        let got = feed_all(
            &mut s,
            &frame(true, true, OP_TEXT, None, &[0xf2, 0x48, 0x05]),
        );
        assert_eq!(got.len(), 1);
        assert!(got[0].compressed);
        assert_eq!(got[0].payload, None);
        assert_eq!(got[0].payload_len, 0);
    }

    #[test]
    fn protocol_violation_stops_parsing() {
        let mut s = stream(WebSocketDirection::Received, None);
        // Reserved opcode 0x3, then a valid frame that must be ignored.
        let mut bytes = frame(true, false, 0x3, None, b"x");
        bytes.extend(frame(true, false, OP_TEXT, None, b"ignored"));
        assert_eq!(feed_all(&mut s, &bytes), Vec::new());
    }

    #[test]
    fn rejects_64_bit_length_with_high_bit_set() {
        let mut bytes = vec![0x81, 0x7f];
        bytes.extend_from_slice(&(1_u64 << 63).to_be_bytes());
        bytes.extend(frame(true, false, OP_TEXT, None, b"ignored"));
        let mut s = stream(WebSocketDirection::Received, None);
        assert_eq!(feed_all(&mut s, &bytes), Vec::new());
    }

    #[test]
    fn zero_length_data_frames() {
        let mut s = stream(WebSocketDirection::Sent, None);
        let mut bytes = frame(true, false, OP_TEXT, Some(MASK), b"");
        bytes.extend(frame(false, false, OP_BINARY, Some(MASK), b""));
        bytes.extend(frame(true, false, OP_CONTINUATION, Some(MASK), b""));
        let got = feed_all(&mut s, &bytes);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].opcode, WebSocketOpcode::Text);
        assert_eq!(got[0].payload, None);
        assert_eq!(got[0].payload_len, 0);
        assert_eq!(got[1].opcode, WebSocketOpcode::Binary);
        assert_eq!(got[1].payload_len, 0);
    }

    #[test]
    fn one_byte_close_payload_is_a_protocol_violation() {
        let mut s = stream(WebSocketDirection::Received, None);
        let mut bytes = frame(true, false, OP_CLOSE, None, &[0x03]);
        bytes.extend(frame(true, false, OP_TEXT, None, b"ignored"));
        assert_eq!(feed_all(&mut s, &bytes), Vec::new());
    }

    #[test]
    fn inflates_with_server_no_context_takeover() {
        let deflate = PerMessageDeflate::from_extension_headers([
            "permessage-deflate; server_no_context_takeover",
        ]);
        assert_eq!(
            deflate,
            Some(PerMessageDeflate {
                client_no_context_takeover: false,
                server_no_context_takeover: true,
            })
        );
        let mut s = stream(WebSocketDirection::Received, deflate);
        let mut got = Vec::new();
        for text in ["same text same text", "same text same text"] {
            let mut c = Compress::new(Compression::default(), false);
            s.feed(
                &frame(
                    true,
                    true,
                    OP_TEXT,
                    None,
                    &deflate_message(&mut c, text.as_bytes()),
                ),
                &mut got,
            );
        }
        assert_eq!(got.len(), 2);
        assert!(
            got.iter()
                .all(|f| f.payload.as_deref() == Some("same text same text"))
        );
    }
}
