//! Pure-Rust HTTP/1.1 and HTTP/2 + HPACK plaintext stream correlator.
//!
//! Consumes decrypted client->server and server->client byte streams from
//! [`crate::tls13::PassiveTls13Decoder`], correlates request URLs with response
//! statuses, headers, and full bodies (with streaming `gzip`/`deflate`/`br`
//! decompression), and tracks exact inflight request counts for `networkidle`.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use flate2::read::{GzDecoder, ZlibDecoder};
use fluke_hpack::Decoder as HpackDecoder;
use waybound_core::CapturedResponse;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const H2_FRAME_DATA: u8 = 0x0;
const H2_FRAME_HEADERS: u8 = 0x1;
const H2_FRAME_RST_STREAM: u8 = 0x3;
const H2_FRAME_CONTINUATION: u8 = 0x9;

const H2_FLAG_END_STREAM: u8 = 0x1;
const H2_FLAG_END_HEADERS: u8 = 0x4;
const H2_FLAG_PADDED: u8 = 0x8;
const H2_FLAG_PRIORITY: u8 = 0x20;

/// Maximum raw response body buffered per stream (4 MiB).
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum decompressed UTF-8 body size (16 MiB).
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum buffered framing bytes per direction.
const MAX_FRAME_BUFFER: usize = 4 * 1024 * 1024;

/// Callback invoked whenever a response is created or receives new streaming body bytes.
pub type ResponseCallback = Arc<dyn Fn(u64, CapturedResponse) + Send + Sync>;

/// Shared atomic counter of currently inflight HTTP/1.1 + HTTP/2 requests across all connections.
#[derive(Debug, Default, Clone)]
pub struct InflightCounter {
    count: Arc<AtomicUsize>,
}

impl InflightCounter {
    /// Increments the active inflight stream count.
    pub fn inc(&self) {
        let _ = self.count.fetch_add(1, Ordering::AcqRel);
    }

    /// Saturating decrement of the active inflight stream count.
    pub fn dec(&self) {
        let _ = self
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Returns the current number of inflight requests.
    #[must_use]
    pub fn get(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoMode {
    Detecting,
    Http2,
    Http1,
}

#[derive(Debug, Default)]
struct H2StreamState {
    seq: u64,
    url: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    body: Vec<u8>,
    inflight: bool,
    emitted: bool,
}

/// Bidirectional HTTP/1.1 + HTTP/2 stream correlator for a single decrypted connection.
pub struct HttpConnectionCorrelator {
    host_fallback: String,
    mode: ProtoMode,
    c2s_buf: Vec<u8>,
    s2c_buf: Vec<u8>,
    c2s_hpack: HpackDecoder<'static>,
    s2c_hpack: HpackDecoder<'static>,
    c2s_pending_headers: HashMap<u32, Vec<u8>>,
    s2c_pending_headers: HashMap<u32, Vec<u8>>,
    h2_streams: HashMap<u32, H2StreamState>,
    /// Queued HTTP/1.1 request URLs awaiting responses on this keep-alive connection.
    h1_pending_urls: Vec<String>,
    h1_current_seq: u64,
    next_seq_base: u64,
    inflight: InflightCounter,
    on_response: ResponseCallback,
}

impl std::fmt::Debug for HttpConnectionCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConnectionCorrelator")
            .field("host_fallback", &self.host_fallback)
            .field("mode", &self.mode)
            .field("h2_streams", &self.h2_streams.len())
            .finish_non_exhaustive()
    }
}

impl Drop for HttpConnectionCorrelator {
    fn drop(&mut self) {
        for st in self.h2_streams.values_mut() {
            if st.inflight {
                st.inflight = false;
                self.inflight.dec();
            }
        }
        for _ in self.h1_pending_urls.drain(..) {
            self.inflight.dec();
        }
    }
}

impl HttpConnectionCorrelator {
    /// Creates a new correlator for a connection targeting `host_fallback`.
    #[must_use]
    pub fn new(
        host_fallback: String,
        seq_base: u64,
        inflight: InflightCounter,
        on_response: ResponseCallback,
    ) -> Self {
        Self {
            host_fallback,
            mode: ProtoMode::Detecting,
            c2s_buf: Vec::new(),
            s2c_buf: Vec::new(),
            c2s_hpack: HpackDecoder::new(),
            s2c_hpack: HpackDecoder::new(),
            c2s_pending_headers: HashMap::new(),
            s2c_pending_headers: HashMap::new(),
            h2_streams: HashMap::new(),
            h1_pending_urls: Vec::new(),
            h1_current_seq: seq_base,
            next_seq_base: seq_base,
            inflight,
            on_response,
        }
    }

    const fn alloc_seq(&mut self) -> u64 {
        self.next_seq_base = self.next_seq_base.saturating_add(1);
        self.next_seq_base
    }

    /// Feeds decrypted client->server plaintext bytes.
    pub fn feed_client(&mut self, data: &[u8]) {
        if data.is_empty() || self.c2s_buf.len() + data.len() > MAX_FRAME_BUFFER {
            return;
        }
        self.c2s_buf.extend_from_slice(data);
        self.detect_protocol();
        match self.mode {
            ProtoMode::Http2 => self.drain_h2_client(),
            ProtoMode::Http1 => self.drain_h1_client(),
            ProtoMode::Detecting => {}
        }
    }

    /// Feeds decrypted server->client plaintext bytes.
    pub fn feed_server(&mut self, data: &[u8]) {
        if data.is_empty() || self.s2c_buf.len() + data.len() > MAX_FRAME_BUFFER {
            return;
        }
        self.s2c_buf.extend_from_slice(data);
        match self.mode {
            ProtoMode::Http2 => self.drain_h2_server(),
            ProtoMode::Http1 => self.drain_h1_server(),
            ProtoMode::Detecting => {}
        }
    }

    fn detect_protocol(&mut self) {
        if self.mode != ProtoMode::Detecting {
            return;
        }
        if self.c2s_buf.starts_with(H2_PREFACE) {
            let _ = self.c2s_buf.drain(..H2_PREFACE.len());
            self.mode = ProtoMode::Http2;
            // Drain any server frames that already arrived before preface detection completed.
            if !self.s2c_buf.is_empty() {
                self.drain_h2_server();
            }
        } else if self.c2s_buf.len() >= H2_PREFACE.len()
            || (!H2_PREFACE.starts_with(&self.c2s_buf) && !self.c2s_buf.is_empty())
        {
            self.mode = ProtoMode::Http1;
            if !self.s2c_buf.is_empty() {
                self.drain_h1_server();
            }
        }
    }

    fn drain_h2_client(&mut self) {
        while let Some((ftype, flags, stream_id, payload)) = pop_h2_frame(&mut self.c2s_buf) {
            if stream_id == 0 {
                continue;
            }
            match ftype {
                H2_FRAME_HEADERS => {
                    let Some(frag) = strip_h2_headers_payload(flags, &payload) else {
                        continue;
                    };
                    if (flags & H2_FLAG_END_HEADERS) != 0 {
                        self.apply_h2_client_headers(stream_id, frag);
                    } else {
                        let _ = self.c2s_pending_headers.insert(stream_id, frag.to_vec());
                    }
                }
                H2_FRAME_CONTINUATION => {
                    let Some(mut acc) = self.c2s_pending_headers.remove(&stream_id) else {
                        continue;
                    };
                    acc.extend_from_slice(&payload);
                    if (flags & H2_FLAG_END_HEADERS) != 0 {
                        self.apply_h2_client_headers(stream_id, &acc);
                    } else {
                        let _ = self.c2s_pending_headers.insert(stream_id, acc);
                    }
                }
                H2_FRAME_RST_STREAM => {
                    if let Some(st) = self.h2_streams.get_mut(&stream_id)
                        && st.inflight
                    {
                        st.inflight = false;
                        self.inflight.dec();
                    }
                }
                _ => {}
            }
        }
    }

    fn apply_h2_client_headers(&mut self, stream_id: u32, block: &[u8]) {
        let Ok(headers) = self.c2s_hpack.decode(block) else {
            return;
        };
        let mut authority = String::new();
        let mut path = String::new();
        for (name, value) in headers {
            if name.as_slice() == b":authority" || name.as_slice() == b"host" {
                authority = String::from_utf8_lossy(&value).into_owned();
            } else if name.as_slice() == b":path" {
                path = String::from_utf8_lossy(&value).into_owned();
            }
        }
        if authority.is_empty() {
            authority.clone_from(&self.host_fallback);
        }
        let url = build_https_url(&authority, &path);
        let seq = self.alloc_seq();
        let st = self
            .h2_streams
            .entry(stream_id)
            .or_insert_with(|| H2StreamState {
                seq,
                ..H2StreamState::default()
            });
        st.url = Some(url);
        if !st.inflight {
            st.inflight = true;
            self.inflight.inc();
        }
    }

    fn drain_h2_server(&mut self) {
        while let Some((ftype, flags, stream_id, payload)) = pop_h2_frame(&mut self.s2c_buf) {
            if stream_id == 0 {
                continue;
            }
            match ftype {
                H2_FRAME_HEADERS => {
                    let Some(frag) = strip_h2_headers_payload(flags, &payload) else {
                        continue;
                    };
                    let end_stream = (flags & H2_FLAG_END_STREAM) != 0;
                    if (flags & H2_FLAG_END_HEADERS) != 0 {
                        self.apply_h2_server_headers(stream_id, frag, end_stream);
                    } else {
                        let _ = self.s2c_pending_headers.insert(stream_id, frag.to_vec());
                    }
                }
                H2_FRAME_CONTINUATION => {
                    let Some(mut acc) = self.s2c_pending_headers.remove(&stream_id) else {
                        continue;
                    };
                    acc.extend_from_slice(&payload);
                    if (flags & H2_FLAG_END_HEADERS) != 0 {
                        self.apply_h2_server_headers(stream_id, &acc, false);
                    } else {
                        let _ = self.s2c_pending_headers.insert(stream_id, acc);
                    }
                }
                H2_FRAME_DATA => {
                    let end_stream = (flags & H2_FLAG_END_STREAM) != 0;
                    let data = strip_h2_padding(flags, &payload);
                    self.apply_h2_server_data(stream_id, data, end_stream);
                }
                H2_FRAME_RST_STREAM => {
                    if let Some(st) = self.h2_streams.get_mut(&stream_id)
                        && st.inflight
                    {
                        st.inflight = false;
                        self.inflight.dec();
                    }
                }
                _ => {}
            }
        }
    }

    fn apply_h2_server_headers(&mut self, stream_id: u32, block: &[u8], end_stream: bool) {
        let Ok(headers) = self.s2c_hpack.decode(block) else {
            return;
        };
        let seq = self.alloc_seq();
        let st = self
            .h2_streams
            .entry(stream_id)
            .or_insert_with(|| H2StreamState {
                seq,
                ..H2StreamState::default()
            });
        for (name, value) in headers {
            let n = String::from_utf8_lossy(&name).to_ascii_lowercase();
            let v = String::from_utf8_lossy(&value).into_owned();
            match n.as_str() {
                ":status" => {
                    if let Ok(code) = v.parse::<u16>() {
                        st.status = Some(code);
                    }
                }
                "content-type" => st.content_type = Some(v),
                "content-encoding" => st.content_encoding = Some(v),
                _ => {}
            }
        }
        if end_stream && st.inflight {
            st.inflight = false;
            self.inflight.dec();
        }
        self.emit_h2_stream(stream_id);
    }

    fn apply_h2_server_data(&mut self, stream_id: u32, data: &[u8], end_stream: bool) {
        if let Some(st) = self.h2_streams.get_mut(&stream_id) {
            let remaining = MAX_BODY_BYTES.saturating_sub(st.body.len());
            if remaining > 0 && !data.is_empty() {
                let take = remaining.min(data.len());
                st.body.extend_from_slice(&data[..take]);
            }
            if end_stream && st.inflight {
                st.inflight = false;
                self.inflight.dec();
            }
        }
        self.emit_h2_stream(stream_id);
    }

    fn emit_h2_stream(&mut self, stream_id: u32) {
        let Some(st) = self.h2_streams.get_mut(&stream_id) else {
            return;
        };
        let (Some(url), Some(status)) = (&st.url, st.status) else {
            return;
        };
        let body = decode_body_bytes(&st.body, st.content_encoding.as_deref());
        let resp = CapturedResponse {
            url: url.clone(),
            status,
            content_type: st.content_type.clone(),
            body,
        };
        let seq = st.seq;
        st.emitted = true;
        (self.on_response)(seq, resp);
    }

    fn drain_h1_client(&mut self) {
        while let Some(end) = find_double_crlf(&self.c2s_buf) {
            let head = String::from_utf8_lossy(&self.c2s_buf[..end]).into_owned();
            let _ = self.c2s_buf.drain(..end + 4);
            let mut lines = head.lines();
            let Some(req_line) = lines.next() else {
                continue;
            };
            let path = req_line.split_whitespace().nth(1).unwrap_or("/");
            let mut host = self.host_fallback.clone();
            for line in lines {
                if let Some((k, v)) = line.split_once(':')
                    && k.trim().eq_ignore_ascii_case("host")
                {
                    v.trim().clone_into(&mut host);
                }
            }
            let url = build_https_url(&host, path);
            self.h1_pending_urls.push(url);
            self.inflight.inc();
        }
    }

    fn drain_h1_server(&mut self) {
        while let Some(end) = find_double_crlf(&self.s2c_buf) {
            let head = String::from_utf8_lossy(&self.s2c_buf[..end]).into_owned();
            let mut lines = head.lines();
            let Some(status_line) = lines.next() else {
                let _ = self.s2c_buf.drain(..end + 4);
                continue;
            };
            let Some(status) = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
            else {
                let _ = self.s2c_buf.drain(..end + 4);
                continue;
            };

            let mut content_type = None;
            let mut content_encoding = None;
            let mut content_length: Option<usize> = None;
            let mut chunked = false;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim().to_ascii_lowercase();
                    let val = v.trim();
                    match key.as_str() {
                        "content-type" => content_type = Some(val.to_owned()),
                        "content-encoding" => content_encoding = Some(val.to_owned()),
                        "content-length" => content_length = val.parse::<usize>().ok(),
                        "transfer-encoding" if val.to_ascii_lowercase().contains("chunked") => {
                            chunked = true;
                        }
                        _ => {}
                    }
                }
            }

            let body_start = end + 4;
            let (raw_body, consumed) = if let Some(cl) = content_length {
                if self.s2c_buf.len() < body_start + cl {
                    break;
                }
                (
                    self.s2c_buf[body_start..body_start + cl].to_vec(),
                    body_start + cl,
                )
            } else if chunked {
                let Some((decoded, chunk_consumed)) = decode_chunked(&self.s2c_buf[body_start..])
                else {
                    break;
                };
                (decoded, body_start + chunk_consumed)
            } else {
                (Vec::new(), body_start)
            };

            let _ = self.s2c_buf.drain(..consumed);
            let url = if self.h1_pending_urls.is_empty() {
                format!("https://{}/", self.host_fallback)
            } else {
                self.inflight.dec();
                self.h1_pending_urls.remove(0)
            };
            self.h1_current_seq = self.alloc_seq();
            let body = decode_body_bytes(&raw_body, content_encoding.as_deref());
            (self.on_response)(
                self.h1_current_seq,
                CapturedResponse {
                    url,
                    status,
                    content_type,
                    body,
                },
            );
        }
    }
}

fn pop_h2_frame(buf: &mut Vec<u8>) -> Option<(u8, u8, u32, Vec<u8>)> {
    if buf.len() < 9 {
        return None;
    }
    let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
    if buf.len() < 9 + len {
        return None;
    }
    let ftype = buf[3];
    let flags = buf[4];
    let stream_id = u32::from_be_bytes([buf[5] & 0x7F, buf[6], buf[7], buf[8]]);
    let payload = buf[9..9 + len].to_vec();
    let _ = buf.drain(..9 + len);
    Some((ftype, flags, stream_id, payload))
}

fn strip_h2_padding(flags: u8, payload: &[u8]) -> &[u8] {
    if (flags & H2_FLAG_PADDED) == 0 {
        return payload;
    }
    let Some(&pad_len) = payload.first() else {
        return &[];
    };
    let end = payload.len().saturating_sub(usize::from(pad_len));
    if end <= 1 {
        return &[];
    }
    &payload[1..end]
}

fn strip_h2_headers_payload(flags: u8, payload: &[u8]) -> Option<&[u8]> {
    let unpadded = strip_h2_padding(flags, payload);
    if (flags & H2_FLAG_PRIORITY) != 0 {
        unpadded.get(5..)
    } else {
        Some(unpadded)
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn decode_chunked(mut data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let total = data.len();
    let mut out = Vec::new();
    loop {
        let crlf = data.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&data[..crlf])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        data = &data[crlf + 2..];
        if size == 0 {
            if data.len() < 2 {
                return None;
            }
            data = &data[2..];
            return Some((out, total - data.len()));
        }
        if data.len() < size + 2 {
            return None;
        }
        if out.len() < MAX_BODY_BYTES {
            let take = size.min(MAX_BODY_BYTES - out.len());
            out.extend_from_slice(&data[..take]);
        }
        data = &data[size + 2..];
    }
}

fn build_https_url(authority: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") || authority.is_empty() {
        path.to_owned()
    } else if path.starts_with('/') {
        format!("https://{authority}{path}")
    } else {
        format!("https://{authority}/{path}")
    }
}

/// Decodes raw response bytes into UTF-8 text, transparently decompressing
/// `gzip`, `deflate`, or `br` (Brotli) and retaining partial prefixes for streaming SSE.
#[must_use]
pub fn decode_body_bytes(raw: &[u8], encoding: Option<&str>) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let enc = encoding.map(str::to_ascii_lowercase);
    let decompressed: Vec<u8> = match enc.as_deref().map(str::trim) {
        Some("gzip" | "x-gzip") => {
            let mut out = Vec::new();
            let mut decoder = GzDecoder::new(raw).take(MAX_DECOMPRESSED_BYTES);
            let _ = decoder.read_to_end(&mut out);
            if out.is_empty() { raw.to_vec() } else { out }
        }
        Some("deflate") => {
            let mut out = Vec::new();
            let mut decoder = ZlibDecoder::new(raw).take(MAX_DECOMPRESSED_BYTES);
            let _ = decoder.read_to_end(&mut out);
            if out.is_empty() { raw.to_vec() } else { out }
        }
        Some("br") => {
            let mut out = Vec::new();
            let mut decoder = brotli::Decompressor::new(raw, 4096).take(MAX_DECOMPRESSED_BYTES);
            let _ = decoder.read_to_end(&mut out);
            if out.is_empty() { raw.to_vec() } else { out }
        }
        _ => raw.to_vec(),
    };

    match String::from_utf8(decompressed) {
        Ok(s) => Some(s),
        Err(err) => {
            let valid_up_to = err.utf8_error().valid_up_to();
            if valid_up_to > 0 {
                let bytes = err.into_bytes();
                String::from_utf8(bytes[..valid_up_to].to_vec()).ok()
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn correlates_http1_request_response_and_tracks_inflight() {
        let captured: Arc<Mutex<Vec<CapturedResponse>>> = Arc::new(Mutex::new(Vec::new()));
        let cap_clone = Arc::clone(&captured);
        let inflight = InflightCounter::default();
        let mut corr = HttpConnectionCorrelator::new(
            "api.example.com".to_owned(),
            1,
            inflight.clone(),
            Arc::new(move |_, resp| {
                if let Ok(mut g) = cap_clone.lock() {
                    g.push(resp);
                }
            }),
        );

        corr.feed_client(b"GET /v1/flights HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        assert_eq!(inflight.get(), 1);
        corr.feed_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        );
        assert_eq!(inflight.get(), 0);

        let list = captured.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].url, "https://api.example.com/v1/flights");
        assert_eq!(list[0].status, 200);
        assert_eq!(list[0].body.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn correlates_http2_hpack_headers_and_data_frames() {
        let captured: Arc<Mutex<Vec<CapturedResponse>>> = Arc::new(Mutex::new(Vec::new()));
        let cap_clone = Arc::clone(&captured);
        let inflight = InflightCounter::default();
        let mut corr = HttpConnectionCorrelator::new(
            "www.united.com".to_owned(),
            100,
            inflight.clone(),
            Arc::new(move |_, resp| {
                if let Ok(mut g) = cap_clone.lock() {
                    g.push(resp);
                }
            }),
        );

        let mut enc = fluke_hpack::Encoder::new();
        let req_block = enc.encode([
            (&b":method"[..], &b"POST"[..]),
            (&b":authority"[..], &b"www.united.com"[..]),
            (&b":path"[..], &b"/api/flight/FetchSSENestedFlights"[..]),
        ]);
        let mut c2s = H2_PREFACE.to_vec();
        c2s.extend_from_slice(&[
            0,
            0,
            u8::try_from(req_block.len()).unwrap_or(0),
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS,
            0,
            0,
            0,
            1,
        ]);
        c2s.extend_from_slice(&req_block);
        corr.feed_client(&c2s);
        assert_eq!(inflight.get(), 1);

        let mut s_enc = fluke_hpack::Encoder::new();
        let resp_block = s_enc.encode([
            (&b":status"[..], &b"200"[..]),
            (&b"content-type"[..], &b"text/event-stream"[..]),
        ]);
        let mut s2c = vec![
            0,
            0,
            u8::try_from(resp_block.len()).unwrap_or(0),
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS,
            0,
            0,
            0,
            1,
        ];
        s2c.extend_from_slice(&resp_block);
        let body = b"data: {\"type\":\"flightOption\"}\n\n";
        s2c.extend_from_slice(&[
            0,
            0,
            u8::try_from(body.len()).unwrap_or(0),
            H2_FRAME_DATA,
            H2_FLAG_END_STREAM,
            0,
            0,
            0,
            1,
        ]);
        s2c.extend_from_slice(body);
        corr.feed_server(&s2c);
        assert_eq!(inflight.get(), 0);

        let list = captured.lock().map(|g| g.clone()).unwrap_or_default();
        assert!(!list.is_empty());
        let final_resp = &list[list.len() - 1];
        assert_eq!(
            final_resp.url,
            "https://www.united.com/api/flight/FetchSSENestedFlights"
        );
        assert_eq!(final_resp.status, 200);
        assert_eq!(
            final_resp.body.as_deref(),
            Some("data: {\"type\":\"flightOption\"}\n\n")
        );
    }
}
