//! Pure-Rust HTTP/1.1 and HTTP/2 + HPACK plaintext stream correlator.
//!
//! Consumes decrypted client->server and server->client byte streams from
//! [`crate::tls13::PassiveTls13Decoder`], correlates request URLs with response
//! statuses, headers, and full bodies (with streaming `gzip`/`deflate`/`br`
//! decompression), and tracks exact inflight request counts for `networkidle`.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use flate2::read::{GzDecoder, ZlibDecoder};
use fluke_hpack::Decoder as HpackDecoder;
use waybound_core::{CapturedResponse, CapturedWebSocketFrame, HttpHeader, WebSocketDirection};

use crate::websocket::{PerMessageDeflate, WebSocketStream};

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
/// Maximum raw request body bytes retained per request (1 MiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Maximum header fields retained per request or response header list.
pub const MAX_HEADERS_PER_MESSAGE: usize = 256;

/// Callback invoked whenever a response is created or receives new streaming body bytes.
pub type ResponseCallback = Arc<dyn Fn(u64, CapturedResponse) + Send + Sync>;

/// Callback invoked with every complete WebSocket message or control frame.
pub type WebSocketCallback = Arc<dyn Fn(CapturedWebSocketFrame) + Send + Sync>;

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
        let mut cur = self.count.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_sub(1);
            match self
                .count
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
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
    /// HTTP/1.1 connection upgraded with `101 Switching Protocols` to RFC 6455 WebSocket.
    WebSocket,
}

#[derive(Debug, Default)]
struct H2StreamState {
    seq: u64,
    url: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
    request_method: Option<String>,
    request_headers: Vec<HttpHeader>,
    request_content_encoding: Option<String>,
    request_body: Vec<u8>,
    inflight: bool,
    emitted: bool,
}

/// HTTP/1.1 request awaiting its response on a keep-alive connection.
#[derive(Debug)]
struct H1PendingRequest {
    id: u64,
    url: String,
    method: String,
    headers: Vec<HttpHeader>,
    content_encoding: Option<String>,
    body: Vec<u8>,
    /// Request carried `Upgrade: websocket`.
    websocket: bool,
}

impl H1PendingRequest {
    /// Moves this request's URL and metadata onto the response it belongs to.
    fn attach_to(self, resp: &mut CapturedResponse) {
        resp.request_body = decode_body_bytes(&self.body, self.content_encoding.as_deref());
        resp.url = self.url;
        resp.request_method = Some(self.method);
        resp.request_headers = self.headers;
    }
}

/// Progress through the body of the HTTP/1.1 request currently being sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H1ClientBody {
    None,
    Length { id: u64, remaining: usize },
    Chunked { id: u64 },
}

#[derive(Debug)]
struct WebSocketSession {
    client: WebSocketStream,
    server: WebSocketStream,
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
    /// Queued HTTP/1.1 requests awaiting responses on this keep-alive connection.
    h1_pending: VecDeque<H1PendingRequest>,
    h1_next_request_id: u64,
    h1_client_body: H1ClientBody,
    /// Client bytes after a WebSocket upgrade request are held until the server answers.
    h1_client_paused: bool,
    h1_current_seq: u64,
    next_seq_base: u64,
    ws: Option<WebSocketSession>,
    inflight: InflightCounter,
    on_response: ResponseCallback,
    on_websocket: Option<WebSocketCallback>,
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
        for _ in self.h1_pending.drain(..) {
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
            h1_pending: VecDeque::new(),
            h1_next_request_id: 0,
            h1_client_body: H1ClientBody::None,
            h1_client_paused: false,
            h1_current_seq: seq_base,
            next_seq_base: seq_base,
            ws: None,
            inflight,
            on_response,
            on_websocket: None,
        }
    }

    /// Enables WebSocket message capture after HTTP/1.1 `101 Switching Protocols` upgrades,
    /// delivering every message to `on_websocket`.
    #[must_use]
    pub fn with_websocket_callback(mut self, on_websocket: WebSocketCallback) -> Self {
        self.on_websocket = Some(on_websocket);
        self
    }

    /// Sets (or replaces) the WebSocket message callback.
    pub fn set_websocket_callback(&mut self, on_websocket: WebSocketCallback) {
        self.on_websocket = Some(on_websocket);
    }

    const fn alloc_seq(&mut self) -> u64 {
        self.next_seq_base = self.next_seq_base.saturating_add(1);
        self.next_seq_base
    }

    /// Feeds decrypted client->server plaintext bytes.
    pub fn feed_client(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.mode == ProtoMode::WebSocket {
            self.feed_websocket(WebSocketDirection::Sent, data);
            return;
        }
        if self.c2s_buf.len() + data.len() > MAX_FRAME_BUFFER {
            return;
        }
        self.c2s_buf.extend_from_slice(data);
        self.detect_protocol();
        match self.mode {
            ProtoMode::Http2 => self.drain_h2_client(),
            ProtoMode::Http1 => self.drain_h1_client(),
            ProtoMode::Detecting | ProtoMode::WebSocket => {}
        }
    }

    /// Feeds decrypted server->client plaintext bytes.
    pub fn feed_server(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.mode == ProtoMode::WebSocket {
            self.feed_websocket(WebSocketDirection::Received, data);
            return;
        }
        if self.s2c_buf.len() + data.len() > MAX_FRAME_BUFFER {
            return;
        }
        self.s2c_buf.extend_from_slice(data);
        match self.mode {
            ProtoMode::Http2 => self.drain_h2_server(),
            ProtoMode::Http1 => self.drain_h1_server(),
            ProtoMode::Detecting | ProtoMode::WebSocket => {}
        }
    }

    fn feed_websocket(&mut self, direction: WebSocketDirection, data: &[u8]) {
        let (Some(ws), Some(callback)) = (self.ws.as_mut(), self.on_websocket.as_ref()) else {
            return;
        };
        let mut frames = Vec::new();
        match direction {
            WebSocketDirection::Sent => ws.client.feed(data, &mut frames),
            WebSocketDirection::Received => ws.server.feed(data, &mut frames),
        }
        for frame in frames {
            callback(frame);
        }
    }

    /// Switches this connection to WebSocket framing after a `101` upgrade response.
    fn start_websocket(&mut self, https_url: &str, deflate: Option<PerMessageDeflate>) {
        self.mode = ProtoMode::WebSocket;
        self.h1_client_paused = false;
        let url = https_url
            .strip_prefix("https://")
            .map_or_else(|| https_url.to_owned(), |rest| format!("wss://{rest}"));
        self.ws = Some(WebSocketSession {
            client: WebSocketStream::new(url.clone(), WebSocketDirection::Sent, deflate),
            server: WebSocketStream::new(url, WebSocketDirection::Received, deflate),
        });
        let s2c = std::mem::take(&mut self.s2c_buf);
        let c2s = std::mem::take(&mut self.c2s_buf);
        if !s2c.is_empty() {
            self.feed_websocket(WebSocketDirection::Received, &s2c);
        }
        if !c2s.is_empty() {
            self.feed_websocket(WebSocketDirection::Sent, &c2s);
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
                H2_FRAME_DATA => {
                    let data = strip_h2_padding(flags, &payload);
                    let response_seen = self.h2_streams.get_mut(&stream_id).is_some_and(|st| {
                        append_capped(&mut st.request_body, data, MAX_REQUEST_BODY_BYTES);
                        st.status.is_some()
                    });
                    // Request bodies normally finish before the response starts; if not,
                    // re-emit so the stored response picks up the rest of the body.
                    if response_seen && !data.is_empty() {
                        self.emit_h2_stream(stream_id);
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
        let Ok(decoded) = self.c2s_hpack.decode(block) else {
            return;
        };
        let mut authority = String::new();
        let mut path = String::new();
        let mut method = None;
        let mut content_encoding = None;
        let mut headers = Vec::new();
        for (name, value) in decoded {
            match name.as_slice() {
                b":authority" => authority = String::from_utf8_lossy(&value).into_owned(),
                b":path" => path = String::from_utf8_lossy(&value).into_owned(),
                b":method" => method = Some(String::from_utf8_lossy(&value).into_owned()),
                n if n.starts_with(b":") => {}
                n => {
                    let header = HttpHeader::new(
                        String::from_utf8_lossy(n).into_owned(),
                        String::from_utf8_lossy(&value).into_owned(),
                    );
                    if header.name.eq_ignore_ascii_case("host") {
                        authority.clone_from(&header.value);
                    } else if header.name.eq_ignore_ascii_case("content-encoding") {
                        content_encoding = Some(header.value.clone());
                    }
                    push_header(&mut headers, header);
                }
            }
        }
        if method.is_none() && path.is_empty() {
            // A header block without request pseudo-headers is a trailer section; the
            // request line was already applied by the initial HEADERS frame.
            return;
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
        st.request_method = method;
        st.request_headers = headers;
        st.request_content_encoding = content_encoding;
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
        let Ok(decoded) = self.s2c_hpack.decode(block) else {
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
        let mut status = None;
        let mut headers = Vec::new();
        for (name, value) in decoded {
            let n = String::from_utf8_lossy(&name).to_ascii_lowercase();
            let v = String::from_utf8_lossy(&value).into_owned();
            match n.as_str() {
                ":status" => status = v.parse::<u16>().ok(),
                _ if n.starts_with(':') => {}
                "content-type" => st.content_type = Some(v.clone()),
                "content-encoding" => st.content_encoding = Some(v.clone()),
                _ => {}
            }
            if !n.starts_with(':') {
                push_header(&mut headers, HttpHeader::new(n, v));
            }
        }
        if let Some(code) = status {
            // A new response header block (an interim 1xx is replaced by the final one).
            st.status = Some(code);
            st.headers = headers;
        } else {
            // Trailer section: appended after the response headers.
            for header in headers {
                push_header(&mut st.headers, header);
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
            headers: st.headers.clone(),
            request_method: st.request_method.clone(),
            request_headers: st.request_headers.clone(),
            request_body: decode_body_bytes(
                &st.request_body,
                st.request_content_encoding.as_deref(),
            ),
        };
        let seq = st.seq;
        st.emitted = true;
        (self.on_response)(seq, resp);
    }

    fn drain_h1_client(&mut self) {
        loop {
            match self.h1_client_body {
                H1ClientBody::Length { id, remaining } => {
                    if self.c2s_buf.is_empty() {
                        return;
                    }
                    let take = remaining.min(self.c2s_buf.len());
                    if let Some(req) = self.h1_pending.iter_mut().find(|r| r.id == id) {
                        append_capped(&mut req.body, &self.c2s_buf[..take], MAX_REQUEST_BODY_BYTES);
                    }
                    let _ = self.c2s_buf.drain(..take);
                    let left = remaining - take;
                    self.h1_client_body = if left == 0 {
                        H1ClientBody::None
                    } else {
                        H1ClientBody::Length {
                            id,
                            remaining: left,
                        }
                    };
                    continue;
                }
                H1ClientBody::Chunked { id } => {
                    let Some((decoded, consumed)) = decode_chunked(&self.c2s_buf) else {
                        return;
                    };
                    if let Some(req) = self.h1_pending.iter_mut().find(|r| r.id == id) {
                        append_capped(&mut req.body, &decoded, MAX_REQUEST_BODY_BYTES);
                    }
                    let _ = self.c2s_buf.drain(..consumed);
                    self.h1_client_body = H1ClientBody::None;
                    continue;
                }
                H1ClientBody::None => {}
            }
            if self.h1_client_paused {
                return;
            }
            let Some(end) = find_double_crlf(&self.c2s_buf) else {
                return;
            };
            let head = String::from_utf8_lossy(&self.c2s_buf[..end]).into_owned();
            let _ = self.c2s_buf.drain(..end + 4);
            let mut lines = head.lines();
            let Some(req_line) = lines.next() else {
                continue;
            };
            let mut parts = req_line.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_owned();
            let path = parts.next().unwrap_or("/");
            let mut host = self.host_fallback.clone();
            let mut headers = Vec::new();
            let mut content_length: Option<usize> = None;
            let mut chunked = false;
            let mut content_encoding = None;
            let mut websocket = false;
            for line in lines {
                let Some((k, v)) = line.split_once(':') else {
                    continue;
                };
                let (key, val) = (k.trim(), v.trim());
                match key.to_ascii_lowercase().as_str() {
                    "host" => val.clone_into(&mut host),
                    "content-length" => content_length = val.parse::<usize>().ok(),
                    "transfer-encoding" if val.to_ascii_lowercase().contains("chunked") => {
                        chunked = true;
                    }
                    "content-encoding" => content_encoding = Some(val.to_owned()),
                    "upgrade" if val.to_ascii_lowercase().contains("websocket") => {
                        websocket = true;
                    }
                    _ => {}
                }
                push_header(&mut headers, HttpHeader::new(key, val));
            }
            let id = self.h1_next_request_id;
            self.h1_next_request_id = self.h1_next_request_id.wrapping_add(1);
            self.h1_pending.push_back(H1PendingRequest {
                id,
                url: build_https_url(&host, path),
                method,
                headers,
                content_encoding,
                body: Vec::new(),
                websocket,
            });
            self.inflight.inc();
            if chunked {
                self.h1_client_body = H1ClientBody::Chunked { id };
            } else if let Some(len) = content_length.filter(|&n| n > 0) {
                self.h1_client_body = H1ClientBody::Length { id, remaining: len };
            }
            if websocket {
                // Whatever follows is WebSocket framing if the server accepts the upgrade.
                self.h1_client_paused = true;
            }
        }
    }

    fn drain_h1_server(&mut self) {
        let mut resume_client = false;
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
            let body_start = end + 4;
            if (100..200).contains(&status) && status != 101 {
                // Interim response (e.g. `100 Continue`); the final response follows.
                let _ = self.s2c_buf.drain(..body_start);
                continue;
            }

            let H1ResponseHead {
                headers,
                content_type,
                content_encoding,
                content_length,
                chunked,
            } = parse_h1_response_head(lines);

            let head_request = self
                .h1_pending
                .front()
                .is_some_and(|r| r.method.eq_ignore_ascii_case("HEAD"));
            let (raw_body, consumed) = if head_request || matches!(status, 101 | 204 | 304) {
                (Vec::new(), body_start)
            } else if let Some(cl) = content_length {
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
            let request = self.h1_pending.pop_front();
            if request.is_some() {
                self.inflight.dec();
            }
            let was_ws_request = request.as_ref().is_some_and(|r| r.websocket);
            let upgrade = was_ws_request && status == 101;
            if was_ws_request && !upgrade {
                self.h1_client_paused = false;
                resume_client = true;
            }
            let mut resp = CapturedResponse {
                url: format!("https://{}/", self.host_fallback),
                status,
                content_type,
                body: decode_body_bytes(&raw_body, content_encoding.as_deref()),
                headers,
                ..CapturedResponse::default()
            };
            if let Some(req) = request {
                req.attach_to(&mut resp);
            }
            let websocket = upgrade.then(|| {
                let deflate = PerMessageDeflate::from_extension_headers(
                    resp.headers
                        .iter()
                        .filter(|h| h.name.eq_ignore_ascii_case("sec-websocket-extensions"))
                        .map(|h| h.value.as_str()),
                );
                (resp.url.clone(), deflate)
            });
            self.h1_current_seq = self.alloc_seq();
            (self.on_response)(self.h1_current_seq, resp);
            if let Some((url, deflate)) = websocket {
                self.start_websocket(&url, deflate);
                return;
            }
        }
        if resume_client {
            self.drain_h1_client();
        }
    }
}

/// Header fields of an HTTP/1.1 response that drive body framing and decoding.
struct H1ResponseHead {
    headers: Vec<HttpHeader>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_h1_response_head<'a>(lines: impl Iterator<Item = &'a str>) -> H1ResponseHead {
    let mut head = H1ResponseHead {
        headers: Vec::new(),
        content_type: None,
        content_encoding: None,
        content_length: None,
        chunked: false,
    };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (key, val) = (k.trim(), v.trim());
        match key.to_ascii_lowercase().as_str() {
            "content-type" => head.content_type = Some(val.to_owned()),
            "content-encoding" => head.content_encoding = Some(val.to_owned()),
            "content-length" => head.content_length = val.parse::<usize>().ok(),
            "transfer-encoding" if val.to_ascii_lowercase().contains("chunked") => {
                head.chunked = true;
            }
            _ => {}
        }
        push_header(&mut head.headers, HttpHeader::new(key, val));
    }
    head
}

/// Appends `data` to `buf` without letting `buf` grow beyond `cap` bytes.
fn append_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize) {
    let room = cap.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..room.min(data.len())]);
}

/// Pushes `header` unless the list already holds [`MAX_HEADERS_PER_MESSAGE`] fields.
fn push_header(headers: &mut Vec<HttpHeader>, header: HttpHeader) {
    if headers.len() < MAX_HEADERS_PER_MESSAGE {
        headers.push(header);
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
        assert_ne!(list.len(), 0);
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

    type Captured = Arc<Mutex<Vec<CapturedResponse>>>;
    type CapturedFrames = Arc<Mutex<Vec<CapturedWebSocketFrame>>>;

    fn correlator(host: &str) -> (HttpConnectionCorrelator, Captured, CapturedFrames) {
        let captured: Captured = Arc::new(Mutex::new(Vec::new()));
        let frames: CapturedFrames = Arc::new(Mutex::new(Vec::new()));
        let (cap, fr) = (Arc::clone(&captured), Arc::clone(&frames));
        let corr = HttpConnectionCorrelator::new(
            host.to_owned(),
            1,
            InflightCounter::default(),
            Arc::new(move |_, resp| {
                if let Ok(mut g) = cap.lock() {
                    g.push(resp);
                }
            }),
        )
        .with_websocket_callback(Arc::new(move |frame| {
            if let Ok(mut g) = fr.lock() {
                g.push(frame);
            }
        }));
        (corr, captured, frames)
    }

    fn snapshot<T: Clone>(items: &Arc<Mutex<Vec<T>>>) -> Vec<T> {
        items.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn header_values<'a>(headers: &'a [HttpHeader], name: &str) -> Vec<&'a str> {
        headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }

    fn h2_frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
        let mut out = vec![len[1], len[2], len[3], ftype, flags];
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn http1_captures_headers_request_metadata_and_post_body() {
        let (mut corr, captured, _) = correlator("api.example.com");
        corr.feed_client(
            b"POST /login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 16\r\n\r\nuser=al",
        );
        // The body arrives in a second read, followed by a pipelined keep-alive GET.
        corr.feed_client(b"ice&pw=xyGET /next HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        corr.feed_server(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: sid=abc; Path=/\r\nSet-Cookie: theme=dark\r\nContent-Length: 2\r\n\r\nok",
        );
        corr.feed_server(b"HTTP/1.1 204 No Content\r\nX-Rate-Limit: 9\r\n\r\n");

        let list = snapshot(&captured);
        assert_eq!(list.len(), 2);
        let login = &list[0];
        assert_eq!(login.url, "https://api.example.com/login");
        assert_eq!(login.status, 200);
        assert_eq!(login.body.as_deref(), Some("ok"));
        assert_eq!(
            header_values(&login.headers, "set-cookie"),
            vec!["sid=abc; Path=/", "theme=dark"]
        );
        assert_eq!(
            login.headers[0],
            HttpHeader::new("Content-Type", "text/plain")
        );
        assert_eq!(login.request_method.as_deref(), Some("POST"));
        assert_eq!(
            header_values(&login.request_headers, "content-type"),
            vec!["application/x-www-form-urlencoded"]
        );
        assert_eq!(login.request_body.as_deref(), Some("user=alice&pw=xy"));

        let next = &list[1];
        assert_eq!(next.url, "https://api.example.com/next");
        assert_eq!(next.status, 204);
        assert_eq!(next.request_method.as_deref(), Some("GET"));
        assert_eq!(next.request_body, None);
        assert_eq!(header_values(&next.headers, "x-rate-limit"), vec!["9"]);
    }

    #[test]
    fn http1_captures_chunked_request_body() {
        let (mut corr, captured, _) = correlator("api.example.com");
        corr.feed_client(
            b"PUT /items/1 HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n",
        );
        corr.feed_client(b"3\r\n:1}\r\n0\r\n\r\n");
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let list = snapshot(&captured);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].request_method.as_deref(), Some("PUT"));
        assert_eq!(list[0].request_body.as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn http1_caps_request_body() {
        let (mut corr, captured, _) = correlator("up.example.com");
        let len = MAX_REQUEST_BODY_BYTES + 100;
        corr.feed_client(
            format!(
                "POST /upload HTTP/1.1\r\nHost: up.example.com\r\nContent-Length: {len}\r\n\r\n"
            )
            .as_bytes(),
        );
        let body = vec![b'q'; len];
        for chunk in body.chunks(64 * 1024) {
            corr.feed_client(chunk);
        }
        corr.feed_client(b"GET /after HTTP/1.1\r\nHost: up.example.com\r\n\r\n");
        corr.feed_server(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let list = snapshot(&captured);
        assert_eq!(list.len(), 2);
        assert_eq!(
            list[0].request_body.as_ref().map(String::len),
            Some(MAX_REQUEST_BODY_BYTES)
        );
        assert_eq!(list[1].url, "https://up.example.com/after");
    }

    #[test]
    fn http2_captures_headers_request_metadata_and_post_body() {
        let (mut corr, captured, _) = correlator("www.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let req_block = c_enc.encode([
            (&b":method"[..], &b"POST"[..]),
            (&b":scheme"[..], &b"https"[..]),
            (&b":authority"[..], &b"www.example.com"[..]),
            (&b":path"[..], &b"/api/search"[..]),
            (&b"content-type"[..], &b"application/json"[..]),
            (&b"x-trace"[..], &b"1"[..]),
            (&b"x-trace"[..], &b"2"[..]),
        ]);
        let mut c2s = H2_PREFACE.to_vec();
        c2s.extend(h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS,
            1,
            &req_block,
        ));
        c2s.extend(h2_frame(H2_FRAME_DATA, 0, 1, b"{\"q\":"));
        c2s.extend(h2_frame(H2_FRAME_DATA, 0, 1, b"\"NRT\"}"));
        // Request trailers must not clobber the URL or the request headers.
        let trailers = c_enc.encode([(&b"x-checksum"[..], &b"abc"[..])]);
        c2s.extend(h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            &trailers,
        ));
        corr.feed_client(&c2s);

        let mut s_enc = fluke_hpack::Encoder::new();
        let resp_block = s_enc.encode([
            (&b":status"[..], &b"200"[..]),
            (&b"content-type"[..], &b"application/json"[..]),
            (&b"set-cookie"[..], &b"a=1"[..]),
            (&b"set-cookie"[..], &b"b=2"[..]),
        ]);
        let mut s2c = h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &resp_block);
        s2c.extend(h2_frame(H2_FRAME_DATA, H2_FLAG_END_STREAM, 1, b"[]"));
        corr.feed_server(&s2c);

        let last = snapshot(&captured).pop().unwrap_or_default();
        assert_eq!(last.url, "https://www.example.com/api/search");
        assert_eq!(last.status, 200);
        assert_eq!(last.body.as_deref(), Some("[]"));
        assert_eq!(
            header_values(&last.headers, "set-cookie"),
            vec!["a=1", "b=2"]
        );
        assert!(last.headers.iter().all(|h| !h.name.starts_with(':')));
        assert_eq!(last.request_method.as_deref(), Some("POST"));
        assert_eq!(
            header_values(&last.request_headers, "x-trace"),
            vec!["1", "2"]
        );
        assert!(
            last.request_headers
                .iter()
                .all(|h| !h.name.starts_with(':'))
        );
        assert_eq!(last.request_body.as_deref(), Some("{\"q\":\"NRT\"}"));
    }

    fn masked(opcode_byte: u8, payload: &[u8]) -> Vec<u8> {
        let key = [1_u8, 2, 3, 4];
        let mut out = vec![opcode_byte, 0x80 | u8::try_from(payload.len()).unwrap_or(0)];
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        out
    }

    #[test]
    fn http1_websocket_upgrade_captures_frames_in_both_directions() {
        let (mut corr, captured, frames) = correlator("chat.example.com");
        corr.feed_client(
            b"GET /socket?v=2 HTTP/1.1\r\nHost: chat.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        );
        // A client frame observed before the server's 101 is held, not parsed as HTTP.
        corr.feed_client(&masked(0x81, b"hello"));
        let mut s2c = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n".to_vec();
        s2c.extend_from_slice(&[0x81, 0x03]);
        s2c.extend_from_slice(b"hey");
        corr.feed_server(&s2c);
        corr.feed_client(&masked(0x88, &[0x03, 0xe8]));

        let responses = snapshot(&captured);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].status, 101);
        assert_eq!(
            header_values(&responses[0].headers, "upgrade"),
            vec!["websocket"]
        );

        let got = snapshot(&frames);
        assert_eq!(got.len(), 3);
        assert!(
            got.iter()
                .all(|f| f.url == "wss://chat.example.com/socket?v=2")
        );
        assert_eq!(got[0].direction, WebSocketDirection::Received);
        assert_eq!(got[0].payload.as_deref(), Some("hey"));
        assert_eq!(got[1].direction, WebSocketDirection::Sent);
        assert_eq!(got[1].payload.as_deref(), Some("hello"));
        assert_eq!(got[2].opcode, waybound_core::WebSocketOpcode::Close);
        assert_eq!(got[2].close_code, Some(1000));
    }

    #[test]
    fn http1_websocket_upgrade_with_permessage_deflate() {
        use flate2::{Compress, Compression, FlushCompress};

        let (mut corr, _, frames) = correlator("feed.example.com");
        corr.feed_client(
            b"GET /ws HTTP/1.1\r\nHost: feed.example.com\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n",
        );
        corr.feed_server(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        );
        let mut c = Compress::new(Compression::default(), false);
        for _ in 0..2 {
            let mut out = Vec::with_capacity(256);
            assert!(
                c.compress_vec(b"{\"tick\":42}", &mut out, FlushCompress::Sync)
                    .is_ok()
            );
            out.truncate(out.len().saturating_sub(4));
            let mut frame = vec![0xC1, u8::try_from(out.len()).unwrap_or(0)];
            frame.extend_from_slice(&out);
            corr.feed_server(&frame);
        }
        let got = snapshot(&frames);
        assert_eq!(got.len(), 2);
        for f in &got {
            assert!(f.compressed);
            assert_eq!(f.payload.as_deref(), Some("{\"tick\":42}"));
        }
    }

    #[test]
    fn rejected_websocket_upgrade_resumes_http_parsing() {
        let (mut corr, captured, frames) = correlator("chat.example.com");
        corr.feed_client(
            b"GET /socket HTTP/1.1\r\nHost: chat.example.com\r\nUpgrade: websocket\r\n\r\nGET /fallback HTTP/1.1\r\nHost: chat.example.com\r\n\r\n",
        );
        corr.feed_server(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let list = snapshot(&captured);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].status, 403);
        assert_eq!(list[1].url, "https://chat.example.com/fallback");
        assert_eq!(list[1].body.as_deref(), Some("ok"));
        assert!(snapshot(&frames).is_empty());
    }
}
