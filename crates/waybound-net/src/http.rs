//! Pure-Rust HTTP/1.1 and HTTP/2 + HPACK plaintext stream correlator.
//!
//! Consumes decrypted client->server and server->client byte streams from
//! [`crate::tls::PassiveTlsDecoder`], correlates request URLs with response
//! statuses, headers, and full bodies (with streaming `gzip`/`deflate`/`br`/`zstd`
//! decompression), and tracks exact inflight request counts for `networkidle`.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use flate2::read::{GzDecoder, ZlibDecoder};
use fluke_hpack::Decoder as HpackDecoder;
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use waybound_core::{
    CapturedResponse, CapturedWebSocketFrame, Http2Setting, Http2StreamDependency, HttpHeader,
    WebSocketDirection,
};

use crate::chunked::{ChunkStatus, ChunkedDecoder};
use crate::fingerprint::FingerprintRecorder;
use crate::websocket::{PerMessageDeflate, WebSocketStream};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const H2_FRAME_DATA: u8 = 0x0;
const H2_FRAME_HEADERS: u8 = 0x1;
const H2_FRAME_RST_STREAM: u8 = 0x3;
const H2_FRAME_SETTINGS: u8 = 0x4;
const H2_FRAME_GOAWAY: u8 = 0x7;
const H2_FRAME_WINDOW_UPDATE: u8 = 0x8;
const H2_FRAME_CONTINUATION: u8 = 0x9;

const H2_FLAG_ACK: u8 = 0x1;

const H2_FLAG_END_STREAM: u8 = 0x1;
const H2_FLAG_END_HEADERS: u8 = 0x4;
const H2_FLAG_PADDED: u8 = 0x8;
const H2_FLAG_PRIORITY: u8 = 0x20;

/// Maximum raw response body buffered per stream (4 MiB).
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum decompressed UTF-8 body size (16 MiB).
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
/// Largest `zstd` window a response may request (RFC 9659 caps HTTP `zstd` at 8 MiB).
const ZSTD_MAX_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
/// `zstd` frame magic number (RFC 8878 §3.1.1) as it appears on the wire.
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// Wire bytes 1..4 of a skippable frame magic (`0x184D2A5?`, RFC 8878 §3.1.2).
const ZSTD_SKIPPABLE_MAGIC_TAIL: [u8; 3] = [0x2A, 0x4D, 0x18];
/// Size of a `zstd` block header (RFC 8878 §3.1.1.2).
const ZSTD_BLOCK_HEADER_BYTES: usize = 3;
/// Size of the optional `zstd` content checksum that ends a frame.
const ZSTD_CHECKSUM_BYTES: usize = 4;
/// Empty raw block flagged `Last_Block`, followed by a placeholder content
/// checksum. Fed to the decoder in place of a block that has not fully arrived,
/// so the frame ends and the decoder releases the output held in its window.
const ZSTD_SYNTHETIC_FRAME_END: [u8; ZSTD_BLOCK_HEADER_BYTES + ZSTD_CHECKSUM_BYTES] =
    [0x01, 0, 0, 0, 0, 0, 0];
/// Maximum buffered framing bytes per direction.
const MAX_FRAME_BUFFER: usize = 4 * 1024 * 1024;
/// Maximum request body bytes retained per request, both raw and after decompression (1 MiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Maximum header fields retained per request or response header list.
pub const MAX_HEADERS_PER_MESSAGE: usize = 256;
/// Maximum total name + value bytes retained per request or response header list (64 KiB).
pub const MAX_HEADER_BYTES_PER_MESSAGE: usize = 64 * 1024;
/// HTTP/1.1 requests awaiting a response that keep their headers and body; older queued
/// requests are reduced to a URL/method placeholder so responses stay correctly paired.
pub const MAX_PENDING_H1_REQUESTS: usize = 64;
/// Hard cap on queued HTTP/1.1 requests (placeholders included). Beyond it the connection
/// is marked out of sync and responses are recorded with the fallback URL, not a wrong one.
pub const MAX_PENDING_H1_PLACEHOLDERS: usize = 1024;
/// Maximum HTTP/2 streams tracked per connection (lowest stream ID dropped first).
pub const MAX_TRACKED_H2_STREAMS: usize = 256;
/// Maximum size of an HTTP/2 header block assembled from `CONTINUATION` frames (1 MiB).
const MAX_HEADER_BLOCK_BYTES: usize = 1024 * 1024;

/// Callback invoked whenever a response is created or receives new streaming body bytes.
///
/// Every call carries the full state known so far (later calls for the same sequence ID
/// may add body bytes, trailers, a final status or late request data). Header lists and
/// the request body are shared `Arc`s, so repeated calls do not copy them.
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

// Independent per-stream flags; grouping them would not make the state machine clearer.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct H2StreamState {
    seq: u64,
    url: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    headers: Arc<[HttpHeader]>,
    body: Vec<u8>,
    request_method: Option<String>,
    request_headers: Arc<[HttpHeader]>,
    request_content_encoding: Option<String>,
    request_body: Vec<u8>,
    /// `request_body` decoded once per change (see `request_dirty`).
    request_body_text: Option<Arc<str>>,
    /// Request metadata or body changed since `request_body_text` was decoded and emitted.
    request_dirty: bool,
    client_ended: bool,
    server_ended: bool,
    inflight: bool,
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
    /// Request carried `Expect: 100-continue`.
    expect_continue: bool,
}

impl H1PendingRequest {
    /// Moves this request's URL and metadata onto the response it belongs to.
    fn attach_to(self, resp: &mut CapturedResponse) {
        resp.request_body =
            decode_request_body(&self.body, self.content_encoding.as_deref()).map(Arc::from);
        resp.url = self.url;
        resp.request_method = Some(self.method);
        resp.request_headers = self.headers.into();
    }
}

/// Progress through the body of the HTTP/1.1 request currently being sent.
#[derive(Debug)]
enum H1ClientBody {
    None,
    Length {
        id: u64,
        remaining: usize,
        /// At least one body byte has been observed.
        seen: bool,
    },
    Chunked {
        id: u64,
        decoder: ChunkedDecoder,
    },
}

/// Chunked response body being decoded in place, resumed on every server feed.
#[derive(Debug, Default)]
struct H1ResponseChunks {
    decoder: ChunkedDecoder,
    body: Vec<u8>,
    /// Bytes after the response head already fed to `decoder`.
    consumed: usize,
}

#[derive(Debug)]
struct WebSocketSession {
    client: WebSocketStream,
    server: WebSocketStream,
}

/// Bidirectional HTTP/1.1 + HTTP/2 stream correlator for a single decrypted connection.
// The flags are independent per-direction/per-protocol states, not one encoded enum.
#[allow(clippy::struct_excessive_bools)]
pub struct HttpConnectionCorrelator {
    host_fallback: String,
    mode: ProtoMode,
    c2s_buf: Vec<u8>,
    s2c_buf: Vec<u8>,
    c2s_hpack: HpackDecoder<'static>,
    s2c_hpack: HpackDecoder<'static>,
    /// Header blocks awaiting `CONTINUATION` frames, with the initial `HEADERS` flags.
    c2s_pending_headers: HashMap<u32, (u8, Vec<u8>)>,
    s2c_pending_headers: HashMap<u32, (u8, Vec<u8>)>,
    h2_streams: HashMap<u32, H2StreamState>,
    /// A client header block was skipped or failed to decode: the HPACK dynamic table is
    /// out of sync, so later client header blocks are not trusted.
    c2s_hpack_broken: bool,
    /// Same for server header blocks.
    s2c_hpack_broken: bool,
    /// Queued HTTP/1.1 requests awaiting responses on this keep-alive connection.
    h1_pending: VecDeque<H1PendingRequest>,
    h1_next_request_id: u64,
    h1_client_body: H1ClientBody,
    /// Client bytes after a WebSocket upgrade request are held until the server answers.
    h1_client_paused: bool,
    /// Requests were dropped from `h1_pending`, so responses can no longer be paired.
    h1_out_of_sync: bool,
    h1_response_chunks: Option<H1ResponseChunks>,
    h1_current_seq: u64,
    next_seq_base: u64,
    ws: Option<WebSocketSession>,
    inflight: InflightCounter,
    on_response: ResponseCallback,
    on_websocket: Option<WebSocketCallback>,
    fingerprint: Option<FingerprintRecorder>,
    /// Number of request-body decodes performed (work bound checked by tests).
    #[cfg(test)]
    request_body_decodes: usize,
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
        Self::with_fingerprint(host_fallback, seq_base, inflight, on_response, None)
    }

    /// Creates a new correlator that also records HTTP/2, header, and cookie fingerprints.
    #[must_use]
    pub fn with_fingerprint(
        host_fallback: String,
        seq_base: u64,
        inflight: InflightCounter,
        on_response: ResponseCallback,
        fingerprint: Option<FingerprintRecorder>,
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
            c2s_hpack_broken: false,
            s2c_hpack_broken: false,
            h1_pending: VecDeque::new(),
            h1_next_request_id: 0,
            h1_client_body: H1ClientBody::None,
            h1_client_paused: false,
            h1_out_of_sync: false,
            h1_response_chunks: None,
            h1_current_seq: seq_base,
            next_seq_base: seq_base,
            ws: None,
            inflight,
            on_response,
            on_websocket: None,
            fingerprint,
            #[cfg(test)]
            request_body_decodes: 0,
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
        // Held client bytes were observed before the 101 completed, so they go first;
        // this keeps cross-direction order independent of how reads were split.
        let c2s = std::mem::take(&mut self.c2s_buf);
        let s2c = std::mem::take(&mut self.s2c_buf);
        if !c2s.is_empty() {
            self.feed_websocket(WebSocketDirection::Sent, &c2s);
        }
        if !s2c.is_empty() {
            self.feed_websocket(WebSocketDirection::Received, &s2c);
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

    // ---------------------------------------------------------------- HTTP/2

    /// Ensures a state entry exists for `stream_id`, evicting the lowest stream ID when
    /// [`MAX_TRACKED_H2_STREAMS`] are already tracked.
    fn ensure_h2_stream(&mut self, stream_id: u32) {
        if self.h2_streams.contains_key(&stream_id) {
            return;
        }
        if self.h2_streams.len() >= MAX_TRACKED_H2_STREAMS
            && let Some(&oldest) = self.h2_streams.keys().min()
        {
            self.remove_h2_stream(oldest);
        }
        let seq = self.alloc_seq();
        let _ = self.h2_streams.insert(
            stream_id,
            H2StreamState {
                seq,
                ..H2StreamState::default()
            },
        );
    }

    fn remove_h2_stream(&mut self, stream_id: u32) {
        if let Some(st) = self.h2_streams.remove(&stream_id)
            && st.inflight
        {
            self.inflight.dec();
        }
        let _ = self.c2s_pending_headers.remove(&stream_id);
        let _ = self.s2c_pending_headers.remove(&stream_id);
    }

    /// Handles `RST_STREAM`: flushes request data not yet emitted, then frees the stream.
    fn reset_h2_stream(&mut self, stream_id: u32) {
        self.emit_pending_request(stream_id);
        self.remove_h2_stream(stream_id);
    }

    /// Emits the stream again if request data changed after its response started.
    fn emit_pending_request(&mut self, stream_id: u32) {
        if self
            .h2_streams
            .get(&stream_id)
            .is_some_and(|st| st.status.is_some() && st.request_dirty)
        {
            self.emit_h2_stream(stream_id);
        }
    }

    /// Frees a stream's state once both directions have ended (after its final emit).
    fn finish_h2_stream_if_done(&mut self, stream_id: u32) {
        if self
            .h2_streams
            .get(&stream_id)
            .is_some_and(|st| st.client_ended && st.server_ended)
        {
            self.remove_h2_stream(stream_id);
        }
    }

    /// Handles a `GOAWAY` sent by the server: client streams above its last processed
    /// stream ID will never complete. (A client `GOAWAY` names server-initiated streams,
    /// which are never tracked, so it is ignored.)
    fn apply_h2_server_goaway(&mut self, payload: &[u8]) {
        let Some(bytes) = payload.get(..4) else {
            return;
        };
        let last = u32::from_be_bytes([bytes[0] & 0x7F, bytes[1], bytes[2], bytes[3]]);
        let dead: Vec<u32> = self
            .h2_streams
            .keys()
            .copied()
            .filter(|&id| id > last)
            .collect();
        for id in dead {
            self.remove_h2_stream(id);
        }
    }

    fn drain_h2_client(&mut self) {
        while let Some((ftype, flags, stream_id, payload)) = pop_h2_frame(&mut self.c2s_buf) {
            if stream_id == 0 {
                if let Some(ref rec) = self.fingerprint {
                    if ftype == H2_FRAME_SETTINGS && (flags & H2_FLAG_ACK) == 0 {
                        let settings: Vec<Http2Setting> = payload
                            .as_chunks::<6>()
                            .0
                            .iter()
                            .map(|c| Http2Setting {
                                id: u16::from_be_bytes([c[0], c[1]]),
                                value: u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                            })
                            .collect();
                        rec.record_h2_settings(settings);
                    } else if ftype == H2_FRAME_WINDOW_UPDATE && payload.len() >= 4 {
                        let inc =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                                & 0x7fff_ffff;
                        rec.record_h2_window_update(inc);
                    }
                }
                continue;
            }
            match ftype {
                H2_FRAME_HEADERS => {
                    if let Some(ref rec) = self.fingerprint
                        && (flags & H2_FLAG_PRIORITY) != 0
                        && let Some(prio) = parse_h2_headers_priority(flags, &payload)
                    {
                        rec.record_h2_headers_priority(prio);
                    }
                    let Some(frag) = strip_h2_headers_payload(flags, &payload) else {
                        continue;
                    };
                    if (flags & H2_FLAG_END_HEADERS) != 0 {
                        self.apply_h2_client_headers(stream_id, frag, flags);
                    } else {
                        let _ = self
                            .c2s_pending_headers
                            .insert(stream_id, (flags, frag.to_vec()));
                    }
                }
                H2_FRAME_CONTINUATION => {
                    match take_continued_block(
                        &mut self.c2s_pending_headers,
                        stream_id,
                        flags,
                        &payload,
                    ) {
                        Continued::Pending => {}
                        Continued::Dropped => self.c2s_hpack_broken = true,
                        Continued::Complete(first_flags, block) => {
                            self.apply_h2_client_headers(stream_id, &block, first_flags);
                        }
                    }
                }
                H2_FRAME_DATA => self.apply_h2_client_data(stream_id, flags, &payload),
                H2_FRAME_RST_STREAM => self.reset_h2_stream(stream_id),
                _ => {}
            }
        }
    }

    fn apply_h2_client_data(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        let data = strip_h2_padding(flags, payload);
        let request_ended = self.h2_streams.get_mut(&stream_id).is_some_and(|st| {
            if !data.is_empty() && st.request_body.len() < MAX_REQUEST_BODY_BYTES {
                append_capped(&mut st.request_body, data, MAX_REQUEST_BODY_BYTES);
                st.request_dirty = true;
            }
            st.client_ended |= (flags & H2_FLAG_END_STREAM) != 0;
            st.client_ended
        });
        // Request bodies normally finish before the response starts; if not, re-emit once
        // the request ends so the stored response picks up the full body (decoded once).
        if request_ended {
            self.emit_pending_request(stream_id);
        }
        self.finish_h2_stream_if_done(stream_id);
    }

    /// Decodes a client header block, or returns `None` (marking the direction broken)
    /// once the HPACK dynamic table can no longer be trusted.
    fn decode_client_block(&mut self, block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.c2s_hpack_broken {
            return None;
        }
        let decoded = self.c2s_hpack.decode(block).ok();
        self.c2s_hpack_broken = decoded.is_none();
        decoded
    }

    fn apply_h2_client_headers(&mut self, stream_id: u32, block: &[u8], flags: u8) {
        let end_stream = (flags & H2_FLAG_END_STREAM) != 0;
        let Some(decoded) = self.decode_client_block(block) else {
            // Undecodable: still track the stream for network-idle, without any
            // header-derived data (a wrong URL is worse than none).
            if !self.h2_streams.contains_key(&stream_id) {
                self.ensure_h2_stream(stream_id);
                if let Some(st) = self.h2_streams.get_mut(&stream_id) {
                    st.inflight = true;
                    self.inflight.inc();
                }
            }
            if let Some(st) = self.h2_streams.get_mut(&stream_id) {
                st.client_ended |= end_stream;
            }
            self.finish_h2_stream_if_done(stream_id);
            return;
        };
        let mut authority = String::new();
        let mut path = String::new();
        let mut method = None;
        let mut content_encoding = None;
        let mut headers = Vec::new();
        let mut pseudo_order = Vec::new();
        let mut ordered_headers = Vec::new();
        for (name, value) in decoded {
            let n_str = String::from_utf8_lossy(&name).into_owned();
            let v_str = String::from_utf8_lossy(&value).into_owned();
            if n_str.starts_with(':') {
                pseudo_order.push(n_str.clone());
            }
            ordered_headers.push((n_str.clone(), v_str.clone()));
            match name.as_slice() {
                b":authority" => authority = v_str,
                b":path" => path = v_str,
                b":method" => method = Some(v_str),
                n if n.starts_with(b":") => {}
                _ => {
                    let header = HttpHeader::new(n_str, v_str);
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
            if let Some(st) = self.h2_streams.get_mut(&stream_id) {
                st.client_ended |= end_stream;
            }
            if end_stream {
                self.emit_pending_request(stream_id);
            }
            self.finish_h2_stream_if_done(stream_id);
            return;
        }
        if authority.is_empty() {
            authority.clone_from(&self.host_fallback);
        }
        if let Some(ref rec) = self.fingerprint {
            rec.record_h2_pseudo_order(pseudo_order);
            rec.record_request_headers(&authority, &ordered_headers);
        }
        let url = build_https_url(&authority, &path);
        self.ensure_h2_stream(stream_id);
        let Some(st) = self.h2_streams.get_mut(&stream_id) else {
            return;
        };
        st.url = Some(url);
        st.request_method = method;
        st.request_headers = headers.into();
        st.request_content_encoding = content_encoding;
        st.request_dirty = true;
        st.client_ended |= end_stream;
        if !st.inflight && !st.server_ended {
            st.inflight = true;
            self.inflight.inc();
        }
    }

    fn drain_h2_server(&mut self) {
        while let Some((ftype, flags, stream_id, payload)) = pop_h2_frame(&mut self.s2c_buf) {
            if stream_id == 0 {
                if ftype == H2_FRAME_GOAWAY {
                    self.apply_h2_server_goaway(&payload);
                }
                continue;
            }
            match ftype {
                H2_FRAME_HEADERS => {
                    let Some(frag) = strip_h2_headers_payload(flags, &payload) else {
                        continue;
                    };
                    if (flags & H2_FLAG_END_HEADERS) != 0 {
                        self.apply_h2_server_headers(stream_id, frag, flags);
                    } else {
                        let _ = self
                            .s2c_pending_headers
                            .insert(stream_id, (flags, frag.to_vec()));
                    }
                }
                H2_FRAME_CONTINUATION => {
                    match take_continued_block(
                        &mut self.s2c_pending_headers,
                        stream_id,
                        flags,
                        &payload,
                    ) {
                        Continued::Pending => {}
                        Continued::Dropped => {
                            self.s2c_hpack_broken = true;
                            // The dropped block's flags are lost; END_STREAM may follow as DATA.
                        }
                        Continued::Complete(first_flags, block) => {
                            self.apply_h2_server_headers(stream_id, &block, first_flags);
                        }
                    }
                }
                H2_FRAME_DATA => {
                    let data = strip_h2_padding(flags, &payload);
                    self.apply_h2_server_data(stream_id, data, flags);
                }
                H2_FRAME_RST_STREAM => self.reset_h2_stream(stream_id),
                _ => {}
            }
        }
    }

    /// Marks the server side of a stream ended, releasing its inflight slot.
    fn end_h2_server_side(&mut self, stream_id: u32) {
        if let Some(st) = self.h2_streams.get_mut(&stream_id) {
            st.server_ended = true;
            if st.inflight {
                st.inflight = false;
                self.inflight.dec();
            }
        }
    }

    fn apply_h2_server_headers(&mut self, stream_id: u32, block: &[u8], flags: u8) {
        let end_stream = (flags & H2_FLAG_END_STREAM) != 0;
        // Always decode (while the table is trusted) so the HPACK dynamic table stays in
        // sync, even for blocks that are not recorded.
        let decoded = if self.s2c_hpack_broken {
            None
        } else {
            let decoded = self.s2c_hpack.decode(block).ok();
            self.s2c_hpack_broken = decoded.is_none();
            decoded
        };
        let Some(decoded) = decoded else {
            if end_stream {
                self.end_h2_server_side(stream_id);
                self.finish_h2_stream_if_done(stream_id);
            }
            return;
        };
        let mut status = None;
        let mut content_type = None;
        let mut content_encoding = None;
        let mut headers = Vec::new();
        for (name, value) in decoded {
            let n = String::from_utf8_lossy(&name).to_ascii_lowercase();
            let v = String::from_utf8_lossy(&value).into_owned();
            match n.as_str() {
                ":status" => status = v.parse::<u16>().ok(),
                _ if n.starts_with(':') => {}
                "content-type" => content_type = Some(v.clone()),
                "content-encoding" => content_encoding = Some(v.clone()),
                _ => {}
            }
            if !n.starts_with(':') {
                push_header(&mut headers, HttpHeader::new(n, v));
            }
        }
        if status.is_some_and(|code| (100..200).contains(&code)) {
            // Interim response (e.g. `103 Early Hints`); the final header block follows.
            return;
        }
        // Never create state from a server block alone: such orphans would evict live streams.
        let Some(st) = self.h2_streams.get_mut(&stream_id) else {
            return;
        };
        if let Some(ref rec) = self.fingerprint {
            let host = st
                .url
                .as_deref()
                .and_then(extract_url_host)
                .unwrap_or(&self.host_fallback);
            for h in &headers {
                if h.name.eq_ignore_ascii_case("set-cookie") {
                    rec.record_set_cookie(host, &h.value);
                }
            }
        }
        if let Some(code) = status {
            st.status = Some(code);
            st.headers = headers.into();
        } else {
            // Trailer section: appended after the response headers.
            let mut all = st.headers.to_vec();
            for header in headers {
                push_header(&mut all, header);
            }
            st.headers = all.into();
        }
        if content_type.is_some() {
            st.content_type = content_type;
        }
        if content_encoding.is_some() {
            st.content_encoding = content_encoding;
        }
        if end_stream {
            self.end_h2_server_side(stream_id);
        }
        self.emit_h2_stream(stream_id);
        self.finish_h2_stream_if_done(stream_id);
    }

    fn apply_h2_server_data(&mut self, stream_id: u32, data: &[u8], flags: u8) {
        if let Some(st) = self.h2_streams.get_mut(&stream_id) {
            append_capped(&mut st.body, data, MAX_BODY_BYTES);
        }
        if (flags & H2_FLAG_END_STREAM) != 0 {
            self.end_h2_server_side(stream_id);
        }
        self.emit_h2_stream(stream_id);
        self.finish_h2_stream_if_done(stream_id);
    }

    /// Emits the full current state of a stream. Shared metadata (`Arc`) makes repeated
    /// emits cheap; the request body is decoded only when request data changed.
    fn emit_h2_stream(&mut self, stream_id: u32) {
        let Some(st) = self.h2_streams.get_mut(&stream_id) else {
            return;
        };
        let (Some(url), Some(status)) = (&st.url, st.status) else {
            return;
        };
        if st.request_dirty {
            st.request_body_text =
                decode_request_body(&st.request_body, st.request_content_encoding.as_deref())
                    .map(Arc::from);
            st.request_dirty = false;
            #[cfg(test)]
            {
                self.request_body_decodes += 1;
            }
        }
        let resp = CapturedResponse {
            url: url.clone(),
            status,
            content_type: st.content_type.clone(),
            body: decode_body_bytes(&st.body, st.content_encoding.as_deref()),
            headers: Arc::clone(&st.headers),
            request_method: st.request_method.clone(),
            request_headers: Arc::clone(&st.request_headers),
            request_body: st.request_body_text.clone(),
        };
        let seq = st.seq;
        (self.on_response)(seq, resp);
    }

    // ---------------------------------------------------------------- HTTP/1.1

    /// Consumes bytes of the request body currently being sent. Returns `false` when more
    /// input is needed before anything else can be parsed.
    fn drain_h1_client_body(&mut self) -> bool {
        match std::mem::replace(&mut self.h1_client_body, H1ClientBody::None) {
            H1ClientBody::None => true,
            H1ClientBody::Length {
                id,
                remaining,
                seen,
            } => {
                let take = remaining.min(self.c2s_buf.len());
                if take > 0
                    && let Some(req) = self.h1_pending.iter_mut().find(|r| r.id == id)
                {
                    append_capped(&mut req.body, &self.c2s_buf[..take], MAX_REQUEST_BODY_BYTES);
                }
                let _ = self.c2s_buf.drain(..take);
                if remaining > take {
                    self.h1_client_body = H1ClientBody::Length {
                        id,
                        remaining: remaining - take,
                        seen: seen || take > 0,
                    };
                    return false;
                }
                true
            }
            H1ClientBody::Chunked { id, mut decoder } => {
                let mut discard = Vec::new();
                let out = match self.h1_pending.iter_mut().find(|r| r.id == id) {
                    Some(req) => &mut req.body,
                    None => &mut discard,
                };
                let (used, status) = decoder.feed(&self.c2s_buf, out, MAX_REQUEST_BODY_BYTES);
                let _ = self.c2s_buf.drain(..used);
                if status == ChunkStatus::NeedMore {
                    self.h1_client_body = H1ClientBody::Chunked { id, decoder };
                    return false;
                }
                // Done, or malformed framing: resume request-head parsing either way.
                true
            }
        }
    }

    fn drain_h1_client(&mut self) {
        loop {
            if !self.drain_h1_client_body() || self.h1_client_paused {
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
            let head = parse_h1_head(lines);
            let host = head
                .headers
                .iter()
                .rev()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .map_or_else(|| self.host_fallback.clone(), |h| h.value.clone());
            let id = self.h1_next_request_id;
            self.h1_next_request_id = self.h1_next_request_id.wrapping_add(1);
            self.make_room_for_h1_request();
            if let Some(ref rec) = self.fingerprint {
                let ordered: Vec<(String, String)> = head
                    .headers
                    .iter()
                    .map(|h| (h.name.clone(), h.value.clone()))
                    .collect();
                rec.record_request_headers(&host, &ordered);
            }
            self.h1_pending.push_back(H1PendingRequest {
                id,
                url: build_https_url(&host, path),
                method,
                headers: head.headers,
                content_encoding: head.content_encoding,
                body: Vec::new(),
                websocket: head.websocket,
                expect_continue: head.expect_continue,
            });
            self.inflight.inc();
            if head.chunked {
                self.h1_client_body = H1ClientBody::Chunked {
                    id,
                    decoder: ChunkedDecoder::new(),
                };
            } else if let Some(len) = head.content_length.filter(|&n| n > 0) {
                self.h1_client_body = H1ClientBody::Length {
                    id,
                    remaining: len,
                    seen: false,
                };
            }
            if head.websocket {
                // Whatever follows is WebSocket framing if the server accepts the upgrade.
                self.h1_client_paused = true;
            }
        }
    }

    /// Keeps the pending-request queue bounded without breaking request/response pairing.
    fn make_room_for_h1_request(&mut self) {
        let len = self.h1_pending.len();
        if len >= MAX_PENDING_H1_REQUESTS
            && let Some(old) = self.h1_pending.get_mut(len - MAX_PENDING_H1_REQUESTS)
        {
            // Keep the entry (its position pairs it with a response) but drop its weight.
            old.headers = Vec::new();
            old.body = Vec::new();
            old.content_encoding = None;
        }
        if len >= MAX_PENDING_H1_PLACEHOLDERS {
            self.h1_out_of_sync = true;
            if self.h1_pending.pop_front().is_some() {
                self.inflight.dec();
            }
        }
    }

    /// Locates the body of the response whose head ends at `body_start`. Returns the raw
    /// body and the total bytes (head included) it occupies, or `None` if incomplete.
    fn h1_response_body(
        &mut self,
        head: &H1Head,
        status: u16,
        body_start: usize,
    ) -> Option<(Vec<u8>, usize)> {
        let head_request = self
            .h1_pending
            .front()
            .is_some_and(|r| r.method.eq_ignore_ascii_case("HEAD"));
        if head_request || matches!(status, 101 | 204 | 304) {
            return Some((Vec::new(), body_start));
        }
        // RFC 9112 section 6.3: chunked framing wins over a conflicting Content-Length.
        if head.chunked {
            let mut chunks = self.h1_response_chunks.take().unwrap_or_default();
            let input = self
                .s2c_buf
                .get(body_start + chunks.consumed..)
                .unwrap_or(&[]);
            let (used, state) = chunks.decoder.feed(input, &mut chunks.body, MAX_BODY_BYTES);
            chunks.consumed += used;
            if state == ChunkStatus::NeedMore {
                self.h1_response_chunks = Some(chunks);
                return None;
            }
            return Some((chunks.body, body_start + chunks.consumed));
        }
        if let Some(cl) = head.content_length {
            if self.s2c_buf.len() < body_start + cl {
                return None;
            }
            return Some((
                self.s2c_buf[body_start..body_start + cl].to_vec(),
                body_start + cl,
            ));
        }
        Some((Vec::new(), body_start))
    }

    fn drain_h1_server(&mut self) {
        let mut resume_client = false;
        while let Some(end) = find_double_crlf(&self.s2c_buf) {
            let head_text = String::from_utf8_lossy(&self.s2c_buf[..end]).into_owned();
            let mut lines = head_text.lines();
            let body_start = end + 4;
            let Some(status) = lines
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
            else {
                let _ = self.s2c_buf.drain(..body_start);
                continue;
            };
            if (100..200).contains(&status) && status != 101 {
                // Interim response (e.g. `100 Continue`); the final response follows.
                let _ = self.s2c_buf.drain(..body_start);
                continue;
            }
            let head = parse_h1_head(lines);
            let Some((raw_body, consumed)) = self.h1_response_body(&head, status, body_start)
            else {
                break;
            };
            let _ = self.s2c_buf.drain(..consumed.min(self.s2c_buf.len()));

            let request = self.h1_pending.pop_front();
            if let Some(req) = &request {
                self.inflight.dec();
                // A final status answering `Expect: 100-continue` before any body byte was
                // sent means the client will not send that body.
                if req.expect_continue
                    && let H1ClientBody::Length {
                        id, seen: false, ..
                    } = self.h1_client_body
                    && id == req.id
                {
                    self.h1_client_body = H1ClientBody::None;
                    resume_client = true;
                }
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
                content_type: head.content_type,
                body: decode_body_bytes(&raw_body, head.content_encoding.as_deref()),
                headers: head.headers.into(),
                ..CapturedResponse::default()
            };
            if let Some(req) = request
                && !self.h1_out_of_sync
            {
                req.attach_to(&mut resp);
            }
            if let Some(ref rec) = self.fingerprint {
                let host = extract_url_host(&resp.url).unwrap_or(&self.host_fallback);
                for h in resp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("set-cookie") {
                        rec.record_set_cookie(host, &h.value);
                    }
                }
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

/// Outcome of appending a `CONTINUATION` fragment to a pending header block.
enum Continued {
    /// More fragments are expected (or there was no pending block for this stream).
    Pending,
    /// `END_HEADERS` reached: initial `HEADERS` flags and the full block.
    Complete(u8, Vec<u8>),
    /// The block exceeded [`MAX_HEADER_BLOCK_BYTES`] and was discarded.
    Dropped,
}

/// Removes the pending header block for `stream_id` and appends a `CONTINUATION` fragment.
fn take_continued_block(
    pending: &mut HashMap<u32, (u8, Vec<u8>)>,
    stream_id: u32,
    flags: u8,
    fragment: &[u8],
) -> Continued {
    let Some((first_flags, mut block)) = pending.remove(&stream_id) else {
        return Continued::Pending;
    };
    if block.len() + fragment.len() > MAX_HEADER_BLOCK_BYTES {
        return Continued::Dropped;
    }
    block.extend_from_slice(fragment);
    if (flags & H2_FLAG_END_HEADERS) != 0 {
        Continued::Complete(first_flags, block)
    } else {
        let _ = pending.insert(stream_id, (first_flags, block));
        Continued::Pending
    }
}

/// Header fields of an HTTP/1.1 request or response that drive framing and decoding.
struct H1Head {
    headers: Vec<HttpHeader>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    content_length: Option<usize>,
    chunked: bool,
    websocket: bool,
    expect_continue: bool,
}

fn parse_h1_head<'a>(lines: impl Iterator<Item = &'a str>) -> H1Head {
    let mut head = H1Head {
        headers: Vec::new(),
        content_type: None,
        content_encoding: None,
        content_length: None,
        chunked: false,
        websocket: false,
        expect_continue: false,
    };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (key, val) = (k.trim(), v.trim());
        let lower = val.to_ascii_lowercase();
        match key.to_ascii_lowercase().as_str() {
            "content-type" => head.content_type = Some(val.to_owned()),
            "content-encoding" => head.content_encoding = Some(val.to_owned()),
            "content-length" => head.content_length = val.parse::<usize>().ok(),
            "transfer-encoding" if lower.contains("chunked") => head.chunked = true,
            "upgrade" if lower.contains("websocket") => head.websocket = true,
            "expect" if lower.contains("100-continue") => head.expect_continue = true,
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

/// Pushes `header` unless the list already holds [`MAX_HEADERS_PER_MESSAGE`] fields or
/// adding it would exceed [`MAX_HEADER_BYTES_PER_MESSAGE`].
fn push_header(headers: &mut Vec<HttpHeader>, header: HttpHeader) {
    if headers.len() >= MAX_HEADERS_PER_MESSAGE {
        return;
    }
    let used: usize = headers.iter().map(|h| h.name.len() + h.value.len()).sum();
    if used + header.name.len() + header.value.len() <= MAX_HEADER_BYTES_PER_MESSAGE {
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

fn parse_h2_headers_priority(flags: u8, payload: &[u8]) -> Option<Http2StreamDependency> {
    if (flags & H2_FLAG_PRIORITY) == 0 {
        return None;
    }
    let unpadded = strip_h2_padding(flags, payload);
    if unpadded.len() < 5 {
        return None;
    }
    let exclusive = (unpadded[0] & 0x80) != 0;
    let dependency_id =
        u32::from_be_bytes([unpadded[0] & 0x7F, unpadded[1], unpadded[2], unpadded[3]]);
    let weight = unpadded[4];
    Some(Http2StreamDependency {
        dependency_id,
        weight,
        exclusive,
    })
}

fn extract_url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next()?;
    if host.is_empty() { None } else { Some(host) }
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

fn build_https_url(authority: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") || authority.is_empty() {
        path.to_owned()
    } else if path.starts_with('/') {
        format!("https://{authority}{path}")
    } else {
        format!("https://{authority}/{path}")
    }
}

/// Decodes a captured request body with [`MAX_REQUEST_BODY_BYTES`] as the decoded cap.
fn decode_request_body(raw: &[u8], encoding: Option<&str>) -> Option<String> {
    decode_body_bytes_limited(raw, encoding, MAX_REQUEST_BODY_BYTES)
}

/// Like [`decode_body_bytes`], but never produces (or, for `gzip`/`deflate`/`br`, never
/// inflates) more than `limit` bytes. The result is cut on a UTF-8 character boundary.
#[must_use]
pub fn decode_body_bytes_limited(
    raw: &[u8],
    encoding: Option<&str>,
    limit: usize,
) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let limit64 = u64::try_from(limit).unwrap_or(u64::MAX);
    let enc = encoding.map(|e| e.trim().to_ascii_lowercase());
    let inflated = match enc.as_deref() {
        None | Some("" | "identity") => None,
        Some("gzip" | "x-gzip") => Some(read_limited(GzDecoder::new(raw), limit64)),
        Some("deflate") => Some(read_limited(ZlibDecoder::new(raw), limit64)),
        Some("br") => Some(read_limited(brotli::Decompressor::new(raw, 4096), limit64)),
        // Other codings are only understood by `decode_body_bytes`; cap its output.
        Some(_) => return decode_body_bytes(raw, encoding).map(|s| truncate_utf8(s, limit)),
    };
    let bytes = match inflated {
        Some(out) if !out.is_empty() => out,
        _ => raw[..limit.min(raw.len())].to_vec(),
    };
    decode_body_bytes(&bytes, None).map(|s| truncate_utf8(s, limit))
}

fn read_limited(reader: impl Read, limit: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = reader.take(limit).read_to_end(&mut out);
    out
}

fn truncate_utf8(mut text: String, limit: usize) -> String {
    if text.len() > limit {
        let mut cut = limit;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    text
}

/// Decodes raw response bytes into UTF-8 text, transparently decompressing
/// `gzip`, `deflate`, `br` (Brotli), or `zstd` and retaining partial prefixes for streaming SSE.
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
        Some("zstd") => {
            let out = decode_zstd(raw);
            if out.is_empty() && !starts_like_zstd(raw) {
                raw.to_vec()
            } else {
                out
            }
        }
        _ => raw.to_vec(),
    };
    if decompressed.is_empty() {
        // A `zstd` body whose first block has not arrived yet: no text so far.
        return None;
    }

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

/// Whether `raw` begins (or could begin, if cut short) with a `zstd` frame or
/// skippable-frame magic number, as opposed to being an unencoded body.
fn starts_like_zstd(raw: &[u8]) -> bool {
    let head = raw
        .get(..raw.len().min(ZSTD_FRAME_MAGIC.len()))
        .unwrap_or_default();
    let skippable = head.first().is_some_and(|b| b & 0xF0 == 0x50)
        && ZSTD_SKIPPABLE_MAGIC_TAIL.starts_with(head.get(1..).unwrap_or_default());
    ZSTD_FRAME_MAGIC.starts_with(head) || skippable
}

/// Decompresses one or more concatenated `zstd` frames (skipping skippable
/// frames), capped at [`MAX_DECOMPRESSED_BYTES`]. A truncated final frame still
/// yields the output of every block that arrived in full.
fn decode_zstd(raw: &[u8]) -> Vec<u8> {
    let limit = usize::try_from(MAX_DECOMPRESSED_BYTES).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(ZSTD_MAX_WINDOW_BYTES);
    let mut rest = raw;
    while !rest.is_empty() && out.len() < limit {
        // Frame_Header_Descriptor bit 2 is Content_Checksum_flag (RFC 8878 §3.1.1.1.1).
        let has_checksum = rest.get(4).is_some_and(|d| d & 0x04 != 0);
        let frame = rest;
        let frame_out_start = out.len();
        match decoder.reset(&mut rest) {
            Ok(()) => {}
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                length,
                ..
            })) => {
                rest = usize::try_from(length)
                    .ok()
                    .and_then(|len| rest.get(len..))
                    .unwrap_or_default();
                continue;
            }
            Err(_) => break,
        }
        match decode_zstd_frame(&mut decoder, &mut rest, has_checksum, &mut out, limit) {
            Ok(true) => {}
            Ok(false) => break,
            Err(remaining) => {
                // A corrupt block leaves the decoder's window unreleased and may
                // have pushed part of that block, so decode the frame again with
                // a fresh reset, ending it right before the corrupt block.
                out.truncate(frame_out_start);
                let complete_len = frame.len().saturating_sub(remaining);
                let mut patched = frame.get(..complete_len).unwrap_or_default().to_vec();
                patched.extend_from_slice(&ZSTD_SYNTHETIC_FRAME_END);
                let mut src = patched.as_slice();
                if decoder.reset(&mut src).is_ok() {
                    let _ =
                        decode_zstd_frame(&mut decoder, &mut src, has_checksum, &mut out, limit);
                }
                break;
            }
        }
    }
    out
}

/// How much of the next `zstd` block is present at the front of the input.
enum ZstdBlock {
    /// The whole block (and the frame checksum, if this block ends the frame).
    Complete,
    /// The whole block, but the frame checksum that follows it is cut short.
    MissingChecksum,
    /// The block header or body is cut short.
    Truncated,
}

/// Classifies the next block from its header without decoding it.
fn peek_zstd_block(rest: &[u8], has_checksum: bool) -> ZstdBlock {
    let Some(&[b0, b1, b2]) = rest.get(..ZSTD_BLOCK_HEADER_BYTES) else {
        return ZstdBlock::Truncated;
    };
    let header = u32::from_le_bytes([b0, b1, b2, 0]);
    let last_block = header & 1 != 0;
    let block_size = usize::try_from(header >> 3).unwrap_or(usize::MAX);
    // Block_Type 1 (RLE) stores a single byte; Raw and Compressed store Block_Size.
    let wire_size = if (header >> 1) & 0b11 == 1 {
        1
    } else {
        block_size
    };
    let block_end = ZSTD_BLOCK_HEADER_BYTES.saturating_add(wire_size);
    let checksum = if last_block && has_checksum {
        ZSTD_CHECKSUM_BYTES
    } else {
        0
    };
    if rest.len() >= block_end.saturating_add(checksum) {
        ZstdBlock::Complete
    } else if rest.len() >= block_end {
        ZstdBlock::MissingChecksum
    } else {
        ZstdBlock::Truncated
    }
}

/// Decodes the blocks of the frame whose header `decoder` has just read,
/// appending to `out` up to `limit` bytes. Returns `Ok(true)` when the frame
/// ended in full and the input may hold another frame, `Ok(false)` when decoding
/// should stop, and `Err(n)` when the block starting `n` bytes before the end of
/// the input is corrupt.
fn decode_zstd_frame(
    decoder: &mut FrameDecoder,
    rest: &mut &[u8],
    has_checksum: bool,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, usize> {
    loop {
        let remaining = rest.len();
        let result = match peek_zstd_block(rest, has_checksum) {
            ZstdBlock::Complete => {
                decoder.decode_blocks(&mut *rest, BlockDecodingStrategy::UptoBlocks(1))
            }
            ZstdBlock::MissingChecksum => {
                let padded = (*rest).chain(&ZSTD_SYNTHETIC_FRAME_END[ZSTD_BLOCK_HEADER_BYTES..]);
                *rest = &[];
                decoder.decode_blocks(padded, BlockDecodingStrategy::UptoBlocks(1))
            }
            ZstdBlock::Truncated => {
                *rest = &[];
                decoder.decode_blocks(
                    &ZSTD_SYNTHETIC_FRAME_END[..],
                    BlockDecodingStrategy::UptoBlocks(1),
                )
            }
        };
        if result.is_err() {
            return Err(remaining);
        }
        if let Some(chunk) = decoder.collect() {
            let room = limit.saturating_sub(out.len());
            out.extend_from_slice(chunk.get(..room).unwrap_or(&chunk));
        }
        if out.len() >= limit {
            return Ok(false);
        }
        if decoder.is_finished() {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

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
        let seqs: Mutex<Vec<u64>> = Mutex::new(Vec::new());
        let corr = HttpConnectionCorrelator::new(
            host.to_owned(),
            1,
            InflightCounter::default(),
            Arc::new(move |seq, resp| {
                if let (Ok(mut g), Ok(mut seen)) = (cap.lock(), seqs.lock()) {
                    if let Some(i) = seen.iter().position(|&x| x == seq) {
                        merge_update(&mut g[i], resp);
                    } else {
                        seen.push(seq);
                        g.push(resp);
                    }
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

    /// Merges a later emit for the same sequence ID, as `ResponseStore::upsert` does.
    fn merge_update(existing: &mut CapturedResponse, update: CapturedResponse) {
        existing.status = update.status;
        if update.body.is_some() {
            existing.body = update.body;
        }
        if existing.content_type.is_none() {
            existing.content_type = update.content_type;
        }
        if !update.headers.is_empty() {
            existing.headers = update.headers;
        }
        if update.request_method.is_some() {
            existing.request_method = update.request_method;
        }
        if !update.request_headers.is_empty() {
            existing.request_headers = update.request_headers;
        }
        if update.request_body.is_some() {
            existing.request_body = update.request_body;
        }
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
            list[0].request_body.as_deref().map(str::len),
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
        // The client frame held before the 101 is delivered before the server's frame.
        assert_eq!(got[0].direction, WebSocketDirection::Sent);
        assert_eq!(got[0].payload.as_deref(), Some("hello"));
        assert_eq!(got[1].direction, WebSocketDirection::Received);
        assert_eq!(got[1].payload.as_deref(), Some("hey"));
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
        assert_eq!(snapshot(&frames), Vec::new());
    }

    fn h2_request_block(enc: &mut fluke_hpack::Encoder<'_>, method: &str, path: &str) -> Vec<u8> {
        enc.encode([
            (&b":method"[..], method.as_bytes()),
            (&b":scheme"[..], &b"https"[..]),
            (&b":authority"[..], &b"h2.example.com"[..]),
            (&b":path"[..], path.as_bytes()),
        ])
    }

    fn h2_preface_with(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = H2_PREFACE.to_vec();
        for f in frames {
            out.extend_from_slice(f);
        }
        out
    }

    #[test]
    fn http2_request_body_is_decoded_once_across_many_response_frames() {
        let emits_with_request: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&emits_with_request);
        let mut corr = HttpConnectionCorrelator::new(
            "h2.example.com".to_owned(),
            1,
            InflightCounter::default(),
            Arc::new(move |_, resp| {
                if resp.request_body.is_some() || !resp.request_headers.is_empty() {
                    let _ = counter.fetch_add(1, Ordering::Relaxed);
                }
            }),
        );
        let mut c_enc = fluke_hpack::Encoder::new();
        let mut req = c_enc.encode([
            (&b":method"[..], &b"POST"[..]),
            (&b":authority"[..], &b"h2.example.com"[..]),
            (&b":path"[..], &b"/upload"[..]),
            (&b"content-type"[..], &b"text/plain"[..]),
        ]);
        let mut c2s = h2_preface_with(&[h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &req)]);
        let chunk = vec![b'p'; 16 * 1024];
        for i in 0..64 {
            let flags = if i == 63 { H2_FLAG_END_STREAM } else { 0 };
            c2s.extend(h2_frame(H2_FRAME_DATA, flags, 1, &chunk));
        }
        corr.feed_client(&c2s);
        req.clear();

        let mut s_enc = fluke_hpack::Encoder::new();
        let block = s_enc.encode([(&b":status"[..], &b"200"[..])]);
        corr.feed_server(&h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &block));
        for i in 0..2000 {
            let flags = if i == 1999 { H2_FLAG_END_STREAM } else { 0 };
            corr.feed_server(&h2_frame(H2_FRAME_DATA, flags, 1, b"data: x\n\n"));
        }
        assert_eq!(corr.request_body_decodes, 1);
        // Every emit (1 for HEADERS + 2000 for DATA) carries the shared request data.
        assert_eq!(emits_with_request.load(Ordering::Relaxed), 2001);
        // Both directions ended: the stream state (and its 1 MiB request body) is freed.
        assert_eq!(corr.h2_streams.len(), 0);
    }

    #[test]
    fn http2_streams_are_freed_on_completion_reset_goaway_and_cap() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let mut s_enc = fluke_hpack::Encoder::new();
        let mut frames = Vec::new();
        for id in [1_u32, 3, 5, 7] {
            let block = h2_request_block(&mut c_enc, "GET", &format!("/s{id}"));
            frames.push(h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                id,
                &block,
            ));
        }
        corr.feed_client(&h2_preface_with(&frames));
        assert_eq!(corr.inflight.get(), 4);

        // Stream 1 completes normally.
        let ok = s_enc.encode([(&b":status"[..], &b"204"[..])]);
        corr.feed_server(&h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            &ok,
        ));
        // Stream 3 is reset by the client.
        corr.feed_client(&h2_frame(H2_FRAME_RST_STREAM, 0, 3, &[0, 0, 0, 8]));
        // The server only processed up to stream 5.
        corr.feed_server(&h2_frame(H2_FRAME_GOAWAY, 0, 0, &[0, 0, 0, 5, 0, 0, 0, 0]));
        assert_eq!(corr.h2_streams.keys().copied().collect::<Vec<_>>(), vec![5]);
        assert_eq!(corr.inflight.get(), 1);
        assert_eq!(responses_urls(&captured), vec!["https://h2.example.com/s1"]);

        // Many concurrent streams never exceed the tracking cap.
        let mut frames = Vec::new();
        for n in 0..300_u32 {
            let block = h2_request_block(&mut c_enc, "GET", "/many");
            frames.push(h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                9 + 2 * n,
                &block,
            ));
        }
        corr.feed_client(&frames.concat());
        assert_eq!(corr.h2_streams.len(), MAX_TRACKED_H2_STREAMS);
        assert_eq!(corr.inflight.get(), MAX_TRACKED_H2_STREAMS);
    }

    fn responses_urls(captured: &Captured) -> Vec<String> {
        snapshot(captured).into_iter().map(|r| r.url).collect()
    }

    #[test]
    fn http1_many_pipelined_requests_keep_their_own_urls() {
        let (mut corr, captured, _) = correlator("api.example.com");
        for i in 0..100 {
            corr.feed_client(
                format!("GET /{i} HTTP/1.1\r\nHost: api.example.com\r\nX-N: {i}\r\n\r\n")
                    .as_bytes(),
            );
        }
        assert_eq!(corr.inflight.get(), 100);
        // Only the newest requests keep their headers; older ones are light placeholders.
        let heavy = corr
            .h1_pending
            .iter()
            .filter(|r| !r.headers.is_empty())
            .count();
        assert_eq!(heavy, MAX_PENDING_H1_REQUESTS);
        for _ in 0..100 {
            corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
        let got = snapshot(&captured);
        assert_eq!(got.len(), 100);
        for (i, resp) in got.iter().enumerate() {
            assert_eq!(resp.url, format!("https://api.example.com/{i}"));
            assert_eq!(resp.request_method.as_deref(), Some("GET"));
        }
        assert_eq!(header_values(&got[99].request_headers, "x-n"), vec!["99"]);
        assert_eq!(corr.inflight.get(), 0);
    }

    #[test]
    fn http1_queue_overflow_records_fallback_urls_not_wrong_ones() {
        let (mut corr, captured, _) = correlator("api.example.com");
        let total = MAX_PENDING_H1_PLACEHOLDERS + 6;
        for i in 0..total {
            corr.feed_client(
                format!("GET /{i} HTTP/1.1\r\nHost: api.example.com\r\n\r\n").as_bytes(),
            );
        }
        assert_eq!(corr.h1_pending.len(), MAX_PENDING_H1_PLACEHOLDERS);
        assert_eq!(corr.inflight.get(), MAX_PENDING_H1_PLACEHOLDERS);
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let got = snapshot(&captured);
        assert_eq!(got[0].url, "https://api.example.com/");
        assert_eq!(got[0].request_method, None);
    }

    #[test]
    fn client_goaway_does_not_tear_down_client_streams() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let block = h2_request_block(&mut c_enc, "GET", "/stream");
        corr.feed_client(&h2_preface_with(&[h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            &block,
        )]));
        let mut s_enc = fluke_hpack::Encoder::new();
        let resp = s_enc.encode([(&b":status"[..], &b"200"[..])]);
        let mut s2c = h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &resp);
        s2c.extend(h2_frame(H2_FRAME_DATA, 0, 1, b"part1-"));
        corr.feed_server(&s2c);
        corr.feed_client(&h2_frame(H2_FRAME_GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(corr.inflight.get(), 1);
        corr.feed_server(&h2_frame(H2_FRAME_DATA, H2_FLAG_END_STREAM, 1, b"part2"));
        assert_eq!(corr.inflight.get(), 0);
        assert_eq!(snapshot(&captured)[0].body.as_deref(), Some("part1-part2"));
    }

    /// HPACK integer with an `prefix_bits`-bit prefix (RFC 7541 section 5.1).
    fn hpack_int(first: u8, prefix_bits: u32, mut value: usize, out: &mut Vec<u8>) {
        let max = (1_usize << prefix_bits) - 1;
        if value < max {
            out.push(first | u8::try_from(value).unwrap_or(0));
            return;
        }
        out.push(first | u8::try_from(max).unwrap_or(0));
        value -= max;
        while value >= 128 {
            out.push(u8::try_from(value % 128).unwrap_or(0) | 0x80);
            value /= 128;
        }
        out.push(u8::try_from(value).unwrap_or(0));
    }

    #[test]
    fn dropped_header_block_stops_recording_header_derived_data() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let first = h2_request_block(&mut c_enc, "GET", "/old");
        // Stream 3 inserts `/new` into the encoder's table, then an oversized literal
        // (without indexing) pushes the block past the cap so the correlator drops it.
        let mut third = h2_request_block(&mut c_enc, "GET", "/new");
        third.push(0x00);
        hpack_int(0, 7, 5, &mut third);
        third.extend_from_slice(b"x-pad");
        let pad = MAX_HEADER_BLOCK_BYTES + 10;
        hpack_int(0, 7, pad, &mut third);
        third.extend(std::iter::repeat_n(b'p', pad));
        // Stream 5 references `/new` by its dynamic index; a desynced decoder would read `/old`.
        let fifth = h2_request_block(&mut c_enc, "GET", "/new");
        let mut frames = vec![h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            &first,
        )];
        let mut chunks = third.chunks(256 * 1024);
        frames.push(h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_STREAM,
            3,
            chunks.next().unwrap_or(&[]),
        ));
        let tail: Vec<&[u8]> = chunks.collect();
        for (i, chunk) in tail.iter().enumerate() {
            let flags = if i + 1 == tail.len() {
                H2_FLAG_END_HEADERS
            } else {
                0
            };
            frames.push(h2_frame(H2_FRAME_CONTINUATION, flags, 3, chunk));
        }
        frames.push(h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            5,
            &fifth,
        ));
        corr.feed_client(&h2_preface_with(&frames));
        let mut s_enc = fluke_hpack::Encoder::new();
        for id in [1_u32, 5] {
            let resp = s_enc.encode([(&b":status"[..], &b"200"[..])]);
            corr.feed_server(&h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                id,
                &resp,
            ));
        }
        assert_eq!(
            responses_urls(&captured),
            vec!["https://h2.example.com/old"]
        );
        // Stream 5 was still tracked for network-idle and released by its response.
        assert_eq!(corr.inflight.get(), 0);
    }

    #[test]
    fn late_request_data_is_emitted_on_trailers_and_reset() {
        for reset in [false, true] {
            let (mut corr, captured, _) = correlator("h2.example.com");
            let mut c_enc = fluke_hpack::Encoder::new();
            let block = h2_request_block(&mut c_enc, "POST", "/late");
            corr.feed_client(&h2_preface_with(&[h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS,
                1,
                &block,
            )]));
            let mut s_enc = fluke_hpack::Encoder::new();
            let resp = s_enc.encode([(&b":status"[..], &b"200"[..])]);
            let mut s2c = h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &resp);
            s2c.extend(h2_frame(H2_FRAME_DATA, H2_FLAG_END_STREAM, 1, b"early"));
            corr.feed_server(&s2c);
            corr.feed_client(&h2_frame(H2_FRAME_DATA, 0, 1, b"payload"));
            if reset {
                corr.feed_client(&h2_frame(H2_FRAME_RST_STREAM, 0, 1, &[0, 0, 0, 0]));
            } else {
                let trailers = c_enc.encode([(&b"x-checksum"[..], &b"1"[..])]);
                corr.feed_client(&h2_frame(
                    H2_FRAME_HEADERS,
                    H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                    1,
                    &trailers,
                ));
            }
            let got = snapshot(&captured);
            assert_eq!(got.len(), 1, "reset={reset}");
            assert_eq!(
                got[0].request_body.as_deref(),
                Some("payload"),
                "reset={reset}"
            );
            assert_eq!(corr.h2_streams.len(), 0, "reset={reset}");
        }
    }

    #[test]
    fn server_headers_without_client_state_create_nothing() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        corr.feed_client(H2_PREFACE);
        let mut s_enc = fluke_hpack::Encoder::new();
        for id in [2_u32, 4, 6] {
            let resp = s_enc.encode([(&b":status"[..], &b"200"[..])]);
            corr.feed_server(&h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, id, &resp));
        }
        assert_eq!(corr.h2_streams.len(), 0);
        assert_eq!(snapshot(&captured), Vec::new());
    }

    #[test]
    fn request_body_decoded_size_and_header_bytes_are_capped() {
        use std::fmt::Write as _;
        use std::io::Write;

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        assert!(gz.write_all(&vec![b'z'; 8 * 1024 * 1024]).is_ok());
        let body = gz.finish().unwrap_or_default();
        let (mut corr, captured, _) = correlator("api.example.com");
        let mut req = format!(
            "POST /bulk HTTP/1.1\r\nHost: api.example.com\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n",
            body.len()
        );
        for i in 0..100 {
            let _ = write!(req, "X-Big-{i}: {}\r\n", "v".repeat(1024));
        }
        req.push_str("\r\n");
        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(&body);
        corr.feed_client(&bytes);
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let got = snapshot(&captured);
        assert_eq!(
            got[0].request_body.as_deref().map(str::len),
            Some(MAX_REQUEST_BODY_BYTES)
        );
        let header_bytes: usize = got[0]
            .request_headers
            .iter()
            .map(|h| h.name.len() + h.value.len())
            .sum();
        assert!(header_bytes <= MAX_HEADER_BYTES_PER_MESSAGE);
        assert!(got[0].request_headers.len() < 100);
        assert_eq!(
            decode_body_bytes_limited("héllo".as_bytes(), None, 2).as_deref(),
            Some("h")
        );
    }

    /// Text spanning several 128 KiB `zstd` blocks that does not collapse into one sequence.
    fn multi_block_text() -> String {
        use std::fmt::Write as _;

        let mut text = String::new();
        for i in 0..40_000u32 {
            let _ = writeln!(text, "line {i}: {}", i.wrapping_mul(7919) % 10_007);
        }
        text
    }

    #[test]
    fn decodes_zstd_round_trip() {
        let payload = br#"{"flights":[{"price":419}]}"#;
        let compressed = ruzstd::encoding::compress_to_vec(
            &payload[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert_ne!(compressed.as_slice(), &payload[..]);
        assert_eq!(
            decode_body_bytes(&compressed, Some("zstd")).as_deref(),
            Some(r#"{"flights":[{"price":419}]}"#)
        );
        assert_eq!(
            decode_body_bytes(&compressed, Some(" ZSTD ")).as_deref(),
            Some(r#"{"flights":[{"price":419}]}"#)
        );

        let text = multi_block_text();
        let compressed = ruzstd::encoding::compress_to_vec(
            text.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert_eq!(
            decode_body_bytes(&compressed, Some("zstd")).as_deref(),
            Some(text.as_str())
        );
    }

    #[test]
    fn http1_chunked_request_with_extensions_and_trailers_keeps_sync() {
        let (mut corr, captured, _) = correlator("api.example.com");
        corr.feed_client(
            b"POST /a HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n",
        );
        corr.feed_client(b"0\r\nX-Sum: 1\r\n\r\nGET /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        corr.feed_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x\r\nok\r\n0\r\nT: 2\r\n\r\n",
        );
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb");
        let got = snapshot(&captured);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].request_body.as_deref(), Some("abc"));
        assert_eq!(got[0].body.as_deref(), Some("ok"));
        assert_eq!(got[1].url, "https://api.example.com/b");
        assert_eq!(got[1].body.as_deref(), Some("b"));
        assert_eq!(corr.inflight.get(), 0);
    }

    #[test]
    fn chunked_response_wins_over_content_length() {
        let (mut corr, captured, _) = correlator("api.example.com");
        corr.feed_client(b"GET /x HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        corr.feed_client(b"GET /y HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        corr.feed_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        );
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\ny");
        let got = snapshot(&captured);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].body.as_deref(), Some("hello"));
        assert_eq!(got[1].body.as_deref(), Some("y"));
    }

    #[test]
    fn expect_continue_answered_with_final_status_does_not_swallow_next_request() {
        let (mut corr, captured, _) = correlator("api.example.com");
        corr.feed_client(
            b"PUT /big HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nContent-Length: 50\r\n\r\n",
        );
        corr.feed_server(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n");
        corr.feed_client(b"GET /next HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let got = snapshot(&captured);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].status, 417);
        assert_eq!(got[1].url, "https://api.example.com/next");
        assert_eq!(corr.inflight.get(), 0);
    }

    #[test]
    fn head_response_with_content_length_has_no_body() {
        let (mut corr, captured, _) = correlator("api.example.com");
        corr.feed_client(b"HEAD /f HTTP/1.1\r\nHost: api.example.com\r\n\r\nGET /g HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
        corr.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\ng");
        let got = snapshot(&captured);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].request_method.as_deref(), Some("HEAD"));
        assert_eq!(got[0].body, None);
        assert_eq!(got[1].body.as_deref(), Some("g"));
    }

    #[test]
    fn http2_interim_103_is_not_emitted_and_final_status_wins() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let block = h2_request_block(&mut c_enc, "GET", "/page");
        corr.feed_client(&h2_preface_with(&[h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            &block,
        )]));
        let mut s_enc = fluke_hpack::Encoder::new();
        let hints = s_enc.encode([
            (&b":status"[..], &b"103"[..]),
            (&b"link"[..], &b"</a.css>; rel=preload"[..]),
        ]);
        corr.feed_server(&h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &hints));
        assert_eq!(snapshot(&captured), Vec::new());
        // The final block references the dynamic table entry added by the 103 block.
        let final_block = s_enc.encode([
            (&b":status"[..], &b"200"[..]),
            (&b"link"[..], &b"</a.css>; rel=preload"[..]),
        ]);
        corr.feed_server(&h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            1,
            &final_block,
        ));
        let got = snapshot(&captured);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].status, 200);
        assert_eq!(
            header_values(&got[0].headers, "link"),
            vec!["</a.css>; rel=preload"]
        );
    }

    #[test]
    fn decodes_concatenated_zstd_frames() {
        let mut compressed = ruzstd::encoding::compress_to_vec(
            &b"data: one\n\n"[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        compressed.extend(ruzstd::encoding::compress_to_vec(
            &b"data: two\n\n"[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        ));
        assert_eq!(
            decode_body_bytes(&compressed, Some("zstd")).as_deref(),
            Some("data: one\n\ndata: two\n\n")
        );
    }

    #[test]
    fn http2_continuation_keeps_end_stream_from_headers() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let block = h2_request_block(&mut c_enc, "DELETE", "/item/1");
        let (a, b) = block.split_at(block.len() / 2);
        corr.feed_client(&h2_preface_with(&[
            h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_STREAM, 1, a),
            h2_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, b),
        ]));
        assert_eq!(corr.inflight.get(), 1);
        let mut s_enc = fluke_hpack::Encoder::new();
        let resp = s_enc.encode([
            (&b":status"[..], &b"204"[..]),
            (&b"x-request-id"[..], &b"abc123"[..]),
        ]);
        let (a, b) = resp.split_at(resp.len() / 2);
        let mut s2c = h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_STREAM, 1, a);
        s2c.extend(h2_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, b));
        corr.feed_server(&s2c);
        assert_eq!(corr.inflight.get(), 0);
        assert_eq!(corr.h2_streams.len(), 0);
        let got = snapshot(&captured);
        assert_eq!(got[0].status, 204);
        assert_eq!(got[0].request_method.as_deref(), Some("DELETE"));
    }

    #[test]
    fn http2_padded_and_priority_frames() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let block = h2_request_block(&mut c_enc, "POST", "/p");
        let mut headers_payload = vec![3_u8];
        headers_payload.extend_from_slice(&[0x80, 0, 0, 0, 15]);
        headers_payload.extend_from_slice(&block);
        headers_payload.extend_from_slice(&[0, 0, 0]);
        let mut data_payload = vec![2_u8];
        data_payload.extend_from_slice(b"body");
        data_payload.extend_from_slice(&[0, 0]);
        corr.feed_client(&h2_preface_with(&[
            h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_PADDED | H2_FLAG_PRIORITY,
                1,
                &headers_payload,
            ),
            h2_frame(
                H2_FRAME_DATA,
                H2_FLAG_PADDED | H2_FLAG_END_STREAM,
                1,
                &data_payload,
            ),
        ]));
        let mut s_enc = fluke_hpack::Encoder::new();
        let resp = s_enc.encode([(&b":status"[..], &b"200"[..])]);
        let mut resp_payload = vec![1_u8];
        resp_payload.extend_from_slice(&resp);
        resp_payload.push(0);
        let mut s2c = h2_frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_PADDED,
            1,
            &resp_payload,
        );
        s2c.extend(h2_frame(
            H2_FRAME_DATA,
            H2_FLAG_PADDED | H2_FLAG_END_STREAM,
            1,
            &[4, b'o', b'k', 0, 0, 0, 0],
        ));
        corr.feed_server(&s2c);
        let got = snapshot(&captured);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].url, "https://h2.example.com/p");
        assert_eq!(got[0].request_body.as_deref(), Some("body"));
        assert_eq!(got[0].body.as_deref(), Some("ok"));
    }

    #[test]
    fn header_cap_keeps_hpack_dynamic_table_in_sync() {
        let (mut corr, captured, _) = correlator("h2.example.com");
        let mut c_enc = fluke_hpack::Encoder::new();
        let names: Vec<(Vec<u8>, Vec<u8>)> = (0..300)
            .map(|i| {
                (
                    format!("x-h-{i}").into_bytes(),
                    format!("v{i}").into_bytes(),
                )
            })
            .collect();
        let mut fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"GET"),
            (b":authority", b"h2.example.com"),
            (b":path", b"/one"),
        ];
        fields.extend(names.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let first = c_enc.encode(fields);
        // The second request repeats the last header, which the encoder sends as an
        // index into the dynamic table filled by the first block.
        let second_fields = [
            (&b":method"[..], &b"GET"[..]),
            (&b":authority"[..], &b"h2.example.com"[..]),
            (&b":path"[..], &b"/two"[..]),
            (&b"x-h-299"[..], &b"v299"[..]),
        ];
        let second = c_enc.encode(second_fields);
        // Shorter than a context-free encoding: it references dynamic-table entries that
        // only exist if every field of the first block (beyond the cap) was decoded.
        let fresh = fluke_hpack::Encoder::new().encode(second_fields);
        assert!(second.len() < fresh.len());
        corr.feed_client(&h2_preface_with(&[
            h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                1,
                &first,
            ),
            h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                3,
                &second,
            ),
        ]));
        let mut s_enc = fluke_hpack::Encoder::new();
        for id in [1_u32, 3] {
            let resp = s_enc.encode([(&b":status"[..], &b"200"[..])]);
            corr.feed_server(&h2_frame(
                H2_FRAME_HEADERS,
                H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                id,
                &resp,
            ));
        }
        let got = snapshot(&captured);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].request_headers.len(), MAX_HEADERS_PER_MESSAGE);
        assert_eq!(got[1].url, "https://h2.example.com/two");
        assert_eq!(
            header_values(&got[1].request_headers, "x-h-299"),
            vec!["v299"]
        );
    }

    #[test]
    fn keeps_partial_output_of_truncated_zstd_frame() {
        let text = multi_block_text();
        let compressed = ruzstd::encoding::compress_to_vec(
            text.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let truncated = &compressed[..compressed.len() * 3 / 4];
        let partial = decode_body_bytes(truncated, Some("zstd")).unwrap_or_default();
        assert_ne!(partial, "");
        assert!(partial.len() < text.len());
        assert!(text.starts_with(&partial));
    }

    #[test]
    fn caps_zstd_output_at_max_decompressed_bytes() {
        // Hand-built frame: no checksum, 1 MiB window, then RLE blocks of 128 KiB
        // of `a` adding up to more than MAX_DECOMPRESSED_BYTES.
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x50];
        let blocks = 130;
        for n in 1..=blocks {
            // Block_Header: Last_Block | Block_Type (1 = RLE) << 1 | Block_Size << 3.
            let header: u32 = u32::from(n == blocks) | (1 << 1) | (128 * 1024) << 3;
            frame.extend_from_slice(&header.to_le_bytes()[..3]);
            frame.push(b'a');
        }
        let body = decode_body_bytes(&frame, Some("zstd")).unwrap_or_default();
        assert_eq!(
            u64::try_from(body.len()).unwrap_or_default(),
            MAX_DECOMPRESSED_BYTES
        );
        assert!(body.bytes().all(|b| b == b'a'));
    }

    /// Hand-built `zstd` frame: 1 MiB window (so the decoder holds back all
    /// output until the frame ends), optional checksum, and one Raw block per
    /// chunk, the last flagged `Last_Block`.
    fn raw_block_frame(chunks: &[&[u8]], checksum: bool) -> Vec<u8> {
        let mut frame = ZSTD_FRAME_MAGIC.to_vec();
        frame.extend_from_slice(&[if checksum { 0x04 } else { 0x00 }, 0x50]);
        for (n, chunk) in chunks.iter().enumerate() {
            let last = u32::from(n + 1 == chunks.len());
            let size = u32::try_from(chunk.len()).unwrap_or_default();
            // Block_Header: Last_Block | Block_Type (0 = Raw) << 1 | Block_Size << 3.
            frame.extend_from_slice(&(last | (size << 3)).to_le_bytes()[..3]);
            frame.extend_from_slice(chunk);
        }
        if checksum {
            // ruzstd leaves checksum verification to the caller.
            frame.extend_from_slice(&[0xAB; 4]);
        }
        frame
    }

    #[test]
    fn keeps_complete_blocks_of_truncated_zstd_frame_inside_window() {
        let chunk = [b'x'; 1000];
        let frame = raw_block_frame(&[&chunk, &chunk, &chunk, &chunk], false);
        // Cut inside the last block's body, then inside its header.
        for cut in [10, 1002] {
            let truncated = &frame[..frame.len() - cut];
            let body = decode_body_bytes(truncated, Some("zstd")).unwrap_or_default();
            assert_eq!(body.len(), 3000, "cut {cut}");
            assert!(body.bytes().all(|b| b == b'x'));
        }
    }

    #[test]
    fn keeps_last_zstd_block_when_only_checksum_is_cut() {
        let frame = raw_block_frame(&[b"data: one\n\n", b"data: two\n\n"], true);
        for cut in 0..=4 {
            assert_eq!(
                decode_body_bytes(&frame[..frame.len() - cut], Some("zstd")).as_deref(),
                Some("data: one\n\ndata: two\n\n"),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn skips_skippable_zstd_frames() {
        let skippable = [0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 0xDE, 0xAD, 0xBE];
        let mut body = skippable.to_vec();
        body.extend(raw_block_frame(&[b"data: one\n\n"], false));
        body.extend_from_slice(&skippable);
        body.extend(raw_block_frame(&[b"data: two\n\n"], true));
        assert_eq!(
            decode_body_bytes(&body, Some("zstd")).as_deref(),
            Some("data: one\n\ndata: two\n\n")
        );
    }

    #[test]
    fn http1_results_do_not_depend_on_read_split_points() {
        let client: &[u8] = b"POST /a HTTP/1.1\r\nHost: s.test\r\nContent-Length: 5\r\n\r\nhelloPUT /b HTTP/1.1\r\nHost: s.test\r\nTransfer-Encoding: chunked\r\n\r\n2;e\r\nhi\r\n0\r\nT: x\r\n\r\nHEAD /c HTTP/1.1\r\nHost: s.test\r\n\r\nGET /d HTTP/1.1\r\nHost: s.test\r\n\r\n";
        let server: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nnew\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nHTTP/1.1 304 Not Modified\r\nETag: \"e\"\r\n\r\n";
        let run = |client_cut: usize, server_cut: usize| {
            let (mut corr, captured, _) = correlator("s.test");
            corr.feed_client(&client[..client_cut]);
            corr.feed_client(&client[client_cut..]);
            corr.feed_server(&server[..server_cut]);
            corr.feed_server(&server[server_cut..]);
            (snapshot(&captured), corr.inflight.get())
        };
        let (baseline, inflight) = run(client.len(), server.len());
        assert_eq!(baseline.len(), 4);
        assert_eq!(inflight, 0);
        assert_eq!(baseline[1].request_body.as_deref(), Some("hi"));
        assert_eq!(baseline[1].body.as_deref(), Some("new"));
        assert_eq!(baseline[3].status, 304);
        for cut in 0..=client.len() {
            assert_eq!(run(cut, server.len()).0, baseline, "client cut {cut}");
        }
        for cut in 0..=server.len() {
            assert_eq!(run(client.len(), cut).0, baseline, "server cut {cut}");
        }
    }

    #[test]
    fn zstd_body_without_complete_block_yields_none() {
        let frame = raw_block_frame(&[b"data: one\n\n"], false);
        for cut in [2, 6, 9, 13] {
            assert_eq!(
                decode_body_bytes(&frame[..cut], Some("zstd")),
                None,
                "cut {cut}"
            );
        }
        assert_eq!(decode_body_bytes(&[0x5A, 0x2A], Some("zstd")), None);
        // A body that is not zstd at all is still passed through as-is.
        assert_eq!(
            decode_body_bytes(b"plain text", Some("zstd")).as_deref(),
            Some("plain text")
        );
    }

    #[test]
    fn keeps_blocks_before_corrupt_zstd_block() {
        let good = raw_block_frame(&[b"aaaa", b"bbbb", b"cccc", b""], false);
        // Drop the empty last block (3 bytes) and replace it with a corrupt one.
        let prefix = &good[..good.len() - 3];

        // Block_Type 3 (reserved), Block_Size 4, body present.
        let mut reserved = prefix.to_vec();
        reserved.extend_from_slice(&[0x26, 0x00, 0x00, 1, 2, 3, 4]);
        assert_eq!(
            decode_body_bytes(&reserved, Some("zstd")).as_deref(),
            Some("aaaabbbbcccc")
        );

        // Raw block declaring 200000 bytes (over the 128 KiB block maximum), body present.
        let mut oversized = prefix.to_vec();
        let header: u32 = 1 | (200_000 << 3);
        oversized.extend_from_slice(&header.to_le_bytes()[..3]);
        oversized.extend(std::iter::repeat_n(b'z', 200_000));
        assert_eq!(
            decode_body_bytes(&oversized, Some("zstd")).as_deref(),
            Some("aaaabbbbcccc")
        );
    }
}
