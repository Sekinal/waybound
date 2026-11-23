//! Passive wire-level TLS/HTTP response tap powered by `SSLKEYLOGFILE` + `tshark`.
//!
//! Only used when attaching to a desktop browser the daemon did not launch; a launched
//! browser is tapped in-process by the loopback forwarder (`waybound-net`), which also feeds
//! the [`ResponseStore`] defined here.
//!
//! Decrypts HTTP/1.1 and HTTP/2 responses off the wire without MITM certificates, proxies,
//! or CDP, decompressing `gzip`, `deflate`, `br` (Brotli), and `zstd` payloads. HTTP/3 is
//! parsed on a best-effort basis but has never been verified against a real capture.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use waybound_core::{CapturedResponse, CapturedWebSocketFrame, Result, WayboundError};
use waybound_net::decode_body_bytes;

const MAX_CAPTURED_RESPONSES: usize = 500;
/// Maximum retained WebSocket messages across all connections (oldest dropped first).
const MAX_CAPTURED_WS_FRAMES: usize = 1_000;
const MAX_PENDING_STREAMS: usize = 1_000;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_WAIT_MS: u64 = 120_000;
/// A matched response is returned once its body has stopped growing for this long.
const BODY_SETTLE: Duration = Duration::from_millis(150);
/// How long to wait for a body after headers before returning a body-less response.
const BODY_GRACE: Duration = Duration::from_millis(500);

struct StoredResponse {
    /// Correlator stream sequence ID (monotonically increasing in arrival order).
    seq: u64,
    response: CapturedResponse,
    first_seen: Instant,
    updated: Instant,
}

#[derive(Default)]
struct StoreInner {
    entries: VecDeque<StoredResponse>,
    websocket_frames: VecDeque<CapturedWebSocketFrame>,
    /// Highest stream sequence ID ever stored; the baseline for [`ResponseStore::wait_for`].
    last_seq: u64,
    /// Set when the `tshark` capture died; [`ResponseStore::wait_for`] reports it instead of
    /// timing out (responses captured before stay listable).
    capture_error: Option<String>,
}

/// Thread-safe store of passively decrypted HTTP responses keyed by stream sequence ID,
/// plus a bounded log of decrypted WebSocket messages.
#[derive(Default)]
pub struct ResponseStore {
    inner: Mutex<StoreInner>,
}

impl ResponseStore {
    /// Inserts a new captured response or updates the exact same stream (`stream_seq`)
    /// when streaming `DATA` frames arrive after initial `HEADERS`.
    pub fn upsert(&self, stream_seq: u64, resp: CapturedResponse) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let now = Instant::now();
        if let Some(existing) = guard.entries.iter_mut().rev().find(|e| e.seq == stream_seq) {
            if resp.body.is_some() {
                existing.response.body = resp.body;
                existing.updated = now;
            }
            // A final status replaces an earlier one for the same stream.
            existing.response.status = resp.status;
            if existing.response.content_type.is_none() {
                existing.response.content_type = resp.content_type;
            }
            if !resp.headers.is_empty() {
                existing.response.headers = resp.headers;
            }
            if resp.request_method.is_some() {
                existing.response.request_method = resp.request_method;
            }
            if !resp.request_headers.is_empty() {
                existing.response.request_headers = resp.request_headers;
            }
            if resp.request_body.is_some() {
                existing.response.request_body = resp.request_body;
            }
            return;
        }
        if guard.entries.len() >= MAX_CAPTURED_RESPONSES {
            let _ = guard.entries.pop_front();
        }
        guard.last_seq = guard.last_seq.max(stream_seq);
        guard.entries.push_back(StoredResponse {
            seq: stream_seq,
            response: resp,
            first_seen: now,
            updated: now,
        });
    }

    /// Records that the capture feeding this store has stopped for good.
    pub fn mark_capture_failed(&self, reason: String) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.capture_error = Some(reason);
        }
    }

    /// Why the capture feeding this store stopped, if it did.
    #[must_use]
    pub fn capture_error(&self) -> Option<String> {
        self.inner.lock().ok().and_then(|g| g.capture_error.clone())
    }

    /// Appends a decrypted WebSocket message, dropping the oldest once
    /// [`MAX_CAPTURED_WS_FRAMES`] are retained.
    pub fn push_websocket_frame(&self, frame: CapturedWebSocketFrame) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard.websocket_frames.len() >= MAX_CAPTURED_WS_FRAMES {
            let _ = guard.websocket_frames.pop_front();
        }
        guard.websocket_frames.push_back(frame);
    }

    /// Returns captured WebSocket messages (oldest first), optionally filtered by
    /// case-insensitive URL substring and limited to the most recent `limit` matches.
    #[must_use]
    pub fn list_websocket_frames(
        &self,
        url_contains: Option<&str>,
        limit: Option<usize>,
    ) -> Vec<CapturedWebSocketFrame> {
        let needle = url_contains.map(str::to_lowercase);
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        let mut newest_first: Vec<CapturedWebSocketFrame> = guard
            .websocket_frames
            .iter()
            .rev()
            .filter(|f| {
                needle
                    .as_ref()
                    .is_none_or(|n| f.url.to_lowercase().contains(n))
            })
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        newest_first.reverse();
        newest_first
    }

    /// Returns all captured responses, optionally filtered by case-insensitive URL substring.
    #[must_use]
    pub fn list(&self, url_contains: Option<&str>) -> Vec<CapturedResponse> {
        let needle = url_contains.map(str::to_lowercase);
        self.inner.lock().map_or_else(
            |_| Vec::new(),
            |guard| {
                guard
                    .entries
                    .iter()
                    .map(|e| &e.response)
                    .filter(|r| {
                        needle
                            .as_ref()
                            .is_none_or(|n| r.url.to_lowercase().contains(n))
                    })
                    .cloned()
                    .collect()
            },
        )
    }

    /// Waits for the first response matching `url_contains` that is captured *after* this
    /// call starts, or until `timeout_ms` elapses.
    ///
    /// Responses already in the store are ignored, so start waiting before triggering the
    /// request (as with Playwright's `expect_response`). Once a match is seen, the call
    /// keeps waiting until its body has stopped growing for [`BODY_SETTLE`], or returns it
    /// without a body after [`BODY_GRACE`] (for example `204`/`304` responses).
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::Timeout`] if no matching response is observed in time, or
    /// [`WayboundError::BackendUnavailable`] once the capture feeding the store has died.
    pub fn wait_for(&self, url_contains: &str, timeout_ms: u64) -> Result<CapturedResponse> {
        let clamped_ms = timeout_ms.min(MAX_WAIT_MS);
        let needle = url_contains.to_lowercase();
        let deadline = Instant::now() + Duration::from_millis(clamped_ms);
        let baseline = self.inner.lock().map_or(0, |g| g.last_seq);

        loop {
            let now = Instant::now();
            let expired = now >= deadline;
            if let Ok(guard) = self.inner.lock()
                && let Some(found) = guard
                    .entries
                    .iter()
                    .find(|e| e.seq > baseline && e.response.url.to_lowercase().contains(&needle))
            {
                let settled = if found.response.body.is_some() {
                    now.duration_since(found.updated) >= BODY_SETTLE
                } else {
                    now.duration_since(found.first_seen) >= BODY_GRACE
                };
                if settled || expired {
                    return Ok(found.response.clone());
                }
            } else if let Some(reason) = self.capture_error() {
                return Err(capture_unavailable(reason));
            } else if expired {
                return Err(WayboundError::Timeout {
                    timeout_ms: clamped_ms,
                    context: format!("no captured HTTP response matched {url_contains:?}"),
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

fn capture_unavailable(reason: String) -> WayboundError {
    WayboundError::BackendUnavailable {
        backend: "net_tap".to_owned(),
        reason,
    }
}

/// RAII owner of the background passive `tshark` capture process.
pub struct PassiveTap {
    child: Child,
    /// Set before the process is killed so the reader does not report the EOF as a failure.
    stopping: Arc<AtomicBool>,
}

impl Drop for PassiveTap {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// HTTP/1.x requests remembered per connection to pair pipelined responses in order.
const MAX_H1_QUEUED_REQUESTS: usize = 16;

#[derive(Debug, Default)]
struct PendingStream {
    seq: u64,
    url: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    body: Vec<u8>,
    emitted: bool,
    /// Source port of the side that sent the response status; only its frames are body bytes.
    response_src: Option<String>,
    /// HTTP/1.x requests on this connection still waiting for their response, as
    /// (`frame.number` of the packet that completed the request, URI).
    h1_requests: VecDeque<(Option<u64>, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H1Message {
    /// A request completed in the packet with this `frame.number`.
    Request { frame: Option<u64> },
    /// A response; `request_in` is tshark's `http.request_in` (the request's `frame.number`).
    Response { request_in: Option<u64> },
}

/// The HTTP-level fields of one protocol instance in a `tshark -T ek` packet: one HTTP/2 or
/// HTTP/3 frame, or one HTTP/1.x message. A TCP segment can carry several HTTP/2 frames of
/// different streams; `-T ek` keeps each frame as its own object, so nothing has to be
/// aligned by position across fields.
#[derive(Debug, Default)]
struct FrameFields {
    /// Correlation key: `h1:<tcp.stream>`, `h2:<tcp.stream>:<stream id>` or
    /// `h3:<udp.stream>:<stream id>`.
    key: String,
    /// Source port of the segment carrying this frame, which tells the two directions apart.
    src_port: Option<String>,
    h1: Option<H1Message>,
    url: Option<String>,
    /// Final (non-1xx, or `101`) response status; interim responses are dropped when parsing.
    status_code: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    body_hex: Option<String>,
    /// `body_hex` is the whole reassembled body (tshark's `http2.body.reassembled.data` on the
    /// `END_STREAM` frame) rather than one more chunk, so it replaces what was collected.
    body_complete: bool,
}

/// Stateful correlator turning `tshark -T ek` lines into [`CapturedResponse`] items.
#[derive(Default)]
struct StreamCorrelator {
    next_seq: u64,
    streams: HashMap<String, PendingStream>,
}

impl StreamCorrelator {
    const fn alloc_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// Drops the oldest quarter of tracked streams (by sequence ID) so recent, possibly
    /// in-flight streams survive when the map is full. Finished streams are never signalled
    /// by the field output, so age is the only eviction signal available.
    fn evict_oldest_streams(&mut self) {
        let mut seqs: Vec<u64> = self.streams.values().map(|s| s.seq).collect();
        seqs.sort_unstable();
        let Some(&cutoff) = seqs.get(seqs.len() / 4) else {
            return;
        };
        self.streams.retain(|_, s| s.seq > cutoff);
    }

    /// Feeds one line of `tshark -T ek` output (one packet; index lines are ignored).
    fn ingest_line(&mut self, line: &str, store: &ResponseStore) {
        let Ok(packet) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let Some(layers) = packet.get("layers") else {
            return;
        };
        for frame in frames_from_ek_layers(layers) {
            self.ingest_frame(frame, store);
        }
    }

    /// Applies the message's URL to the stream and, for HTTP/1.x, the request queue or the new
    /// exchange. Returns `false` when the frame needs no further processing (an HTTP/1.x
    /// request).
    fn route_message(&mut self, key: &str, h1: Option<H1Message>, url: Option<String>) -> bool {
        match h1 {
            Some(H1Message::Request { frame }) => {
                if let (Some(entry), Some(uri)) = (self.streams.get_mut(key), url) {
                    if entry.h1_requests.len() >= MAX_H1_QUEUED_REQUESTS {
                        let _ = entry.h1_requests.pop_front();
                    }
                    entry.h1_requests.push_back((frame, uri));
                }
                false
            }
            Some(H1Message::Response { request_in }) => {
                // Each HTTP/1.x response is a new exchange on the keep-alive connection.
                // Never recycle `entry.url` from the previous exchange if this response's
                // request was missed and tshark did not supply `http.request.full_uri`.
                let fresh_seq = self.alloc_seq();
                if let Some(entry) = self.streams.get_mut(key) {
                    let uri = pair_h1_response(&mut entry.h1_requests, request_in).or(url);
                    *entry = PendingStream {
                        seq: fresh_seq,
                        url: uri,
                        h1_requests: std::mem::take(&mut entry.h1_requests),
                        ..PendingStream::default()
                    };
                }
                true
            }
            None => {
                if let (Some(entry), Some(u)) = (self.streams.get_mut(key), url) {
                    entry.url = Some(u);
                }
                true
            }
        }
    }

    fn ingest_frame(&mut self, frame: FrameFields, store: &ResponseStore) {
        let FrameFields {
            key,
            src_port,
            h1,
            url,
            status_code,
            content_type,
            content_encoding,
            body_hex,
            body_complete,
        } = frame;

        if self.streams.len() >= MAX_PENDING_STREAMS && !self.streams.contains_key(&key) {
            self.evict_oldest_streams();
        }
        if !self.streams.contains_key(&key) {
            let seq = self.alloc_seq();
            let _ = self.streams.insert(
                key.clone(),
                PendingStream {
                    seq,
                    ..PendingStream::default()
                },
            );
        }

        if !self.route_message(&key, h1, url) {
            // Request bodies are never response bodies.
            return;
        }

        let Some(entry) = self.streams.get_mut(&key) else {
            return;
        };

        if let Some(code) = status_code {
            entry.status = Some(code);
            if src_port.is_some() {
                entry.response_src.clone_from(&src_port);
            }
        }

        // Headers and payload count only once the response status is known, and only from
        // the side that sent it, so request bodies (including tshark's reassembled request
        // body on the client's END_STREAM frame) never leak into the response.
        let from_responder = entry.status.is_some()
            && match (&entry.response_src, &src_port) {
                (Some(responder), Some(src)) => responder == src,
                _ => true,
            };

        if from_responder {
            if let Some(ct) = content_type {
                entry.content_type = Some(ct);
            }
            if let Some(ce) = content_encoding {
                entry.content_encoding = Some(ce);
            }
        }

        let body_updated = if from_responder && let Some(hex) = body_hex {
            if body_complete {
                let mut full = Vec::new();
                append_hex_bytes(&hex, &mut full, MAX_BODY_BYTES);
                let changed = full != entry.body;
                entry.body = full;
                changed
            } else if entry.body.len() < MAX_BODY_BYTES {
                let before = entry.body.len();
                append_hex_bytes(&hex, &mut entry.body, MAX_BODY_BYTES);
                entry.body.len() > before
            } else {
                false
            }
        } else {
            false
        };

        if let (Some(url), Some(status)) = (&entry.url, entry.status)
            && (!entry.emitted || body_updated)
        {
            let body = decode_body_bytes(&entry.body, entry.content_encoding.as_deref());
            store.upsert(
                entry.seq,
                CapturedResponse {
                    url: url.clone(),
                    status,
                    content_type: entry.content_type.clone(),
                    body,
                    ..CapturedResponse::default()
                },
            );
            entry.emitted = true;
        }
    }
}

/// Pairs an HTTP/1.x response with its request.
///
/// tshark links a response to the packet that completed its request (`http.request_in`), so
/// requests queued from earlier packets are answers that were never captured and are dropped;
/// pairing purely by order would shift every later URL after one lost response. Pipelined
/// requests completed in the same packet share that frame number and are taken in order
/// (tshark gives only the first of such responses a `request_in`, and mislabels its URI).
/// Returns `None` when the request itself was not captured, so tshark's URI is used.
fn pair_h1_response(
    queue: &mut VecDeque<(Option<u64>, String)>,
    request_in: Option<u64>,
) -> Option<String> {
    if let Some(request_frame) = request_in {
        while queue
            .front()
            .is_some_and(|(frame, _)| frame.is_some_and(|f| f < request_frame))
        {
            let _ = queue.pop_front();
        }
    }
    let matches = queue
        .front()
        .is_some_and(|(frame, _)| match (request_in, frame) {
            (Some(wanted), Some(queued)) => *queued == wanted,
            _ => true,
        });
    if matches {
        queue.pop_front().map(|(_, uri)| uri)
    } else {
        None
    }
}

/// Protocol layers kept by `tshark -T ek -J`: only these top-level layers are written, each
/// with all of its child fields (packet selection is `-Y`'s job). Each HTTP/2 frame, HTTP/3
/// frame and HTTP/1.x message becomes its own object under `layers.<proto>` (an array when a
/// packet carries several), with keys named `<proto>_<field with '.' replaced by '_'>`.
const EK_PROTOCOLS: &str = "frame tcp udp quic http http2 http3";

/// The objects of one protocol layer, which `-T ek` emits as a single object or as an array
/// of objects when the protocol occurs several times in the packet.
fn ek_layer<'a>(layers: &'a Value, proto: &str) -> &'a [Value] {
    match layers.get(proto) {
        Some(Value::Array(items)) => items,
        Some(value @ Value::Object(_)) => std::slice::from_ref(value),
        _ => &[],
    }
}

/// The scalar values of an ek field: a string or number, or an array of them when the field
/// occurs several times within the object.
fn ek_strs<'a>(obj: &'a Value, key: &str) -> impl Iterator<Item = Cow<'a, str>> {
    let items: &'a [Value] = match obj.get(key) {
        Some(Value::Array(items)) => items,
        Some(value) => std::slice::from_ref(value),
        None => &[],
    };
    items.iter().filter_map(|value| match value {
        Value::String(s) => Some(Cow::Borrowed(s.as_str())),
        Value::Number(n) => Some(Cow::Owned(n.to_string())),
        _ => None,
    })
}

/// The first non-empty value of an ek field, trimmed.
fn ek_str(obj: &Value, key: &str) -> Option<String> {
    ek_strs(obj, key).find_map(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn ek_u64(obj: &Value, key: &str) -> Option<u64> {
    ek_str(obj, key).and_then(|s| s.parse::<u64>().ok())
}

/// A response status, ignoring interim `1xx` responses other than `101 Switching Protocols`.
fn ek_final_status(obj: &Value, key: &str) -> Option<u16> {
    ek_str(obj, key)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|code| !(100..200).contains(code) || *code == 101)
}

/// Splits one `tshark -T ek` packet into per-frame / per-message fields, in wire order.
fn frames_from_ek_layers(layers: &Value) -> Vec<FrameFields> {
    let mut frames = Vec::new();
    let tcp = ek_layer(layers, "tcp").first();
    let udp = ek_layer(layers, "udp").first();

    if let Some(tcp) = tcp
        && let Some(tcp_stream) = ek_str(tcp, "tcp_tcp_stream")
    {
        let src_port = ek_str(tcp, "tcp_tcp_srcport");
        let frame_number = ek_layer(layers, "frame")
            .first()
            .and_then(|f| ek_u64(f, "frame_frame_number"));

        for msg in ek_layer(layers, "http") {
            let uri = ek_str(msg, "http_http_request_full_uri");
            let kind = if msg.get("http_http_response_code").is_some() {
                // Interim 1xx responses carry no body of their own; skip them entirely.
                if ek_final_status(msg, "http_http_response_code").is_none() {
                    continue;
                }
                H1Message::Response {
                    request_in: ek_u64(msg, "http_http_request_in"),
                }
            } else if uri.is_some() {
                H1Message::Request {
                    frame: frame_number,
                }
            } else {
                continue;
            };
            frames.push(FrameFields {
                key: format!("h1:{tcp_stream}"),
                src_port: src_port.clone(),
                h1: Some(kind),
                url: uri,
                status_code: ek_final_status(msg, "http_http_response_code"),
                content_type: ek_str(msg, "http_http_content_type"),
                content_encoding: ek_str(msg, "http_http_content_encoding"),
                body_hex: ek_str(msg, "http_http_file_data"),
                body_complete: false,
            });
        }

        for frame in ek_layer(layers, "http2") {
            // Stream 0 carries connection-level frames (SETTINGS, PING, WINDOW_UPDATE...).
            let Some(stream_id) = ek_str(frame, "http2_http2_streamid").filter(|s| s != "0") else {
                continue;
            };
            let reassembled = ek_str(frame, "http2_http2_body_reassembled_data");
            let body_complete = reassembled.is_some();
            let body_hex = reassembled.or_else(|| ek_str(frame, "http2_http2_data_data"));
            frames.push(FrameFields {
                key: format!("h2:{tcp_stream}:{stream_id}"),
                src_port: src_port.clone(),
                h1: None,
                url: frame_url(
                    frame,
                    "http2_http2_headers_authority",
                    "http2_http2_headers_path",
                )
                .or_else(|| ek_str(frame, "http2_http2_request_full_uri")),
                status_code: ek_final_status(frame, "http2_http2_headers_status"),
                content_type: ek_str(frame, "http2_http2_headers_content_type"),
                content_encoding: ek_str(frame, "http2_http2_headers_content_encoding"),
                body_hex,
                body_complete,
            });
        }
    }

    if let Some(udp) = udp
        && let Some(udp_stream) = ek_str(udp, "udp_udp_stream")
    {
        let src_port = ek_str(udp, "udp_udp_srcport");
        frames.extend(http3_frames(layers, &udp_stream, src_port.as_deref()));
    }
    frames
}

/// HTTP/3 frames of one datagram. Unverified against a real capture: HTTP/3 frames do not
/// carry their QUIC stream ID in tshark's output, so they are attributed only when the
/// datagram holds a single request stream (client-initiated bidirectional, id % 4 == 0); a
/// datagram multiplexing several request streams is skipped rather than mixed.
fn http3_frames(layers: &Value, udp_stream: &str, src_port: Option<&str>) -> Vec<FrameFields> {
    let h3 = ek_layer(layers, "http3");
    if h3.is_empty() {
        return Vec::new();
    }
    let mut request_streams: Vec<u64> = ek_layer(layers, "quic")
        .iter()
        .flat_map(|q| ek_strs(q, "quic_quic_stream_stream_id"))
        .filter_map(|id| id.trim().parse::<u64>().ok())
        .filter(|id| id % 4 == 0)
        .collect();
    request_streams.sort_unstable();
    request_streams.dedup();
    let [stream_id] = request_streams.as_slice() else {
        tracing::debug!(
            streams = request_streams.len(),
            "skipping HTTP/3 datagram with ambiguous request stream"
        );
        return Vec::new();
    };
    h3.iter()
        .map(|frame| FrameFields {
            key: format!("h3:{udp_stream}:{stream_id}"),
            src_port: src_port.map(str::to_owned),
            h1: None,
            url: frame_url(
                frame,
                "http3_http3_headers_authority",
                "http3_http3_headers_path",
            ),
            status_code: ek_final_status(frame, "http3_http3_headers_status"),
            content_type: ek_str(frame, "http3_http3_headers_content_type"),
            content_encoding: ek_str(frame, "http3_http3_headers_content_encoding"),
            body_hex: ek_str(frame, "http3_http3_data"),
            body_complete: false,
        })
        .collect()
}

/// Builds `https://<authority><path>` from a request `HEADERS` frame, if it has either.
fn frame_url(frame: &Value, authority_key: &str, path_key: &str) -> Option<String> {
    let authority = ek_str(frame, authority_key).unwrap_or_default();
    let path = ek_str(frame, path_key).unwrap_or_default();
    (!authority.is_empty() || !path.is_empty()).then(|| build_https_url(&authority, &path))
}

fn build_https_url(authority: &str, path: &str) -> String {
    if authority.is_empty() {
        path.to_owned()
    } else if path.starts_with('/') {
        format!("https://{authority}{path}")
    } else {
        format!("https://{authority}/{path}")
    }
}

/// Streams hex nibbles directly into `out` with zero intermediate allocation,
/// stopping immediately once `out.len() >= max_bytes`.
fn append_hex_bytes(hex: &str, out: &mut Vec<u8>, max_bytes: usize) {
    let mut pending_hi: Option<u8> = None;
    for byte in hex.bytes() {
        if out.len() >= max_bytes {
            break;
        }
        let Some(nibble) = hex_nibble(byte) else {
            continue;
        };
        if let Some(hi) = pending_hi.take() {
            out.push((hi << 4) | nibble);
        } else {
            pending_hi = Some(nibble);
        }
    }
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LineRead {
    Eof,
    Line,
    /// The line exceeded the cap; it was discarded up to and including its newline.
    Oversized,
}

/// Reads one `\n`-terminated line into `buf` (without the newline), never buffering more than
/// `cap + 1` bytes of it.
fn read_capped_line(
    reader: &mut impl BufRead,
    buf: &mut Vec<u8>,
    cap: usize,
) -> io::Result<LineRead> {
    buf.clear();
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let read = reader.by_ref().take(limit).read_until(b'\n', buf)?;
    if read == 0 {
        return Ok(LineRead::Eof);
    }
    if buf.last() == Some(&b'\n') {
        let _ = buf.pop();
        return Ok(LineRead::Line);
    }
    if buf.len() <= cap {
        // Final line without a trailing newline.
        return Ok(LineRead::Line);
    }
    buf.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if available.is_empty() {
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        reader.consume(len);
    }
    Ok(LineRead::Oversized)
}

/// Well-known install locations checked after `PATH`, for daemons started with a minimal
/// environment (launchd, IDEs, GUI apps). Keep in sync with `waybound doctor` (`cli.py`).
#[cfg(not(windows))]
const TSHARK_FALLBACK_PATHS: &[&str] = &[
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
    "/opt/local/bin/tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/run/current-system/sw/bin/tshark",
];
#[cfg(windows)]
const TSHARK_FALLBACK_PATHS: &[&str] = &[r"C:\Program Files\Wireshark\tshark.exe"];

/// Longest `tshark` output line accepted. Bodies are colon-separated hex (3 bytes per body
/// byte), and the `END_STREAM` frame carries both `http2.data.data` and the reassembled body,
/// so a body near [`MAX_BODY_BYTES`] makes a line of about six times that.
const MAX_EK_LINE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STDERR_LINE_BYTES: usize = 64 * 1024;
/// Lines of `tshark` stderr kept for error messages.
const STDERR_TAIL_LINES: usize = 20;
/// How long to wait for `tshark` to report `Capturing on ...` (or to exit) at startup. It runs
/// before the daemon binds its socket, so together with [`STARTUP_GRACE`] it must stay well
/// under the SDK's default `startup_timeout_s` (5 s).
const STARTUP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long `tshark` must stay alive after `Capturing on ...`: it prints that line before
/// dumpcap has opened the device, so a missing interface or permission fails just after it.
const STARTUP_GRACE: Duration = Duration::from_secs(1);
/// How long to wait for the stderr reader to drain after `tshark` exits during startup.
const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Absolute directories of a `PATH`-style variable. Empty and relative entries (which would
/// resolve against the daemon's working directory) are skipped.
fn absolute_path_dirs(path_var: Option<&OsStr>) -> Vec<PathBuf> {
    path_var
        .into_iter()
        .flat_map(env::split_paths)
        .filter(|dir| dir.is_absolute())
        .collect()
}

fn is_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Finds `name` (plus the platform executable suffix) in the absolute directories of
/// `path_var`, then in `fallbacks`, requiring an executable regular file.
fn find_executable(name: &str, path_var: Option<&OsStr>, fallbacks: &[&str]) -> Option<PathBuf> {
    let file_name = format!("{name}{}", env::consts::EXE_SUFFIX);
    absolute_path_dirs(path_var)
        .into_iter()
        .map(|dir| dir.join(&file_name))
        .chain(
            fallbacks
                .iter()
                .map(PathBuf::from)
                .filter(|p| p.is_absolute()),
        )
        .find(|candidate| is_executable_file(candidate))
}

/// Extracts the interface from `route -n get default` output (macOS/BSD), e.g.
/// `  interface: en0`.
fn parse_route_get_interface(output: &str) -> Option<&str> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(str::trim)
        .filter(|iface| !iface.is_empty())
}

/// Picks the capture interface: an explicit `--net-iface` / `WAYBOUND_NET_IFACE` value, else
/// the default-route interface on macOS (which has no `any` device), else Linux's `any`.
/// Windows (Npcap) has no `any` device either, so it requires an explicit interface.
fn capture_interface(explicit: Option<&str>) -> Result<String> {
    if let Some(iface) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(iface.to_owned());
    }
    let unavailable = |reason: String| {
        capture_unavailable(format!(
            "{reason}; pass --net-iface <interface> (or WAYBOUND_NET_IFACE), see `tshark -D`"
        ))
    };
    if cfg!(windows) {
        return Err(unavailable(
            "Npcap has no `any` capture device, so the interface must be chosen".to_owned(),
        ));
    }
    if !cfg!(target_os = "macos") {
        return Ok("any".to_owned());
    }
    let output = waybound_core::process::command("/sbin/route")
        .args(["-n", "get", "default"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| unavailable(format!("could not run `route -n get default`: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_route_get_interface(&stdout)
        .map(str::to_owned)
        .ok_or_else(|| unavailable("no default route found to pick a capture interface".to_owned()))
}

type StderrTail = Arc<Mutex<VecDeque<String>>>;

fn stderr_summary(tail: &StderrTail) -> String {
    let lines = tail
        .lock()
        .map(|lines| lines.iter().cloned().collect::<Vec<_>>().join(" | "))
        .unwrap_or_default();
    if lines.is_empty() {
        "no stderr output".to_owned()
    } else {
        lines
    }
}

/// Forwards `tshark` stderr to the log, keeps its last lines for error messages, and sets
/// `capturing` once tshark reports `Capturing on ...` (printed with `-q`, not with `-Q`).
fn spawn_stderr_reader(
    stderr: ChildStderr,
    capturing: Arc<AtomicBool>,
) -> (StderrTail, thread::JoinHandle<()>) {
    let tail: StderrTail = Arc::default();
    let writer = Arc::clone(&tail);
    let handle = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut buf = Vec::new();
        while let Ok(read) = read_capped_line(&mut reader, &mut buf, MAX_STDERR_LINE_BYTES) {
            if read == LineRead::Eof {
                break;
            }
            let text = String::from_utf8_lossy(&buf);
            let line = text.trim();
            if line.is_empty() {
                continue;
            }
            // `-q` status lines: the start banner and the final packet count.
            let is_capturing = line.starts_with("Capturing on");
            if is_capturing
                || line.ends_with("packets captured")
                || line.ends_with("packet captured")
            {
                if is_capturing {
                    capturing.store(true, Ordering::SeqCst);
                }
                tracing::info!(target: "waybound::net_tap::tshark", "{line}");
                continue;
            }
            tracing::warn!(target: "waybound::net_tap::tshark", "{line}");
            if let Ok(mut guard) = writer.lock() {
                if guard.len() >= STDERR_TAIL_LINES {
                    let _ = guard.pop_front();
                }
                guard.push_back(line.to_owned());
            }
        }
    });
    (tail, handle)
}

/// Feeds `tshark` stdout to the correlator; when it ends without the tap being dropped, the
/// capture is dead and the store is told so.
fn spawn_stdout_reader(
    stdout: ChildStdout,
    store: Arc<ResponseStore>,
    stopping: Arc<AtomicBool>,
    stderr_tail: StderrTail,
    iface: String,
) {
    let _ = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut correlator = StreamCorrelator::default();
        let mut buf = Vec::new();
        let mut warned_oversized = false;
        let end = loop {
            match read_capped_line(&mut reader, &mut buf, MAX_EK_LINE_BYTES) {
                Ok(LineRead::Line) => {
                    correlator.ingest_line(&String::from_utf8_lossy(&buf), &store);
                }
                Ok(LineRead::Oversized) => {
                    if !warned_oversized {
                        tracing::warn!(
                            max_bytes = MAX_EK_LINE_BYTES,
                            "skipping oversized tshark output line (further ones skipped silently)"
                        );
                        warned_oversized = true;
                    }
                }
                Ok(LineRead::Eof) => break "its output ended".to_owned(),
                Err(err) => break format!("reading its output failed: {err}"),
            }
        };
        // Give the stderr reader a moment to collect tshark's last words (and a failed
        // startup time to mark the tap as stopping).
        thread::sleep(POLL_INTERVAL * 4);
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let reason = format!(
            "tshark capture on interface {iface} stopped ({end}): {}",
            stderr_summary(&stderr_tail)
        );
        tracing::error!("{reason}");
        store.mark_capture_failed(reason);
    });
}

/// Starts a background passive `tshark` capture reading TLS secrets from `ssl_keylog`.
///
/// This is the fallback used when attaching to a browser the daemon did not launch: it only
/// sees TLS on port 443 sent directly from this host over the capture interface (see
/// [`capture_interface`]), so traffic through a proxy is invisible to it.
///
/// Waits (up to [`STARTUP_TIMEOUT`]) until tshark reports that it is capturing and then stays
/// alive for [`STARTUP_GRACE`]. If tshark dies later, the store is marked failed and
/// `wait_for_response` reports that instead of timing out.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `tshark` is not installed, no capture
/// interface can be determined, or `tshark` exits during startup (for example because the
/// interface does not exist or capture permission is missing); the error includes its stderr.
pub fn start_passive_tap(
    ssl_keylog: &Path,
    net_iface: Option<&str>,
    store: Arc<ResponseStore>,
) -> Result<PassiveTap> {
    let path_var = env::var_os("PATH");
    let tshark =
        find_executable("tshark", path_var.as_deref(), TSHARK_FALLBACK_PATHS).ok_or_else(|| {
            capture_unavailable(
                "tshark not found on PATH or in the usual install locations (install \
                 Wireshark/tshark for passive SSLKEYLOGFILE capture when attaching to a \
                 running browser)"
                    .to_owned(),
            )
        })?;

    let iface = capture_interface(net_iface)?;
    let mut cmd = waybound_core::process::command(&tshark);
    let _ = cmd
        .args([
            "-l",
            "-n",
            // `-q` (unlike `-Q`) still prints `Capturing on ...` to stderr, which marks a
            // successful start; with `-T ek` it does not suppress the packet output.
            "-q",
            "-i",
            &iface,
            "-o",
            &format!("tls.keylog_file:{}", ssl_keylog.display()),
            "-f",
            "tcp port 443 or udp port 443",
            "-Y",
            "http or http2 or http3",
            // One JSON object per packet with one object per HTTP/2 or HTTP/3 frame, so frames
            // of different streams sharing a TCP segment stay separate (`-T fields` merges them
            // into comma lists whose positions do not line up across fields).
            "-T",
            "ek",
            "-J",
            EK_PROTOCOLS,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(WayboundError::Io)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let capturing = Arc::new(AtomicBool::new(false));
    let (stderr_tail, stderr_handle) = child.stderr.take().map_or_else(
        || (StderrTail::default(), None),
        |stderr| {
            let (tail, handle) = spawn_stderr_reader(stderr, Arc::clone(&capturing));
            (tail, Some(handle))
        },
    );
    if let Some(stdout) = child.stdout.take() {
        spawn_stdout_reader(
            stdout,
            store,
            Arc::clone(&stopping),
            Arc::clone(&stderr_tail),
            iface.clone(),
        );
    }
    // Own the child from here on so every early return kills it.
    let mut tap = PassiveTap { child, stopping };

    let mut deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut reported_capturing = false;
    loop {
        if !reported_capturing && capturing.load(Ordering::SeqCst) {
            reported_capturing = true;
            deadline = Instant::now() + STARTUP_GRACE;
        }
        if let Some(status) = tap.child.try_wait().map_err(WayboundError::Io)? {
            tap.stopping.store(true, Ordering::SeqCst);
            let drain_deadline = Instant::now() + STDERR_DRAIN_TIMEOUT;
            while stderr_handle.as_ref().is_some_and(|h| !h.is_finished())
                && Instant::now() < drain_deadline
            {
                thread::sleep(POLL_INTERVAL);
            }
            return Err(capture_unavailable(format!(
                "{} exited during startup on interface {iface} with {status}: {}",
                tshark.display(),
                stderr_summary(&stderr_tail)
            )));
        }
        if Instant::now() >= deadline {
            if reported_capturing {
                break;
            }
            tracing::warn!(
                iface = %iface,
                "tshark has not reported `Capturing on` after {}s; continuing (capture calls \
                 will report it if tshark dies)",
                STARTUP_TIMEOUT.as_secs()
            );
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    tracing::info!(
        iface = %iface,
        keylog = %ssl_keylog.display(),
        "started passive SSLKEYLOGFILE network tap"
    );
    Ok(tap)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    use serde_json::json;

    // Output of the daemon's tshark arguments (Wireshark 4.6.7, `-T ek -J "frame tcp udp quic
    // http http2 http3"`) with `-r <pcap> -d tcp.port==...,http2|http` in place of `-i`/`-f`,
    // for synthetic cleartext captures; see each test.
    const EK_H2_MUX: &str = include_str!("../testdata/tshark_ek_h2_mux.jsonl");
    const EK_H2_SPLIT: &str = include_str!("../testdata/tshark_ek_h2_split.jsonl");
    const EK_H2_REQBODY: &str = include_str!("../testdata/tshark_ek_h2_reqbody.jsonl");
    const EK_H2_HINTS: &str = include_str!("../testdata/tshark_ek_h2_hints.jsonl");
    const EK_H1_KEEPALIVE: &str = include_str!("../testdata/tshark_ek_h1_keepalive.jsonl");
    const EK_H1_PIPELINED: &str = include_str!("../testdata/tshark_ek_h1_pipelined.jsonl");
    const EK_H1_LOST_RESPONSE: &str = include_str!("../testdata/tshark_ek_h1_lost_response.jsonl");

    fn replay(ek: &str) -> Vec<CapturedResponse> {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();
        for line in ek.lines() {
            correlator.ingest_line(line, &store);
        }
        store.list(None)
    }

    /// A hand-written ek packet line with the given per-frame `http2` objects.
    fn h2_packet(tcp_stream: u32, src_port: u16, frames: &[Value]) -> String {
        json!({
            "timestamp": "1700000000000",
            "layers": {
                "tcp": {
                    "tcp_tcp_stream": tcp_stream.to_string(),
                    "tcp_tcp_srcport": src_port.to_string(),
                },
                "http2": frames,
            },
        })
        .to_string()
    }

    fn h2_request(stream_id: u32, path: &str) -> Value {
        json!({
            "http2_http2_streamid": stream_id.to_string(),
            "http2_http2_type": "1",
            "http2_http2_headers_authority": "api.example.com",
            "http2_http2_headers_path": path,
        })
    }

    fn h2_response(stream_id: u32, status: &str, content_type: &str) -> Value {
        json!({
            "http2_http2_streamid": stream_id.to_string(),
            "http2_http2_type": "1",
            "http2_http2_headers_status": status,
            "http2_http2_headers_content_type": content_type,
        })
    }

    fn h2_data(stream_id: u32, hex: &str) -> Value {
        json!({
            "http2_http2_streamid": stream_id.to_string(),
            "http2_http2_type": "0",
            "http2_http2_data_data": hex,
        })
    }

    /// One server segment carrying `SETTINGS`, `SETTINGS` ack, `HEADERS[1]` (200, JSON),
    /// `HEADERS[3]` (204), `DATA[1]` (partial), `HEADERS[5]` (200, a content type containing a
    /// comma), `DATA[5]`, `DATA[1]` + `END_STREAM`, empty `DATA[5]` + `END_STREAM`, after one
    /// client segment carrying the three requests (the first `:path` contains a comma).
    #[test]
    fn correlator_splits_http2_frames_sharing_a_segment() {
        let captured = replay(EK_H2_MUX);
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].url, "https://a.test/one?ids=1,2");
        assert_eq!(captured[0].status, 200);
        assert_eq!(
            captured[0].content_type.as_deref(),
            Some("application/json")
        );
        assert_eq!(captured[0].body.as_deref(), Some(r#"{"a":1}"#));
        assert_eq!(captured[1].url, "https://a.test/two");
        assert_eq!(captured[1].status, 204);
        assert_eq!(captured[1].content_type, None);
        assert_eq!(captured[1].body, None);
        assert_eq!(captured[2].url, "https://a.test/three");
        assert_eq!(captured[2].status, 200);
        assert_eq!(
            captured[2].content_type.as_deref(),
            Some("text/plain; charset=utf-8, x")
        );
        assert_eq!(captured[2].body.as_deref(), Some("five"));
    }

    /// `DATA[1]` chunks in three segments; tshark repeats the whole reassembled body on the
    /// `END_STREAM` frame, which must replace (not extend) the chunks seen so far.
    #[test]
    fn correlator_uses_reassembled_body_on_end_stream() {
        let captured = replay(EK_H2_SPLIT);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].url, "https://a.test/split");
        assert_eq!(captured[0].body.as_deref(), Some(r#"{"a":1,"b":2}"#));
    }

    /// Client `HEADERS[1]` and `DATA[1]` "REQ1"; server `HEADERS[1]` 200; client `DATA[1]`
    /// "REQ2" with `END_STREAM` (tshark attaches the reassembled request body "REQ1REQ2" to it);
    /// server `DATA[1]` "resp" with `END_STREAM`. Only the server's bytes are the response body.
    #[test]
    fn correlator_never_takes_request_body_after_the_status() {
        let captured = replay(EK_H2_REQBODY);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].url, "https://a.test/upload");
        assert_eq!(captured[0].status, 200);
        assert_eq!(captured[0].body.as_deref(), Some("resp"));
    }

    /// `HEADERS[1]` 103 Early Hints, then `HEADERS[1]` 200 and `DATA[1]` "ok" in one segment.
    #[test]
    fn correlator_ignores_interim_1xx_statuses() {
        let captured = replay(EK_H2_HINTS);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].status, 200);
        assert_eq!(captured[0].content_type.as_deref(), Some("text/plain"));
        assert_eq!(captured[0].body.as_deref(), Some("ok"));
    }

    /// `GET /a?x=1,2` answered with a chunked gzip body (tshark already de-chunks and
    /// decompresses `http.file_data`), then `POST /b` with a request body answered `201`.
    #[test]
    fn correlator_resets_http1_keepalive_requests() {
        let captured = replay(EK_H1_KEEPALIVE);
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].url, "http://h.test/a?x=1,2");
        assert_eq!(captured[0].status, 200);
        assert_eq!(captured[0].body.as_deref(), Some(r#"{"ok":true}"#));
        assert_eq!(captured[1].url, "http://h.test/b");
        assert_eq!(captured[1].status, 201);
        assert_eq!(captured[1].body.as_deref(), Some("two"));
    }

    /// `GET /b` and `GET /c` in one segment, both responses in one segment. tshark labels the
    /// first response `/c` and the second with no URI; responses pair with requests in order.
    #[test]
    fn correlator_splits_pipelined_http1_responses() {
        let captured = replay(EK_H1_PIPELINED);
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].url, "http://h.test/b");
        assert_eq!(captured[0].body.as_deref(), Some("bbb"));
        assert_eq!(captured[1].url, "http://h.test/c");
        assert_eq!(captured[1].body.as_deref(), Some("ccc"));
    }

    /// `GET /a1` whose response was never captured, then `/a2`, `/a3`, `/a4` each answered.
    /// tshark's `http.request_in` keeps the later responses on their own requests.
    #[test]
    fn correlator_survives_a_lost_http1_response() {
        let captured = replay(EK_H1_LOST_RESPONSE);
        let got: Vec<(&str, Option<&str>)> = captured
            .iter()
            .map(|r| (r.url.as_str(), r.body.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("http://h.test/a2", Some("body2")),
                ("http://h.test/a3", Some("body3")),
                ("http://h.test/a4", Some("body4")),
            ]
        );
    }

    #[test]
    fn h1_pairing_drops_requests_whose_response_was_lost() {
        let mut queue: VecDeque<(Option<u64>, String)> = [
            (Some(4), "/a1"),
            (Some(5), "/a2"),
            (Some(7), "/b"),
            (Some(7), "/c"),
        ]
        .into_iter()
        .map(|(f, u)| (f, u.to_owned()))
        .collect();
        assert_eq!(
            pair_h1_response(&mut queue, Some(5)).as_deref(),
            Some("/a2")
        );
        assert_eq!(pair_h1_response(&mut queue, Some(7)).as_deref(), Some("/b"));
        // tshark gives the second pipelined response no `request_in`: take the next in order.
        assert_eq!(pair_h1_response(&mut queue, None).as_deref(), Some("/c"));
        // The request itself was never captured: fall back to tshark's URI.
        queue.push_back((Some(20), "/later".to_owned()));
        assert_eq!(pair_h1_response(&mut queue, Some(9)), None);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn correlator_ignores_post_request_body_and_keeps_distinct_streams() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();

        // Two requests in one segment, the first with a request body.
        correlator.ingest_line(
            &h2_packet(
                3,
                50_000,
                &[
                    h2_request(1, "/v1/fares"),
                    h2_data(1, "52:45"),
                    h2_request(3, "/v1/fares"),
                ],
            ),
            &store,
        );
        assert_eq!(store.list(None).len(), 0);

        // Both responses interleaved in one segment.
        correlator.ingest_line(
            &h2_packet(
                3,
                443,
                &[
                    h2_response(3, "200", "application/json"),
                    h2_response(1, "200", "application/json"),
                    h2_data(1, "7b:22:6f:6b:22:3a:74:72:75:65:7d"),
                    h2_data(3, "7b:22:6e:22:3a:32:7d"),
                ],
            ),
            &store,
        );

        // Stored in the order the response headers arrived: stream 3, then stream 1.
        let captured = store.list(Some("/v1/fares"));
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].body.as_deref(), Some(r#"{"n":2}"#));
        assert_eq!(captured[1].body.as_deref(), Some(r#"{"ok":true}"#));
    }

    #[test]
    fn ek_values_may_be_numbers() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();
        let line = json!({
            "layers": {
                "tcp": { "tcp_tcp_stream": 7, "tcp_tcp_srcport": 443 },
                "http2": [
                    { "http2_http2_streamid": 1, "http2_http2_headers_path": "/n",
                      "http2_http2_headers_authority": "num.test" },
                    { "http2_http2_streamid": 1, "http2_http2_headers_status": 200 },
                    { "http2_http2_streamid": 1, "http2_http2_data_data": "6f:6b" },
                ],
            },
        });
        correlator.ingest_line(&line.to_string(), &store);
        let captured = store.list(None);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].url, "https://num.test/n");
        assert_eq!(captured[0].status, 200);
        assert_eq!(captured[0].body.as_deref(), Some("ok"));
    }

    #[test]
    fn correlator_attributes_http3_only_with_a_single_request_stream() {
        let h3_packet = |quic_streams: &[&str]| {
            json!({
                "layers": {
                    "udp": { "udp_udp_stream": "9", "udp_udp_srcport": "443" },
                    "quic": { "quic_quic_stream_stream_id": quic_streams },
                    "http3": [
                        { "http3_http3_headers_authority": "h3.test", "http3_http3_headers_path": "/q" },
                        { "http3_http3_headers_status": "200" },
                        { "http3_http3_data": "6f:6b" },
                    ],
                },
            })
            .to_string()
        };

        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();
        // Two request streams in one datagram: ambiguous, skipped.
        correlator.ingest_line(&h3_packet(&["0", "4"]), &store);
        assert_eq!(store.list(None).len(), 0);
        // One request stream plus a unidirectional control stream (id 3): attributed.
        correlator.ingest_line(&h3_packet(&["3", "8"]), &store);
        let captured = store.list(None);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].url, "https://h3.test/q");
        assert_eq!(captured[0].body.as_deref(), Some("ok"));
    }

    #[test]
    fn correlator_skips_non_packet_lines() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();
        correlator.ingest_line(r#"{"index":{"_index":"packets-2026-11-22"}}"#, &store);
        correlator.ingest_line("not json", &store);
        assert_eq!(correlator.streams.len(), 0);
    }

    #[test]
    fn capped_line_reader_skips_oversized_lines() {
        let input = b"short\nthis line is far too long\nok\nlast";
        let mut reader = BufReader::with_capacity(4, &input[..]);
        let mut buf = Vec::new();
        let mut lines = Vec::new();
        loop {
            match read_capped_line(&mut reader, &mut buf, 8) {
                Ok(LineRead::Eof) | Err(_) => break,
                Ok(LineRead::Oversized) => lines.push("<oversized>".to_owned()),
                Ok(LineRead::Line) => lines.push(String::from_utf8_lossy(&buf).into_owned()),
            }
        }
        assert_eq!(lines, ["short", "<oversized>", "ok", "last"]);
    }

    #[test]
    fn wait_for_reports_a_dead_capture_instead_of_timing_out() {
        let store = ResponseStore::default();
        store.mark_capture_failed("tshark capture on interface en0 stopped".to_owned());
        let started = Instant::now();
        let got = store.wait_for("/api", 5_000);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            got,
            Err(WayboundError::BackendUnavailable { ref reason, .. }) if reason.contains("en0")
        ));
    }

    #[test]
    fn path_lookup_skips_empty_and_relative_entries() {
        // `temp_dir()` is absolute on every platform (`/usr/bin` is not absolute on Windows,
        // which needs a drive or UNC prefix).
        let absolute = env::temp_dir();
        assert!(absolute.is_absolute());
        let relative = [Path::new(""), Path::new("."), Path::new("bin")];
        let joined = env::join_paths(relative.iter().copied().chain([absolute.as_path()])).ok();
        assert!(joined.is_some());
        assert_eq!(absolute_path_dirs(joined.as_deref()), [absolute]);
    }

    #[test]
    fn finds_executable_on_path_before_fallbacks() {
        let dir = env::temp_dir().join(format!("wb-net-tap-{}", std::process::id()));
        let file_name = format!("tshark{}", env::consts::EXE_SUFFIX);
        let tool = dir.join(&file_name);
        assert!(std::fs::create_dir_all(&dir).is_ok());
        assert!(std::fs::write(&tool, b"").is_ok());
        let path_var = env::join_paths([Path::new("/nonexistent-wb"), dir.as_path()]).ok();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Not executable: skipped.
            assert!(
                std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o644)).is_ok()
            );
            assert_eq!(find_executable("tshark", path_var.as_deref(), &[]), None);
            assert!(
                std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).is_ok()
            );
        }
        let found = find_executable("tshark", path_var.as_deref(), &["/nonexistent-wb/tshark"]);
        assert_eq!(found, Some(tool));
        assert_eq!(
            find_executable("tshark", None, &["/nonexistent-wb/tshark"]),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_default_route_interface() {
        let vpn = "   route to: default\ndestination: default\n       mask: default\n    \
                   gateway: 10.8.0.1\n  interface: utun4\n      flags: <UP,GATEWAY,DONE>\n";
        assert_eq!(parse_route_get_interface(vpn), Some("utun4"));
        assert_eq!(
            parse_route_get_interface("route: writing to routing socket: not in table"),
            None
        );
        assert_eq!(parse_route_get_interface("  interface: \n"), None);
    }

    #[test]
    fn explicit_capture_interface_wins() {
        assert_eq!(
            capture_interface(Some(" en7 ")).ok().as_deref(),
            Some("en7")
        );
        if cfg!(windows) {
            assert!(capture_interface(None).is_err());
        }
    }

    fn sample(url: &str, body: Option<&str>) -> CapturedResponse {
        CapturedResponse {
            url: url.to_owned(),
            status: 200,
            content_type: None,
            body: body.map(str::to_owned),
            ..CapturedResponse::default()
        }
    }

    #[test]
    fn wait_for_ignores_responses_captured_before_the_call() {
        let store = Arc::new(ResponseStore::default());
        store.upsert(1, sample("https://a.test/api?q=old", Some("old")));

        // Only the stale response exists: the wait must time out rather than return it.
        assert!(matches!(
            store.wait_for("/api", 120),
            Err(WayboundError::Timeout { .. })
        ));

        let writer = Arc::clone(&store);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            writer.upsert(2, sample("https://a.test/api?q=new", Some("new")));
        });
        let got = store.wait_for("/api", 3_000);
        assert!(handle.join().is_ok());
        assert_eq!(got.ok().and_then(|r| r.body).as_deref(), Some("new"));
    }

    #[test]
    fn wait_for_waits_for_body_after_headers() {
        let store = Arc::new(ResponseStore::default());
        let writer = Arc::clone(&store);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            writer.upsert(1, sample("https://a.test/data", None));
            thread::sleep(Duration::from_millis(120));
            writer.upsert(1, sample("https://a.test/data", Some("{}")));
        });
        let got = store.wait_for("/data", 3_000);
        assert!(handle.join().is_ok());
        assert_eq!(got.ok().and_then(|r| r.body).as_deref(), Some("{}"));
    }

    #[test]
    fn wait_for_returns_bodyless_response_after_grace() {
        let store = Arc::new(ResponseStore::default());
        let writer = Arc::clone(&store);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            writer.upsert(1, sample("https://a.test/empty", None));
        });
        let got = store.wait_for("/empty", 3_000);
        assert!(handle.join().is_ok());
        assert!(matches!(got, Ok(ref r) if r.body.is_none()));
    }

    #[test]
    fn upsert_merges_headers_and_request_metadata_into_existing_entry() {
        use waybound_core::HttpHeader;

        let store = ResponseStore::default();
        store.upsert(7, sample("https://a.test/form", None));
        store.upsert(
            7,
            CapturedResponse {
                headers: vec![HttpHeader::new("set-cookie", "a=1")].into(),
                request_method: Some("POST".to_owned()),
                request_headers: vec![HttpHeader::new("content-type", "text/plain")].into(),
                request_body: Some("x=1".into()),
                ..sample("https://a.test/form", Some("ok"))
            },
        );
        store.upsert(
            7,
            CapturedResponse {
                status: 201,
                ..sample("https://a.test/form", None)
            },
        );
        let got = store.list(None);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].status, 201);
        assert_eq!(got[0].body.as_deref(), Some("ok"));
        assert_eq!(&*got[0].headers, [HttpHeader::new("set-cookie", "a=1")]);
        assert_eq!(got[0].request_method.as_deref(), Some("POST"));
        assert_eq!(got[0].request_body.as_deref(), Some("x=1"));
    }

    /// HPACK literal header field without indexing, new name, no Huffman (short strings).
    fn hpack_literal(out: &mut Vec<u8>, name: &str, value: &str) {
        out.push(0x00);
        out.push(u8::try_from(name.len()).unwrap_or(0));
        out.extend_from_slice(name.as_bytes());
        out.push(u8::try_from(value.len()).unwrap_or(0));
        out.extend_from_slice(value.as_bytes());
    }

    fn h2_frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
        let mut out = vec![len[1], len[2], len[3], ftype, flags];
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn streaming_response_metadata_survives_store_eviction() {
        use waybound_net::{HttpConnectionCorrelator, InflightCounter, ResponseCallback};

        let store = Arc::new(ResponseStore::default());
        let sink = |store: &Arc<ResponseStore>| -> ResponseCallback {
            let store = Arc::clone(store);
            Arc::new(move |seq, resp| store.upsert(seq, resp))
        };
        let mut live = HttpConnectionCorrelator::new(
            "live.test".to_owned(),
            1,
            InflightCounter::default(),
            sink(&store),
        );
        let mut req = Vec::new();
        hpack_literal(&mut req, ":method", "POST");
        hpack_literal(&mut req, ":authority", "live.test");
        hpack_literal(&mut req, ":path", "/sse");
        hpack_literal(&mut req, "x-token", "t1");
        let mut c2s = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        c2s.extend(h2_frame(0x1, 0x4, 1, &req));
        c2s.extend(h2_frame(0x0, 0x1, 1, b"q=1"));
        live.feed_client(&c2s);
        let mut resp = Vec::new();
        hpack_literal(&mut resp, ":status", "200");
        hpack_literal(&mut resp, "set-cookie", "a=1");
        let mut s2c = h2_frame(0x1, 0x4, 1, &resp);
        s2c.extend(h2_frame(0x0, 0, 1, b"data: 1\n\n"));
        live.feed_server(&s2c);

        // Enough other responses to evict the long-lived stream's entry.
        let mut other = HttpConnectionCorrelator::new(
            "other.test".to_owned(),
            10_000_000,
            InflightCounter::default(),
            sink(&store),
        );
        for i in 0..MAX_CAPTURED_RESPONSES + 100 {
            other.feed_client(format!("GET /{i} HTTP/1.1\r\nHost: other.test\r\n\r\n").as_bytes());
            other.feed_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
        assert_eq!(store.list(Some("/sse")).len(), 0);

        live.feed_server(&h2_frame(0x0, 0, 1, b"data: 2\n\n"));
        let got = store.list(Some("/sse"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].request_method.as_deref(), Some("POST"));
        assert_eq!(got[0].request_body.as_deref(), Some("q=1"));
        assert_eq!(got[0].request_headers.len(), 1);
        assert_eq!(got[0].headers.len(), 1);
        assert_eq!(got[0].body.as_deref(), Some("data: 1\n\ndata: 2\n\n"));
    }

    #[test]
    fn websocket_frames_are_bounded_and_filterable() {
        use waybound_core::{WebSocketDirection, WebSocketOpcode};

        let store = ResponseStore::default();
        for i in 0..=MAX_CAPTURED_WS_FRAMES {
            let host = if i % 2 == 0 { "even" } else { "odd" };
            store.push_websocket_frame(CapturedWebSocketFrame {
                url: format!("wss://{host}.test/ws"),
                direction: WebSocketDirection::Received,
                opcode: WebSocketOpcode::Text,
                payload: Some(i.to_string()),
                payload_len: 1,
                compressed: false,
                truncated: false,
                close_code: None,
            });
        }
        let all = store.list_websocket_frames(None, None);
        assert_eq!(all.len(), MAX_CAPTURED_WS_FRAMES);
        assert_eq!(all[0].payload.as_deref(), Some("1"));
        let odd = store.list_websocket_frames(Some("ODD.test"), None);
        assert_eq!(odd.len(), MAX_CAPTURED_WS_FRAMES / 2);
        let recent = store.list_websocket_frames(Some("even"), Some(2));
        let recent_payloads: Vec<_> = recent.iter().map(|f| f.payload.as_deref()).collect();
        let last = MAX_CAPTURED_WS_FRAMES.to_string();
        let before = (MAX_CAPTURED_WS_FRAMES - 2).to_string();
        assert_eq!(
            recent_payloads,
            vec![Some(before.as_str()), Some(last.as_str())]
        );
        // The legacy tshark path never produces WebSocket frames or the new response fields.
        assert_eq!(store.list(None), Vec::new());
    }

    #[test]
    fn correlator_keeps_recent_streams_when_full() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();

        for id in 0..MAX_PENDING_STREAMS {
            let stream = u32::try_from(id * 2 + 1).unwrap_or(u32::MAX);
            correlator.ingest_line(&h2_packet(3, 50_000, &[h2_request(stream, "/old")]), &store);
        }
        // Request headers of an in-flight stream, then enough new streams to overflow the map.
        correlator.ingest_line(&h2_packet(4, 50_001, &[h2_request(1, "/inflight")]), &store);
        assert!(correlator.streams.len() <= MAX_PENDING_STREAMS);
        assert!(correlator.streams.len() > MAX_PENDING_STREAMS / 2);

        correlator.ingest_line(
            &h2_packet(
                4,
                443,
                &[
                    h2_response(1, "200", "application/json"),
                    h2_data(1, "7b7d"),
                ],
            ),
            &store,
        );
        let captured = store.list(Some("/inflight"));
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].body.as_deref(), Some("{}"));
    }

    #[test]
    fn decodes_gzip_and_brotli_bodies() {
        let payload = br#"{"flights":[{"price":419}]}"#;

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        assert!(gz.write_all(payload).is_ok());
        let gz_bytes = gz.finish().unwrap_or_default();
        assert_eq!(
            decode_body_bytes(&gz_bytes, Some("gzip")).as_deref(),
            Some(r#"{"flights":[{"price":419}]}"#)
        );

        let mut br_bytes = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut br_bytes, 4096, 4, 22);
            assert!(writer.write_all(payload).is_ok());
        }
        assert_eq!(
            decode_body_bytes(&br_bytes, Some("br")).as_deref(),
            Some(r#"{"flights":[{"price":419}]}"#)
        );
    }
}
