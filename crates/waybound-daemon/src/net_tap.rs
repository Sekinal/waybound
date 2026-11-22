//! Passive wire-level TLS/HTTP response tap powered by `SSLKEYLOGFILE` + `tshark`.
//!
//! Decrypts HTTP/1.1, HTTP/2, and HTTP/3 responses off the wire without MITM
//! certificates, proxies, or CDP, automatically decompressing `gzip`, `deflate`,
//! and `br` (Brotli) payloads.

use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flate2::read::{GzDecoder, ZlibDecoder};
use waybound_core::{CapturedResponse, Result, WayboundError};

const MAX_CAPTURED_RESPONSES: usize = 500;
const MAX_PENDING_STREAMS: usize = 1_000;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
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
    /// Highest stream sequence ID ever stored; the baseline for [`ResponseStore::wait_for`].
    last_seq: u64,
}

/// Thread-safe store of passively decrypted HTTP responses keyed by stream sequence ID.
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
            if existing.response.content_type.is_none() {
                existing.response.content_type = resp.content_type;
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
    /// Returns [`WayboundError::Timeout`] if no matching response is observed in time.
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

/// RAII owner of the background passive `tshark` capture process.
pub struct PassiveTap {
    child: Child,
}

impl Drop for PassiveTap {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Default)]
struct PendingStream {
    seq: u64,
    url: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    body: Vec<u8>,
    emitted: bool,
}

/// Stateful correlator turning `tshark -T fields` lines into [`CapturedResponse`] items.
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

    fn ingest_line(&mut self, line: &str, store: &ResponseStore) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 15 {
            return;
        }

        let tcp_stream = cols[0].trim();
        let udp_stream = cols[1].trim();
        let h2_stream = cols[2].trim();
        let h3_stream = cols[3].trim();

        let h1_status = cols[4].trim();
        let h2_status = cols[5].trim();
        let h3_status = cols[6].trim();

        let h1_uri = cols[7].trim();
        let h2_auth = cols[8].trim();
        let h2_path = cols[9].trim();
        let h3_auth = cols[10].trim();
        let h3_path = cols[11].trim();

        let content_type = first_non_empty(&[cols[12], cols[13], cols[14]]);
        let body_hex = (cols.len() >= 18)
            .then(|| first_non_empty(&[cols[15], cols[16], cols[17]]))
            .flatten();
        let content_encoding = (cols.len() >= 21)
            .then(|| first_non_empty(&[cols[18], cols[19], cols[20]]))
            .flatten();

        let Some(key) = build_stream_key(tcp_stream, udp_stream, h2_stream, h3_stream) else {
            return;
        };

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

        // On HTTP/1.1 keep-alive connections, a new request resets stream state with a fresh seq ID.
        if !h1_uri.is_empty() {
            let fresh_seq = self.alloc_seq();
            if let Some(entry) = self.streams.get_mut(&key) {
                entry.seq = fresh_seq;
                entry.url = Some(h1_uri.to_owned());
                entry.status = None;
                entry.content_type = None;
                entry.content_encoding = None;
                entry.body.clear();
                entry.emitted = false;
            }
        }

        let Some(entry) = self.streams.get_mut(&key) else {
            return;
        };

        if !h2_auth.is_empty() || !h2_path.is_empty() {
            entry.url = Some(build_https_url(h2_auth, h2_path));
        } else if !h3_auth.is_empty() || !h3_path.is_empty() {
            entry.url = Some(build_https_url(h3_auth, h3_path));
        }

        if let Some(code_str) = first_non_empty(&[h1_status, h2_status, h3_status])
            && let Ok(code) = code_str.parse::<u16>()
        {
            entry.status = Some(code);
        }

        if entry.status.is_some() {
            if let Some(ct) = content_type {
                entry.content_type = Some(ct.to_owned());
            }
            if let Some(ce) = content_encoding {
                entry.content_encoding = Some(ce.to_owned());
            }
        }

        // Only collect payload bytes after response status headers are observed so POST/PUT
        // request bodies are never mixed into response bodies.
        let body_updated = if entry.status.is_some()
            && let Some(hex) = body_hex
            && entry.body.len() < MAX_BODY_BYTES
        {
            let before = entry.body.len();
            append_hex_bytes(hex, &mut entry.body, MAX_BODY_BYTES);
            entry.body.len() > before
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
                },
            );
            entry.emitted = true;
        }
    }
}

/// Decodes raw HTTP response bytes into UTF-8 text, transparently decompressing
/// `gzip`, `deflate`, or `br` (Brotli) up to [`MAX_DECOMPRESSED_BYTES`].
fn decode_body_bytes(raw: &[u8], encoding: Option<&str>) -> Option<String> {
    if raw.is_empty() {
        return None;
    }

    let enc = encoding.map(str::to_ascii_lowercase);
    let decompressed: Vec<u8> = match enc.as_deref().map(str::trim) {
        Some("gzip" | "x-gzip") => {
            let mut out = Vec::new();
            let mut decoder = GzDecoder::new(raw).take(MAX_DECOMPRESSED_BYTES);
            // Retain decompressed prefix even on UnexpectedEof (e.g. streaming SSE / truncated frames).
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

fn build_stream_key(
    tcp_stream: &str,
    udp_stream: &str,
    h2_stream: &str,
    h3_stream: &str,
) -> Option<String> {
    if !h2_stream.is_empty() && !tcp_stream.is_empty() {
        Some(format!("h2:{tcp_stream}:{h2_stream}"))
    } else if !h3_stream.is_empty() && !udp_stream.is_empty() {
        Some(format!("h3:{udp_stream}:{h3_stream}"))
    } else if !tcp_stream.is_empty() {
        Some(format!("h1:{tcp_stream}"))
    } else {
        None
    }
}

fn first_non_empty<'a>(items: &[&'a str]) -> Option<&'a str> {
    items.iter().map(|s| s.trim()).find(|s| !s.is_empty())
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

fn resolve_tshark_binary() -> Option<PathBuf> {
    let candidates = [
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

fn default_interface() -> String {
    if let Ok(iface) = env::var("WAYBOUND_NET_IFACE")
        && !iface.trim().is_empty()
    {
        return iface;
    }
    if cfg!(target_os = "macos") {
        "en0".to_owned()
    } else {
        "any".to_owned()
    }
}

/// Starts a background passive `tshark` capture reading TLS secrets from `ssl_keylog`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `tshark` is not installed, fails to spawn,
/// or exits immediately (for example due to missing BPF permissions).
pub fn start_passive_tap(ssl_keylog: &Path, store: Arc<ResponseStore>) -> Result<PassiveTap> {
    let tshark = resolve_tshark_binary().ok_or_else(|| WayboundError::BackendUnavailable {
        backend: "net_tap".to_owned(),
        reason:
            "tshark binary not found (install Wireshark/tshark for passive SSLKEYLOGFILE capture)"
                .to_owned(),
    })?;

    let iface = default_interface();
    let mut cmd = Command::new(&tshark);
    let _ = cmd
        .args([
            "-l",
            "-n",
            "-Q",
            "-i",
            &iface,
            "-o",
            &format!("tls.keylog_file:{}", ssl_keylog.display()),
            "-f",
            "tcp port 443 or udp port 443",
            "-Y",
            "http or http2 or http3",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=n",
            "-E",
            "occurrence=l",
            "-e",
            "tcp.stream",
            "-e",
            "udp.stream",
            "-e",
            "http2.streamid",
            "-e",
            "http3.frame_streamid",
            "-e",
            "http.response.code",
            "-e",
            "http2.headers.status",
            "-e",
            "http3.headers.status",
            "-e",
            "http.request.full_uri",
            "-e",
            "http2.headers.authority",
            "-e",
            "http2.headers.path",
            "-e",
            "http3.headers.authority",
            "-e",
            "http3.headers.path",
            "-e",
            "http.content_type",
            "-e",
            "http2.headers.content_type",
            "-e",
            "http3.headers.content_type",
            "-e",
            "http.file_data",
            "-e",
            "http2.data.data",
            "-e",
            "http3.data",
            "-e",
            "http.content_encoding",
            "-e",
            "http2.headers.content_encoding",
            "-e",
            "http3.headers.content_encoding",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().map_err(WayboundError::Io)?;
    if let Some(stdout) = child.stdout.take() {
        let _ = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut correlator = StreamCorrelator::default();
            for line in reader.lines().map_while(std::result::Result::ok) {
                correlator.ingest_line(&line, &store);
            }
        });
    }

    // Give tshark a brief moment to open BPF before Chrome fires its initial TLS handshake.
    thread::sleep(Duration::from_millis(450));
    if let Some(status) = child.try_wait().map_err(WayboundError::Io)? {
        return Err(WayboundError::BackendUnavailable {
            backend: "net_tap".to_owned(),
            reason: format!("tshark exited immediately on interface {iface} with {status}"),
        });
    }

    tracing::info!(
        iface = %iface,
        keylog = %ssl_keylog.display(),
        "started passive SSLKEYLOGFILE network tap"
    );
    Ok(PassiveTap { child })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    #[test]
    fn correlator_ignores_post_request_body_and_keeps_distinct_streams() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();

        correlator.ingest_line(
            "3\t\t1\t\t\t\t\t\tapi.example.com\t/v1/fares\t\t\t\t\t\t\t524551\t",
            &store,
        );
        assert_eq!(store.list(None).len(), 0);

        correlator.ingest_line(
            "3\t\t1\t\t\t200\t\t\t\t\t\t\t\tapplication/json\t\t\t7b226f6b223a747275657d\t",
            &store,
        );

        correlator.ingest_line(
            "3\t\t3\t\t\t\t\t\tapi.example.com\t/v1/fares\t\t\t\t\t\t\t\t",
            &store,
        );
        correlator.ingest_line(
            "3\t\t3\t\t\t200\t\t\t\t\t\t\t\tapplication/json\t\t\t7b226e223a327d\t",
            &store,
        );

        let captured = store.list(Some("/v1/fares"));
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].body.as_deref(), Some(r#"{"ok":true}"#));
        assert_eq!(captured[1].body.as_deref(), Some(r#"{"n":2}"#));
    }

    #[test]
    fn correlator_resets_http1_keepalive_requests() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();

        correlator.ingest_line(
            "7\t\t\t\t\t\t\thttps://a.test/1\t\t\t\t\t\t\t\t\t\t",
            &store,
        );
        correlator.ingest_line(
            "7\t\t\t\t200\t\t\t\t\t\t\t\ttext/plain\t\t\t6f6e65\t\t",
            &store,
        );

        correlator.ingest_line(
            "7\t\t\t\t\t\t\thttps://a.test/2\t\t\t\t\t\t\t\t626164\t\t",
            &store,
        );
        correlator.ingest_line(
            "7\t\t\t\t201\t\t\t\t\t\t\t\ttext/plain\t\t\t74776f\t\t",
            &store,
        );

        let captured = store.list(None);
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].url, "https://a.test/1");
        assert_eq!(captured[0].body.as_deref(), Some("one"));
        assert_eq!(captured[1].url, "https://a.test/2");
        assert_eq!(captured[1].status, 201);
        assert_eq!(captured[1].body.as_deref(), Some("two"));
    }

    fn sample(url: &str, body: Option<&str>) -> CapturedResponse {
        CapturedResponse {
            url: url.to_owned(),
            status: 200,
            content_type: None,
            body: body.map(str::to_owned),
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
    fn correlator_keeps_recent_streams_when_full() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();

        for id in 0..MAX_PENDING_STREAMS {
            let stream = id * 2 + 1;
            correlator.ingest_line(
                &format!("3\t\t{stream}\t\t\t\t\t\tapi.example.com\t/old\t\t\t\t\t\t\t\t"),
                &store,
            );
        }
        // Request headers of an in-flight stream, then enough new streams to overflow the map.
        correlator.ingest_line(
            "4\t\t1\t\t\t\t\t\tapi.example.com\t/inflight\t\t\t\t\t\t\t\t",
            &store,
        );
        assert!(correlator.streams.len() <= MAX_PENDING_STREAMS);
        assert!(correlator.streams.len() > MAX_PENDING_STREAMS / 2);

        correlator.ingest_line(
            "4\t\t1\t\t\t200\t\t\t\t\t\t\t\tapplication/json\t\t\t7b7d\t",
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
