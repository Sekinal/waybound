//! Passive wire-level TLS/HTTP response tap powered by `SSLKEYLOGFILE` + `tshark`.
//!
//! Decrypts HTTP/1.1, HTTP/2, and HTTP/3 responses off the wire without MITM
//! certificates, proxies, or CDP.

use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use waybound_core::{CapturedResponse, Result, WayboundError};

const MAX_CAPTURED_RESPONSES: usize = 500;
const MAX_PENDING_STREAMS: usize = 1_000;
const MAX_BODY_BYTES: usize = 512 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_WAIT_MS: u64 = 120_000;

/// Thread-safe store of passively decrypted HTTP responses.
#[derive(Default)]
pub struct ResponseStore {
    responses: Mutex<VecDeque<CapturedResponse>>,
}

impl ResponseStore {
    /// Inserts a new captured response or updates an existing response with the same URL
    /// when streaming `DATA` frames arrive after initial `HEADERS`.
    pub fn upsert(&self, resp: CapturedResponse) {
        if let Ok(mut guard) = self.responses.lock() {
            if let Some(existing) = guard
                .iter_mut()
                .rev()
                .find(|r| r.url == resp.url && r.status == resp.status)
            {
                if resp.body.is_some() {
                    existing.body = resp.body;
                }
                if existing.content_type.is_none() {
                    existing.content_type = resp.content_type;
                }
                return;
            }
            if guard.len() >= MAX_CAPTURED_RESPONSES {
                let _ = guard.pop_front();
            }
            guard.push_back(resp);
        }
    }

    /// Returns all captured responses, optionally filtered by case-insensitive URL substring.
    #[must_use]
    pub fn list(&self, url_contains: Option<&str>) -> Vec<CapturedResponse> {
        let needle = url_contains.map(str::to_lowercase);
        self.responses.lock().map_or_else(
            |_| Vec::new(),
            |guard| {
                guard
                    .iter()
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

    /// Polls until a captured response matches `url_contains` or `timeout_ms` elapses.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::Timeout`] if no matching response is observed in time.
    pub fn wait_for(&self, url_contains: &str, timeout_ms: u64) -> Result<CapturedResponse> {
        let clamped_ms = timeout_ms.min(MAX_WAIT_MS);
        let needle = url_contains.to_lowercase();
        let deadline = Instant::now() + Duration::from_millis(clamped_ms);

        loop {
            if let Ok(guard) = self.responses.lock()
                && let Some(found) = guard
                    .iter()
                    .rev()
                    .find(|r| r.url.to_lowercase().contains(&needle))
            {
                return Ok(found.clone());
            }

            if Instant::now() >= deadline {
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
    url: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
    body: Vec<u8>,
    emitted: bool,
}

/// Stateful correlator turning `tshark -T fields` lines into [`CapturedResponse`] items.
#[derive(Default)]
struct StreamCorrelator {
    streams: HashMap<String, PendingStream>,
}

impl StreamCorrelator {
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
        let body_hex = if cols.len() >= 18 {
            first_non_empty(&[cols[15], cols[16], cols[17]])
        } else {
            None
        };

        let key = if !h2_stream.is_empty() && !tcp_stream.is_empty() {
            format!("h2:{tcp_stream}:{h2_stream}")
        } else if !h3_stream.is_empty() && !udp_stream.is_empty() {
            format!("h3:{udp_stream}:{h3_stream}")
        } else if !tcp_stream.is_empty() {
            format!("h1:{tcp_stream}")
        } else {
            return;
        };

        if self.streams.len() >= MAX_PENDING_STREAMS && !self.streams.contains_key(&key) {
            self.streams.clear();
        }

        let entry = self.streams.entry(key).or_default();

        if !h1_uri.is_empty() {
            entry.url = Some(h1_uri.to_owned());
        } else if !h2_auth.is_empty() || !h2_path.is_empty() {
            entry.url = Some(build_https_url(h2_auth, h2_path));
        } else if !h3_auth.is_empty() || !h3_path.is_empty() {
            entry.url = Some(build_https_url(h3_auth, h3_path));
        }

        if let Some(code_str) = first_non_empty(&[h1_status, h2_status, h3_status])
            && let Ok(code) = code_str.parse::<u16>()
        {
            entry.status = Some(code);
        }

        if let Some(ct) = content_type {
            entry.content_type = Some(ct.to_owned());
        }

        if let Some(hex) = body_hex
            && entry.body.len() < MAX_BODY_BYTES
        {
            append_hex_bytes(hex, &mut entry.body, MAX_BODY_BYTES);
        }

        if let (Some(url), Some(status)) = (&entry.url, entry.status)
            && (!entry.emitted || body_hex.is_some())
        {
            let body = if entry.body.is_empty() {
                None
            } else {
                String::from_utf8(entry.body.clone()).ok()
            };
            store.upsert(CapturedResponse {
                url: url.clone(),
                status,
                content_type: entry.content_type.clone(),
                body,
            });
            entry.emitted = true;
        }
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

fn append_hex_bytes(hex: &str, out: &mut Vec<u8>, max_bytes: usize) {
    let clean: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
    for pair in clean.chunks_exact(2) {
        if out.len() >= max_bytes {
            break;
        }
        if let (Some(hi), Some(lo)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            out.push((hi << 4) | lo);
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
/// Returns [`WayboundError::BackendUnavailable`] if `tshark` is not installed or fails to spawn.
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

    tracing::info!(
        iface = %iface,
        keylog = %ssl_keylog.display(),
        "started passive SSLKEYLOGFILE network tap"
    );
    Ok(PassiveTap { child })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlator_joins_http2_request_and_response() {
        let store = ResponseStore::default();
        let mut correlator = StreamCorrelator::default();

        // Request packet: tcp.stream=3, http2.streamid=1, authority=api.example.com, path=/v1/fares
        let req_line = "3\t\t1\t\t\t\t\t\tapi.example.com\t/v1/fares\t\t\t\t\t\t\t\t";
        correlator.ingest_line(req_line, &store);
        assert!(store.list(None).is_empty());

        // Response packet: tcp.stream=3, http2.streamid=1, status=200, content-type=application/json, body='{"ok":true}'
        let resp_line =
            "3\t\t1\t\t\t200\t\t\t\t\t\t\t\tapplication/json\t\t\t7b226f6b223a747275657d\t";
        correlator.ingest_line(resp_line, &store);

        let captured = store.list(Some("/v1/fares"));
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].url, "https://api.example.com/v1/fares");
        assert_eq!(captured[0].status, 200);
        assert_eq!(
            captured[0].content_type.as_deref(),
            Some("application/json")
        );
        assert_eq!(captured[0].body.as_deref(), Some(r#"{"ok":true}"#));
    }
}
