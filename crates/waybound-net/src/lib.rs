//! Pure-Rust passive TLS 1.3 + HTTP/1.1–2 + SSE decryptor and L4 hostname blocker.
//!
//! Designed for zero-MITM, zero-`CAP_NET_RAW`, zero-`tshark` passive HTTPS inspection:
//! a local pass-through TCP relay forwards unmodified Chrome ciphertext bytes while
//! teeing a read-only copy into [`PassiveConnectionTap`], which decrypts records
//! using `SSLKEYLOGFILE` and correlates HTTP/1.1 & HTTP/2 streams in-process.

#![forbid(unsafe_code)]

pub mod http;
pub mod keylog;
pub mod tls13;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub use http::{HttpConnectionCorrelator, InflightCounter, ResponseCallback, decode_body_bytes};
pub use keylog::{KeyLogStore, TrafficSecrets};
pub use tls13::{Direction, PassiveTls13Decoder, Tls13CipherSuite};

static NEXT_CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Passive per-connection TLS 1.3 + HTTP/1.1–2 tap fed directly from a zero-MITM TCP relay.
#[derive(Debug, Clone)]
pub struct PassiveConnectionTap {
    inner: Arc<Mutex<TapInner>>,
}

#[derive(Debug)]
struct TapInner {
    tls: PassiveTls13Decoder,
    http: HttpConnectionCorrelator,
}

impl PassiveConnectionTap {
    /// Creates a new passive tap for a single TCP tunnel targeting `host`.
    #[must_use]
    pub fn new(
        host: String,
        keylog: KeyLogStore,
        inflight: InflightCounter,
        on_response: ResponseCallback,
    ) -> Self {
        let seq_base = NEXT_CONN_SEQ
            .fetch_add(1_000_000, Ordering::Relaxed)
            .saturating_add(1);
        Self {
            inner: Arc::new(Mutex::new(TapInner {
                tls: PassiveTls13Decoder::new(keylog),
                http: HttpConnectionCorrelator::new(host, seq_base, inflight, on_response),
            })),
        }
    }

    /// Feeds raw unmodified ciphertext bytes observed in `dir`.
    pub fn observe(&self, dir: Direction, ciphertext: &[u8]) {
        if ciphertext.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.inner.lock() {
            let plain = guard.tls.feed(dir, ciphertext);
            if !plain.is_empty() {
                match dir {
                    Direction::ClientToServer => guard.http.feed_client(&plain),
                    Direction::ServerToClient => guard.http.feed_server(&plain),
                }
            }
        }
    }
}

/// Suffix-matching L4 hostname blocker (blocks `CONNECT host:port` before TLS starts, zero MITM).
#[derive(Debug, Clone, Default)]
pub struct HostBlocker {
    patterns: Vec<String>,
}

impl HostBlocker {
    /// Builds a [`HostBlocker`] from case-insensitive hostname or suffix patterns
    /// (for example `["google-analytics.com", "doubleclick.net"]`).
    #[must_use]
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let normalized = patterns
            .into_iter()
            .map(|s| {
                s.as_ref()
                    .trim()
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
            })
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            patterns: normalized,
        }
    }

    /// Returns `true` if no block patterns are configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns `true` when `host` equals or is a subdomain of any blocked pattern.
    #[must_use]
    pub fn is_blocked(&self, host: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        self.patterns.iter().any(|pat| {
            h == *pat
                || (h.len() > pat.len()
                    && h.ends_with(pat.as_str())
                    && h.as_bytes().get(h.len() - pat.len() - 1) == Some(&b'.'))
        })
    }
}

/// Waits until `inflight` remains at `0` continuously for `idle_duration` (or until `timeout`).
///
/// Returns `true` when network idle was achieved, or `false` if `timeout` elapsed first.
#[must_use]
pub fn wait_for_network_idle(
    inflight: &InflightCounter,
    idle_duration: Duration,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    let mut idle_since: Option<Instant> = None;

    loop {
        let now = Instant::now();
        if inflight.get() == 0 {
            let start = *idle_since.get_or_insert(now);
            if now.duration_since(start) >= idle_duration {
                return true;
            }
        } else {
            idle_since = None;
        }
        if now >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_blocker_matches_exact_and_subdomains_only() {
        let blocker = HostBlocker::new(["google-analytics.com", ".doubleclick.net"]);
        assert!(blocker.is_blocked("google-analytics.com"));
        assert!(blocker.is_blocked("www.google-analytics.com"));
        assert!(blocker.is_blocked("ad.doubleclick.net"));
        assert!(!blocker.is_blocked("notgoogle-analytics.com"));
        assert!(!blocker.is_blocked("www.united.com"));
    }

    #[test]
    fn wait_for_network_idle_returns_when_counter_is_zero() {
        let counter = InflightCounter::default();
        assert!(wait_for_network_idle(
            &counter,
            Duration::from_millis(40),
            Duration::from_millis(500),
        ));

        counter.inc();
        assert!(!wait_for_network_idle(
            &counter,
            Duration::from_millis(40),
            Duration::from_millis(80),
        ));
        counter.dec();
    }
}
