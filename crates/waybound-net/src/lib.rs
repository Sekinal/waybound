//! Pure-Rust passive TLS 1.2/1.3 + HTTP/1.1–2 + SSE decryptor and L4 hostname blocker.
//!
//! Designed for zero-MITM, zero-`CAP_NET_RAW`, zero-`tshark` passive HTTPS inspection:
//! a local pass-through TCP relay forwards unmodified Chrome ciphertext bytes while
//! teeing a read-only copy into [`PassiveConnectionTap`], which decrypts records
//! using `SSLKEYLOGFILE` and correlates HTTP/1.1 & HTTP/2 streams in-process.

#![forbid(unsafe_code)]

mod chunked;
pub mod fingerprint;
pub mod http;
pub mod keylog;
pub mod tls;
pub mod tls12;
pub mod tls13;
pub mod websocket;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub use fingerprint::{
    FingerprintRecorder, compute_akamai_h2, compute_ja4, is_grease, parse_client_hello,
};
pub use http::{
    HttpConnectionCorrelator, InflightCounter, ResponseCallback, WebSocketCallback,
    decode_body_bytes, decode_body_bytes_limited,
};
pub use keylog::{KeyLogStore, TrafficSecrets};
pub use tls::{PassiveTlsDecoder, Plaintext, TlsVersion};
pub use tls12::{PassiveTls12Decoder, Tls12CipherSuite};
pub use tls13::{Direction, PassiveTls13Decoder, Tls13CipherSuite};

static NEXT_CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Passive per-connection TLS 1.2/1.3 + HTTP/1.1–2 tap fed directly from a zero-MITM TCP relay.
#[derive(Debug, Clone)]
pub struct PassiveConnectionTap {
    inner: Arc<Mutex<TapInner>>,
}

#[derive(Debug)]
struct TapInner {
    tls: PassiveTlsDecoder,
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
        Self::new_with_fingerprint(host, keylog, inflight, on_response, None)
    }

    /// Creates a new passive tap that also records live TLS/HTTP2/header/cookie fingerprints.
    #[must_use]
    pub fn new_with_fingerprint(
        host: String,
        keylog: KeyLogStore,
        inflight: InflightCounter,
        on_response: ResponseCallback,
        fingerprint: Option<FingerprintRecorder>,
    ) -> Self {
        let seq_base = NEXT_CONN_SEQ
            .fetch_add(1_000_000, Ordering::Relaxed)
            .saturating_add(1);
        Self {
            inner: Arc::new(Mutex::new(TapInner {
                tls: PassiveTlsDecoder::with_fingerprint(keylog, fingerprint.clone()),
                http: HttpConnectionCorrelator::with_fingerprint(
                    host,
                    seq_base,
                    inflight,
                    on_response,
                    fingerprint,
                ),
            })),
        }
    }

    /// Enables WebSocket message capture on this connection, delivering every decrypted
    /// message to `on_websocket`.
    #[must_use]
    pub fn with_websocket_callback(self, on_websocket: WebSocketCallback) -> Self {
        if let Ok(mut guard) = self.inner.lock() {
            guard.http.set_websocket_callback(on_websocket);
        }
        self
    }

    /// Feeds raw unmodified ciphertext bytes observed in `dir`.
    pub fn observe(&self, dir: Direction, ciphertext: &[u8]) {
        if ciphertext.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.inner.lock() {
            let plain = guard.tls.feed(dir, ciphertext);
            // One feed can release plaintext for both directions (version detection replay,
            // or records queued until the keylog line appeared). Always hand the correlator
            // the client side first so requests are known before their responses.
            if !plain.client_to_server.is_empty() {
                guard.http.feed_client(&plain.client_to_server);
            }
            if !plain.server_to_client.is_empty() {
                guard.http.feed_server(&plain.server_to_client);
            }
        }
    }
}

/// Valid opt-in host blocklist preset names accepted by [`preset_hosts`] and [`expand_block_presets`].
pub const BLOCK_PRESET_NAMES: &[&str] = &["analytics", "ads", "media"];

const ANALYTICS_PRESET_HOSTS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "hotjar.com",
    "amplitude.com",
    "fullstory.com",
    "clarity.ms",
    "sentry.io",
    "newrelic.com",
    "datadoghq.com",
    "plausible.io",
];

const ADS_PRESET_HOSTS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adnxs.com",
    "adsrvr.org",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "pubmatic.com",
    "rubiconproject.com",
    "amazon-adsystem.com",
    "facebook.net",
];

const MEDIA_PRESET_HOSTS: &[&str] = &[
    "youtube.com",
    "ytimg.com",
    "googlevideo.com",
    "vimeo.com",
    "vimeocdn.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "use.typekit.net",
];

/// Curated opt-in L4 host blocklist presets for reducing bandwidth on third-party traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockPreset {
    /// Common analytics and telemetry endpoints.
    Analytics,
    /// Common ad-network endpoints.
    Ads,
    /// Common heavy video, image, and font CDN endpoints.
    Media,
}

impl BlockPreset {
    /// Parses a preset name case-insensitively (`"analytics"`, `"ads"`, or `"media"`).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "analytics" => Some(Self::Analytics),
            "ads" => Some(Self::Ads),
            "media" => Some(Self::Media),
            _ => None,
        }
    }

    /// Returns the canonical lowercase name of this preset.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analytics => "analytics",
            Self::Ads => "ads",
            Self::Media => "media",
        }
    }

    /// Returns the static hostname suffix list belonging to this preset.
    #[must_use]
    pub const fn hosts(self) -> &'static [&'static str] {
        match self {
            Self::Analytics => ANALYTICS_PRESET_HOSTS,
            Self::Ads => ADS_PRESET_HOSTS,
            Self::Media => MEDIA_PRESET_HOSTS,
        }
    }
}

/// Looks up the hostname suffix list for a named opt-in blocklist preset.
#[must_use]
pub fn preset_hosts(name: &str) -> Option<&'static [&'static str]> {
    BlockPreset::parse(name).map(BlockPreset::hosts)
}

/// Expands one or more opt-in blocklist preset names into a deduplicated list of host patterns.
///
/// # Errors
///
/// Returns an error naming the first unrecognized preset along with the valid preset names.
pub fn expand_block_presets<I, S>(presets: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut hosts = Vec::new();
    for raw in presets {
        let name = raw.as_ref();
        let Some(preset) = BlockPreset::parse(name) else {
            return Err(format!(
                "unknown block preset {name:?} (expected one of: {})",
                BLOCK_PRESET_NAMES.join(", ")
            ));
        };
        for &host in preset.hosts() {
            if seen.insert(host) {
                hosts.push(host.to_owned());
            }
        }
    }
    Ok(hosts)
}

/// Suffix-matching L4 hostname blocker (blocks `CONNECT host:port` before TLS starts, zero MITM).
#[derive(Debug, Clone, Default)]
pub struct HostBlocker {
    patterns: Vec<String>,
}

impl HostBlocker {
    /// Builds a [`HostBlocker`] from case-insensitive hostname or suffix patterns
    /// (for example `["google-analytics.com", "doubleclick.net"]`).
    ///
    /// Duplicate patterns are removed case-insensitively while preserving first-seen order.
    #[must_use]
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut normalized = Vec::new();
        for pat in patterns {
            let clean = pat
                .as_ref()
                .trim()
                .trim_start_matches('.')
                .to_ascii_lowercase();
            if !clean.is_empty() && seen.insert(clean.clone()) {
                normalized.push(clean);
            }
        }
        Self {
            patterns: normalized,
        }
    }

    /// Returns `true` if no block patterns are configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns the number of unique normalized host patterns in this blocker.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
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
    fn host_blocker_deduplicates_case_insensitively() {
        let blocker = HostBlocker::new([
            "Google-Analytics.COM",
            ".google-analytics.com",
            "  google-analytics.com ",
            "doubleclick.net",
        ]);
        assert_eq!(blocker.len(), 2);
        assert!(blocker.is_blocked("www.google-analytics.com"));
        assert!(blocker.is_blocked("doubleclick.net"));
    }

    #[test]
    fn preset_hosts_and_expand_block_presets_work() {
        assert!(preset_hosts("analytics").is_some_and(|h| h.contains(&"google-analytics.com")));
        assert!(preset_hosts("ADS").is_some_and(|h| h.contains(&"doubleclick.net")));
        assert!(preset_hosts(" media ").is_some_and(|h| h.contains(&"googlevideo.com")));
        assert!(preset_hosts("unknown").is_none());

        let expanded = expand_block_presets(["analytics", "ads", "ANALYTICS"]);
        assert!(expanded.is_ok());
        if let Ok(hosts) = expanded {
            let expected_len = ANALYTICS_PRESET_HOSTS.len() + ADS_PRESET_HOSTS.len();
            assert_eq!(hosts.len(), expected_len);
            assert!(hosts.iter().any(|h| h == "google-analytics.com"));
            assert!(hosts.iter().any(|h| h == "doubleclick.net"));

            let mut combined = hosts;
            combined.push("custom.tracker.example".to_owned());
            combined.push("DOUBLECLICK.NET".to_owned());
            let blocker = HostBlocker::new(combined);
            assert_eq!(blocker.len(), expected_len + 1);
            assert!(blocker.is_blocked("region1.google-analytics.com"));
            assert!(blocker.is_blocked("pagead2.googlesyndication.com"));
            assert!(blocker.is_blocked("sub.custom.tracker.example"));
            assert!(!blocker.is_blocked("example.com"));
        }

        let err = expand_block_presets(["analytics", "bogus"]);
        assert!(err.is_err());
        if let Err(msg) = err {
            assert!(msg.contains("bogus"));
            assert!(msg.contains("analytics"));
            assert!(msg.contains("ads"));
            assert!(msg.contains("media"));
        }
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
