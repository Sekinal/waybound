//! Live browser TLS, HTTP/2, header, and cookie fingerprint types.
//!
//! Captured passively from the wire by `waybound-net` without MITM certificates
//! or CDP, and consumed by `waybound-http` to replay an identical wire fingerprint
//! after closing the browser.

use serde::{Deserialize, Serialize};

/// Exact TLS `ClientHello` fingerprint observed on the wire from the live browser.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TlsFingerprint {
    /// Legacy `client_version` field from `ClientHello` (typically `0x0303`).
    pub tls_version: u16,
    /// Offered cipher suite IDs in exact wire order (including any GREASE values).
    pub cipher_suites: Vec<u16>,
    /// Offered TLS extension type IDs in exact wire order (including any GREASE values).
    pub extensions: Vec<u16>,
    /// Offered `supported_groups` (extension `0x000a`) IDs in exact wire order.
    pub supported_groups: Vec<u16>,
    /// Offered `ec_point_formats` (extension `0x000b`) values in exact wire order.
    pub ec_point_formats: Vec<u8>,
    /// Offered `signature_algorithms` (extension `0x000d`) IDs in exact wire order.
    pub signature_algorithms: Vec<u16>,
    /// Offered ALPN protocol names (extension `0x0010`), e.g. `["h2", "http/1.1"]`.
    pub alpn_protocols: Vec<String>,
    /// Offered `supported_versions` (extension `0x002b`) values in exact wire order.
    pub supported_versions: Vec<u16>,
    /// Offered `compress_certificate` (extension `0x001b`) algorithm IDs (e.g. `2` = brotli).
    pub cert_compression_algorithms: Vec<u16>,
    /// Offered ALPS protocol names (extension `0x4469` or `0x44cd`).
    pub alps_protocols: Vec<String>,
    /// Whether Chrome used the new ALPS extension codepoint (`0x44cd`) vs legacy (`0x4469`).
    pub alps_use_new_codepoint: bool,
    /// Offered `psk_key_exchange_modes` (extension `0x002d`) values.
    pub psk_key_exchange_modes: Vec<u8>,
    /// `true` if any GREASE value (`0x?a?a`) was observed in ciphers, extensions, or groups.
    pub grease_present: bool,
    /// `true` if `status_request` (OCSP stapling, `0x0005`) was offered.
    pub has_status_request: bool,
    /// `true` if `signed_certificate_timestamp` (`0x0012`) was offered.
    pub has_signed_cert_timestamp: bool,
    /// `true` if `session_ticket` (`0x0023`) was offered.
    pub has_session_ticket: bool,
    /// `true` if `extended_master_secret` (`0x0017`) was offered.
    pub has_extended_master_secret: bool,
    /// `true` if `renegotiation_info` (`0xff01`) was offered.
    pub has_renegotiation_info: bool,
    /// `true` if `encrypted_client_hello` (`0xfe0d`) was offered.
    pub has_ech: bool,
    /// Classic JA3 fingerprint string (GREASE filtered).
    pub ja3_string: String,
    /// MD5 hex digest of `ja3_string`.
    pub ja3_hash: String,
    /// `FoxIO` JA4 fingerprint string (e.g. `t13d1516h2_8daaf6152771_d8a2da3f94cd`).
    pub ja4: String,
}

/// Single HTTP/2 `SETTINGS` frame parameter in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http2Setting {
    /// RFC 9113 setting identifier (e.g. `1` = `HEADER_TABLE_SIZE`, `4` = `INITIAL_WINDOW_SIZE`).
    pub id: u16,
    /// Setting value.
    pub value: u32,
}

/// Exact HTTP/2 connection & header framing fingerprint observed from the live browser.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Http2Fingerprint {
    /// Initial client `SETTINGS` frame parameters in exact wire order.
    pub settings: Vec<Http2Setting>,
    /// Initial connection-level `WINDOW_UPDATE` increment sent on stream `0`, if observed.
    pub initial_window_update: Option<u32>,
    /// Pseudo-header wire order from the client's first `HEADERS` frame
    /// (e.g. `[":method", ":authority", ":scheme", ":path"]`).
    pub pseudo_header_order: Vec<String>,
    /// Akamai HTTP/2 fingerprint string (`settings|window_update|priorities|pseudo_initials`).
    pub akamai_fingerprint: String,
}

/// Ordered HTTP header `(name, value)` pair preserving exact wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEntry {
    /// Header name (lowercase for HTTP/2, original case for HTTP/1.1).
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Cookie captured passively from live browser `Cookie` / `Set-Cookie` headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedCookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain scope (e.g. `www.example.com` or `.example.com`).
    pub domain: String,
    /// Path scope (e.g. `/`).
    pub path: String,
    /// `Secure` attribute.
    #[serde(default)]
    pub secure: bool,
    /// `HttpOnly` attribute.
    #[serde(default)]
    pub http_only: bool,
}

/// Complete live wire fingerprint + cookie jar snapshot of a running browser session.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionFingerprint {
    /// Captured TLS `ClientHello` fingerprint, if any TLS handshake was observed.
    pub tls: Option<TlsFingerprint>,
    /// Captured HTTP/2 connection fingerprint, if any HTTP/2 connection was observed.
    pub http2: Option<Http2Fingerprint>,
    /// Ordered default request headers observed from the browser (User-Agent, Client Hints, Accept, etc.).
    pub default_headers: Vec<HeaderEntry>,
    /// Live cookies observed across the session (from both `Set-Cookie` and `Cookie` headers).
    pub cookies: Vec<CapturedCookie>,
}
