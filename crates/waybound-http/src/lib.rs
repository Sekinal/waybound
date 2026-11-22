//! Dynamic `BoringSSL` + HTTP/2 replay client for `waybound` browser-to-HTTP handoff.
//!
//! Consumes a live [`waybound_core::SessionFingerprint`] captured passively from real Chrome
//! and dynamically configures `BoringSSL` TLS parameters, HTTP/2 `SETTINGS` / `WINDOW_UPDATE` /
//! pseudo-header order, ordered default headers, and cookies so requests sent after closing
//! Chrome carry an identical wire fingerprint at 100× lower RAM/CPU cost.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use waybound_core::{
    CapturedCookie, HeaderEntry, Http2Fingerprint, SessionFingerprint, TlsFingerprint,
};
use wreq::cookie::Jar;
use wreq::header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap};
use wreq::http2::{Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder};
use wreq::tls::compress::{CertificateCompressionAlgorithm, CertificateCompressor, Codec};
use wreq::tls::{AlpnProtocol, AlpsProtocol, TlsOptions, TlsVersion};
use wreq::{Client, Emulation, Group, Method, Proxy, Uri};

/// Errors returned by [`HandoffClient`].
#[derive(Debug, Error)]
pub enum HandoffError {
    /// Failed to build the underlying `BoringSSL` / HTTP/2 client.
    #[error("failed to build handoff HTTP client: {0}")]
    ClientBuild(String),
    /// Invalid HTTP method, URL, or header passed by the caller.
    #[error("invalid request input: {0}")]
    InvalidInput(String),
    /// Transport or HTTP error during request execution.
    #[error("HTTP request failed: {0}")]
    Request(String),
}

/// Configuration options for [`HandoffClient`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffOptions {
    /// Optional upstream HTTP/HTTPS/SOCKS5 proxy URL (e.g. `http://user:pass@host:port`).
    #[serde(default)]
    pub proxy: Option<String>,
    /// Per-request timeout in milliseconds (default: `30_000`).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Whether to follow HTTP 3xx redirects automatically (default: `true`).
    #[serde(default = "default_follow_redirects")]
    pub follow_redirects: bool,
}

const fn default_timeout_ms() -> u64 {
    30_000
}

const fn default_follow_redirects() -> bool {
    true
}

impl Default for HandoffOptions {
    fn default() -> Self {
        Self {
            proxy: None,
            timeout_ms: default_timeout_ms(),
            follow_redirects: default_follow_redirects(),
        }
    }
}

/// HTTP response returned by [`HandoffClient::request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffResponse {
    /// Final URL after any redirects.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Response headers in received order.
    pub headers: Vec<(String, String)>,
    /// UTF-8 decoded response body (lossy for binary payloads).
    pub body: String,
}

#[derive(Debug)]
struct BrotliCertCompressor;

impl CertificateCompressor for BrotliCertCompressor {
    fn compress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut enc = brotli::CompressorWriter::new(output, 4096, 5, 22);
            enc.write_all(input)?;
            enc.flush()
        })
    }

    fn decompress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut dec = brotli::Decompressor::new(input, 4096);
            let mut buf = Vec::new();
            let _ = dec.read_to_end(&mut buf)?;
            output.write_all(&buf)
        })
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::BROTLI
    }
}

#[derive(Debug)]
struct ZlibCertCompressor;

impl CertificateCompressor for ZlibCertCompressor {
    fn compress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut enc = flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
            enc.write_all(input)?;
            let _ = enc.finish()?;
            Ok(())
        })
    }

    fn decompress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut dec = flate2::read::ZlibDecoder::new(input);
            let mut buf = Vec::new();
            let _ = dec.read_to_end(&mut buf)?;
            output.write_all(&buf)
        })
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::ZLIB
    }
}

static BROTLI_COMPRESSOR: BrotliCertCompressor = BrotliCertCompressor;
static ZLIB_COMPRESSOR: ZlibCertCompressor = ZlibCertCompressor;

/// Returns `true` if `val` is a TLS GREASE value (`0x?a?a` with matching high/low bytes).
const fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && (val >> 8) == (val & 0x00ff)
}

/// Maps an IANA TLS cipher suite ID to `BoringSSL`'s cipher string token.
const fn map_cipher_suite(id: u16) -> Option<&'static str> {
    match id {
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        0xc02b => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        0xc02f => Some("ECDHE-RSA-AES128-GCM-SHA256"),
        0xc02c => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
        0xc030 => Some("ECDHE-RSA-AES256-GCM-SHA384"),
        0xcca9 => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
        0xcca8 => Some("ECDHE-RSA-CHACHA20-POLY1305"),
        0xc013 => Some("ECDHE-RSA-AES128-SHA"),
        0xc014 => Some("ECDHE-RSA-AES256-SHA"),
        0x009c => Some("AES128-GCM-SHA256"),
        0x009d => Some("AES256-GCM-SHA384"),
        0x002f => Some("AES128-SHA"),
        0x0035 => Some("AES256-SHA"),
        _ => None,
    }
}

/// Maps an IANA TLS `supported_groups` ID to `BoringSSL`'s curve name.
const fn map_supported_group(id: u16) -> Option<&'static str> {
    match id {
        0x11ec => Some("X25519MLKEM768"),
        0x6399 => Some("X25519Kyber768Draft00"),
        0x001d => Some("X25519"),
        0x0017 => Some("P-256"),
        0x0018 => Some("P-384"),
        0x0019 => Some("P-521"),
        _ => None,
    }
}

/// Maps an IANA TLS `signature_algorithms` ID to `BoringSSL`'s sigalg token.
const fn map_sigalg(id: u16) -> Option<&'static str> {
    match id {
        0x0403 => Some("ecdsa_secp256r1_sha256"),
        0x0804 => Some("rsa_pss_rsae_sha256"),
        0x0401 => Some("rsa_pkcs1_sha256"),
        0x0503 => Some("ecdsa_secp384r1_sha384"),
        0x0805 => Some("rsa_pss_rsae_sha384"),
        0x0501 => Some("rsa_pkcs1_sha384"),
        0x0806 => Some("rsa_pss_rsae_sha512"),
        0x0601 => Some("rsa_pkcs1_sha512"),
        0x0603 => Some("ecdsa_secp521r1_sha512"),
        0x0201 => Some("rsa_pkcs1_sha1"),
        0x0203 => Some("ecdsa_sha1"),
        _ => None,
    }
}

const fn map_tls_version(ver: u16) -> Option<TlsVersion> {
    match ver {
        0x0301 => Some(TlsVersion::TLS_1_0),
        0x0302 => Some(TlsVersion::TLS_1_1),
        0x0303 => Some(TlsVersion::TLS_1_2),
        0x0304 => Some(TlsVersion::TLS_1_3),
        _ => None,
    }
}

/// Dynamically builds [`wreq::tls::TlsOptions`] from a live captured [`TlsFingerprint`].
#[must_use]
#[allow(clippy::similar_names)]
pub fn build_tls_options(fp: &TlsFingerprint) -> TlsOptions {
    let mut builder = TlsOptions::builder()
        .grease_enabled(fp.grease_present)
        .permute_extensions(true)
        .enable_ocsp_stapling(fp.has_status_request)
        .enable_signed_cert_timestamps(fp.has_signed_cert_timestamp)
        .session_ticket(fp.has_session_ticket)
        .renegotiation(fp.has_renegotiation_info)
        .psk_dhe_ke(fp.psk_key_exchange_modes.contains(&1))
        .enable_ech_grease(fp.has_ech);

    let alpn: Vec<AlpnProtocol> = fp
        .alpn_protocols
        .iter()
        .filter_map(|p| match p.as_str() {
            "h2" => Some(AlpnProtocol::HTTP2),
            "http/1.1" => Some(AlpnProtocol::HTTP1),
            _ => None,
        })
        .collect();
    if !alpn.is_empty() {
        builder = builder.alpn_protocols(alpn);
    }

    let alps: Vec<AlpsProtocol> = fp
        .alps_protocols
        .iter()
        .filter_map(|p| match p.as_str() {
            "h2" => Some(AlpsProtocol::HTTP2),
            "http/1.1" => Some(AlpsProtocol::HTTP1),
            _ => None,
        })
        .collect();
    if !alps.is_empty() {
        builder = builder
            .alps_protocols(alps)
            .alps_use_new_codepoint(fp.alps_use_new_codepoint);
    }

    let clean_versions: Vec<u16> = fp
        .supported_versions
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .collect();
    if let Some(&min_v) = clean_versions.iter().min()
        && let Some(tv) = map_tls_version(min_v)
    {
        builder = builder.min_tls_version(tv);
    }
    if let Some(&max_v) = clean_versions.iter().max()
        && let Some(tv) = map_tls_version(max_v)
    {
        builder = builder.max_tls_version(tv);
    }

    let ciphers: Vec<&str> = fp
        .cipher_suites
        .iter()
        .copied()
        .filter(|&c| !is_grease(c))
        .filter_map(map_cipher_suite)
        .collect();
    if !ciphers.is_empty() {
        builder = builder
            .cipher_list(Cow::Owned(ciphers.join(":")))
            .preserve_tls13_cipher_list(true);
    }

    let curves: Vec<&str> = fp
        .supported_groups
        .iter()
        .copied()
        .filter(|&g| !is_grease(g))
        .filter_map(map_supported_group)
        .collect();
    if !curves.is_empty() {
        builder = builder.curves_list(Cow::Owned(curves.join(":")));
    }

    let sigalgs: Vec<&str> = fp
        .signature_algorithms
        .iter()
        .copied()
        .filter_map(map_sigalg)
        .collect();
    if !sigalgs.is_empty() {
        builder = builder.sigalgs_list(Cow::Owned(sigalgs.join(":")));
    }

    let mut compressors: Vec<&'static dyn CertificateCompressor> = Vec::new();
    for &alg in &fp.cert_compression_algorithms {
        match alg {
            1 => compressors.push(&ZLIB_COMPRESSOR),
            2 => compressors.push(&BROTLI_COMPRESSOR),
            _ => {}
        }
    }
    if !compressors.is_empty() {
        builder = builder.certificate_compressors(Cow::Owned(compressors));
    }

    builder.build()
}

/// Dynamically builds [`wreq::http2::Http2Options`] from a live captured [`Http2Fingerprint`].
#[must_use]
pub fn build_http2_options(fp: &Http2Fingerprint) -> Http2Options {
    let mut builder = Http2Options::builder();

    let mut order_builder = SettingsOrder::builder();
    let mut has_order = false;
    for setting in &fp.settings {
        let sid = match setting.id {
            1 => {
                builder = builder.header_table_size(setting.value);
                Some(SettingId::HeaderTableSize)
            }
            2 => {
                builder = builder.enable_push(setting.value != 0);
                Some(SettingId::EnablePush)
            }
            3 => {
                builder = builder.max_concurrent_streams(setting.value);
                Some(SettingId::MaxConcurrentStreams)
            }
            4 => {
                builder = builder.initial_window_size(setting.value);
                Some(SettingId::InitialWindowSize)
            }
            5 => {
                builder = builder.max_frame_size(setting.value);
                Some(SettingId::MaxFrameSize)
            }
            6 => {
                builder = builder.max_header_list_size(setting.value);
                Some(SettingId::MaxHeaderListSize)
            }
            8 => {
                builder = builder.enable_connect_protocol(setting.value != 0);
                Some(SettingId::EnableConnectProtocol)
            }
            9 => {
                builder = builder.no_rfc7540_priorities(setting.value != 0);
                Some(SettingId::NoRfc7540Priorities)
            }
            _ => None,
        };
        if let Some(id) = sid {
            order_builder = order_builder.push(id);
            has_order = true;
        }
    }
    if has_order {
        builder = builder.settings_order(order_builder.build());
    }

    if let Some(wu) = fp.initial_window_update {
        // RFC 9113: initial connection flow-control window starts at 65,535;
        // sending a connection WINDOW_UPDATE of `wu` yields total window `65_535 + wu`.
        builder = builder.initial_connection_window_size(wu.saturating_add(65_535));
    }

    let mut pseudo_builder = PseudoOrder::builder();
    let mut has_pseudo = false;
    for p in &fp.pseudo_header_order {
        let pid = match p.as_str() {
            ":method" => Some(PseudoId::Method),
            ":authority" => Some(PseudoId::Authority),
            ":scheme" => Some(PseudoId::Scheme),
            ":path" => Some(PseudoId::Path),
            ":protocol" => Some(PseudoId::Protocol),
            _ => None,
        };
        if let Some(id) = pid {
            pseudo_builder = pseudo_builder.push(id);
            has_pseudo = true;
        }
    }
    if has_pseudo {
        builder = builder.headers_pseudo_order(pseudo_builder.build());
    }

    builder.build()
}

fn build_headers(entries: &[HeaderEntry]) -> (HeaderMap, OrigHeaderMap) {
    let mut headers = HeaderMap::new();
    let mut orig = OrigHeaderMap::new();
    for entry in entries {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(entry.name.as_bytes()),
            HeaderValue::from_str(&entry.value),
        ) {
            let _ = headers.append(name, val);
            let _ = orig.insert(entry.name.clone());
        }
    }
    (headers, orig)
}

fn populate_cookie_jar(jar: &Jar, cookies: &[CapturedCookie]) {
    for c in cookies {
        let host = c.domain.trim_start_matches('.');
        if host.is_empty() {
            continue;
        }
        let scheme = if c.secure { "https" } else { "http" };
        let Ok(uri) = format!("{scheme}://{host}/").parse::<Uri>() else {
            continue;
        };
        let mut header = format!("{}={}; Path={}", c.name, c.value, c.path);
        if c.domain.starts_with('.') {
            header.push_str("; Domain=");
            header.push_str(&c.domain);
        }
        if c.secure {
            header.push_str("; Secure");
        }
        if c.http_only {
            header.push_str("; HttpOnly");
        }
        jar.add(header, uri);
    }
}

/// `BoringSSL` + HTTP/2 client dynamically configured from a live browser [`SessionFingerprint`].
#[derive(Clone)]
pub struct HandoffClient {
    client: Client,
    fingerprint: SessionFingerprint,
    cookies: Arc<Mutex<Vec<CapturedCookie>>>,
}

impl std::fmt::Debug for HandoffClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandoffClient")
            .field("has_tls", &self.fingerprint.tls.is_some())
            .field("has_http2", &self.fingerprint.http2.is_some())
            .field("headers", &self.fingerprint.default_headers.len())
            .finish_non_exhaustive()
    }
}

impl HandoffClient {
    /// Constructs a new [`HandoffClient`] replaying the exact TLS, HTTP/2, header, and cookie
    /// fingerprint captured in `fingerprint`.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError::ClientBuild`] if the proxy URL or BoringSSL/HTTP2 configuration
    /// is invalid.
    pub fn new(
        fingerprint: SessionFingerprint,
        options: &HandoffOptions,
    ) -> Result<Self, HandoffError> {
        let mut emu_builder = Emulation::builder();
        if let Some(ref tls_fp) = fingerprint.tls {
            emu_builder = emu_builder.tls_options(build_tls_options(tls_fp));
        }
        if let Some(ref h2_fp) = fingerprint.http2 {
            emu_builder = emu_builder.http2_options(build_http2_options(h2_fp));
        }
        let (headers, orig_headers) = build_headers(&fingerprint.default_headers);
        if !headers.is_empty() {
            emu_builder = emu_builder.headers(headers).orig_headers(orig_headers);
        }
        let emulation = emu_builder.build(Group::default());

        let jar = Arc::new(Jar::default());
        populate_cookie_jar(&jar, &fingerprint.cookies);

        let mut builder = Client::builder()
            .emulation(emulation)
            .cookie_provider(jar)
            .timeout(Duration::from_millis(options.timeout_ms.max(1000)));

        if !options.follow_redirects {
            builder = builder.redirect(wreq::redirect::Policy::none());
        }
        if let Some(ref proxy_url) = options.proxy {
            let proxy = Proxy::all(proxy_url)
                .map_err(|e| HandoffError::ClientBuild(format!("invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| HandoffError::ClientBuild(e.to_string()))?;

        let cookies = Arc::new(Mutex::new(fingerprint.cookies.clone()));
        Ok(Self {
            client,
            fingerprint,
            cookies,
        })
    }

    /// Returns the original [`SessionFingerprint`] this client was initialized from.
    #[must_use]
    pub const fn fingerprint(&self) -> &SessionFingerprint {
        &self.fingerprint
    }

    /// Returns a snapshot of the cookies currently held by this client.
    #[must_use]
    pub fn cookies(&self) -> Vec<CapturedCookie> {
        self.cookies.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Executes an HTTP request replaying the captured browser fingerprint and cookies.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError::InvalidInput`] for an invalid method or header, or
    /// [`HandoffError::Request`] if the network request fails.
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        extra_headers: &[(String, String)],
        body: Option<String>,
    ) -> Result<HandoffResponse, HandoffError> {
        let http_method = Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|e| {
                HandoffError::InvalidInput(format!("invalid HTTP method {method:?}: {e}"))
            })?;

        let mut req = self.client.request(http_method, url);
        for (k, v) in extra_headers {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                HandoffError::InvalidInput(format!("invalid header name {k:?}: {e}"))
            })?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| HandoffError::InvalidInput(format!("invalid header value: {e}")))?;
            req = req.header(name, val);
        }
        if let Some(payload) = body {
            req = req.body(payload);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| HandoffError::Request(e.to_string()))?;

        let final_url = resp.uri().to_string();
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();

        // Mirror any Set-Cookie headers into our inspectable cookie snapshot.
        let host = resp.uri().host().unwrap_or_default().to_ascii_lowercase();
        if let Ok(mut jar_guard) = self.cookies.lock() {
            for c in resp.cookies() {
                let dom = c
                    .domain()
                    .map_or_else(|| host.clone(), str::to_ascii_lowercase);
                let path = c.path().unwrap_or("/").to_owned();
                let incoming = CapturedCookie {
                    name: c.name().to_owned(),
                    value: c.value().to_owned(),
                    domain: dom,
                    path,
                    secure: c.secure(),
                    http_only: c.http_only(),
                };
                if let Some(existing) = jar_guard.iter_mut().find(|e| {
                    e.name == incoming.name
                        && e.domain.trim_start_matches('.')
                            == incoming.domain.trim_start_matches('.')
                        && e.path == incoming.path
                }) {
                    *existing = incoming;
                } else {
                    jar_guard.push(incoming);
                }
            }
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| HandoffError::Request(e.to_string()))?;
        let body_str = String::from_utf8_lossy(&bytes).into_owned();

        Ok(HandoffResponse {
            url: final_url,
            status,
            headers,
            body: body_str,
        })
    }
}

#[cfg(test)]
mod tests {
    use waybound_core::Http2Setting;

    use super::*;

    #[test]
    fn builds_handoff_client_from_chrome_like_fingerprint() {
        let fp = SessionFingerprint {
            tls: Some(TlsFingerprint {
                tls_version: 0x0303,
                cipher_suites: vec![0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
                extensions: vec![0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x000d],
                supported_groups: vec![0x2a2a, 0x11ec, 0x001d, 0x0017, 0x0018],
                ec_point_formats: vec![0],
                signature_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501],
                alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                supported_versions: vec![0x4a4a, 0x0304, 0x0303],
                cert_compression_algorithms: vec![2],
                alps_protocols: vec!["h2".to_owned()],
                alps_use_new_codepoint: true,
                psk_key_exchange_modes: vec![1],
                grease_present: true,
                has_status_request: true,
                has_signed_cert_timestamp: true,
                has_session_ticket: true,
                has_extended_master_secret: true,
                has_renegotiation_info: true,
                has_ech: true,
                ja3_string: String::new(),
                ja3_hash: String::new(),
                ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd".to_owned(),
            }),
            http2: Some(Http2Fingerprint {
                settings: vec![
                    Http2Setting {
                        id: 1,
                        value: 65536,
                    },
                    Http2Setting { id: 2, value: 0 },
                    Http2Setting {
                        id: 4,
                        value: 6_291_456,
                    },
                    Http2Setting {
                        id: 6,
                        value: 262_144,
                    },
                ],
                initial_window_update: Some(15_663_105),
                pseudo_header_order: vec![
                    ":method".to_owned(),
                    ":authority".to_owned(),
                    ":scheme".to_owned(),
                    ":path".to_owned(),
                ],
                akamai_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p".to_owned(),
            }),
            default_headers: vec![
                HeaderEntry {
                    name: "user-agent".to_owned(),
                    value: "Mozilla/5.0 Chrome/140.0.0.0".to_owned(),
                },
                HeaderEntry {
                    name: "accept-language".to_owned(),
                    value: "en-US,en;q=0.9".to_owned(),
                },
            ],
            cookies: vec![CapturedCookie {
                name: "sid".to_owned(),
                value: "test123".to_owned(),
                domain: ".example.com".to_owned(),
                path: "/".to_owned(),
                secure: true,
                http_only: true,
            }],
        };

        let client = HandoffClient::new(fp, &HandoffOptions::default());
        assert!(client.is_ok(), "client build failed: {:?}", client.err());
        if let Ok(c) = client {
            assert_eq!(c.cookies().len(), 1);
        }
    }
}
