//! Live browser TLS `ClientHello`, HTTP/2, header, and cookie fingerprint recorder.
//!
//! Passively extracts the exact wire fingerprint of the running Chrome/Chromium
//! session observed by [`crate::PassiveConnectionTap`] so [`waybound_core::SessionFingerprint`]
//! can be exported and replayed with zero static impersonation drift.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use md5::Md5;
use sha2::{Digest, Sha256};
use waybound_core::{
    CapturedCookie, HeaderEntry, Http2Fingerprint, Http2Setting, Http2StreamDependency,
    SessionFingerprint, TlsFingerprint,
};

const HANDSHAKE_CLIENT_HELLO: u8 = 1;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_ALPS_OLD: u16 = 0x4469;
const EXT_ALPS_NEW: u16 = 0x44cd;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Returns `true` if `val` is a TLS GREASE value (`0x?a?a` with matching high/low bytes, RFC 8701).
#[must_use]
pub const fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && (val >> 8) == (val & 0x00ff)
}

/// Parses a plaintext TLS `ClientHello` handshake message into a [`TlsFingerprint`].
///
/// Expects `payload` to start at the 4-byte TLS handshake header (`payload[0] == 1`).
#[must_use]
#[allow(clippy::too_many_lines, clippy::similar_names)]
pub fn parse_client_hello(payload: &[u8]) -> Option<TlsFingerprint> {
    if payload.len() < 42 || payload[0] != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let hs_len =
        (usize::from(payload[1]) << 16) | (usize::from(payload[2]) << 8) | usize::from(payload[3]);
    let msg_end = 4usize.checked_add(hs_len)?.min(payload.len());
    let body = payload.get(4..msg_end)?;

    // client_version (2) + random (32) + session_id_len (1)
    if body.len() < 35 {
        return None;
    }
    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 34usize;

    let sid_len = usize::from(*body.get(pos)?);
    pos = pos.checked_add(1)?.checked_add(sid_len)?;

    let cs_len = usize::from(read_u16(body, pos)?);
    pos = pos.checked_add(2)?;
    if cs_len % 2 != 0 || body.len() < pos.checked_add(cs_len)? {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    let mut grease_present = false;
    for chunk in body[pos..pos + cs_len].as_chunks::<2>().0 {
        let cs = u16::from_be_bytes(*chunk);
        if is_grease(cs) {
            grease_present = true;
        }
        cipher_suites.push(cs);
    }
    pos += cs_len;

    let comp_len = usize::from(*body.get(pos)?);
    pos = pos.checked_add(1)?.checked_add(comp_len)?;

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn_protocols = Vec::new();
    let mut supported_versions = Vec::new();
    let mut cert_compression_algorithms = Vec::new();
    let mut alps_protocols = Vec::new();
    let mut alps_use_new_codepoint = false;
    let mut psk_key_exchange_modes = Vec::new();
    let mut has_sni = false;
    let mut has_status_request = false;
    let mut has_signed_cert_timestamp = false;
    let mut has_session_ticket = false;
    let mut has_extended_master_secret = false;
    let mut has_renegotiation_info = false;
    let mut has_ech = false;

    if pos + 2 <= body.len() {
        let exts_len = usize::from(read_u16(body, pos)?);
        pos += 2;
        let exts_end = pos.checked_add(exts_len)?.min(body.len());

        while pos + 4 <= exts_end {
            let ext_type = read_u16(body, pos)?;
            let ext_len = usize::from(read_u16(body, pos + 2)?);
            pos += 4;
            if pos + ext_len > exts_end {
                break;
            }
            let ext_data = &body[pos..pos + ext_len];
            pos += ext_len;

            if is_grease(ext_type) {
                grease_present = true;
            }
            extensions.push(ext_type);

            match ext_type {
                EXT_SERVER_NAME => has_sni = true,
                EXT_STATUS_REQUEST => has_status_request = true,
                EXT_SUPPORTED_GROUPS => {
                    if let Some(list_len) = read_u16(ext_data, 0).map(usize::from) {
                        let end = (2 + list_len).min(ext_data.len());
                        for c in ext_data[2..end].as_chunks::<2>().0 {
                            let g = u16::from_be_bytes(*c);
                            if is_grease(g) {
                                grease_present = true;
                            }
                            supported_groups.push(g);
                        }
                    }
                }
                EXT_EC_POINT_FORMATS => {
                    if let Some(&list_len) = ext_data.first() {
                        let end = (1 + usize::from(list_len)).min(ext_data.len());
                        ec_point_formats.extend_from_slice(&ext_data[1..end]);
                    }
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    if let Some(list_len) = read_u16(ext_data, 0).map(usize::from) {
                        let end = (2 + list_len).min(ext_data.len());
                        for c in ext_data[2..end].as_chunks::<2>().0 {
                            signature_algorithms.push(u16::from_be_bytes(*c));
                        }
                    }
                }
                EXT_ALPN => {
                    parse_protocol_name_list(ext_data, &mut alpn_protocols);
                }
                EXT_SIGNED_CERT_TIMESTAMP => has_signed_cert_timestamp = true,
                EXT_EXTENDED_MASTER_SECRET => has_extended_master_secret = true,
                EXT_COMPRESS_CERTIFICATE => {
                    if let Some(&list_len) = ext_data.first() {
                        let end = (1 + usize::from(list_len)).min(ext_data.len());
                        for c in ext_data[1..end].as_chunks::<2>().0 {
                            cert_compression_algorithms.push(u16::from_be_bytes(*c));
                        }
                    }
                }
                EXT_SESSION_TICKET => has_session_ticket = true,
                EXT_SUPPORTED_VERSIONS => {
                    if let Some(&list_len) = ext_data.first() {
                        let end = (1 + usize::from(list_len)).min(ext_data.len());
                        for c in ext_data[1..end].as_chunks::<2>().0 {
                            let v = u16::from_be_bytes(*c);
                            if is_grease(v) {
                                grease_present = true;
                            }
                            supported_versions.push(v);
                        }
                    }
                }
                EXT_PSK_KEY_EXCHANGE_MODES => {
                    if let Some(&list_len) = ext_data.first() {
                        let end = (1 + usize::from(list_len)).min(ext_data.len());
                        psk_key_exchange_modes.extend_from_slice(&ext_data[1..end]);
                    }
                }
                EXT_ALPS_OLD | EXT_ALPS_NEW => {
                    alps_use_new_codepoint = ext_type == EXT_ALPS_NEW;
                    parse_protocol_name_list(ext_data, &mut alps_protocols);
                }
                EXT_ECH => has_ech = true,
                EXT_RENEGOTIATION_INFO => has_renegotiation_info = true,
                _ => {}
            }
        }
    }

    let ja3_string = compute_ja3_string(
        tls_version,
        &cipher_suites,
        &extensions,
        &supported_groups,
        &ec_point_formats,
    );
    let ja3_hash = md5_hex(ja3_string.as_bytes());
    let ja4 = compute_ja4(
        tls_version,
        has_sni,
        &cipher_suites,
        &extensions,
        &signature_algorithms,
        &alpn_protocols,
        &supported_versions,
    );

    Some(TlsFingerprint {
        tls_version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
        signature_algorithms,
        alpn_protocols,
        supported_versions,
        cert_compression_algorithms,
        alps_protocols,
        alps_use_new_codepoint,
        psk_key_exchange_modes,
        grease_present,
        has_status_request,
        has_signed_cert_timestamp,
        has_session_ticket,
        has_extended_master_secret,
        has_renegotiation_info,
        has_ech,
        ja3_string,
        ja3_hash,
        ja4,
    })
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let hi = *data.get(offset)?;
    let lo = *data.get(offset + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

fn parse_protocol_name_list(ext_data: &[u8], out: &mut Vec<String>) {
    let Some(list_len) = read_u16(ext_data, 0).map(usize::from) else {
        return;
    };
    let end = (2 + list_len).min(ext_data.len());
    let mut pos = 2usize;
    while pos < end {
        let len = usize::from(ext_data[pos]);
        pos += 1;
        if pos + len > end {
            break;
        }
        if let Ok(proto) = std::str::from_utf8(&ext_data[pos..pos + len]) {
            out.push(proto.to_owned());
        }
        pos += len;
    }
}

fn compute_ja3_string(
    tls_version: u16,
    cipher_suites: &[u16],
    extensions: &[u16],
    supported_groups: &[u16],
    ec_point_formats: &[u8],
) -> String {
    let join_u16 = |items: &[u16]| -> String {
        items
            .iter()
            .copied()
            .filter(|&v| !is_grease(v))
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let ec_str = ec_point_formats
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("-");

    format!(
        "{},{},{},{},{}",
        tls_version,
        join_u16(cipher_suites),
        join_u16(extensions),
        join_u16(supported_groups),
        ec_str,
    )
}

/// Computes the `FoxIO` JA4 fingerprint string (`a_b_c`).
#[must_use]
pub fn compute_ja4(
    tls_version: u16,
    has_sni: bool,
    cipher_suites: &[u16],
    extensions: &[u16],
    signature_algorithms: &[u16],
    alpn_protocols: &[String],
    supported_versions: &[u16],
) -> String {
    let max_ver = supported_versions
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .max()
        .unwrap_or(tls_version);
    let ver_str = match max_ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let sni_char = if has_sni { 'd' } else { 'i' };

    let mut clean_ciphers: Vec<u16> = cipher_suites
        .iter()
        .copied()
        .filter(|&c| !is_grease(c))
        .collect();
    let clean_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e))
        .collect();

    let cipher_count = clean_ciphers.len().min(99);
    let ext_count = clean_exts.len().min(99);

    let alpn_code = alpn_protocols.first().map_or_else(
        || "00".to_owned(),
        |first| {
            let bytes = first.as_bytes();
            if bytes.is_empty() {
                "00".to_owned()
            } else {
                let first_b = bytes[0];
                let last_b = bytes[bytes.len() - 1];
                if first_b.is_ascii_alphanumeric() && last_b.is_ascii_alphanumeric() {
                    format!("{}{}", char::from(first_b), char::from(last_b))
                } else {
                    format!("{first_b:02x}")
                }
            }
        },
    );

    let part_a = format!("t{ver_str}{sni_char}{cipher_count:02}{ext_count:02}{alpn_code}");

    clean_ciphers.sort_unstable();
    let part_b = if clean_ciphers.is_empty() {
        "000000000000".to_owned()
    } else {
        let joined = clean_ciphers
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        sha256_prefix12(joined.as_bytes())
    };

    let mut hash_exts: Vec<u16> = clean_exts
        .into_iter()
        .filter(|&e| e != EXT_SERVER_NAME && e != EXT_ALPN)
        .collect();
    hash_exts.sort_unstable();

    let clean_sigs: Vec<u16> = signature_algorithms
        .iter()
        .copied()
        .filter(|&s| !is_grease(s))
        .collect();

    let part_c = if hash_exts.is_empty() && clean_sigs.is_empty() {
        "000000000000".to_owned()
    } else {
        let ext_str = hash_exts
            .iter()
            .map(|e| format!("{e:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let input = if clean_sigs.is_empty() {
            ext_str
        } else {
            let sig_str = clean_sigs
                .iter()
                .map(|s| format!("{s:04x}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{ext_str}_{sig_str}")
        };
        sha256_prefix12(input.as_bytes())
    };

    format!("{part_a}_{part_b}_{part_c}")
}

fn sha256_prefix12(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(12);
    for b in &digest[..6] {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Computes the Akamai HTTP/2 fingerprint string (`settings|window_update|priorities|pseudo`).
#[must_use]
pub fn compute_akamai_h2(
    settings: &[Http2Setting],
    initial_window_update: Option<u32>,
    pseudo_header_order: &[String],
) -> String {
    let settings_str = settings
        .iter()
        .map(|s| format!("{}:{}", s.id, s.value))
        .collect::<Vec<_>>()
        .join(";");
    let window_str = initial_window_update.map_or_else(|| "00".to_owned(), |w| w.to_string());
    let pseudo_str = pseudo_header_order
        .iter()
        .filter_map(|p| p.strip_prefix(':').and_then(|rest| rest.chars().next()))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("{settings_str}|{window_str}|0|{pseudo_str}")
}

/// Thread-safe session-wide recorder shared across all [`crate::PassiveConnectionTap`] instances.
#[derive(Debug, Default, Clone)]
pub struct FingerprintRecorder {
    inner: Arc<Mutex<RecorderState>>,
}

#[derive(Debug, Default)]
struct RecorderState {
    tls: Option<TlsFingerprint>,
    h2_settings: Vec<Http2Setting>,
    h2_window_update: Option<u32>,
    h2_pseudo_order: Vec<String>,
    h2_headers_priority: Option<Http2StreamDependency>,
    default_headers: Vec<HeaderEntry>,
    default_headers_score: usize,
    api_headers: Vec<HeaderEntry>,
    api_headers_score: usize,
    cookies: Vec<CapturedCookie>,
}

/// Headers that are per-request or transport-specific and should not be copied into `default_headers`.
fn is_volatile_request_header(name_lower: &str) -> bool {
    name_lower.starts_with(':')
        || matches!(
            name_lower,
            "host"
                | "cookie"
                | "content-length"
                | "content-type"
                | "authorization"
                | "proxy-authorization"
                | "origin"
                | "referer"
                | "if-none-match"
                | "if-modified-since"
                | "range"
                | "connection"
                | "transfer-encoding"
                | "te"
        )
}

impl FingerprintRecorder {
    /// Creates a new empty [`FingerprintRecorder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a parsed TLS `ClientHello` fingerprint, preferring one that negotiates `h2`.
    pub fn record_tls(&self, fp: TlsFingerprint) {
        if let Ok(mut st) = self.inner.lock() {
            let new_has_h2 = fp.alpn_protocols.iter().any(|p| p == "h2");
            let cur_has_h2 = st
                .tls
                .as_ref()
                .is_some_and(|cur| cur.alpn_protocols.iter().any(|p| p == "h2"));
            if st.tls.is_none() || (new_has_h2 && !cur_has_h2) {
                st.tls = Some(fp);
            }
        }
    }

    /// Records the client's initial HTTP/2 `SETTINGS` frame parameters.
    pub fn record_h2_settings(&self, settings: Vec<Http2Setting>) {
        if settings.is_empty() {
            return;
        }
        if let Ok(mut st) = self.inner.lock()
            && st.h2_settings.is_empty()
        {
            st.h2_settings = settings;
        }
    }

    /// Records the client's initial connection-level HTTP/2 `WINDOW_UPDATE` increment (stream 0).
    pub fn record_h2_window_update(&self, increment: u32) {
        if increment == 0 {
            return;
        }
        if let Ok(mut st) = self.inner.lock()
            && st.h2_window_update.is_none()
        {
            st.h2_window_update = Some(increment);
        }
    }

    /// Records the pseudo-header order from the client's HTTP/2 `HEADERS` frame.
    pub fn record_h2_pseudo_order(&self, order: Vec<String>) {
        if order.is_empty() {
            return;
        }
        if let Ok(mut st) = self.inner.lock()
            && st.h2_pseudo_order.is_empty()
        {
            st.h2_pseudo_order = order;
        }
    }

    /// Records the stream priority/dependency carried on the client's HTTP/2 `HEADERS` frame.
    pub fn record_h2_headers_priority(&self, priority: Http2StreamDependency) {
        if let Ok(mut st) = self.inner.lock()
            && st.h2_headers_priority.is_none()
        {
            st.h2_headers_priority = Some(priority);
        }
    }

    /// Records ordered request headers (extracting both `default_headers` and any `Cookie` values).
    pub fn record_request_headers(&self, host: &str, headers: &[(String, String)]) {
        if headers.is_empty() {
            return;
        }
        if let Ok(mut st) = self.inner.lock() {
            // 1. Extract cookies sent by the browser so pre-existing profile cookies are captured.
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("cookie") {
                    for pair in v.split(';') {
                        let trimmed = pair.trim();
                        if let Some((name, val)) = trimmed.split_once('=') {
                            let cname = name.trim();
                            if !cname.is_empty() {
                                upsert_cookie(
                                    &mut st.cookies,
                                    CapturedCookie {
                                        name: cname.to_owned(),
                                        value: val.trim().to_owned(),
                                        domain: host.to_ascii_lowercase(),
                                        path: "/".to_owned(),
                                        secure: true,
                                        http_only: false,
                                    },
                                    false,
                                );
                            }
                        }
                    }
                }
            }

            // 2. Score this request to prefer top-level navigation headers (`default_headers`)
            //    and separately record `fetch()`/`XHR` API headers (`api_headers`).
            let mut has_ua = false;
            let mut has_ch_ua = false;
            let mut has_accept_lang = false;
            let mut is_navigate = false;
            let mut is_api = false;
            let mut filtered = Vec::new();
            for (k, v) in headers {
                let lower = k.to_ascii_lowercase();
                if lower == "user-agent" {
                    has_ua = true;
                } else if lower == "sec-ch-ua" {
                    has_ch_ua = true;
                } else if lower == "accept-language" {
                    has_accept_lang = true;
                } else if lower == "sec-fetch-mode" && v.eq_ignore_ascii_case("navigate") {
                    is_navigate = true;
                } else if (lower == "sec-fetch-mode" && v.eq_ignore_ascii_case("cors"))
                    || (lower == "sec-fetch-dest" && v.eq_ignore_ascii_case("empty"))
                {
                    is_api = true;
                }
                if !is_volatile_request_header(&lower) {
                    filtered.push(HeaderEntry {
                        name: k.clone(),
                        value: v.clone(),
                    });
                }
            }

            let base_score = usize::from(has_ua) * 10
                + usize::from(has_ch_ua) * 5
                + usize::from(has_accept_lang) * 3
                + filtered.len();
            if has_ua && is_api && base_score > st.api_headers_score {
                st.api_headers.clone_from(&filtered);
                st.api_headers_score = base_score;
            }
            let nav_score = base_score + usize::from(is_navigate) * 20;
            if has_ua && nav_score > st.default_headers_score {
                st.default_headers = filtered;
                st.default_headers_score = nav_score;
            }
        }
    }

    /// Parses and records a `Set-Cookie` response header for `host`.
    pub fn record_set_cookie(&self, host: &str, set_cookie: &str) {
        let mut parts = set_cookie.split(';');
        let Some(first) = parts.next() else {
            return;
        };
        let Some((raw_name, raw_value)) = first.split_once('=') else {
            return;
        };
        let name = raw_name.trim();
        if name.is_empty() {
            return;
        }
        let value = raw_value.trim().to_owned();
        let mut domain = host.to_ascii_lowercase();
        let mut path = "/".to_owned();
        let mut secure = false;
        let mut http_only = false;
        let mut expired = false;

        for attr in parts {
            let attr = attr.trim();
            if attr.eq_ignore_ascii_case("secure") {
                secure = true;
            } else if attr.eq_ignore_ascii_case("httponly") {
                http_only = true;
            } else if let Some((k, v)) = attr.split_once('=') {
                let k_trim = k.trim();
                let v_trim = v.trim();
                if k_trim.eq_ignore_ascii_case("domain") && !v_trim.is_empty() {
                    domain = v_trim.to_ascii_lowercase();
                } else if k_trim.eq_ignore_ascii_case("path") && !v_trim.is_empty() {
                    v_trim.clone_into(&mut path);
                } else if k_trim.eq_ignore_ascii_case("max-age")
                    && v_trim.parse::<i64>().is_ok_and(|n| n <= 0)
                {
                    expired = true;
                }
            }
        }

        if let Ok(mut st) = self.inner.lock() {
            if expired {
                let norm_dom = domain.trim_start_matches('.');
                st.cookies.retain(|c| {
                    !(c.name == name
                        && c.domain.trim_start_matches('.') == norm_dom
                        && c.path == path)
                });
            } else {
                upsert_cookie(
                    &mut st.cookies,
                    CapturedCookie {
                        name: name.to_owned(),
                        value,
                        domain,
                        path,
                        secure,
                        http_only,
                    },
                    true,
                );
            }
        }
    }

    /// Exports a point-in-time [`SessionFingerprint`] snapshot.
    #[must_use]
    pub fn snapshot(&self) -> SessionFingerprint {
        let Ok(st) = self.inner.lock() else {
            return SessionFingerprint::default();
        };
        let http2 = if st.h2_settings.is_empty()
            && st.h2_window_update.is_none()
            && st.h2_pseudo_order.is_empty()
        {
            None
        } else {
            let akamai =
                compute_akamai_h2(&st.h2_settings, st.h2_window_update, &st.h2_pseudo_order);
            Some(Http2Fingerprint {
                settings: st.h2_settings.clone(),
                initial_window_update: st.h2_window_update,
                pseudo_header_order: st.h2_pseudo_order.clone(),
                headers_priority: st.h2_headers_priority,
                akamai_fingerprint: akamai,
            })
        };
        SessionFingerprint {
            tls: st.tls.clone(),
            http2,
            default_headers: st.default_headers.clone(),
            api_headers: st.api_headers.clone(),
            cookies: st.cookies.clone(),
        }
    }
}

fn domain_matches_host(cookie_domain: &str, host: &str) -> bool {
    let cd = cookie_domain.trim_start_matches('.');
    let h = host.trim_start_matches('.');
    h == cd
        || (h.len() > cd.len()
            && h.ends_with(cd)
            && h.as_bytes().get(h.len() - cd.len() - 1) == Some(&b'.'))
}

/// Maximum number of cookies retained in [`FingerprintRecorder`] to bound memory.
const MAX_COOKIES: usize = 256;

fn upsert_cookie(jar: &mut Vec<CapturedCookie>, incoming: CapturedCookie, overwrite_meta: bool) {
    let incoming_dom = incoming.domain.trim_start_matches('.');
    if let Some(existing) = jar.iter_mut().find(|c| {
        if c.name != incoming.name {
            return false;
        }
        if overwrite_meta {
            c.domain.trim_start_matches('.') == incoming_dom && c.path == incoming.path
        } else {
            domain_matches_host(&c.domain, incoming_dom)
        }
    }) {
        existing.value = incoming.value;
        if overwrite_meta {
            existing.domain = incoming.domain;
            existing.path = incoming.path;
            existing.secure = incoming.secure;
            existing.http_only = incoming.http_only;
        }
    } else {
        if jar.len() >= MAX_COOKIES {
            let _ = jar.remove(0);
        }
        jar.push(incoming);
    }
}

/// Computes the lowercase hex MD5 digest (used exclusively for JA3 fingerprint hashing).
fn md5_hex(input: &[u8]) -> String {
    let digest = Md5::digest(input);
    let mut out = String::with_capacity(32);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_chrome_like_client_hello() -> Vec<u8> {
        let mut exts = Vec::new();
        let push_ext = |buf: &mut Vec<u8>, ext_type: u16, data: &[u8]| {
            buf.extend_from_slice(&ext_type.to_be_bytes());
            buf.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
            buf.extend_from_slice(data);
        };

        // GREASE extension
        push_ext(&mut exts, 0x0a0a, &[]);
        // SNI (example.com)
        let mut sni = vec![0, 14, 0, 0, 11];
        sni.extend_from_slice(b"example.com");
        push_ext(&mut exts, EXT_SERVER_NAME, &sni);
        // extended_master_secret, renegotiation_info, status_request, sct, session_ticket
        push_ext(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
        push_ext(&mut exts, EXT_RENEGOTIATION_INFO, &[0]);
        push_ext(&mut exts, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0]);
        push_ext(&mut exts, EXT_SIGNED_CERT_TIMESTAMP, &[]);
        push_ext(&mut exts, EXT_SESSION_TICKET, &[]);
        // supported_groups: GREASE, X25519MLKEM768 (0x11ec), X25519 (0x001d), P-256 (0x0017), P-384 (0x0018)
        let mut groups = vec![0, 10];
        for g in [0x2a2au16, 0x11ec, 0x001d, 0x0017, 0x0018] {
            groups.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut exts, EXT_SUPPORTED_GROUPS, &groups);
        // ec_point_formats: uncompressed (0)
        push_ext(&mut exts, EXT_EC_POINT_FORMATS, &[1, 0]);
        // ALPN: h2, http/1.1
        let mut alpn = vec![0, 12, 2];
        alpn.extend_from_slice(b"h2");
        alpn.push(8);
        alpn.extend_from_slice(b"http/1.1");
        push_ext(&mut exts, EXT_ALPN, &alpn);
        // signature_algorithms
        let sigs = [
            0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sig_buf = vec![0, u8::try_from(sigs.len() * 2).unwrap_or(0)];
        for s in sigs {
            sig_buf.extend_from_slice(&s.to_be_bytes());
        }
        push_ext(&mut exts, EXT_SIGNATURE_ALGORITHMS, &sig_buf);
        // compress_certificate: brotli (2)
        push_ext(&mut exts, EXT_COMPRESS_CERTIFICATE, &[2, 0, 2]);
        // supported_versions: GREASE, TLS 1.3 (0x0304), TLS 1.2 (0x0303)
        push_ext(
            &mut exts,
            EXT_SUPPORTED_VERSIONS,
            &[6, 0x4a, 0x4a, 0x03, 0x04, 0x03, 0x03],
        );
        // psk_key_exchange_modes: psk_dhe_ke (1)
        push_ext(&mut exts, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1]);
        // ALPS new codepoint (0x44cd): h2
        push_ext(&mut exts, EXT_ALPS_NEW, &[0, 3, 2, b'h', b'2']);

        let ciphers = [
            0x1a1au16, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        ];
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11u8; 32]); // random
        body.push(32); // session_id_len
        body.extend_from_slice(&[0x22u8; 32]); // session_id
        body.extend_from_slice(&u16::try_from(ciphers.len() * 2).unwrap_or(0).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]); // compression methods: null
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = vec![
            HANDSHAKE_CLIENT_HELLO,
            u8::try_from((body.len() >> 16) & 0xff).unwrap_or(0),
            u8::try_from((body.len() >> 8) & 0xff).unwrap_or(0),
            u8::try_from(body.len() & 0xff).unwrap_or(0),
        ];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn parses_chrome_client_hello_and_computes_ja3_ja4() {
        let ch = build_chrome_like_client_hello();
        let fp = parse_client_hello(&ch);
        assert!(fp.is_some());
        let Some(fp) = fp else {
            return;
        };

        assert_eq!(fp.tls_version, 0x0303);
        assert!(fp.grease_present);
        assert_eq!(fp.alpn_protocols, vec!["h2", "http/1.1"]);
        assert_eq!(fp.alps_protocols, vec!["h2"]);
        assert!(fp.alps_use_new_codepoint);
        assert_eq!(fp.cert_compression_algorithms, vec![2]);
        assert!(fp.supported_groups.contains(&0x11ec));
        assert!(fp.has_status_request);
        assert!(fp.has_signed_cert_timestamp);
        assert!(fp.has_session_ticket);
        assert!(fp.has_extended_master_secret);
        assert!(fp.has_renegotiation_info);
        assert_eq!(fp.ja3_hash.len(), 32);
        assert!(fp.ja4.starts_with("t13d0914h2_"));
        assert_eq!(fp.ja4.split('_').count(), 3);
    }

    #[test]
    fn md5_matches_rfc1321_test_vector() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn computes_akamai_h2_and_merges_cookies() {
        let rec = FingerprintRecorder::new();
        rec.record_h2_settings(vec![
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
        ]);
        rec.record_h2_window_update(15_663_105);
        rec.record_h2_pseudo_order(vec![
            ":method".to_owned(),
            ":authority".to_owned(),
            ":scheme".to_owned(),
            ":path".to_owned(),
        ]);
        rec.record_set_cookie(
            "www.example.com",
            "sid=abc123; Domain=.example.com; Path=/; Secure; HttpOnly",
        );
        rec.record_request_headers(
            "www.example.com",
            &[
                ("user-agent".to_owned(), "Mozilla/5.0 Chrome/140".to_owned()),
                ("accept-language".to_owned(), "en-US,en;q=0.9".to_owned()),
                ("cookie".to_owned(), "sid=abc123; theme=dark".to_owned()),
            ],
        );

        let snap = rec.snapshot();
        assert_eq!(
            snap.http2.as_ref().map(|h| h.akamai_fingerprint.as_str()),
            Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")
        );
        assert_eq!(snap.default_headers.len(), 2);
        assert_eq!(snap.cookies.len(), 2);
        let sid = snap.cookies.iter().find(|c| c.name == "sid");
        assert!(sid.is_some_and(|c| c.http_only && c.secure && c.domain == ".example.com"));
    }
}
