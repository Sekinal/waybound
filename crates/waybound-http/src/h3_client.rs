//! Pure-Rust HTTP/3 (QUIC) client for opt-in `waybound` browser-to-HTTP handoff.
//!
//! Uses `quinn` + `h3` + `h3-quinn` with `rustls` (`ring` crypto provider + `webpki-roots`)
//! and shares the cookie store with [`crate::HandoffClient`]'s `BoringSSL` HTTP/2 transport.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use waybound_core::{CapturedCookie, HeaderEntry};
use wreq::cookie::Jar;

use crate::{HandoffError, HandoffResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, base64};

/// Maximum HTTP 3xx redirect hops followed automatically.
const MAX_REDIRECTS: usize = 10;

/// QUIC connection idle timeout matching the HTTP/2 connection pool.
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// QUIC keep-alive ping interval for warm pooled connections.
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum time spent waiting for a QUIC/TLS/H3 handshake before falling back to HTTP/2.
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

type PooledSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Outcome error of an HTTP/3 request attempt.
#[derive(Debug)]
pub(crate) enum H3AttemptError {
    /// QUIC/H3 connect, handshake, or transport setup failed — caller should transparently
    /// fall back to the `BoringSSL` HTTP/2 client.
    Fallback(String),
    /// Invalid HTTP method, URI, header, or oversized request body.
    InvalidInput(String),
    /// Post-handshake HTTP/3 request or response error.
    Request(String),
}

#[derive(Default)]
struct Endpoints {
    v4: Option<quinn::Endpoint>,
    v6: Option<quinn::Endpoint>,
}

/// Pure-Rust HTTP/3 (QUIC) client with per-origin connection pooling and shared cookie state.
#[derive(Clone)]
pub struct Http3Client {
    client_config: quinn::ClientConfig,
    endpoints: Arc<tokio::sync::Mutex<Endpoints>>,
    pool: Arc<tokio::sync::Mutex<HashMap<(String, u16), PooledSender>>>,
    default_headers: Vec<HeaderEntry>,
    cookies: Arc<Mutex<Vec<CapturedCookie>>>,
    jar: Arc<Jar>,
    timeout: Duration,
    follow_redirects: bool,
}

impl std::fmt::Debug for Http3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3Client")
            .field("default_headers", &self.default_headers.len())
            .field("timeout", &self.timeout)
            .field("follow_redirects", &self.follow_redirects)
            .finish_non_exhaustive()
    }
}

fn build_quinn_client_config(
    roots: rustls::RootCertStore,
) -> Result<quinn::ClientConfig, HandoffError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| HandoffError::ClientBuild(format!("rustls TLS 1.3 config failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| HandoffError::ClientBuild(format!("QUIC TLS config failed: {e}")))?;

    let mut transport = quinn::TransportConfig::default();
    let _ = transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));
    if let Ok(idle) = QUIC_IDLE_TIMEOUT.try_into() {
        let _ = transport.max_idle_timeout(Some(idle));
    }

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let _ = client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

impl Http3Client {
    /// Constructs a new [`Http3Client`] trusting the `webpki-roots` CA bundle.
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError::ClientBuild`] if the `rustls` / QUIC configuration cannot be built.
    pub fn new(
        default_headers: Vec<HeaderEntry>,
        cookies: Arc<Mutex<Vec<CapturedCookie>>>,
        jar: Arc<Jar>,
        timeout: Duration,
        follow_redirects: bool,
    ) -> Result<Self, HandoffError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_root_store(
            roots,
            default_headers,
            cookies,
            jar,
            timeout,
            follow_redirects,
        )
    }

    /// Constructs a test [`Http3Client`] trusting custom DER-encoded root certificate(s).
    ///
    /// # Errors
    ///
    /// Returns [`HandoffError::ClientBuild`] if any DER certificate or the QUIC TLS configuration
    /// is invalid.
    #[cfg(test)]
    pub(crate) fn with_custom_roots(
        certs: &[rustls::pki_types::CertificateDer<'static>],
        default_headers: Vec<HeaderEntry>,
        cookies: Arc<Mutex<Vec<CapturedCookie>>>,
        jar: Arc<Jar>,
        timeout: Duration,
        follow_redirects: bool,
    ) -> Result<Self, HandoffError> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert.clone()).map_err(|e| {
                HandoffError::ClientBuild(format!("invalid custom root certificate: {e}"))
            })?;
        }
        Self::with_root_store(
            roots,
            default_headers,
            cookies,
            jar,
            timeout,
            follow_redirects,
        )
    }

    fn with_root_store(
        roots: rustls::RootCertStore,
        default_headers: Vec<HeaderEntry>,
        cookies: Arc<Mutex<Vec<CapturedCookie>>>,
        jar: Arc<Jar>,
        timeout: Duration,
        follow_redirects: bool,
    ) -> Result<Self, HandoffError> {
        let client_config = build_quinn_client_config(roots)?;
        Ok(Self {
            client_config,
            endpoints: Arc::new(tokio::sync::Mutex::new(Endpoints::default())),
            pool: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            default_headers,
            cookies,
            jar,
            timeout,
            follow_redirects,
        })
    }

    /// Executes an HTTP/3 request, honoring `timeout`, redirects, cookies, and body size limits.
    pub(crate) async fn send(
        &self,
        method: &str,
        url: &str,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<HandoffResponse, H3AttemptError> {
        let mut current_method = Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|e| {
                H3AttemptError::InvalidInput(format!("invalid HTTP method {method:?}: {e}"))
            })?;

        if let Some(payload) = body
            && payload.len() > MAX_REQUEST_BYTES
        {
            return Err(H3AttemptError::InvalidInput(format!(
                "request body exceeded {MAX_REQUEST_BYTES}-byte limit"
            )));
        }

        // Validate caller-supplied headers up front so invalid input never triggers H2 fallback.
        for (k, v) in extra_headers {
            let _ = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                H3AttemptError::InvalidInput(format!("invalid header name {k:?}: {e}"))
            })?;
            let _ = HeaderValue::from_str(v)
                .map_err(|e| H3AttemptError::InvalidInput(format!("invalid header value: {e}")))?;
        }

        let mut current_url = url.to_owned();
        let mut current_body = body.map(Cow::Borrowed);
        let mut current_extra_headers: Vec<(String, String)> = extra_headers.to_vec();

        let deadline = tokio::time::Instant::now() + self.timeout;

        for hop in 0..=MAX_REDIRECTS {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(if hop == 0 {
                    H3AttemptError::Fallback("HTTP/3 request timed out".to_owned())
                } else {
                    H3AttemptError::Request("HTTP/3 request timed out".to_owned())
                });
            }

            let uri: Uri = current_url.parse().map_err(|e| {
                H3AttemptError::InvalidInput(format!("invalid URL {current_url:?}: {e}"))
            })?;
            if uri.scheme_str() != Some("https") {
                let msg = format!("HTTP/3 requires https:// scheme (got {current_url:?})");
                return Err(if hop == 0 {
                    H3AttemptError::Fallback(msg)
                } else {
                    H3AttemptError::Request(msg)
                });
            }

            let resp = self
                .send_single(
                    &current_method,
                    &uri,
                    &current_extra_headers,
                    current_body.as_deref(),
                    remaining,
                    hop == 0,
                )
                .await?;

            if self.follow_redirects
                && matches!(resp.status, 301 | 302 | 303 | 307 | 308)
                && let Some(location) = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .map(|(_, v)| v.as_str())
            {
                if hop == MAX_REDIRECTS {
                    return Err(H3AttemptError::Request(format!(
                        "too many redirects (exceeded {MAX_REDIRECTS})"
                    )));
                }
                let next_url = resolve_redirect_url(&uri, location).map_err(|msg| {
                    H3AttemptError::Request(format!(
                        "invalid redirect location {location:?}: {msg}"
                    ))
                })?;

                // Strip sensitive headers on cross-origin redirect.
                if let Ok(next_uri) = next_url.parse::<Uri>()
                    && !is_same_origin(&uri, &next_uri)
                {
                    current_extra_headers.retain(|(k, _)| {
                        !k.eq_ignore_ascii_case("authorization")
                            && !k.eq_ignore_ascii_case("proxy-authorization")
                            && !k.eq_ignore_ascii_case("cookie")
                    });
                }

                // RFC 9110: 303 always becomes GET; 301/302 convert POST to GET and drop body.
                if resp.status == 303
                    || (matches!(resp.status, 301 | 302) && current_method == Method::POST)
                {
                    current_method = Method::GET;
                    current_body = None;
                    current_extra_headers.retain(|(k, _)| {
                        !k.eq_ignore_ascii_case("content-length")
                            && !k.eq_ignore_ascii_case("content-type")
                    });
                }

                current_url = next_url;
                continue;
            }

            return Ok(resp);
        }

        Err(H3AttemptError::Request(format!(
            "too many redirects (exceeded {MAX_REDIRECTS})"
        )))
    }

    async fn send_single(
        &self,
        method: &Method,
        uri: &Uri,
        extra_headers: &[(String, String)],
        body: Option<&[u8]>,
        remaining: Duration,
        allow_fallback: bool,
    ) -> Result<HandoffResponse, H3AttemptError> {
        let host = uri
            .host()
            .ok_or_else(|| H3AttemptError::InvalidInput("URL missing host".to_owned()))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let pool_key = (host.clone(), port);

        // Try pooled connection first; on send failure evict and establish a fresh connection once.
        let pooled = {
            let guard = self.pool.lock().await;
            guard.get(&pool_key).cloned()
        };

        let mut stream = if let Some(mut sender) = pooled {
            let req = self.build_request(method, uri, extra_headers)?;
            if let Ok(Ok(s)) = tokio::time::timeout(remaining, sender.send_request(req)).await {
                s
            } else {
                let mut guard = self.pool.lock().await;
                let _ = guard.remove(&pool_key);
                drop(guard);
                self.connect_and_send(method, uri, extra_headers, remaining, allow_fallback)
                    .await?
            }
        } else {
            self.connect_and_send(method, uri, extra_headers, remaining, allow_fallback)
                .await?
        };

        let exchange = async {
            if let Some(payload) = body
                && !payload.is_empty()
            {
                stream
                    .send_data(Bytes::copy_from_slice(payload))
                    .await
                    .map_err(|e| {
                        H3AttemptError::Request(format!("HTTP/3 send body failed: {e}"))
                    })?;
            }
            stream.finish().await.map_err(|e| {
                H3AttemptError::Request(format!("HTTP/3 finish stream failed: {e}"))
            })?;

            let resp = stream.recv_response().await.map_err(|e| {
                H3AttemptError::Request(format!("HTTP/3 recv response failed: {e}"))
            })?;

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

            // Persist any Set-Cookie headers back into both the shared cookie list and wreq Jar.
            self.store_set_cookies(uri, &headers);

            let mut raw_bytes = Vec::new();
            while let Some(mut chunk) = stream
                .recv_data()
                .await
                .map_err(|e| H3AttemptError::Request(format!("HTTP/3 recv body failed: {e}")))?
            {
                let chunk_len = chunk.remaining();
                if raw_bytes.len().saturating_add(chunk_len) > MAX_RESPONSE_BYTES {
                    return Err(H3AttemptError::Request(format!(
                        "response body exceeded {MAX_RESPONSE_BYTES}-byte limit"
                    )));
                }
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    raw_bytes.extend_from_slice(slice);
                    let n = slice.len();
                    chunk.advance(n);
                }
            }

            let decoded_bytes = decompress_body(&headers, raw_bytes)?;
            let body_base64 = base64::encode(&decoded_bytes);
            let body_str = String::from_utf8_lossy(&decoded_bytes).into_owned();

            Ok(HandoffResponse {
                url: uri.to_string(),
                status,
                headers,
                body_bytes: decoded_bytes,
                body_base64,
                body: body_str,
            })
        };

        tokio::time::timeout(remaining, exchange)
            .await
            .map_err(|_| H3AttemptError::Request("HTTP/3 response timed out".to_owned()))?
    }

    async fn connect_and_send(
        &self,
        method: &Method,
        uri: &Uri,
        extra_headers: &[(String, String)],
        remaining: Duration,
        allow_fallback: bool,
    ) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, H3AttemptError> {
        let host = uri
            .host()
            .ok_or_else(|| H3AttemptError::InvalidInput("URL missing host".to_owned()))?
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);

        let handshake_budget = remaining.min(QUIC_HANDSHAKE_TIMEOUT);
        let mut sender = tokio::time::timeout(handshake_budget, self.open_connection(&host, port))
            .await
            .map_err(|_| {
                let msg = format!("QUIC handshake to {host}:{port} timed out");
                if allow_fallback {
                    H3AttemptError::Fallback(msg)
                } else {
                    H3AttemptError::Request(msg)
                }
            })?
            .map_err(|msg| {
                if allow_fallback {
                    H3AttemptError::Fallback(msg)
                } else {
                    H3AttemptError::Request(msg)
                }
            })?;

        let req = self.build_request(method, uri, extra_headers)?;
        let stream = tokio::time::timeout(remaining, sender.send_request(req))
            .await
            .map_err(|_| {
                let msg = format!("HTTP/3 send_request to {host}:{port} timed out");
                if allow_fallback {
                    H3AttemptError::Fallback(msg)
                } else {
                    H3AttemptError::Request(msg)
                }
            })?
            .map_err(|e| {
                let msg = format!("HTTP/3 send_request failed: {e}");
                if allow_fallback {
                    H3AttemptError::Fallback(msg)
                } else {
                    H3AttemptError::Request(msg)
                }
            })?;

        {
            let mut guard = self.pool.lock().await;
            let _ = guard.insert((host, port), sender);
        }

        Ok(stream)
    }

    async fn open_connection(&self, host: &str, port: u16) -> Result<PooledSender, String> {
        let lookup_host = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((lookup_host, port))
            .await
            .map_err(|e| format!("DNS lookup failed for {host}:{port}: {e}"))?
            .collect();

        let Some(&remote_addr) = addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first())
        else {
            return Err(format!(
                "DNS lookup returned no addresses for {host}:{port}"
            ));
        };

        let endpoint = self.get_endpoint(remote_addr.is_ipv6()).await?;
        let connecting = endpoint
            .connect(remote_addr, lookup_host)
            .map_err(|e| format!("QUIC connect setup failed for {host}:{port}: {e}"))?;
        let quinn_conn = connecting
            .await
            .map_err(|e| format!("QUIC handshake failed for {host}:{port}: {e}"))?;

        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(quinn_conn))
            .await
            .map_err(|e| format!("HTTP/3 session init failed for {host}:{port}: {e}"))?;

        drop(tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));

        Ok(send_request)
    }

    async fn get_endpoint(&self, is_ipv6: bool) -> Result<quinn::Endpoint, String> {
        let mut guard = self.endpoints.lock().await;
        let slot = if is_ipv6 {
            &mut guard.v6
        } else {
            &mut guard.v4
        };
        if let Some(ep) = slot {
            return Ok(ep.clone());
        }
        let bind_addr = if is_ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|e| format!("failed to bind QUIC UDP socket {bind_addr}: {e}"))?;
        endpoint.set_default_client_config(self.client_config.clone());
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    fn build_request(
        &self,
        method: &Method,
        uri: &Uri,
        extra_headers: &[(String, String)],
    ) -> Result<Request<()>, H3AttemptError> {
        let mut builder = Request::builder().method(method.clone()).uri(uri.clone());

        let has_extra = |target: &str| {
            extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(target))
        };

        // 1. Ordered default headers from SessionFingerprint (skipping H3-forbidden or overridden ones).
        for entry in &self.default_headers {
            if is_h3_forbidden_header(&entry.name) || has_extra(&entry.name) {
                continue;
            }
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(entry.name.as_bytes()),
                HeaderValue::from_str(&entry.value),
            ) {
                builder = builder.header(name, val);
            }
        }

        // 2. Ensure Accept-Encoding is present unless already supplied by fingerprint or caller.
        let has_accept_encoding = has_extra("accept-encoding")
            || self
                .default_headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("accept-encoding"));
        if !has_accept_encoding {
            builder = builder.header("accept-encoding", "gzip, br, deflate");
        }

        // 3. Attach Cookie header from the shared cookie store unless caller explicitly set one.
        if !has_extra("cookie")
            && let Some(cookie_header) = self.build_cookie_header(uri)
            && let Ok(val) = HeaderValue::from_str(&cookie_header)
        {
            builder = builder.header("cookie", val);
        }

        // 4. Caller-supplied extra headers.
        for (k, v) in extra_headers {
            if is_h3_forbidden_header(k) {
                continue;
            }
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                H3AttemptError::InvalidInput(format!("invalid header name {k:?}: {e}"))
            })?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| H3AttemptError::InvalidInput(format!("invalid header value: {e}")))?;
            builder = builder.header(name, val);
        }

        builder.body(()).map_err(|e| {
            H3AttemptError::InvalidInput(format!("failed to build HTTP/3 request: {e}"))
        })
    }

    fn build_cookie_header(&self, uri: &Uri) -> Option<String> {
        let req_host = uri.host()?.to_ascii_lowercase();
        let req_path = uri.path();
        let is_https = uri.scheme_str() == Some("https");

        let mut pairs = Vec::new();
        {
            let guard = self.cookies.lock().ok()?;
            for c in guard.iter() {
                if c.secure && !is_https {
                    continue;
                }
                if !cookie_domain_matches(&c.domain, &req_host) {
                    continue;
                }
                if !cookie_path_matches(&c.path, req_path) {
                    continue;
                }
                pairs.push(format!("{}={}", c.name, c.value));
            }
        }

        if pairs.is_empty() {
            None
        } else {
            Some(pairs.join("; "))
        }
    }

    fn store_set_cookies(&self, uri: &Uri, headers: &[(String, String)]) {
        let req_host = uri.host().unwrap_or_default().to_ascii_lowercase();
        let wreq_uri = uri.to_string().parse::<Uri>().ok();

        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            if let Some(ref target_uri) = wreq_uri {
                self.jar.add(value.clone(), target_uri.clone());
            }
            if let Some(parsed) = parse_set_cookie(value, &req_host)
                && let Ok(mut guard) = self.cookies.lock()
            {
                if let Some(existing) = guard.iter_mut().find(|e| {
                    e.name == parsed.name
                        && e.domain.trim_start_matches('.') == parsed.domain.trim_start_matches('.')
                        && e.path == parsed.path
                }) {
                    *existing = parsed;
                } else {
                    guard.push(parsed);
                }
            }
        }
    }
}

fn is_h3_forbidden_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

fn cookie_domain_matches(cookie_domain: &str, req_host: &str) -> bool {
    let trimmed = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    if req_host == trimmed {
        return true;
    }
    if cookie_domain.starts_with('.') {
        let suffix_len = trimmed.len();
        if req_host.len() > suffix_len
            && req_host.ends_with(&trimmed)
            && req_host.as_bytes()[req_host.len() - suffix_len - 1] == b'.'
        {
            return true;
        }
    }
    false
}

fn cookie_path_matches(cookie_path: &str, req_path: &str) -> bool {
    if cookie_path.is_empty() || cookie_path == "/" {
        return true;
    }
    if req_path == cookie_path {
        return true;
    }
    if let Some(rest) = req_path.strip_prefix(cookie_path) {
        return cookie_path.ends_with('/') || rest.starts_with('/');
    }
    false
}

fn parse_set_cookie(raw: &str, default_host: &str) -> Option<CapturedCookie> {
    let mut parts = raw.split(';');
    let first = parts.next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let value = value.trim().to_owned();

    let default_host_lower = default_host.to_ascii_lowercase();
    let mut domain = default_host_lower.clone();
    let mut path = "/".to_owned();
    let mut secure = false;
    let mut http_only = false;

    for attr in parts {
        let trimmed = attr.trim();
        if trimmed.eq_ignore_ascii_case("secure") {
            secure = true;
        } else if trimmed.eq_ignore_ascii_case("httponly") {
            http_only = true;
        } else if let Some((k, v)) = trimmed.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("domain") && !v.is_empty() {
                let candidate = v.trim_start_matches('.').to_ascii_lowercase();
                if candidate.is_empty() {
                    return None;
                }
                let matches_host = default_host_lower == candidate
                    || (default_host_lower.len() > candidate.len()
                        && default_host_lower.ends_with(&candidate)
                        && default_host_lower.as_bytes()
                            [default_host_lower.len() - candidate.len() - 1]
                            == b'.');
                if !matches_host {
                    // Reject cross-domain Set-Cookie per RFC 6265 §5.3 step 6.
                    return None;
                }
                // Leading dot marks an explicit Domain= cookie (matches subdomains per RFC 6265 §5.2.3).
                domain = format!(".{candidate}");
            } else if k.eq_ignore_ascii_case("path") && !v.is_empty() {
                v.clone_into(&mut path);
            }
        }
    }

    Some(CapturedCookie {
        name: name.to_owned(),
        value,
        domain,
        path,
        secure,
        http_only,
    })
}

fn default_port_for_scheme(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    }
}

fn is_same_origin(a: &Uri, b: &Uri) -> bool {
    let port_a = a
        .port_u16()
        .or_else(|| default_port_for_scheme(a.scheme_str()));
    let port_b = b
        .port_u16()
        .or_else(|| default_port_for_scheme(b.scheme_str()));
    a.scheme_str() == b.scheme_str()
        && a.host().map(str::to_ascii_lowercase) == b.host().map(str::to_ascii_lowercase)
        && port_a == port_b
}

fn resolve_redirect_url(base: &Uri, location: &str) -> Result<String, &'static str> {
    let loc = location.trim();
    if loc.starts_with("https://") || loc.starts_with("http://") {
        return Ok(loc.to_owned());
    }
    let scheme = base.scheme_str().ok_or("base URI missing scheme")?;
    if loc.starts_with("//") {
        return Ok(format!("{scheme}:{loc}"));
    }
    let authority = base
        .authority()
        .ok_or("base URI missing authority")?
        .as_str();
    if loc.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{loc}"));
    }
    let base_path = base.path();
    let dir = base_path.rfind('/').map_or("/", |idx| &base_path[..=idx]);
    Ok(format!("{scheme}://{authority}{dir}{loc}"))
}

fn read_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, H3AttemptError> {
    let limit = (MAX_RESPONSE_BYTES as u64).saturating_add(1);
    let mut out = Vec::new();
    let _ = reader
        .by_ref()
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| {
            H3AttemptError::Request(format!("HTTP/3 response decompression failed: {e}"))
        })?;
    if out.len() > MAX_RESPONSE_BYTES {
        return Err(H3AttemptError::Request(format!(
            "decompressed response body exceeded {MAX_RESPONSE_BYTES}-byte limit"
        )));
    }
    Ok(out)
}

fn decompress_body(
    headers: &[(String, String)],
    mut bytes: Vec<u8>,
) -> Result<Vec<u8>, H3AttemptError> {
    if bytes.is_empty() {
        return Ok(bytes);
    }

    let encodings: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .flat_map(|(_, v)| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "identity")
        .collect();

    for enc in encodings.into_iter().rev() {
        bytes = match enc.as_str() {
            "gzip" | "x-gzip" => read_bounded(flate2::read::GzDecoder::new(bytes.as_slice()))?,
            "br" => read_bounded(brotli::Decompressor::new(bytes.as_slice(), 4096))?,
            "deflate" => {
                let zlib_res = read_bounded(flate2::read::ZlibDecoder::new(bytes.as_slice()));
                if let Ok(decoded) = zlib_res {
                    decoded
                } else {
                    read_bounded(flate2::read::DeflateDecoder::new(bytes.as_slice()))?
                }
            }
            _ => bytes,
        };
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http::Response;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use waybound_core::SessionFingerprint;

    use super::*;
    use crate::{HandoffClient, HandoffOptions};

    fn generate_test_cert()
    -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])?;
        let cert_der = certified.cert.der().clone();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        Ok((cert_der, key_der))
    }

    async fn handle_test_h3_request(
        req: Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) {
        let path = req.uri().path().to_owned();
        if path == "/binary" {
            let mut body = Vec::new();
            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    body.extend_from_slice(slice);
                    let n = slice.len();
                    chunk.advance(n);
                }
            }
            if let Ok(resp) = Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .body(())
                && stream.send_response(resp).await.is_ok()
            {
                let _ = stream.send_data(Bytes::from(body)).await;
                let _ = stream.finish().await;
            }
            return;
        }

        if path == "/gzip" {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = enc.write_all(b"hello-compressed-h3");
            if let Ok(gz) = enc.finish()
                && let Ok(resp) = Response::builder()
                    .status(200)
                    .header("content-encoding", "gzip")
                    .header("content-type", "text/plain")
                    .body(())
                && stream.send_response(resp).await.is_ok()
            {
                let _ = stream.send_data(Bytes::from(gz)).await;
                let _ = stream.finish().await;
            }
            return;
        }

        if path == "/redirect" {
            if let Ok(resp) = Response::builder()
                .status(302)
                .header("location", "/echo")
                .body(())
                && stream.send_response(resp).await.is_ok()
            {
                let _ = stream.finish().await;
            }
            return;
        }

        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let custom = req
            .headers()
            .get("x-custom")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let cookie = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let payload = format!("ua={ua};custom={custom};cookie={cookie}");

        if let Ok(resp) = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .header("set-cookie", "h3_session=abc123; Path=/; Secure; HttpOnly")
            .body(())
            && stream.send_response(resp).await.is_ok()
        {
            let _ = stream.send_data(Bytes::from(payload)).await;
            let _ = stream.finish().await;
        }
    }

    fn start_h3_test_server(
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
        bind_addr: SocketAddr,
    ) -> Result<(SocketAddr, Arc<AtomicUsize>, quinn::Endpoint), Box<dyn std::error::Error>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;
        server_tls.alpn_protocols = vec![b"h3".to_vec()];

        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)?;
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        let endpoint = quinn::Endpoint::server(server_cfg, bind_addr)?;
        let local_addr = endpoint.local_addr()?;
        let conn_count = Arc::new(AtomicUsize::new(0));
        let conn_count_task = Arc::clone(&conn_count);
        let endpoint_task = endpoint.clone();

        drop(tokio::spawn(async move {
            while let Some(incoming) = endpoint_task.accept().await {
                let conn_count_inner = Arc::clone(&conn_count_task);
                drop(tokio::spawn(async move {
                    let Ok(conn) = incoming.await else {
                        return;
                    };
                    let _ = conn_count_inner.fetch_add(1, Ordering::SeqCst);
                    let Ok(mut h3_conn) = h3::server::builder()
                        .build(h3_quinn::Connection::new(conn))
                        .await
                    else {
                        return;
                    };

                    while let Ok(Some(resolver)) = h3_conn.accept().await {
                        let Ok((req, stream)) = resolver.resolve_request().await else {
                            break;
                        };
                        drop(tokio::spawn(handle_test_h3_request(req, stream)));
                    }
                }));
            }
        }));

        Ok((local_addr, conn_count, endpoint))
    }

    #[tokio::test]
    async fn h3_get_custom_headers_cookies_pooling_gzip_and_redirect()
    -> Result<(), Box<dyn std::error::Error>> {
        let (cert, key) = generate_test_cert()?;
        let (addr, conn_count, server_ep) =
            start_h3_test_server(cert.clone(), key, "127.0.0.1:0".parse()?)?;

        let fp = SessionFingerprint {
            tls: None,
            http2: None,
            default_headers: vec![HeaderEntry {
                name: "user-agent".to_owned(),
                value: "WayboundH3Test/1.0".to_owned(),
            }],
            api_headers: Vec::new(),
            cookies: vec![CapturedCookie {
                name: "init".to_owned(),
                value: "1".to_owned(),
                domain: "localhost".to_owned(),
                path: "/".to_owned(),
                secure: true,
                http_only: false,
            }],
        };

        let opts = HandoffOptions {
            http3: true,
            ..HandoffOptions::default()
        };
        let client = HandoffClient::with_h3_custom_roots(fp, &opts, &[cert])?;
        let base_url = format!("https://localhost:{}", addr.port());

        // 1. First GET with custom header and initial cookie -> server sets h3_session cookie.
        let r1 = client
            .request(
                "GET",
                &format!("{base_url}/echo"),
                &[("X-Custom".to_owned(), "hello-h3".to_owned())],
                None,
            )
            .await?;
        assert_eq!(r1.status, 200);
        assert!(
            r1.body.contains("ua=WayboundH3Test/1.0"),
            "body: {}",
            r1.body
        );
        assert!(r1.body.contains("custom=hello-h3"), "body: {}", r1.body);
        assert!(r1.body.contains("init=1"), "body: {}", r1.body);
        assert!(
            client
                .cookies()
                .iter()
                .any(|c| c.name == "h3_session" && c.value == "abc123")
        );

        // 2. Second GET reuses pooled QUIC connection and sends persisted h3_session cookie.
        let r2 = client
            .request("GET", &format!("{base_url}/echo"), &[], None)
            .await?;
        assert_eq!(r2.status, 200);
        assert!(r2.body.contains("h3_session=abc123"), "body: {}", r2.body);

        // 3. Gzip response is transparently decompressed.
        let r3 = client
            .request("GET", &format!("{base_url}/gzip"), &[], None)
            .await?;
        assert_eq!(r3.status, 200);
        assert_eq!(r3.body, "hello-compressed-h3");

        // 4. 302 redirect is followed automatically.
        let r4 = client
            .request("GET", &format!("{base_url}/redirect"), &[], None)
            .await?;
        assert_eq!(r4.status, 200);
        assert_eq!(r4.url, format!("{base_url}/echo"));
        assert!(r4.body.contains("h3_session=abc123"), "body: {}", r4.body);

        // All 4 requests multiplexed over a single pooled QUIC connection.
        assert_eq!(conn_count.load(Ordering::SeqCst), 1);

        server_ep.close(0u32.into(), b"done");
        Ok(())
    }

    #[tokio::test]
    async fn h3_post_raw_binary_roundtrip_is_lossless() -> Result<(), Box<dyn std::error::Error>> {
        let (cert, key) = generate_test_cert()?;
        let (addr, _conn_count, server_ep) =
            start_h3_test_server(cert.clone(), key, "127.0.0.1:0".parse()?)?;

        let fp = SessionFingerprint {
            tls: None,
            http2: None,
            default_headers: Vec::new(),
            api_headers: Vec::new(),
            cookies: Vec::new(),
        };
        let opts = HandoffOptions {
            http3: true,
            ..HandoffOptions::default()
        };
        let client = HandoffClient::with_h3_custom_roots(fp, &opts, &[cert])?;

        let payload: Vec<u8> = (0..=u8::MAX).collect();
        let resp = client
            .request(
                "POST",
                &format!("https://localhost:{}/binary", addr.port()),
                &[(
                    "content-type".to_owned(),
                    "application/octet-stream".to_owned(),
                )],
                Some(payload.clone()),
            )
            .await?;

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_bytes, payload);
        assert_eq!(base64::decode(&resp.body_base64), Ok(payload));

        server_ep.close(0u32.into(), b"done");
        Ok(())
    }

    #[tokio::test]
    async fn h3_transparent_fallback_to_wreq_on_non_h3_and_handshake_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        // Part A: http3: true targeting plain http:// works seamlessly via wreq.
        let tcp_http = std::net::TcpListener::bind("127.0.0.1:0")?;
        let http_addr = tcp_http.local_addr()?;
        let http_srv = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = tcp_http.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let reply =
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhttp-compat";
                let _ = stream.write_all(reply);
                let _ = stream.flush();
            }
        });

        let fp = SessionFingerprint {
            tls: None,
            http2: None,
            default_headers: Vec::new(),
            api_headers: Vec::new(),
            cookies: Vec::new(),
        };
        let opts = HandoffOptions {
            http3: true,
            timeout_ms: 2_000,
            ..HandoffOptions::default()
        };
        let client = HandoffClient::new(fp, &opts)?;

        let http_resp = client
            .request("GET", &format!("http://{http_addr}/compat"), &[], None)
            .await?;
        let _ = http_srv.join();
        assert_eq!(http_resp.status, 200);
        assert_eq!(http_resp.body, "http-compat");

        // Part B: https:// where QUIC handshake fails immediately (untrusted cert on UDP)
        // transparently falls back to BoringSSL/TCP (observed via TCP listener on same port).
        let (untrusted_cert, untrusted_key) = generate_test_cert()?;
        let tcp_fallback = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let fallback_addr = tcp_fallback.local_addr()?;
        let (_udp_addr, _conn_count, server_ep) =
            start_h3_test_server(untrusted_cert, untrusted_key, fallback_addr)?;

        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let tcp_hits_srv = Arc::clone(&tcp_hits);
        let tcp_task = tokio::spawn(async move {
            if let Ok((_stream, _)) = tcp_fallback.accept().await {
                let _ = tcp_hits_srv.fetch_add(1, Ordering::SeqCst);
            }
        });

        // H3 fails TLS verification -> falls back to wreq over TCP -> hits tcp_fallback listener.
        let _ = client
            .request(
                "GET",
                &format!("https://{fallback_addr}/fallback"),
                &[],
                None,
            )
            .await;

        let _ = tokio::time::timeout(Duration::from_secs(2), tcp_task).await;
        assert_eq!(
            tcp_hits.load(Ordering::SeqCst),
            1,
            "expected transparent fallback to BoringSSL/TCP after QUIC handshake failure"
        );

        server_ep.close(0u32.into(), b"done");
        Ok(())
    }
}
