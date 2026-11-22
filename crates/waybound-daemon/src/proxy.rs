//! Embedded localhost HTTP/CONNECT proxy forwarder supporting both authenticated
//! HTTP (`http://user:pass@host:port`) and SOCKS5 (`socks5://user:pass@host:port`)
//! upstream proxies.
//!
//! Chrome's `--proxy-server` flag does not support inline `user:pass` credentials.
//! This module binds a loopback-only unauthenticated listener (`127.0.0.1:0`) and
//! handles upstream authentication transparently — without extensions, auth prompts,
//! or TLS MITM.

use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use waybound_core::Result;

const ACCEPT_POLL: Duration = Duration::from_millis(50);
const HEADER_IO_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 128;
const MAX_CONCURRENT_TUNNELS: usize = 128;

/// RAII guard decrementing the active tunnel counter on drop.
struct TunnelGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        let _ = self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Supported upstream proxy protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    /// Upstream HTTP/CONNECT proxy.
    Http,
    /// Upstream RFC 1928/1929 SOCKS5 proxy with remote DNS resolution.
    Socks5,
}

/// Parsed upstream proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    /// Upstream protocol (`http` or `socks5`).
    pub protocol: ProxyProtocol,
    /// Upstream proxy `host:port`.
    pub host_port: String,
    /// Optional decoded `(username, password)` credentials.
    pub credentials: Option<(Vec<u8>, Vec<u8>)>,
    /// Optional `Basic <base64>` `Proxy-Authorization` header value (for HTTP upstream).
    pub auth_header: Option<String>,
}

impl UpstreamProxy {
    /// Parses `http://[user:pass@]host:port` or `socks5[h]://[user:pass@]host:port`.
    ///
    /// Credentials are percent-decoded and redacted from any error messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL scheme is unsupported or `host:port` is missing/invalid.
    pub fn parse(raw: &str) -> std::result::Result<Self, String> {
        let trimmed = raw.trim();
        let (protocol, rest) = if let Some(stripped) = trimmed.strip_prefix("http://") {
            (ProxyProtocol::Http, stripped)
        } else if let Some(stripped) = trimmed
            .strip_prefix("socks5://")
            .or_else(|| trimmed.strip_prefix("socks5h://"))
        {
            (ProxyProtocol::Socks5, stripped)
        } else if let Some((scheme, _)) = trimmed.split_once("://") {
            return Err(format!(
                "unsupported proxy scheme {scheme:?} (expected http:// or socks5://)"
            ));
        } else {
            (ProxyProtocol::Http, trimmed)
        };

        let authority = rest.split('/').next().unwrap_or(rest);
        let (creds, host_port) = match authority.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, authority),
        };

        let Some((host, port_str)) = host_port.rsplit_once(':') else {
            return Err(format!("proxy must include host:port, got {host_port:?}"));
        };
        if host.is_empty() || port_str.parse::<u16>().is_err() {
            return Err(format!("invalid proxy host:port {host_port:?}"));
        }

        let (credentials, auth_header) = creds.map_or((None, None), |c| {
            let decoded_full = percent_decode(c);
            let header = format!("Basic {}", base64_encode(&decoded_full));
            let pair = c.split_once(':').map_or_else(
                || (decoded_full, Vec::new()),
                |(u, p)| (percent_decode(u), percent_decode(p)),
            );
            (Some(pair), Some(header))
        });

        Ok(Self {
            protocol,
            host_port: host_port.to_owned(),
            credentials,
            auth_header,
        })
    }
}

/// RAII handle for the local loopback proxy forwarder thread.
pub struct ProxyForwarder {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl ProxyForwarder {
    /// Starts a loopback HTTP/CONNECT proxy forwarder targeting `upstream`.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::Io`] if `127.0.0.1:0` cannot be bound or
    /// the listener thread cannot be spawned.
    pub fn start(upstream: UpstreamProxy) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_ref = Arc::clone(&shutdown);
        let upstream_arc = Arc::new(upstream);
        let upstream_thread = Arc::clone(&upstream_arc);
        let active_tunnels = Arc::new(AtomicUsize::new(0));

        let _ = thread::Builder::new()
            .name("waybound-proxy-accept".to_owned())
            .spawn(move || {
                while !shutdown_ref.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            let current = active_tunnels.fetch_add(1, Ordering::AcqRel);
                            if current >= MAX_CONCURRENT_TUNNELS {
                                let _ = active_tunnels.fetch_sub(1, Ordering::AcqRel);
                                tracing::warn!("proxy forwarder at max concurrent tunnels");
                                continue;
                            }
                            let up = Arc::clone(&upstream_thread);
                            let guard = TunnelGuard {
                                counter: Arc::clone(&active_tunnels),
                            };
                            let spawn_res = thread::Builder::new()
                                .name("waybound-proxy-conn".to_owned())
                                .spawn(move || {
                                    let _guard = guard;
                                    if let Err(err) = handle_client(client, &up) {
                                        tracing::debug!(error = %err, "proxy client tunnel closed");
                                    }
                                });
                            if let Err(err) = spawn_res {
                                tracing::warn!(error = %err, "failed to spawn proxy worker thread");
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(ACCEPT_POLL);
                        }
                        Err(err) if err.kind() == ErrorKind::Interrupted => {}
                        Err(err) => {
                            tracing::warn!(error = %err, "proxy listener accept error");
                            break;
                        }
                    }
                }
            })?;

        tracing::info!(
            listen = %local_addr,
            protocol = ?upstream_arc.protocol,
            upstream = %upstream_arc.host_port,
            authenticated = upstream_arc.credentials.is_some(),
            "started local proxy auth forwarder"
        );

        Ok(Self {
            local_addr,
            shutdown,
        })
    }

    /// Returns the `--proxy-server` argument value (`http://127.0.0.1:<port>`).
    #[must_use]
    pub fn chrome_proxy_arg(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

impl Drop for ProxyForwarder {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

fn connect_upstream(host_port: &str) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in host_port.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            ErrorKind::AddrNotAvailable,
            format!("no resolved addresses for upstream proxy {host_port}"),
        )
    }))
}

fn handle_client(mut client: TcpStream, upstream: &UpstreamProxy) -> io::Result<()> {
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(HEADER_IO_TIMEOUT))?;
    client.set_write_timeout(Some(HEADER_IO_TIMEOUT))?;

    let mut client_reader = BufReader::new(client.try_clone()?);
    let mut header_lines = Vec::new();
    let mut total_bytes = 0usize;

    loop {
        let remaining = MAX_HEADER_BYTES.saturating_sub(total_bytes);
        let mut line = String::new();
        let n = (&mut client_reader)
            .take((remaining as u64) + 1)
            .read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        total_bytes += n;
        if total_bytes > MAX_HEADER_BYTES || header_lines.len() >= MAX_HEADER_LINES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "HTTP proxy request headers exceeded limit",
            ));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        header_lines.push(line);
    }

    if header_lines.is_empty() {
        return Ok(());
    }

    let mut upstream_stream = connect_upstream(&upstream.host_port)?;
    upstream_stream.set_read_timeout(Some(HEADER_IO_TIMEOUT))?;
    upstream_stream.set_write_timeout(Some(HEADER_IO_TIMEOUT))?;

    match upstream.protocol {
        ProxyProtocol::Http => {
            forward_http_upstream(&mut upstream_stream, &header_lines, total_bytes, upstream)?;
            let buffered = client_reader.buffer();
            if !buffered.is_empty() {
                upstream_stream.write_all(buffered)?;
                upstream_stream.flush()?;
            }
        }
        ProxyProtocol::Socks5 => {
            let (target_host, target_port, is_connect) = parse_request_target(&header_lines[0])?;
            socks5_handshake(&mut upstream_stream, upstream, &target_host, target_port)?;
            if is_connect {
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                client.flush()?;
            } else {
                forward_plain_http_over_socks(&mut upstream_stream, &header_lines, total_bytes)?;
            }
            let buffered = client_reader.buffer();
            if !buffered.is_empty() {
                upstream_stream.write_all(buffered)?;
                upstream_stream.flush()?;
            }
        }
    }

    client.set_read_timeout(Some(TUNNEL_IDLE_TIMEOUT))?;
    client.set_write_timeout(Some(TUNNEL_IDLE_TIMEOUT))?;
    upstream_stream.set_read_timeout(Some(TUNNEL_IDLE_TIMEOUT))?;
    upstream_stream.set_write_timeout(Some(TUNNEL_IDLE_TIMEOUT))?;

    let mut client_to_up_src = client_reader.into_inner();
    let mut client_to_up_dst = upstream_stream.try_clone()?;
    let mut up_to_client_src = upstream_stream;
    let mut up_to_client_dst = client;

    let forward_thread = thread::Builder::new()
        .name("waybound-proxy-pipe".to_owned())
        .spawn(move || {
            let _ = copy_stream(&mut client_to_up_src, &mut client_to_up_dst);
            let _ = client_to_up_dst.shutdown(std::net::Shutdown::Write);
        })?;

    let _ = copy_stream(&mut up_to_client_src, &mut up_to_client_dst);
    let _ = up_to_client_dst.shutdown(std::net::Shutdown::Write);
    let _ = forward_thread.join();
    Ok(())
}

fn forward_http_upstream(
    upstream_stream: &mut TcpStream,
    header_lines: &[String],
    total_bytes: usize,
    upstream: &UpstreamProxy,
) -> io::Result<()> {
    let is_connect = header_lines[0].to_ascii_uppercase().starts_with("CONNECT ");
    let mut outbound = Vec::with_capacity(total_bytes + 160);
    for (idx, line) in header_lines.iter().enumerate() {
        if idx > 0 {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("proxy-authorization:") {
                continue;
            }
            if !is_connect
                && (lower.starts_with("connection:") || lower.starts_with("proxy-connection:"))
            {
                continue;
            }
        }
        outbound.extend_from_slice(line.as_bytes());
    }
    if let Some(auth) = &upstream.auth_header {
        outbound.extend_from_slice(format!("Proxy-Authorization: {auth}\r\n").as_bytes());
    }
    if !is_connect {
        outbound.extend_from_slice(b"Connection: close\r\nProxy-Connection: close\r\n");
    }
    outbound.extend_from_slice(b"\r\n");
    upstream_stream.write_all(&outbound)?;
    upstream_stream.flush()
}

fn forward_plain_http_over_socks(
    upstream_stream: &mut TcpStream,
    header_lines: &[String],
    total_bytes: usize,
) -> io::Result<()> {
    let mut outbound = Vec::with_capacity(total_bytes + 64);
    for (idx, line) in header_lines.iter().enumerate() {
        if idx == 0 {
            outbound.extend_from_slice(rewrite_origin_form(line).as_bytes());
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-") || lower.starts_with("connection:") {
            continue;
        }
        outbound.extend_from_slice(line.as_bytes());
    }
    outbound.extend_from_slice(b"Connection: close\r\n\r\n");
    upstream_stream.write_all(&outbound)?;
    upstream_stream.flush()
}

/// Converts proxy-form (`GET http://host/path HTTP/1.1`) to origin-form (`GET /path HTTP/1.1`).
fn rewrite_origin_form(request_line: &str) -> String {
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return request_line.to_owned();
    };
    let Some(target) = parts.next() else {
        return request_line.to_owned();
    };
    let version = parts.next().unwrap_or("HTTP/1.1");

    let origin_target = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .map_or(target, |rest| {
            rest.find('/').map_or("/", |idx| &rest[idx..])
        });
    format!("{method} {origin_target} {version}\r\n")
}

fn split_host_port(authority: &str, default_port: Option<u16>) -> io::Result<(String, u16)> {
    if let Some(after_open) = authority.strip_prefix('[') {
        let Some((ipv6, remainder)) = after_open.split_once(']') else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "unterminated IPv6 bracket in target authority",
            ));
        };
        if ipv6.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "empty IPv6 host"));
        }
        let port = if let Some(port_str) = remainder.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid IPv6 port"))?
        } else if remainder.is_empty() {
            default_port.ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidInput, "CONNECT target missing port")
            })?
        } else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid characters after IPv6 host",
            ));
        };
        return Ok((ipv6.to_owned(), port));
    }

    if let Some((h, p)) = authority.rsplit_once(':') {
        if h.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "empty target host"));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid target port"))?;
        Ok((h.to_owned(), port))
    } else {
        if authority.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "empty target host"));
        }
        let port = default_port.ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "CONNECT target missing host:port")
        })?;
        Ok((authority.to_owned(), port))
    }
}

fn parse_request_target(request_line: &str) -> io::Result<(String, u16, bool)> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let is_connect = method.eq_ignore_ascii_case("CONNECT");

    if is_connect {
        let (host, port) = split_host_port(target, None)?;
        return Ok((host, port, true));
    }

    let (default_port, stripped) = target.strip_prefix("https://").map_or_else(
        || {
            target
                .strip_prefix("http://")
                .map_or((80u16, target), |rest| (80u16, rest))
        },
        |rest| (443u16, rest),
    );
    let authority = stripped.split('/').next().unwrap_or("");
    let (host, port) = split_host_port(authority, Some(default_port))?;
    Ok((host, port, false))
}

fn drain_socks5_reply_addr(stream: &mut TcpStream, atyp: u8) -> io::Result<()> {
    match atyp {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip)
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf)?;
            let mut skip = vec![0u8; usize::from(len_buf[0]) + 2];
            stream.read_exact(&mut skip)
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip)
        }
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid SOCKS5 reply address type",
        )),
    }
}

/// Performs RFC 1928 + RFC 1929 SOCKS5 handshake with remote domain resolution (`ATYP=0x03`).
fn socks5_handshake(
    stream: &mut TcpStream,
    upstream: &UpstreamProxy,
    target_host: &str,
    target_port: u16,
) -> io::Result<()> {
    let want_auth = upstream.credentials.is_some();
    if want_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }
    stream.flush()?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp)?;
    if method_resp[0] != 0x05 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid SOCKS5 server version",
        ));
    }

    match method_resp[1] {
        0x00 => {}
        0x02 => {
            let Some((user, pass)) = &upstream.credentials else {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "SOCKS5 server requires auth but no credentials provided",
                ));
            };
            let ulen = u8::try_from(user.len()).map_err(|_| {
                io::Error::new(ErrorKind::InvalidInput, "SOCKS5 username exceeds 255 bytes")
            })?;
            let plen = u8::try_from(pass.len()).map_err(|_| {
                io::Error::new(ErrorKind::InvalidInput, "SOCKS5 password exceeds 255 bytes")
            })?;
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01);
            auth_req.push(ulen);
            auth_req.extend_from_slice(user);
            auth_req.push(plen);
            auth_req.extend_from_slice(pass);
            stream.write_all(&auth_req)?;
            stream.flush()?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp)?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "SOCKS5 username/password authentication rejected",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "SOCKS5 server rejected all offered auth methods",
            ));
        }
    }

    let mut connect_req = Vec::with_capacity(22);
    connect_req.extend_from_slice(&[0x05, 0x01, 0x00]);
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            connect_req.push(0x01);
            connect_req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            connect_req.push(0x04);
            connect_req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let host_bytes = target_host.as_bytes();
            let hlen = u8::try_from(host_bytes.len()).map_err(|_| {
                io::Error::new(ErrorKind::InvalidInput, "target domain exceeds 255 bytes")
            })?;
            connect_req.push(0x03);
            connect_req.push(hlen);
            connect_req.extend_from_slice(host_bytes);
        }
    }
    connect_req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect_req)?;
    stream.flush()?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(io::Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed with reply code {}", hdr[1]),
        ));
    }

    drain_socks5_reply_addr(stream, hdr[3])
}

fn copy_stream(src: &mut TcpStream, dst: &mut TcpStream) -> io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..n])?;
    }
}

fn percent_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Minimal RFC 4648 standard Base64 encoder (zero extra dependencies).
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = usize::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, usize::from);
        let b2 = chunk.get(2).copied().map_or(0, usize::from);

        out.push(char::from(TABLE[b0 >> 2]));
        out.push(char::from(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)]));
        if chunk.len() > 1 {
            out.push(char::from(TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(TABLE[b2 & 0x3F]));
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_socks5_and_redacts_bad_schemes() {
        let auth = UpstreamProxy::parse("http://alice:p%40ss@proxy.example.com:8080");
        assert!(auth.is_ok());
        if let Ok(p) = auth {
            assert_eq!(p.protocol, ProxyProtocol::Http);
            assert_eq!(p.host_port, "proxy.example.com:8080");
            assert_eq!(p.auth_header.as_deref(), Some("Basic YWxpY2U6cEBzcw=="));
        }

        let socks = UpstreamProxy::parse("socks5://bob:s3cr3t@127.0.0.1:1080");
        assert!(socks.is_ok());
        if let Ok(p) = socks {
            assert_eq!(p.protocol, ProxyProtocol::Socks5);
            assert_eq!(p.credentials, Some((b"bob".to_vec(), b"s3cr3t".to_vec())));
        }

        let err = UpstreamProxy::parse("ftp://secretuser:secretpass@127.0.0.1:21");
        assert!(err.is_err());
        if let Err(msg) = err {
            assert!(!msg.contains("secretpass"));
        }

        assert!(UpstreamProxy::parse("http://:8080").is_err());
        assert!(UpstreamProxy::parse("http://host:notaport").is_err());
    }

    #[test]
    fn forwarder_injects_proxy_authorization_header() {
        let Ok(upstream_listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(upstream_addr) = upstream_listener.local_addr() else {
            return;
        };

        let server_thread = thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    return req;
                }
            }
            String::new()
        });

        let Ok(upstream) = UpstreamProxy::parse(&format!("http://user:pass@{upstream_addr}"))
        else {
            return;
        };
        let Ok(forwarder) = ProxyForwarder::start(upstream) else {
            return;
        };

        let Ok(mut client) = TcpStream::connect(forwarder.local_addr) else {
            return;
        };
        let _ =
            client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        let mut resp = [0u8; 128];
        let n = client.read(&mut resp).unwrap_or(0);
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200 Connection Established"));
        drop(client);

        let received = server_thread.join().unwrap_or_default();
        assert!(received.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[test]
    fn forwarder_bridges_http_connect_to_authenticated_socks5() {
        let Ok(socks_listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(socks_addr) = socks_listener.local_addr() else {
            return;
        };

        let socks_thread = thread::spawn(move || {
            let Ok((mut s, _)) = socks_listener.accept() else {
                return false;
            };
            let mut greet = [0u8; 4];
            if s.read_exact(&mut greet).is_err() || greet != [0x05, 0x02, 0x00, 0x02] {
                return false;
            }
            let _ = s.write_all(&[0x05, 0x02]);

            // Auth: 0x01, 3, "bob", 4, "pass"
            let mut auth = [0u8; 10];
            if s.read_exact(&mut auth).is_err() || &auth[2..5] != b"bob" || &auth[6..10] != b"pass"
            {
                return false;
            }
            let _ = s.write_all(&[0x01, 0x00]);

            // CONNECT domain "api.test":443
            let mut hdr = [0u8; 5];
            if s.read_exact(&mut hdr).is_err() || hdr[3] != 0x03 {
                return false;
            }
            let mut domain_and_port = vec![0u8; usize::from(hdr[4]) + 2];
            if s.read_exact(&mut domain_and_port).is_err() {
                return false;
            }
            let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
            &domain_and_port[..usize::from(hdr[4])] == b"api.test"
        });

        let Ok(upstream) = UpstreamProxy::parse(&format!("socks5://bob:pass@{socks_addr}")) else {
            return;
        };
        let Ok(forwarder) = ProxyForwarder::start(upstream) else {
            return;
        };
        let Ok(mut client) = TcpStream::connect(forwarder.local_addr) else {
            return;
        };
        let _ = client.write_all(b"CONNECT api.test:443 HTTP/1.1\r\nHost: api.test:443\r\n\r\n");
        let mut resp = [0u8; 128];
        let n = client.read(&mut resp).unwrap_or(0);
        assert!(String::from_utf8_lossy(&resp[..n]).contains("200 Connection Established"));
        drop(client);

        assert!(socks_thread.join().unwrap_or(false));
    }
}
