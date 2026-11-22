//! Embedded localhost HTTP/CONNECT proxy forwarder for authenticated upstream proxies.
//!
//! Chrome's `--proxy-server` flag does not support inline `user:pass` credentials.
//! This module binds a loopback-only unauthenticated listener (`127.0.0.1:0`) and
//! injects `Proxy-Authorization: Basic ...` when forwarding to an authenticated
//! upstream HTTP proxy — without extensions, auth prompts, or TLS MITM.

use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
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

/// Parsed upstream HTTP proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    /// Upstream proxy `host:port`.
    pub host_port: String,
    /// Optional `Basic <base64>` `Proxy-Authorization` header value.
    pub auth_header: Option<String>,
}

impl UpstreamProxy {
    /// Parses `http://[user:pass@]host:port` (or `host:port`) into an [`UpstreamProxy`].
    ///
    /// Credentials are percent-decoded before Base64 encoding and redacted from any error messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL scheme is unsupported or `host:port` is missing/invalid.
    pub fn parse(raw: &str) -> std::result::Result<Self, String> {
        let trimmed = raw.trim();
        let rest = if let Some(stripped) = trimmed.strip_prefix("http://") {
            stripped
        } else if let Some((scheme, _)) = trimmed.split_once("://") {
            return Err(format!(
                "unsupported proxy scheme {scheme:?} (local forwarder supports http://)"
            ));
        } else {
            trimmed
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

        let auth_header = creds.map(|c| {
            let decoded = percent_decode(c);
            format!("Basic {}", base64_encode(&decoded))
        });

        Ok(Self {
            host_port: host_port.to_owned(),
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
            upstream = %upstream_arc.host_port,
            authenticated = upstream_arc.auth_header.is_some(),
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

fn handle_client(client: TcpStream, upstream: &UpstreamProxy) -> io::Result<()> {
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

    let is_connect = header_lines[0].to_ascii_uppercase().starts_with("CONNECT ");

    let mut upstream_stream = connect_upstream(&upstream.host_port)?;
    upstream_stream.set_read_timeout(Some(HEADER_IO_TIMEOUT))?;
    upstream_stream.set_write_timeout(Some(HEADER_IO_TIMEOUT))?;

    // Buffer the entire outbound header block into a single write to avoid TCP fragmentation.
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

    let buffered = client_reader.buffer();
    if !buffered.is_empty() {
        outbound.extend_from_slice(buffered);
    }
    upstream_stream.write_all(&outbound)?;
    upstream_stream.flush()?;

    // Switch to longer idle timeout for established tunnels.
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
    fn parses_authenticated_percent_encoded_and_rejects_bad_urls() {
        let auth = UpstreamProxy::parse("http://alice:p%40ss@proxy.example.com:8080");
        assert!(auth.is_ok());
        if let Ok(p) = auth {
            assert_eq!(p.host_port, "proxy.example.com:8080");
            // "alice:p@ss" -> YWxpY2U6cEBzcw==
            assert_eq!(p.auth_header.as_deref(), Some("Basic YWxpY2U6cEBzcw=="));
        }

        let err = UpstreamProxy::parse("socks5://secretuser:secretpass@127.0.0.1:1080");
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
}
