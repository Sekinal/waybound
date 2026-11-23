//! Embedded localhost HTTP/CONNECT proxy forwarder supporting both authenticated
//! HTTP (`http://user:pass@host:port`) and SOCKS5 (`socks5://user:pass@host:port`)
//! upstream proxies.
//!
//! Chrome's `--proxy-server` flag does not support inline `user:pass` credentials.
//! This module binds a loopback-only unauthenticated listener (`127.0.0.1:0`) and
//! handles upstream authentication transparently — without extensions, auth prompts,
//! or TLS MITM.
//!
//! # Local exposure
//!
//! Because the listener needs no credentials, anything that can connect to it can relay
//! traffic through the user's authenticated upstream proxy. Every accepted connection is
//! therefore checked by a [`PeerVerifier`] before a single byte is read: refused clients get
//! `403 Forbidden`, no upstream connection is opened and no credentials are sent.
//!
//! - **Linux:** only sockets owned by the daemon's effective UID are admitted (looked up in
//!   `/proc/net/tcp{,6}`). Other users are locked out; other processes of the *same* user
//!   are not, as they could read the credentials from the daemon's environment anyway.
//!   Caveats, each logged as a startup warning: if the daemon cannot see its own listener
//!   in `/proc/net/tcp` it runs unrestricted, and as root (UID 0) or the overflow UID 65534
//!   the UID check does not separate users.
//! - **macOS / Windows:** no check is possible without FFI or a per-connection subprocess,
//!   so any local process, under any user, can use the forwarder while a session runs.
//!
//! See [`crate::peer`] for the details and rationale. Child processes never inherit the
//! `WAYBOUND_PROXY` variable (see [`waybound_core::process`]).

use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use waybound_core::{NetworkStats, Result};

use crate::peer::{PeerDecision, PeerVerifier, platform_verifier};
use waybound_net::{
    Direction, FingerprintRecorder, HostBlocker, InflightCounter, KeyLogStore,
    PassiveConnectionTap, ResponseCallback, WebSocketCallback,
};

const ACCEPT_POLL: Duration = Duration::from_millis(50);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(200);
const HEADER_IO_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 128;
const MAX_CONCURRENT_TUNNELS: usize = 128;
const MAX_REASON_PHRASE_CHARS: usize = 64;
const CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// How long a refused client gets to finish sending its request before the socket closes
/// (closing with unread data would reset the connection and could discard the `403`).
const REJECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
/// Minimum spacing of refusal warnings, so another local user cannot flood the log.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Read-only observer of the bytes relayed through a `CONNECT` tunnel.
///
/// Production code uses [`PassiveConnectionTap`]; tests substitute a recorder.
trait TunnelObserver: Send + Sync {
    fn observe(&self, dir: Direction, bytes: &[u8]);
}

impl TunnelObserver for PassiveConnectionTap {
    fn observe(&self, dir: Direction, bytes: &[u8]) {
        Self::observe(self, dir, bytes);
    }
}

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
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for UpstreamProxy {
    /// Redacts credentials so they cannot reach logs through `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |present: bool| if present { "<redacted>" } else { "<none>" };
        f.debug_struct("UpstreamProxy")
            .field("protocol", &self.protocol)
            .field("host_port", &self.host_port)
            .field("credentials", &redacted(self.credentials.is_some()))
            .field("auth_header", &redacted(self.auth_header.is_some()))
            .finish()
    }
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

        // Split userinfo at the last `@` before touching `/`: a password may contain `/`,
        // and cutting the path first would put part of the credentials into `host_port`
        // (and from there into error messages and logs).
        let (creds, after_creds) = match rest.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, rest),
        };
        let host_port = after_creds.split('/').next().unwrap_or(after_creds);

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

/// Configuration for passive, zero-MITM TLS 1.3 + HTTP/1.1–2 decryption inside the proxy relay.
#[derive(Clone)]
pub struct PassiveTapConfig {
    /// Live `SSLKEYLOGFILE` reader.
    pub keylog: KeyLogStore,
    /// Shared inflight request counter powering `wait_for_network_idle`.
    pub inflight: InflightCounter,
    /// Shared session-wide TLS/HTTP2/header/cookie fingerprint recorder.
    pub fingerprint: FingerprintRecorder,
    /// Callback invoked with each decrypted HTTP response.
    pub on_response: ResponseCallback,
    /// Callback invoked with each decrypted WebSocket message (`None` disables WebSocket capture).
    pub on_websocket: Option<WebSocketCallback>,
}

impl PassiveTapConfig {
    /// Creates the per-connection passive tap for a tunnel to `host`.
    fn connection_tap(&self, host: String) -> PassiveConnectionTap {
        let tap = PassiveConnectionTap::new_with_fingerprint(
            host,
            self.keylog.clone(),
            self.inflight.clone(),
            Arc::clone(&self.on_response),
            Some(self.fingerprint.clone()),
        );
        match &self.on_websocket {
            Some(cb) => tap.with_websocket_callback(Arc::clone(cb)),
            None => tap,
        }
    }
}

/// Lock-free per-session bandwidth and connection counters tracked by [`ProxyForwarder`].
#[derive(Debug, Default)]
pub struct ProxyStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    connections_total: AtomicU64,
    connections_blocked: AtomicU64,
}

impl ProxyStats {
    fn record_connection(&self) {
        let _ = self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_blocked(&self) {
        let _ = self.connections_blocked.fetch_add(1, Ordering::Relaxed);
    }

    fn add_bytes_sent(&self, bytes: usize) {
        let delta = u64::try_from(bytes).unwrap_or(u64::MAX);
        let _ = self.bytes_sent.fetch_add(delta, Ordering::Relaxed);
    }

    fn add_bytes_received(&self, bytes: usize) {
        let delta = u64::try_from(bytes).unwrap_or(u64::MAX);
        let _ = self.bytes_received.fetch_add(delta, Ordering::Relaxed);
    }

    /// Returns a point-in-time snapshot of the proxy bandwidth and connection counters.
    #[must_use]
    pub fn snapshot(&self) -> NetworkStats {
        NetworkStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_blocked: self.connections_blocked.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
struct ForwarderConfig {
    upstream: Option<UpstreamProxy>,
    blocker: HostBlocker,
    tap: Option<PassiveTapConfig>,
    stats: Arc<ProxyStats>,
    /// Test seam: when set, replaces the passive tap for every `CONNECT` tunnel.
    #[cfg(test)]
    test_observer: Option<Arc<dyn TunnelObserver>>,
    /// Test seam: when set, replaces the platform's peer verifier.
    #[cfg(test)]
    test_peer_verifier: Option<Arc<dyn PeerVerifier>>,
}

impl ForwarderConfig {
    /// Creates the observer attached to an established `CONNECT` tunnel to `host`, if any.
    fn tunnel_observer(&self, host: &str) -> Option<Arc<dyn TunnelObserver>> {
        #[cfg(test)]
        {
            if let Some(observer) = &self.test_observer {
                return Some(Arc::clone(observer));
            }
        }
        self.tap.as_ref().map(|t| {
            let tap: Arc<dyn TunnelObserver> = Arc::new(t.connection_tap(host.to_owned()));
            tap
        })
    }
}

/// RAII handle for the local loopback proxy forwarder thread.
pub struct ProxyForwarder {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    stats: Arc<ProxyStats>,
}

impl ProxyForwarder {
    /// Starts a loopback HTTP/CONNECT proxy forwarder targeting `upstream`.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::Io`] if `127.0.0.1:0` cannot be bound or
    /// the listener thread cannot be spawned.
    #[cfg(test)]
    pub fn start(upstream: UpstreamProxy) -> Result<Self> {
        Self::start_with_verifier(upstream, Arc::new(crate::peer::AllowAll))
    }

    /// Starts a forwarder that admits clients according to `verifier`.
    #[cfg(test)]
    fn start_with_verifier(
        upstream: UpstreamProxy,
        verifier: Arc<dyn PeerVerifier>,
    ) -> Result<Self> {
        Self::spawn(ForwarderConfig {
            upstream: Some(upstream),
            blocker: HostBlocker::default(),
            tap: None,
            stats: Arc::new(ProxyStats::default()),
            test_observer: None,
            test_peer_verifier: Some(verifier),
        })
    }

    /// Starts a forwarder whose `CONNECT` tunnels report relayed bytes to `observer`.
    #[cfg(test)]
    fn start_with_observer(
        upstream: UpstreamProxy,
        observer: Arc<dyn TunnelObserver>,
    ) -> Result<Self> {
        Self::spawn(ForwarderConfig {
            upstream: Some(upstream),
            blocker: HostBlocker::default(),
            tap: None,
            stats: Arc::new(ProxyStats::default()),
            test_observer: Some(observer),
            test_peer_verifier: Some(Arc::new(crate::peer::AllowAll)),
        })
    }

    /// Starts a loopback HTTP/CONNECT proxy with optional upstream proxy, L4 host blocker,
    /// and passive zero-MITM `SSLKEYLOGFILE` TLS 1.3 decryption tap.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::Io`] if `127.0.0.1:0` cannot be bound or
    /// the listener thread cannot be spawned.
    pub fn start_with_options(
        upstream: Option<UpstreamProxy>,
        blocker: HostBlocker,
        tap: Option<PassiveTapConfig>,
    ) -> Result<Self> {
        Self::spawn(ForwarderConfig {
            upstream,
            blocker,
            tap,
            stats: Arc::new(ProxyStats::default()),
            #[cfg(test)]
            test_observer: None,
            #[cfg(test)]
            test_peer_verifier: None,
        })
    }

    fn spawn(cfg: ForwarderConfig) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        #[cfg(test)]
        let verifier = cfg
            .test_peer_verifier
            .clone()
            .unwrap_or_else(|| platform_verifier(local_addr));
        #[cfg(not(test))]
        let verifier = platform_verifier(local_addr);
        let refusals = Arc::new(RefusalLog::default());

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_ref = Arc::clone(&shutdown);
        let stats = Arc::clone(&cfg.stats);
        let has_tap = cfg.tap.is_some();
        let has_blocker = !cfg.blocker.is_empty();
        let upstream_desc = cfg
            .upstream
            .as_ref()
            .map(|u| (u.protocol, u.host_port.clone()));
        let cfg = Arc::new(cfg);
        let cfg_thread = Arc::clone(&cfg);
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
                            let c = Arc::clone(&cfg_thread);
                            let v = Arc::clone(&verifier);
                            let r = Arc::clone(&refusals);
                            let guard = TunnelGuard {
                                counter: Arc::clone(&active_tunnels),
                            };
                            let spawn_res = thread::Builder::new()
                                .name("waybound-proxy-conn".to_owned())
                                .spawn(move || {
                                    let _guard = guard;
                                    if let Err(err) = serve_client(client, &c, v.as_ref(), &r) {
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
                            // ECONNABORTED, EMFILE and friends are transient. Exiting here
                            // would leave Chrome pointed at a dead proxy for the rest of
                            // the session, so back off briefly and keep accepting.
                            tracing::warn!(error = %err, "proxy listener accept error");
                            thread::sleep(ACCEPT_ERROR_BACKOFF);
                        }
                    }
                }
            })?;

        tracing::info!(
            listen = %local_addr,
            upstream = ?upstream_desc,
            passive_tls_tap = has_tap,
            host_blocker = has_blocker,
            "started local pass-through proxy"
        );

        Ok(Self {
            local_addr,
            shutdown,
            stats,
        })
    }

    /// Returns the `--proxy-server` argument value (`http://127.0.0.1:<port>`).
    #[must_use]
    pub fn chrome_proxy_arg(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Returns a snapshot of the proxy's per-session bandwidth and connection counters.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn stats(&self) -> NetworkStats {
        self.stats.snapshot()
    }

    /// Returns a shared handle to the proxy's live atomic counters.
    #[must_use]
    pub fn stats_handle(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Returns the loopback address the proxy is listening on.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
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

/// Checks the local process behind `client` before anything is read from it, so a refused
/// client never causes an upstream connection or sees credentials being used.
/// Rate limiter for refusal warnings: the first refusal is logged at `warn`, later ones at
/// most once per [`REFUSAL_LOG_INTERVAL`] with a count of those logged only at `debug`.
#[derive(Default)]
struct RefusalLog {
    state: std::sync::Mutex<RefusalLogState>,
}

#[derive(Default)]
struct RefusalLogState {
    last_warn: Option<Instant>,
    suppressed: u64,
}

impl RefusalLog {
    /// Records a refusal at `now`. Returns `Some(suppressed since the last warning)` when
    /// this one should be logged at `warn`.
    fn record(&self, now: Instant) -> Option<u64> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        match state.last_warn {
            Some(last) if now.saturating_duration_since(last) < REFUSAL_LOG_INTERVAL => {
                state.suppressed += 1;
                None
            }
            _ => {
                state.last_warn = Some(now);
                Some(std::mem::take(&mut state.suppressed))
            }
        }
    }
}

fn admit_client(
    client: &TcpStream,
    verifier: &dyn PeerVerifier,
    refusals: &RefusalLog,
) -> PeerDecision {
    match (client.peer_addr(), client.local_addr()) {
        (Ok(peer), Ok(local)) => match verifier.verify(peer, local) {
            PeerDecision::Allow => PeerDecision::Allow,
            PeerDecision::Deny(reason) => {
                if let Some(suppressed) = refusals.record(Instant::now()) {
                    tracing::warn!(
                        %peer,
                        %reason,
                        suppressed_since_last_warning = suppressed,
                        "refused local proxy client"
                    );
                } else {
                    tracing::debug!(%peer, %reason, "refused local proxy client");
                }
                PeerDecision::Deny(reason)
            }
        },
        (Err(err), _) | (_, Err(err)) => {
            tracing::debug!(error = %err, "proxy client vanished before verification");
            PeerDecision::Deny(err.to_string())
        }
    }
}

/// Replies `403 Forbidden` and closes, draining briefly so the reply is not lost to a reset.
fn reject_client(mut client: TcpStream) {
    let _ = write_proxy_error(&mut client, 403, "Forbidden");
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = client.set_read_timeout(Some(REJECT_DRAIN_TIMEOUT));
    let deadline = Instant::now() + REJECT_DRAIN_TIMEOUT;
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    while drained <= MAX_HEADER_BYTES && Instant::now() < deadline {
        match client.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// Verifies the client's process, then relays its request or refuses it.
fn serve_client(
    client: TcpStream,
    cfg: &ForwarderConfig,
    verifier: &dyn PeerVerifier,
    refusals: &RefusalLog,
) -> io::Result<()> {
    // Accepted sockets inherit the listener's non-blocking mode on BSD-derived systems.
    client.set_nonblocking(false)?;
    client.set_write_timeout(Some(HEADER_IO_TIMEOUT))?;
    if admit_client(&client, verifier, refusals) != PeerDecision::Allow {
        reject_client(client);
        return Ok(());
    }
    handle_client(client, cfg)
}

#[allow(clippy::too_many_lines)]
fn handle_client(mut client: TcpStream, cfg: &ForwarderConfig) -> io::Result<()> {
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

    let (target_host, target_port, is_connect) = parse_request_target(&header_lines[0])?;
    cfg.stats.record_connection();

    // L4 hostname blocking (zero MITM — drops before upstream connect or TLS handshake).
    if cfg.blocker.is_blocked(&target_host) {
        cfg.stats.record_blocked();
        tracing::debug!(host = %target_host, "blocked host at L4 proxy");
        client.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        client.flush()?;
        return Ok(());
    }

    let Some((mut upstream_stream, upstream_leftover)) = open_upstream_tunnel(
        &mut client,
        cfg.upstream.as_ref(),
        &header_lines,
        total_bytes,
        &target_host,
        target_port,
        is_connect,
        &cfg.stats,
    )?
    else {
        // The upstream refused the tunnel and the failure was already relayed to the client.
        return Ok(());
    };

    // Every path that reaches this point has consumed any proxy-level reply, so a `CONNECT`
    // tunnel now carries only end-to-end TLS bytes and can be observed.
    let tap = if is_connect {
        cfg.tunnel_observer(&target_host)
    } else {
        None
    };

    let buffered = client_reader.buffer();
    if !buffered.is_empty() {
        upstream_stream.write_all(buffered)?;
        upstream_stream.flush()?;
        cfg.stats.add_bytes_sent(buffered.len());
        if let Some(t) = &tap {
            t.observe(Direction::ClientToServer, buffered);
        }
    }

    // Bytes the upstream proxy sent right behind its `CONNECT` reply already belong to the
    // tunnelled stream (the first server-side TLS bytes); they must not be dropped.
    if !upstream_leftover.is_empty() {
        client.write_all(&upstream_leftover)?;
        client.flush()?;
        cfg.stats.add_bytes_received(upstream_leftover.len());
        if let Some(t) = &tap {
            t.observe(Direction::ServerToClient, &upstream_leftover);
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
    let tap_c2s = tap.clone();
    let stats_c2s = Arc::clone(&cfg.stats);

    let forward_thread = thread::Builder::new()
        .name("waybound-proxy-pipe".to_owned())
        .spawn(move || {
            let _ = copy_stream(
                &mut client_to_up_src,
                &mut client_to_up_dst,
                tap_c2s.as_deref(),
                &stats_c2s,
                Direction::ClientToServer,
            );
            let _ = client_to_up_dst.shutdown(std::net::Shutdown::Write);
        })?;

    let _ = copy_stream(
        &mut up_to_client_src,
        &mut up_to_client_dst,
        tap.as_deref(),
        &cfg.stats,
        Direction::ServerToClient,
    );
    let _ = up_to_client_dst.shutdown(std::net::Shutdown::Write);
    let _ = forward_thread.join();
    Ok(())
}

/// Connects to the target (directly or through `upstream`) and, for `CONNECT`, tells the
/// client the tunnel is established exactly once.
///
/// Returns the upstream stream plus any tunnelled server bytes that were read while
/// consuming an upstream HTTP proxy's `CONNECT` reply. Returns `Ok(None)` when the upstream
/// proxy rejected the tunnel; the rejection has then already been relayed to the client.
#[allow(clippy::too_many_arguments)]
fn open_upstream_tunnel(
    client: &mut TcpStream,
    upstream: Option<&UpstreamProxy>,
    header_lines: &[String],
    total_bytes: usize,
    target_host: &str,
    target_port: u16,
    is_connect: bool,
    stats: &ProxyStats,
) -> io::Result<Option<(TcpStream, Vec<u8>)>> {
    match upstream {
        None => {
            let dest = format!("{target_host}:{target_port}");
            let mut s = connect_upstream(&dest)?;
            s.set_read_timeout(Some(HEADER_IO_TIMEOUT))?;
            s.set_write_timeout(Some(HEADER_IO_TIMEOUT))?;
            if is_connect {
                client.write_all(CONNECT_ESTABLISHED)?;
                client.flush()?;
            } else {
                let sent = forward_plain_http_over_socks(&mut s, header_lines, total_bytes)?;
                stats.add_bytes_sent(sent);
            }
            Ok(Some((s, Vec::new())))
        }
        Some(up) => {
            let mut s = connect_upstream(&up.host_port)?;
            s.set_read_timeout(Some(HEADER_IO_TIMEOUT))?;
            s.set_write_timeout(Some(HEADER_IO_TIMEOUT))?;
            match up.protocol {
                ProxyProtocol::Http => {
                    let sent = forward_http_upstream(&mut s, header_lines, total_bytes, up)?;
                    if !is_connect {
                        stats.add_bytes_sent(sent);
                        // Plain HTTP: the upstream's response is relayed to the client as-is.
                        return Ok(Some((s, Vec::new())));
                    }
                    finish_http_upstream_connect(client, s)
                }
                ProxyProtocol::Socks5 => {
                    socks5_handshake(&mut s, up, target_host, target_port)?;
                    if is_connect {
                        client.write_all(CONNECT_ESTABLISHED)?;
                        client.flush()?;
                    } else {
                        let sent =
                            forward_plain_http_over_socks(&mut s, header_lines, total_bytes)?;
                        stats.add_bytes_sent(sent);
                    }
                    Ok(Some((s, Vec::new())))
                }
            }
        }
    }
}

/// Consumes an upstream HTTP proxy's reply to `CONNECT` and reports the outcome to the client.
fn finish_http_upstream_connect(
    client: &mut TcpStream,
    mut upstream_stream: TcpStream,
) -> io::Result<Option<(TcpStream, Vec<u8>)>> {
    match read_http_connect_reply(&mut upstream_stream) {
        Ok(ConnectReply::Established { leftover }) => {
            client.write_all(CONNECT_ESTABLISHED)?;
            client.flush()?;
            Ok(Some((upstream_stream, leftover)))
        }
        Ok(ConnectReply::Rejected { status, reason }) => {
            tracing::debug!(status, "upstream HTTP proxy rejected CONNECT");
            // Only the status line is relayed: upstream headers such as `Proxy-Authenticate`
            // would make Chrome prompt for credentials this forwarder strips anyway.
            write_proxy_error(client, status, &reason)?;
            Ok(None)
        }
        Err(err) => {
            let _ = write_proxy_error(client, 502, "Bad Gateway");
            Err(err)
        }
    }
}

/// Upstream HTTP proxy's answer to a `CONNECT` request.
#[derive(Debug, PartialEq, Eq)]
enum ConnectReply {
    /// `2xx`: the tunnel is open. `leftover` holds tunnelled bytes read past the header block.
    Established { leftover: Vec<u8> },
    /// Any other status; the tunnel was not opened.
    Rejected { status: u16, reason: String },
}

/// Reads the upstream proxy's `CONNECT` reply header block, bounded in size and total time.
fn read_http_connect_reply(stream: &mut TcpStream) -> io::Result<ConnectReply> {
    let deadline = Instant::now() + HEADER_IO_TIMEOUT;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = find_header_end(&head) {
            break end;
        }
        let room = MAX_HEADER_BYTES.saturating_sub(head.len());
        if room == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "upstream proxy CONNECT reply header exceeded limit",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "timed out reading upstream proxy CONNECT reply",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let want = room.min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "upstream proxy closed before completing CONNECT reply",
                ));
            }
            Ok(n) => head.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    };
    stream.set_read_timeout(Some(HEADER_IO_TIMEOUT))?;

    let leftover = head.split_off(head_end);
    let (status, reason) = parse_status_line(&head)?;
    if (200..300).contains(&status) {
        Ok(ConnectReply::Established { leftover })
    } else {
        Ok(ConnectReply::Rejected { status, reason })
    }
}

/// Returns the offset just past the blank line ending an HTTP header block (`\r\n\r\n`,
/// tolerating bare `\n\n`), if the block is complete.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.iter().enumerate().find_map(|(idx, &byte)| {
        if byte != b'\n' {
            return None;
        }
        let rest = &buf[idx + 1..];
        if rest.starts_with(b"\n") {
            Some(idx + 2)
        } else if rest.starts_with(b"\r\n") {
            Some(idx + 3)
        } else {
            None
        }
    })
}

/// Parses `HTTP/1.x <code> <reason>` into a status code and a sanitized reason phrase.
fn parse_status_line(head: &[u8]) -> io::Result<(u16, String)> {
    let malformed = || {
        io::Error::new(
            ErrorKind::InvalidData,
            "malformed upstream proxy CONNECT reply status line",
        )
    };
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).map_err(|_| malformed())?;
    let line = line.trim_end_matches('\r');
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") || code.len() != 3 {
        return Err(malformed());
    }
    let status = code.parse::<u16>().map_err(|_| malformed())?;
    if !(100..600).contains(&status) {
        return Err(malformed());
    }
    let reason = parts
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_REASON_PHRASE_CHARS)
        .collect::<String>()
        .trim()
        .to_owned();
    Ok((status, reason))
}

/// Sends a body-less error status to the client. Statuses other than 4xx/5xx become `502`.
fn write_proxy_error(client: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    let (status, reason) = if (400..600).contains(&status) {
        (status, reason)
    } else {
        (502, "Bad Gateway")
    };
    let reply =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(reply.as_bytes())?;
    client.flush()
}

fn forward_http_upstream(
    upstream_stream: &mut TcpStream,
    header_lines: &[String],
    total_bytes: usize,
    upstream: &UpstreamProxy,
) -> io::Result<usize> {
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
    upstream_stream.flush()?;
    Ok(outbound.len())
}

fn forward_plain_http_over_socks(
    upstream_stream: &mut TcpStream,
    header_lines: &[String],
    total_bytes: usize,
) -> io::Result<usize> {
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
    upstream_stream.flush()?;
    Ok(outbound.len())
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
        .map_or_else(
            || target.to_owned(),
            |rest| match rest.find(['/', '?']) {
                Some(idx) if rest[idx..].starts_with('?') => format!("/{}", &rest[idx..]),
                Some(idx) => rest[idx..].to_owned(),
                None => "/".to_owned(),
            },
        );
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

fn copy_stream(
    src: &mut TcpStream,
    dst: &mut TcpStream,
    tap: Option<&dyn TunnelObserver>,
    stats: &ProxyStats,
    dir: Direction,
) -> io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..n])?;
        match dir {
            Direction::ClientToServer => stats.add_bytes_sent(n),
            Direction::ServerToClient => stats.add_bytes_received(n),
        }
        if let Some(t) = tap {
            t.observe(dir, &buf[..n]);
        }
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
    fn password_with_slash_is_parsed_and_never_leaks() {
        let parsed = UpstreamProxy::parse("socks5://bob:pa/ss@proxy.example.com:1080/");
        assert!(parsed.is_ok());
        if let Ok(p) = parsed {
            assert_eq!(p.host_port, "proxy.example.com:1080");
            assert_eq!(p.credentials, Some((b"bob".to_vec(), b"pa/ss".to_vec())));
            let debug = format!("{p:?}");
            assert!(
                !debug.contains("pa/ss") && !debug.contains("bob"),
                "{debug}"
            );
        }

        // A malformed host must not echo any part of the credentials.
        let err = UpstreamProxy::parse("http://bob:s3/cret@nohostport");
        assert!(
            matches!(&err, Err(e) if !e.contains("s3") && !e.contains("cret") && !e.contains("bob")),
            "{err:?}"
        );
    }

    #[test]
    fn rewrite_origin_form_keeps_query_without_path() {
        assert_eq!(
            rewrite_origin_form("GET http://example.com?x=1 HTTP/1.1"),
            "GET /?x=1 HTTP/1.1\r\n"
        );
        assert_eq!(
            rewrite_origin_form("GET http://example.com/a?x=1 HTTP/1.1"),
            "GET /a?x=1 HTTP/1.1\r\n"
        );
        assert_eq!(
            rewrite_origin_form("GET http://example.com HTTP/1.1"),
            "GET / HTTP/1.1\r\n"
        );
    }

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
    fn refusal_warnings_are_rate_limited() {
        let log = RefusalLog::default();
        let t0 = Instant::now();
        assert_eq!(log.record(t0), Some(0));
        assert_eq!(log.record(t0 + Duration::from_secs(1)), None);
        assert_eq!(log.record(t0 + Duration::from_secs(59)), None);
        assert_eq!(log.record(t0 + REFUSAL_LOG_INTERVAL), Some(2));
        assert_eq!(log.record(t0 + REFUSAL_LOG_INTERVAL), None);
        assert_eq!(log.record(t0 + 3 * REFUSAL_LOG_INTERVAL), Some(1));
    }

    /// Fake verifier that refuses everyone and records the addresses it was asked about.
    #[derive(Default)]
    struct DenyingVerifier {
        seen: std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>>,
    }

    impl PeerVerifier for DenyingVerifier {
        fn verify(&self, peer: SocketAddr, local: SocketAddr) -> PeerDecision {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((peer, local));
            }
            PeerDecision::Deny("test: client owned by another user".to_owned())
        }
    }

    #[test]
    fn refused_peer_gets_403_and_no_upstream_connection() {
        let Ok(upstream_listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(upstream_addr) = upstream_listener.local_addr() else {
            return;
        };
        let Ok(upstream) = UpstreamProxy::parse(&format!("http://user:pass@{upstream_addr}"))
        else {
            return;
        };
        let verifier = Arc::new(DenyingVerifier::default());
        let Ok(forwarder) = ProxyForwarder::start_with_verifier(upstream, verifier.clone()) else {
            return;
        };
        let Some(mut client) = connect_client(&forwarder) else {
            return;
        };
        let _ =
            client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        let reply = String::from_utf8_lossy(&read_to_close(&mut client)).into_owned();
        assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{reply:?}");

        let seen = verifier.seen.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(
            seen,
            vec![(
                client.local_addr().unwrap_or(forwarder.local_addr),
                forwarder.local_addr
            )]
        );

        // No upstream connection was ever attempted, so no credentials left the daemon.
        let _ = upstream_listener.set_nonblocking(true);
        assert!(matches!(
            upstream_listener.accept(),
            Err(err) if err.kind() == ErrorKind::WouldBlock
        ));
    }

    /// With the real platform policy, connections from this (same-user) process still work.
    #[test]
    fn platform_policy_admits_own_process() {
        let Ok(upstream_listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(upstream_addr) = upstream_listener.local_addr() else {
            return;
        };
        let server_thread = thread::spawn(move || {
            if let Ok((mut stream, _)) = upstream_listener.accept() {
                let _ = read_request_head(&mut stream);
                let _ = stream.write_all(CONNECT_ESTABLISHED);
            }
        });
        let Ok(upstream) = UpstreamProxy::parse(&format!("http://user:pass@{upstream_addr}"))
        else {
            return;
        };
        let Ok(forwarder) =
            ProxyForwarder::start_with_options(Some(upstream), HostBlocker::default(), None)
        else {
            return;
        };
        let Some(mut client) = connect_client(&forwarder) else {
            return;
        };
        let _ =
            client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        let reply = read_up_to(&mut client, CONNECT_ESTABLISHED.len());
        assert_eq!(reply, CONNECT_ESTABLISHED);
        drop(client);
        let _ = server_thread.join();
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

    /// Records every byte a tunnel observer is shown, per direction.
    #[derive(Default)]
    struct RecordingObserver {
        c2s: std::sync::Mutex<Vec<u8>>,
        s2c: std::sync::Mutex<Vec<u8>>,
    }

    impl TunnelObserver for RecordingObserver {
        fn observe(&self, dir: Direction, bytes: &[u8]) {
            let slot = match dir {
                Direction::ClientToServer => &self.c2s,
                Direction::ServerToClient => &self.s2c,
            };
            if let Ok(mut buf) = slot.lock() {
                buf.extend_from_slice(bytes);
            }
        }
    }

    impl RecordingObserver {
        fn snapshot(&self) -> (Vec<u8>, Vec<u8>) {
            let c2s = self.c2s.lock().map(|b| b.clone()).unwrap_or_default();
            let s2c = self.s2c.lock().map(|b| b.clone()).unwrap_or_default();
            (c2s, s2c)
        }
    }

    const TEST_IO_TIMEOUT: Duration = Duration::from_secs(10);

    /// Reads from `stream` until the bytes seen so far contain `\r\n\r\n`; returns them all.
    fn read_request_head(stream: &mut TcpStream) -> Vec<u8> {
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while find_header_end(&head).is_none() {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        head
    }

    /// Reads exactly `len` bytes, or whatever arrived before EOF/error/timeout.
    fn read_up_to(stream: &mut TcpStream, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        while out.len() < len {
            let want = (len - out.len()).min(buf.len());
            match stream.read(&mut buf[..want]) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    }

    fn read_to_close(stream: &mut TcpStream) -> Vec<u8> {
        read_up_to(stream, usize::MAX)
    }

    /// Starts a forwarder chained to a one-shot fake upstream HTTP proxy run by `upstream`.
    fn forwarder_with_fake_http_upstream<F>(
        upstream: F,
    ) -> Option<(
        ProxyForwarder,
        Arc<RecordingObserver>,
        thread::JoinHandle<Vec<u8>>,
    )>
    where
        F: FnOnce(TcpStream) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let server = thread::spawn(move || match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(TEST_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(TEST_IO_TIMEOUT));
                upstream(stream)
            }
            Err(_) => Vec::new(),
        });
        let proxy = UpstreamProxy::parse(&format!("http://user:pass@{addr}")).ok()?;
        let recorder = Arc::new(RecordingObserver::default());
        let observer: Arc<dyn TunnelObserver> = recorder.clone();
        let forwarder = ProxyForwarder::start_with_observer(proxy, observer).ok()?;
        Some((forwarder, recorder, server))
    }

    fn connect_client(forwarder: &ProxyForwarder) -> Option<TcpStream> {
        let client = TcpStream::connect(forwarder.local_addr).ok()?;
        client.set_read_timeout(Some(TEST_IO_TIMEOUT)).ok()?;
        client.set_write_timeout(Some(TEST_IO_TIMEOUT)).ok()?;
        Some(client)
    }

    /// Waits until the recorder holds the expected bytes (observation trails the relay write).
    fn wait_for_tap(recorder: &RecordingObserver, c2s: &[u8], s2c: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let deadline = Instant::now() + TEST_IO_TIMEOUT;
        loop {
            let seen = recorder.snapshot();
            if (seen.0 == c2s && seen.1 == s2c) || Instant::now() >= deadline {
                return seen;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    const SERVER_FIRST: &[u8] = b"\x16\x03\x03server-first-flight";
    const CLIENT_HELLO: &[u8] = b"\x16\x03\x01client-hello-bytes";
    const SERVER_REPLY: &[u8] = b"\x17\x03\x03server-app-data";
    const UPSTREAM_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: fake\r\n\r\n";

    #[test]
    fn http_upstream_connect_is_tapped_without_proxy_reply_bytes() {
        // The 200 header and the first tunnelled bytes arrive in a single write.
        let mut first = UPSTREAM_200.to_vec();
        first.extend_from_slice(SERVER_FIRST);
        assert_http_upstream_connect_is_tapped(vec![first]);
    }

    #[test]
    fn http_upstream_connect_reply_split_across_writes_is_tapped() {
        // The reply header is cut mid status line; its tail shares a write with the payload.
        let (head, tail) = UPSTREAM_200.split_at(16);
        let mut second = tail.to_vec();
        second.extend_from_slice(SERVER_FIRST);
        assert_http_upstream_connect_is_tapped(vec![head.to_vec(), second]);
    }

    /// Runs a tapped `CONNECT` through a fake upstream that sends `reply_writes` (the 200
    /// header followed by [`SERVER_FIRST`]) as separate writes with a short pause in between.
    fn assert_http_upstream_connect_is_tapped(reply_writes: Vec<Vec<u8>>) {
        let Some((forwarder, recorder, server)) =
            forwarder_with_fake_http_upstream(move |mut s| {
                let request = read_request_head(&mut s);
                for (idx, chunk) in reply_writes.iter().enumerate() {
                    if idx > 0 {
                        thread::sleep(Duration::from_millis(50));
                    }
                    if s.write_all(chunk).and_then(|()| s.flush()).is_err() {
                        return request;
                    }
                }
                let hello = read_up_to(&mut s, CLIENT_HELLO.len());
                if hello == CLIENT_HELLO {
                    let _ = s.write_all(SERVER_REPLY);
                }
                request
            })
        else {
            return;
        };
        let Some(mut client) = connect_client(&forwarder) else {
            return;
        };
        assert!(
            client
                .write_all(b"CONNECT api.test:443 HTTP/1.1\r\nHost: api.test:443\r\n\r\n")
                .is_ok()
        );

        let mut expected_head = CONNECT_ESTABLISHED.to_vec();
        expected_head.extend_from_slice(SERVER_FIRST);
        let head = read_up_to(&mut client, expected_head.len());
        assert_eq!(head, expected_head, "{}", String::from_utf8_lossy(&head));

        assert!(client.write_all(CLIENT_HELLO).is_ok());
        let rest = read_to_close(&mut client);
        assert_eq!(
            rest, SERVER_REPLY,
            "exactly one 200 and an unmodified tunnel"
        );

        let request = server.join().unwrap_or_default();
        let request = String::from_utf8_lossy(&request);
        assert!(
            request.starts_with("CONNECT api.test:443 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));

        let mut s2c_expected = SERVER_FIRST.to_vec();
        s2c_expected.extend_from_slice(SERVER_REPLY);
        let (c2s, s2c) = wait_for_tap(&recorder, CLIENT_HELLO, &s2c_expected);
        assert_eq!(c2s, CLIENT_HELLO);
        assert_eq!(
            s2c, s2c_expected,
            "tap must see leftover bytes but no proxy header"
        );
    }

    fn assert_upstream_rejection_is_relayed(reply: &'static [u8], expected_status: &str) {
        let Some((forwarder, recorder, server)) =
            forwarder_with_fake_http_upstream(move |mut s| {
                let request = read_request_head(&mut s);
                // Bytes behind the rejection must never reach the client or the tap.
                let mut out = reply.to_vec();
                out.extend_from_slice(b"\x16\x03\x03not-a-tunnel");
                let _ = s.write_all(&out);
                let _ = read_to_close(&mut s);
                request
            })
        else {
            return;
        };
        let Some(mut client) = connect_client(&forwarder) else {
            return;
        };
        assert!(
            client
                .write_all(b"CONNECT api.test:443 HTTP/1.1\r\nHost: api.test:443\r\n\r\n")
                .is_ok()
        );
        let response = read_to_close(&mut client);
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}")),
            "{response}"
        );
        assert!(response.ends_with("\r\n\r\n"), "{response}");
        assert!(!response.contains("200"), "{response}");
        assert!(!response.contains("Proxy-Authenticate"), "{response}");
        assert!(!response.contains("not-a-tunnel"), "{response}");
        drop(client);
        let _ = server.join();
        assert_eq!(recorder.snapshot(), (Vec::new(), Vec::new()));
    }

    #[test]
    fn http_upstream_407_is_relayed_and_not_tapped() {
        assert_upstream_rejection_is_relayed(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"upstream\"\r\nContent-Length: 0\r\n\r\n",
            "407 Proxy Authentication Required\r\n",
        );
    }

    #[test]
    fn http_upstream_502_is_relayed_and_not_tapped() {
        assert_upstream_rejection_is_relayed(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            "502 Bad Gateway\r\n",
        );
    }

    #[test]
    fn http_upstream_malformed_or_oversized_reply_becomes_502() {
        assert_upstream_rejection_is_relayed(b"SSH-2.0-not-http\r\n\r\n", "502 Bad Gateway\r\n");

        let oversized: &'static [u8] = Vec::leak(vec![b'a'; MAX_HEADER_BYTES + 16]);
        assert_upstream_rejection_is_relayed(oversized, "502 Bad Gateway\r\n");
    }

    #[test]
    fn header_end_and_status_line_parsing() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\nTLS"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.0 200 OK\n\nTLS"), Some(17));
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 Connection established\r\n").ok(),
            Some((200, "Connection established".to_owned()))
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.0 407\r\n").ok(),
            Some((407, String::new()))
        );
        assert!(parse_status_line(b"HTTP/1.1 2000 nope\r\n").is_err());
        assert!(parse_status_line(b"ICY 200 OK\r\n").is_err());
    }

    #[test]
    fn header_end_found_only_once_complete_when_fed_bytewise() {
        let mut wire = UPSTREAM_200.to_vec();
        wire.extend_from_slice(SERVER_FIRST);
        let mut fed = Vec::new();
        for (idx, &byte) in wire.iter().enumerate() {
            fed.push(byte);
            let expected = (idx + 1 >= UPSTREAM_200.len()).then_some(UPSTREAM_200.len());
            assert_eq!(find_header_end(&fed), expected, "after {} bytes", idx + 1);
        }

        let mut fed = Vec::new();
        for &byte in b"HTTP/1.0 200 OK\n\nX" {
            fed.push(byte);
            let expected = (fed.len() >= 17).then_some(17);
            assert_eq!(find_header_end(&fed), expected, "after {} bytes", fed.len());
        }
    }

    #[test]
    fn proxy_stats_count_bytes_connections_and_blocked_hosts() {
        let Ok(origin_listener) = TcpListener::bind("127.0.0.1:0") else {
            return;
        };
        let Ok(origin_addr) = origin_listener.local_addr() else {
            return;
        };

        let http_body = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        let tunnel_payload = b"tunnel-request-payload-12345";
        let tunnel_reply = b"tunnel-echo-reply-67890";

        let origin_thread = thread::spawn(move || {
            // Connection 1: plain HTTP GET.
            if let Ok((mut s1, _)) = origin_listener.accept() {
                let _ = s1.set_read_timeout(Some(TEST_IO_TIMEOUT));
                let _ = read_request_head(&mut s1);
                let _ = s1.write_all(http_body);
                let _ = s1.flush();
            }
            // Connection 2: CONNECT tunnel echo.
            if let Ok((mut s2, _)) = origin_listener.accept() {
                let _ = s2.set_read_timeout(Some(TEST_IO_TIMEOUT));
                let got = read_up_to(&mut s2, tunnel_payload.len());
                if got == tunnel_payload {
                    let _ = s2.write_all(tunnel_reply);
                    let _ = s2.flush();
                }
            }
        });

        let preset_hosts = waybound_net::expand_block_presets(["analytics"]).unwrap_or_default();
        let blocker = HostBlocker::new(preset_hosts);
        let Ok(forwarder) = ProxyForwarder::start_with_options(None, blocker, None) else {
            return;
        };

        // 1) Plain HTTP request through direct proxy.
        let Some(mut c1) = connect_client(&forwarder) else {
            return;
        };
        let req = format!(
            "GET http://{origin_addr}/ping HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
        );
        assert!(c1.write_all(req.as_bytes()).is_ok());
        let resp1 = read_to_close(&mut c1);
        assert_eq!(resp1, http_body);
        drop(c1);

        // 2) CONNECT tunnel to local TCP server.
        let Some(mut c2) = connect_client(&forwarder) else {
            return;
        };
        let connect_req = format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
        assert!(c2.write_all(connect_req.as_bytes()).is_ok());
        let est = read_up_to(&mut c2, CONNECT_ESTABLISHED.len());
        assert_eq!(est, CONNECT_ESTABLISHED);
        assert!(c2.write_all(tunnel_payload).is_ok());
        let resp2 = read_to_close(&mut c2);
        assert_eq!(resp2, tunnel_reply);
        drop(c2);

        // 3) Blocked analytics host via preset.
        let Some(mut c3) = connect_client(&forwarder) else {
            return;
        };
        assert!(
            c3.write_all(
                b"CONNECT www.google-analytics.com:443 HTTP/1.1\r\nHost: www.google-analytics.com:443\r\n\r\n"
            )
            .is_ok()
        );
        let resp3 = String::from_utf8_lossy(&read_to_close(&mut c3)).into_owned();
        assert!(resp3.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{resp3:?}");
        drop(c3);

        let _ = origin_thread.join();

        let expected_received = (http_body.len() + tunnel_reply.len()) as u64;
        let deadline = Instant::now() + TEST_IO_TIMEOUT;
        let stats = loop {
            let s = forwarder.stats();
            if (s.connections_total == 3
                && s.connections_blocked == 1
                && s.bytes_received == expected_received)
                || Instant::now() >= deadline
            {
                break s;
            }
            thread::sleep(Duration::from_millis(10));
        };

        assert_eq!(stats.connections_total, 3);
        assert_eq!(stats.connections_blocked, 1);
        assert_eq!(stats.bytes_received, expected_received);
        assert!(
            stats.bytes_sent >= tunnel_payload.len() as u64,
            "expected bytes_sent >= tunnel payload, got {}",
            stats.bytes_sent
        );
    }
}
