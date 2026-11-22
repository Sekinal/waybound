//! Line-delimited JSON-RPC server over a local Unix domain socket or loopback TCP socket.

#[cfg(unix)]
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use waybound_core::{
    BackendKind, Driver, InputEvent, KeyCode, KeyModifier, LocatorQuery, MotionConfig, MouseButton,
    Point, Request, Response, Result, SplitMix64, WayboundError, hover_pause_before_click,
    key_delay, key_hold_ms, mouse_hold_ms, pick_click_point, plan_human_pointer_path,
    plan_scroll_burst,
};

use crate::net_tap::ResponseStore;

#[cfg(unix)]
const MAX_UNIX_PATH_BYTES: usize = 100;
const MAX_FRAME_BYTES: u64 = 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// How often an idle connection wakes up to check for shutdown.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(75);
const MAX_WAIT_TIMEOUT_MS: u64 = 120_000;

/// RAII guard that removes a bound Unix socket file on drop.
#[cfg(unix)]
struct SocketGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// RAII guard decrementing the active connection counter even on unwind.
struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let _ = self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Runtime options for daemon request execution.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    /// Whether to execute smooth minimum-jerk pointer trajectories before clicks.
    pub use_motion: bool,
}

struct SessionState {
    /// Last pointer position sent by the daemon; `None` until the first move.
    last_cursor: Mutex<Option<Point>>,
    shutdown: Arc<AtomicBool>,
    responses: Arc<ResponseStore>,
    options: ServerOptions,
}

impl SessionState {
    const fn new(
        options: ServerOptions,
        responses: Arc<ResponseStore>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            last_cursor: Mutex::new(None),
            shutdown,
            responses,
            options,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn handle_request(driver: &dyn Driver, state: &SessionState, request: Request) -> Response {
    match request {
        Request::Ping => Response::Pong {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        Request::SnapshotTree => match driver.snapshot_tree() {
            Ok(nodes) => Response::Tree { nodes },
            Err(err) => Response::from(&err),
        },
        Request::LocateAll { query } => match driver.locate_all(&query) {
            Ok(nodes) => Response::Tree { nodes },
            Err(err) => Response::from(&err),
        },
        Request::CurrentUrl => match driver.current_url() {
            Ok(url) => Response::Url { url },
            Err(err) => Response::from(&err),
        },
        Request::WaitFor { query, timeout_ms } => {
            match wait_for_element(driver, &query, timeout_ms) {
                Ok(node) => Response::Node { node },
                Err(err) => Response::from(&err),
            }
        }
        Request::Hover { query } => match hover_element(driver, state, &query) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Click { query } => match click_element(driver, state, &query) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Fill { query, text } => match fill_element(driver, state, &query, &text) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Navigate { url } => match navigate_url(driver, &url) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Reload => match browser_shortcut(driver, BrowserAction::Reload) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::GoBack => match browser_shortcut(driver, BrowserAction::GoBack) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::GoForward => match browser_shortcut(driver, BrowserAction::GoForward) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::NewTab { url } => match open_new_tab(driver, url.as_deref()) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::CloseTab => match browser_shortcut(driver, BrowserAction::CloseTab) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::NextTab => match browser_shortcut(driver, BrowserAction::NextTab) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::PrevTab => match browser_shortcut(driver, BrowserAction::PrevTab) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Scroll { delta_x, delta_y } => {
            if !delta_x.is_finite() || !delta_y.is_finite() {
                return Response::Error {
                    code: "invalid_request".to_owned(),
                    message: "scroll deltas must be finite numbers".to_owned(),
                };
            }
            match scroll_viewport(driver, state, delta_x, delta_y) {
                Ok(()) => Response::Ok,
                Err(err) => Response::from(&err),
            }
        }
        Request::Press { key, modifiers } => {
            let hold_ms = if state.options.use_motion {
                key_hold_ms(&mut SplitMix64::from_entropy())
            } else {
                0
            };
            match driver.dispatch_input(&InputEvent::KeyPress {
                key,
                modifiers,
                hold_ms,
            }) {
                Ok(()) => Response::Ok,
                Err(err) => Response::from(&err),
            }
        }
        Request::CapturedResponses { url_contains } => Response::HttpResponses {
            responses: state.responses.list(url_contains.as_deref()),
        },
        Request::WaitForResponse {
            url_contains,
            timeout_ms,
        } => match state.responses.wait_for(&url_contains, timeout_ms) {
            Ok(response) => Response::HttpResponse { response },
            Err(err) => Response::from(&err),
        },
        Request::Screenshot { path } => match driver.screenshot(Path::new(&path)) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Shutdown => {
            state.shutdown.store(true, Ordering::Release);
            Response::Ok
        }
    }
}

fn wait_for_element(
    driver: &dyn Driver,
    query: &LocatorQuery,
    timeout_ms: u64,
) -> Result<waybound_core::AccessibilityNode> {
    let clamped_ms = timeout_ms.min(MAX_WAIT_TIMEOUT_MS);
    let deadline = Instant::now() + Duration::from_millis(clamped_ms);

    loop {
        match driver.locate(query) {
            Ok(node) => return Ok(node),
            Err(WayboundError::ElementNotFound { .. }) => {
                if Instant::now() >= deadline {
                    return Err(WayboundError::Timeout {
                        timeout_ms: clamped_ms,
                        context: format!("element not found for query: {query:?}"),
                    });
                }
                thread::sleep(WAIT_POLL_INTERVAL);
            }
            Err(other) => return Err(other),
        }
    }
}

fn move_pointer(
    driver: &dyn Driver,
    state: &SessionState,
    target: Point,
    rng: &mut SplitMix64,
) -> Result<()> {
    // Start from where the cursor really is: the tracked position is stale whenever the
    // physical mouse moved since the last request, and is (0, 0) before the first one.
    let tracked = state.last_cursor.lock().map_or(None, |g| *g);
    let start = driver
        .cursor_position()
        .ok()
        .flatten()
        .or(tracked)
        .unwrap_or(target);

    if state.options.use_motion && driver.backend_kind() != BackendKind::AndroidWaydroid {
        let path = plan_human_pointer_path(start, target, MotionConfig::default(), rng);
        for step in path {
            if !step.delay.is_zero() {
                thread::sleep(step.delay);
            }
            driver.dispatch_input(&InputEvent::PointerMove { to: step.point })?;
        }
    } else {
        driver.dispatch_input(&InputEvent::PointerMove { to: target })?;
    }

    if let Ok(mut guard) = state.last_cursor.lock() {
        *guard = Some(target);
    }
    Ok(())
}

fn scroll_viewport(
    driver: &dyn Driver,
    state: &SessionState,
    delta_x: f64,
    delta_y: f64,
) -> Result<()> {
    if !state.options.use_motion || driver.backend_kind() == BackendKind::AndroidWaydroid {
        return driver.dispatch_input(&InputEvent::Scroll { delta_x, delta_y });
    }
    let mut rng = SplitMix64::from_entropy();
    for step in plan_scroll_burst(delta_x, delta_y, &mut rng) {
        if !step.delay.is_zero() {
            thread::sleep(step.delay);
        }
        driver.dispatch_input(&InputEvent::Scroll {
            delta_x: step.delta_x,
            delta_y: step.delta_y,
        })?;
    }
    Ok(())
}

const MAX_SCROLL_INTO_VIEW_ATTEMPTS: usize = 6;
/// Default actionability auto-wait duration for `hover`, `click`, and `fill`.
const DEFAULT_ACTION_WAIT: Duration = Duration::from_secs(5);
const ACTION_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn locate_with_auto_wait(
    driver: &dyn Driver,
    query: &LocatorQuery,
) -> Result<waybound_core::AccessibilityNode> {
    let deadline = Instant::now() + DEFAULT_ACTION_WAIT;
    loop {
        match driver.locate(query) {
            Ok(node) => return Ok(node),
            Err(WayboundError::ElementNotFound { .. }) if Instant::now() < deadline => {
                thread::sleep(ACTION_POLL_INTERVAL);
            }
            Err(err) => return Err(err),
        }
    }
}

fn validate_bounds(b: waybound_core::Bounds, query: &LocatorQuery) -> Result<()> {
    if !b.x.is_finite()
        || !b.y.is_finite()
        || !b.width.is_finite()
        || !b.height.is_finite()
        || b.width <= 0.0
        || b.height <= 0.0
    {
        return Err(WayboundError::ElementNotFound {
            query: format!("element matched {query:?} but has invalid bounds {b:?}"),
        });
    }
    Ok(())
}

fn hover_element(driver: &dyn Driver, state: &SessionState, query: &LocatorQuery) -> Result<()> {
    let mut node = locate_with_auto_wait(driver, query)?;
    validate_bounds(node.bounds, query)?;

    // Auto-scroll off-screen elements into the visible viewport when viewport bounds are known.
    if let Ok(Some(vp)) = driver.viewport_bounds()
        && vp.height > 40.0
    {
        let mut positioned_in_vp = false;
        for _ in 0..MAX_SCROLL_INTO_VIEW_ATTEMPTS {
            let (_, cy) = node.bounds.center();
            let top = vp.y + 12.0;
            let bottom = vp.y + vp.height - 12.0;
            if cy >= top && cy <= bottom {
                break;
            }
            // On macOS, wheel events go to the window under the cursor — ensure cursor is inside vp.
            if !positioned_in_vp && driver.backend_kind() == BackendKind::MacOsNative {
                let (vx, vy) = vp.center();
                let mut rng = SplitMix64::from_entropy();
                move_pointer(driver, state, Point { x: vx, y: vy }, &mut rng)?;
                positioned_in_vp = true;
            }
            let step = (vp.height * 0.6).clamp(180.0, 520.0);
            let delta_y = if cy > bottom { -step } else { step };
            scroll_viewport(driver, state, 0.0, delta_y)?;
            thread::sleep(Duration::from_millis(120));
            node = driver.locate(query)?;
            validate_bounds(node.bounds, query)?;
        }
    }

    let b = node.bounds;

    let mut rng = SplitMix64::from_entropy();
    let target = if state.options.use_motion {
        pick_click_point(b, &mut rng)
    } else {
        let (x, y) = b.center();
        Point { x, y }
    };

    move_pointer(driver, state, target, &mut rng)
}

fn click_element(driver: &dyn Driver, state: &SessionState, query: &LocatorQuery) -> Result<()> {
    hover_element(driver, state, query)?;
    let hold_ms = if state.options.use_motion {
        let mut rng = SplitMix64::from_entropy();
        thread::sleep(hover_pause_before_click(&mut rng));
        mouse_hold_ms(&mut rng)
    } else {
        0
    };

    driver.dispatch_input(&InputEvent::MouseClick {
        button: MouseButton::Left,
        hold_ms,
    })
}

#[derive(Clone, Copy)]
enum BrowserAction {
    Reload,
    GoBack,
    GoForward,
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
}

fn open_new_tab(driver: &dyn Driver, url: Option<&str>) -> Result<()> {
    browser_shortcut(driver, BrowserAction::NewTab)?;
    if let Some(dest) = url {
        thread::sleep(Duration::from_millis(120));
        navigate_url(driver, dest)?;
    }
    Ok(())
}

fn browser_shortcut(driver: &dyn Driver, action: BrowserAction) -> Result<()> {
    let is_macos = driver.backend_kind() == BackendKind::MacOsNative;
    let (key, modifiers) = match (action, is_macos) {
        (BrowserAction::Reload, true) => (KeyCode::Char('r'), vec![KeyModifier::Meta]),
        (BrowserAction::Reload, false) => (KeyCode::Char('r'), vec![KeyModifier::Control]),
        (BrowserAction::GoBack, true) => (KeyCode::Char('['), vec![KeyModifier::Meta]),
        (BrowserAction::GoBack, false) => (KeyCode::ArrowLeft, vec![KeyModifier::Alt]),
        (BrowserAction::GoForward, true) => (KeyCode::Char(']'), vec![KeyModifier::Meta]),
        (BrowserAction::GoForward, false) => (KeyCode::ArrowRight, vec![KeyModifier::Alt]),
        (BrowserAction::NewTab, true) => (KeyCode::Char('t'), vec![KeyModifier::Meta]),
        (BrowserAction::NewTab, false) => (KeyCode::Char('t'), vec![KeyModifier::Control]),
        (BrowserAction::CloseTab, true) => (KeyCode::Char('w'), vec![KeyModifier::Meta]),
        (BrowserAction::CloseTab, false) => (KeyCode::Char('w'), vec![KeyModifier::Control]),
        (BrowserAction::NextTab, _) => (KeyCode::Tab, vec![KeyModifier::Control]),
        (BrowserAction::PrevTab, _) => {
            (KeyCode::Tab, vec![KeyModifier::Control, KeyModifier::Shift])
        }
    };
    driver.dispatch_input(&InputEvent::KeyPress {
        key,
        modifiers,
        hold_ms: 0,
    })
}

fn fill_element(
    driver: &dyn Driver,
    state: &SessionState,
    query: &LocatorQuery,
    text: &str,
) -> Result<()> {
    click_element(driver, state, query)?;
    replace_field_content(driver, text, state.options.use_motion)
}

/// Replaces the focused field's content with `text` (Playwright `fill` semantics).
///
/// The click lands at an arbitrary point inside the field, so typing straight away would
/// insert into the middle of any existing value. Select everything first; the first typed
/// character then replaces the selection, or Backspace clears it when `text` is empty.
fn replace_field_content(driver: &dyn Driver, text: &str, pace: bool) -> Result<()> {
    let select_all_mod = match driver.backend_kind() {
        BackendKind::MacOsNative => KeyModifier::Meta,
        // `adb shell input` cannot send modifier chords (they are dropped), so a select-all
        // would type a literal "a". Keep append semantics there until the driver supports it.
        BackendKind::AndroidWaydroid => return type_text(driver, text, pace),
        _ => KeyModifier::Control,
    };

    thread::sleep(Duration::from_millis(40));
    driver.dispatch_input(&InputEvent::KeyPress {
        key: KeyCode::Char('a'),
        modifiers: vec![select_all_mod],
        hold_ms: 0,
    })?;
    thread::sleep(Duration::from_millis(40));

    if text.is_empty() {
        return driver.dispatch_input(&InputEvent::KeyPress {
            key: KeyCode::Backspace,
            modifiers: Vec::new(),
            hold_ms: 0,
        });
    }
    type_text(driver, text, pace)
}

fn type_text(driver: &dyn Driver, text: &str, pace: bool) -> Result<()> {
    let mut rng = SplitMix64::from_entropy();
    for ch in text.chars() {
        let key = match ch {
            '\n' | '\r' => KeyCode::Enter,
            '\t' => KeyCode::Tab,
            other => KeyCode::Char(other),
        };
        let hold_ms = if pace { key_hold_ms(&mut rng) } else { 0 };
        driver.dispatch_input(&InputEvent::KeyPress {
            key,
            modifiers: Vec::new(),
            hold_ms,
        })?;
        if pace {
            thread::sleep(key_delay(ch, &mut rng));
        }
    }
    Ok(())
}

fn navigate_url(driver: &dyn Driver, url: &str) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(WayboundError::Io(std::io::Error::new(
            ErrorKind::InvalidInput,
            "url must start with http:// or https://",
        )));
    }

    if driver.navigate(url)? {
        return Ok(());
    }

    let focus_mod = match driver.backend_kind() {
        BackendKind::MacOsNative => KeyModifier::Meta,
        _ => KeyModifier::Control,
    };

    driver.dispatch_input(&InputEvent::KeyPress {
        key: KeyCode::Char('l'),
        modifiers: vec![focus_mod],
        hold_ms: 0,
    })?;
    thread::sleep(Duration::from_millis(60));
    type_text(driver, url, false)?;
    driver.dispatch_input(&InputEvent::KeyPress {
        key: KeyCode::Enter,
        modifiers: Vec::new(),
        hold_ms: 0,
    })
}

#[cfg(unix)]
fn prepare_socket_path(socket_path: &Path) -> Result<()> {
    let path_len = socket_path.as_os_str().as_encoded_bytes().len();
    if path_len >= MAX_UNIX_PATH_BYTES {
        return Err(WayboundError::Io(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "unix socket path length ({path_len} bytes) exceeds {MAX_UNIX_PATH_BYTES}-byte limit"
            ),
        )));
    }

    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(WayboundError::Io(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "refusing to overwrite non-socket file at {}",
                        socket_path.display()
                    ),
                )));
            }
            if UnixStream::connect(socket_path).is_ok() {
                return Err(WayboundError::Io(std::io::Error::new(
                    ErrorKind::AddrInUse,
                    format!(
                        "another daemon is already listening at {}",
                        socket_path.display()
                    ),
                )));
            }
            fs::remove_file(socket_path)?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(WayboundError::Io(err)),
    }

    Ok(())
}

/// Binds a Unix domain socket at `socket_path` and serves requests concurrently
/// until a graceful [`Request::Shutdown`] is received or `shutdown` is set (for example
/// by a termination signal handler).
///
/// # Errors
///
/// Returns an error if the socket path is invalid, already in use, or cannot be bound.
#[cfg(unix)]
pub fn serve_unix(
    socket_path: &Path,
    driver: &Arc<dyn Driver>,
    responses: Arc<ResponseStore>,
    options: ServerOptions,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    prepare_socket_path(socket_path)?;

    let listener = UnixListener::bind(socket_path)?;
    let _guard = SocketGuard {
        path: socket_path.to_path_buf(),
    };
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    tracing::info!(socket = %socket_path.display(), "listening on unix socket");

    let active_connections = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(SessionState::new(options, responses, shutdown));

    while !state.shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if let Err(err) = stream.set_nonblocking(false) {
                    tracing::warn!(error = %err, "failed to configure accepted stream");
                    continue;
                }

                let current = active_connections.fetch_add(1, Ordering::AcqRel);
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    let _ = active_connections.fetch_sub(1, Ordering::AcqRel);
                    tracing::warn!("rejecting connection: max concurrent connections reached");
                    continue;
                }

                let driver_ref = Arc::clone(driver);
                let state_ref = Arc::clone(&state);
                let conn_guard = ConnectionGuard {
                    counter: Arc::clone(&active_connections),
                };
                let _ = thread::spawn(move || {
                    let _guard = conn_guard;
                    if let Err(err) =
                        handle_unix_connection(stream, driver_ref.as_ref(), state_ref.as_ref())
                    {
                        tracing::warn!(error = %err, "client connection closed with error");
                    }
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::Interrupted
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                ) =>
            {
                tracing::debug!(error = %err, "transient accept error, continuing");
            }
            Err(err) => return Err(WayboundError::Io(err)),
        }
    }

    drain_connections(&active_connections);
    Ok(())
}

/// Binds a loopback-only TCP socket at `bind_addr` (for example `127.0.0.1:49222`)
/// and serves requests concurrently until a graceful [`Request::Shutdown`] is received
/// or `shutdown` is set (for example by a termination signal handler).
///
/// # Errors
///
/// Returns an error if `bind_addr` is not a valid loopback socket address or cannot be bound.
pub fn serve_tcp(
    bind_addr: &str,
    driver: &Arc<dyn Driver>,
    responses: Arc<ResponseStore>,
    options: ServerOptions,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let addr: SocketAddr = bind_addr.parse().map_err(|_| {
        WayboundError::Io(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid --tcp socket address: {bind_addr}"),
        ))
    })?;
    if !addr.ip().is_loopback() {
        return Err(WayboundError::Io(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!("refusing to bind --tcp to non-loopback address {addr}"),
        )));
    }

    let listener = TcpListener::bind(addr)?;
    let local_addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    tracing::info!(tcp = %local_addr, "listening on loopback tcp socket");

    let active_connections = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(SessionState::new(options, responses, shutdown));

    while !state.shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if let Err(err) = stream.set_nonblocking(false) {
                    tracing::warn!(error = %err, "failed to configure accepted tcp stream");
                    continue;
                }

                let current = active_connections.fetch_add(1, Ordering::AcqRel);
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    let _ = active_connections.fetch_sub(1, Ordering::AcqRel);
                    tracing::warn!("rejecting tcp connection: max concurrent connections reached");
                    continue;
                }

                let driver_ref = Arc::clone(driver);
                let state_ref = Arc::clone(&state);
                let conn_guard = ConnectionGuard {
                    counter: Arc::clone(&active_connections),
                };
                let _ = thread::spawn(move || {
                    let _guard = conn_guard;
                    if let Err(err) =
                        handle_tcp_connection(stream, driver_ref.as_ref(), state_ref.as_ref())
                    {
                        tracing::warn!(error = %err, "tcp client connection closed with error");
                    }
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::Interrupted
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                ) =>
            {
                tracing::debug!(error = %err, "transient tcp accept error, continuing");
            }
            Err(err) => return Err(WayboundError::Io(err)),
        }
    }

    drain_connections(&active_connections);
    Ok(())
}

fn drain_connections(active_connections: &AtomicUsize) {
    tracing::info!("shutdown requested; draining active connections");
    let drain_deadline = Instant::now() + Duration::from_millis(250);
    while active_connections.load(Ordering::Acquire) > 0 && Instant::now() < drain_deadline {
        thread::sleep(Duration::from_millis(10));
    }
}

fn write_response<W: Write>(stream: &mut W, response: &Response) -> Result<()> {
    let mut encoded = serde_json::to_string(response).unwrap_or_else(|_| {
        r#"{"status":"error","code":"serialization_error","message":"failed to encode response"}"#
            .to_owned()
    });
    encoded.push('\n');
    stream.write_all(encoded.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(unix)]
fn handle_unix_connection(
    stream: UnixStream,
    driver: &dyn Driver,
    state: &SessionState,
) -> Result<()> {
    // Reads wake up periodically so an idle connection stays open (clients hold one
    // long-lived connection) while still noticing shutdown promptly.
    stream.set_read_timeout(Some(IDLE_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let reader_stream = stream.try_clone()?;
    handle_io_streams(reader_stream, stream, driver, state)
}

fn handle_tcp_connection(
    stream: TcpStream,
    driver: &dyn Driver,
    state: &SessionState,
) -> Result<()> {
    // Reads wake up periodically so an idle connection stays open (clients hold one
    // long-lived connection) while still noticing shutdown promptly.
    stream.set_read_timeout(Some(IDLE_POLL_INTERVAL))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let _ = stream.set_nodelay(true);
    let reader_stream = stream.try_clone()?;
    handle_io_streams(reader_stream, stream, driver, state)
}

fn handle_io_streams<R: Read, W: Write>(
    reader_stream: R,
    mut writer_stream: W,
    driver: &dyn Driver,
    state: &SessionState,
) -> Result<()> {
    let mut reader = BufReader::new(reader_stream);
    let mut frame: Vec<u8> = Vec::new();
    let mut frame_started: Option<Instant> = None;

    loop {
        let budget = (MAX_FRAME_BYTES + 1).saturating_sub(frame.len() as u64);
        match (&mut reader).take(budget).read_until(b'\n', &mut frame) {
            Ok(0) if frame.is_empty() => break,
            Ok(_) => {}
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if state.shutdown.load(Ordering::Acquire) {
                    break;
                }
                // Idle between requests is fine; a request that stalls mid-frame is not.
                if frame.is_empty() {
                    frame_started = None;
                } else if frame_started.get_or_insert_with(Instant::now).elapsed() >= IO_TIMEOUT {
                    return Err(WayboundError::Io(err));
                }
                continue;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(WayboundError::Io(err)),
        }

        if (frame.len() as u64) > MAX_FRAME_BYTES {
            let err_resp = Response::Error {
                code: "frame_too_large".to_owned(),
                message: format!("request exceeded {MAX_FRAME_BYTES}-byte limit"),
            };
            let _ = write_response(&mut writer_stream, &err_resp);
            break;
        }
        let at_eof = frame.last() != Some(&b'\n');
        let line = String::from_utf8_lossy(&frame).into_owned();
        frame.clear();
        frame_started = None;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            if at_eof {
                break;
            }
            continue;
        }

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(request) => handle_request(driver, state, request),
            Err(err) => Response::Error {
                code: "invalid_request".to_owned(),
                message: err.to_string(),
            },
        };

        write_response(&mut writer_stream, &response)?;
        if at_eof || state.shutdown.load(Ordering::Acquire) {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use waybound_core::Role;

    use super::*;
    use crate::mock_driver::MockDriver;

    fn state() -> SessionState {
        SessionState::new(
            ServerOptions { use_motion: false },
            Arc::new(ResponseStore::default()),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn key_events(driver: &MockDriver) -> Vec<(KeyCode, Vec<KeyModifier>)> {
        driver
            .recorded_events()
            .into_iter()
            .filter_map(|event| match event {
                InputEvent::KeyPress {
                    key,
                    modifiers,
                    hold_ms: _,
                } => Some((key, modifiers)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn fill_selects_existing_content_before_typing() {
        let driver = MockDriver::sample_page();
        let query = LocatorQuery::by_role(Role::TextBox, Some("Origin".to_owned()));
        assert!(fill_element(&driver, &state(), &query, "NRT").is_ok());

        assert_eq!(
            key_events(&driver),
            vec![
                (KeyCode::Char('a'), vec![KeyModifier::Meta]),
                (KeyCode::Char('N'), Vec::new()),
                (KeyCode::Char('R'), Vec::new()),
                (KeyCode::Char('T'), Vec::new()),
            ]
        );
    }

    #[test]
    fn fill_with_empty_text_clears_the_field() {
        let driver = MockDriver::sample_page();
        let query = LocatorQuery::by_role(Role::TextBox, Some("Origin".to_owned()));
        assert!(fill_element(&driver, &state(), &query, "").is_ok());

        assert_eq!(
            key_events(&driver),
            vec![
                (KeyCode::Char('a'), vec![KeyModifier::Meta]),
                (KeyCode::Backspace, Vec::new()),
            ]
        );
    }
}
