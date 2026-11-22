//! Line-delimited JSON-RPC server over a local Unix domain socket.

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use waybound_core::{
    BackendKind, Driver, InputEvent, KeyCode, KeyModifier, LocatorQuery, MotionConfig, MouseButton,
    Point, Request, Response, Result, SplitMix64, WayboundError, hover_pause_before_click,
    key_delay, mouse_hold_ms, pick_click_point, plan_human_pointer_path, plan_scroll_burst,
};

use crate::net_tap::ResponseStore;

const MAX_UNIX_PATH_BYTES: usize = 100;
const MAX_FRAME_BYTES: u64 = 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(75);
const MAX_WAIT_TIMEOUT_MS: u64 = 120_000;

/// RAII guard that removes a bound Unix socket file on drop.
struct SocketGuard {
    path: PathBuf,
}

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
    last_cursor: Mutex<Point>,
    shutdown: AtomicBool,
    responses: Arc<ResponseStore>,
    options: ServerOptions,
}

impl SessionState {
    const fn new(options: ServerOptions, responses: Arc<ResponseStore>) -> Self {
        Self {
            last_cursor: Mutex::new(Point { x: 0.0, y: 0.0 }),
            shutdown: AtomicBool::new(false),
            responses,
            options,
        }
    }
}

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
            match driver.dispatch_input(&InputEvent::KeyPress { key, modifiers }) {
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
    let start = state
        .last_cursor
        .lock()
        .map_or(Point { x: 0.0, y: 0.0 }, |g| *g);

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
        *guard = target;
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

fn click_element(driver: &dyn Driver, state: &SessionState, query: &LocatorQuery) -> Result<()> {
    let mut node = driver.locate(query)?;

    // Auto-scroll off-screen elements into the visible viewport when viewport bounds are known.
    if let Ok(Some(vp)) = driver.viewport_bounds()
        && vp.height > 40.0
    {
        for _ in 0..MAX_SCROLL_INTO_VIEW_ATTEMPTS {
            let (_, cy) = node.bounds.center();
            let top = vp.y + 12.0;
            let bottom = vp.y + vp.height - 12.0;
            if cy >= top && cy <= bottom {
                break;
            }
            let step = (vp.height * 0.6).clamp(180.0, 520.0);
            let delta_y = if cy > bottom { -step } else { step };
            scroll_viewport(driver, state, 0.0, delta_y)?;
            thread::sleep(Duration::from_millis(120));
            node = driver.locate(query)?;
        }
    }

    let b = node.bounds;
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

    let mut rng = SplitMix64::from_entropy();
    let target = if state.options.use_motion {
        pick_click_point(b, &mut rng)
    } else {
        let (x, y) = b.center();
        Point { x, y }
    };

    move_pointer(driver, state, target, &mut rng)?;
    let hold_ms = if state.options.use_motion {
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

fn fill_element(
    driver: &dyn Driver,
    state: &SessionState,
    query: &LocatorQuery,
    text: &str,
) -> Result<()> {
    click_element(driver, state, query)?;
    type_text(driver, text, state.options.use_motion)
}

fn type_text(driver: &dyn Driver, text: &str, pace: bool) -> Result<()> {
    let mut rng = SplitMix64::from_entropy();
    for ch in text.chars() {
        let key = match ch {
            '\n' | '\r' => KeyCode::Enter,
            '\t' => KeyCode::Tab,
            other => KeyCode::Char(other),
        };
        driver.dispatch_input(&InputEvent::KeyPress {
            key,
            modifiers: Vec::new(),
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
    })?;
    thread::sleep(Duration::from_millis(60));
    type_text(driver, url, false)?;
    driver.dispatch_input(&InputEvent::KeyPress {
        key: KeyCode::Enter,
        modifiers: Vec::new(),
    })
}

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
/// until a graceful [`Request::Shutdown`] is received.
///
/// # Errors
///
/// Returns an error if the socket path is invalid, already in use, or cannot be bound.
pub fn serve_unix(
    socket_path: &Path,
    driver: &Arc<dyn Driver>,
    responses: Arc<ResponseStore>,
    options: ServerOptions,
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
    let state = Arc::new(SessionState::new(options, responses));

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
                        handle_connection(stream, driver_ref.as_ref(), state_ref.as_ref())
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

    tracing::info!("shutdown requested; draining active connections");
    let drain_deadline = Instant::now() + Duration::from_millis(250);
    while active_connections.load(Ordering::Acquire) > 0 && Instant::now() < drain_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let mut encoded = serde_json::to_string(response).unwrap_or_else(|_| {
        r#"{"status":"error","code":"serialization_error","message":"failed to encode response"}"#
            .to_owned()
    });
    encoded.push('\n');
    stream.write_all(encoded.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn handle_connection(
    mut stream: UnixStream,
    driver: &dyn Driver,
    state: &SessionState,
) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = (&mut reader)
            .take(MAX_FRAME_BYTES + 1)
            .read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        if (bytes_read as u64) > MAX_FRAME_BYTES {
            let err_resp = Response::Error {
                code: "frame_too_large".to_owned(),
                message: format!("request exceeded {MAX_FRAME_BYTES}-byte limit"),
            };
            let _ = write_response(&mut stream, &err_resp);
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(request) => handle_request(driver, state, request),
            Err(err) => Response::Error {
                code: "invalid_request".to_owned(),
                message: err.to_string(),
            },
        };

        write_response(&mut stream, &response)?;
        if state.shutdown.load(Ordering::Acquire) {
            break;
        }
    }

    Ok(())
}
