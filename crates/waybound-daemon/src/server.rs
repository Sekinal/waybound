//! Line-delimited JSON-RPC server over a local Unix domain socket.

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use waybound_core::{
    Driver, InputEvent, KeyCode, LocatorQuery, MouseButton, Point, Request, Response, Result,
    WayboundError,
};

const MAX_UNIX_PATH_BYTES: usize = 100;
const MAX_FRAME_BYTES: u64 = 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// RAII guard that removes a bound Unix socket file on drop.
struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Dispatches a single protocol [`Request`] against `driver`.
#[must_use]
pub fn handle_request(driver: &dyn Driver, request: Request) -> Response {
    match request {
        Request::Ping => Response::Pong {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        Request::SnapshotTree => match driver.snapshot_tree() {
            Ok(nodes) => Response::Tree { nodes },
            Err(err) => Response::from(&err),
        },
        Request::Click { query } => match click_element(driver, &query) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
        Request::Fill { query, text } => match fill_element(driver, &query, &text) {
            Ok(()) => Response::Ok,
            Err(err) => Response::from(&err),
        },
    }
}

fn click_element(driver: &dyn Driver, query: &LocatorQuery) -> Result<()> {
    let node = driver.locate(query)?;
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

    let (x, y) = b.center();
    driver.dispatch_input(&InputEvent::PointerMove { to: Point { x, y } })?;
    driver.dispatch_input(&InputEvent::MouseClick {
        button: MouseButton::Left,
    })
}

fn fill_element(driver: &dyn Driver, query: &LocatorQuery, text: &str) -> Result<()> {
    click_element(driver, query)?;
    for ch in text.chars() {
        let key = match ch {
            '\n' | '\r' => KeyCode::Enter,
            '\t' => KeyCode::Tab,
            other => KeyCode::Char(other),
        };
        driver.dispatch_input(&InputEvent::KeyPress { key })?;
    }
    Ok(())
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

/// Binds a Unix domain socket at `socket_path` and serves requests concurrently.
///
/// # Errors
///
/// Returns an error if the socket path is invalid, already in use, or cannot be bound.
pub fn serve_unix(socket_path: &Path, driver: &Arc<dyn Driver>) -> Result<()> {
    prepare_socket_path(socket_path)?;

    let listener = UnixListener::bind(socket_path)?;
    let _guard = SocketGuard {
        path: socket_path.to_path_buf(),
    };
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    tracing::info!(socket = %socket_path.display(), "listening on unix socket");

    let active_connections = Arc::new(AtomicUsize::new(0));

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let current = active_connections.fetch_add(1, Ordering::AcqRel);
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    let _ = active_connections.fetch_sub(1, Ordering::AcqRel);
                    tracing::warn!("rejecting connection: max concurrent connections reached");
                    continue;
                }

                let driver_ref = Arc::clone(driver);
                let counter_ref = Arc::clone(&active_connections);
                let _ = thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, driver_ref.as_ref()) {
                        tracing::warn!(error = %err, "client connection closed with error");
                    }
                    let _ = counter_ref.fetch_sub(1, Ordering::AcqRel);
                });
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

fn handle_connection(mut stream: UnixStream, driver: &dyn Driver) -> Result<()> {
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
            Ok(request) => handle_request(driver, request),
            Err(err) => Response::Error {
                code: "invalid_request".to_owned(),
                message: err.to_string(),
            },
        };

        write_response(&mut stream, &response)?;
    }

    Ok(())
}
