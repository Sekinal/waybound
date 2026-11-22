//! Line-delimited JSON-RPC server over a local Unix domain socket.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use waybound_core::{
    Driver, InputEvent, KeyCode, MouseButton, Point, Request, Response, Result, WayboundError,
};

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

fn click_element(driver: &dyn Driver, query: &waybound_core::LocatorQuery) -> Result<()> {
    let node = driver.locate(query)?;
    let (x, y) = node.bounds.center();
    driver.dispatch_input(&InputEvent::PointerMove { to: Point { x, y } })?;
    driver.dispatch_input(&InputEvent::MouseClick {
        button: MouseButton::Left,
    })
}

fn fill_element(
    driver: &dyn Driver,
    query: &waybound_core::LocatorQuery,
    text: &str,
) -> Result<()> {
    click_element(driver, query)?;
    for ch in text.chars() {
        driver.dispatch_input(&InputEvent::KeyPress {
            key: KeyCode::Char(ch),
        })?;
    }
    Ok(())
}

/// Binds a Unix domain socket at `socket_path` and serves requests until interrupted.
///
/// # Errors
///
/// Returns an error if the socket cannot be bound or fails to accept connections.
pub fn serve_unix(socket_path: &Path, driver: &dyn Driver) -> Result<()> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(socket = %socket_path.display(), "listening on unix socket");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Err(err) = handle_connection(stream, driver) {
                    tracing::warn!(error = %err, "client connection closed with error");
                }
            }
            Err(err) => return Err(WayboundError::Io(err)),
        }
    }

    Ok(())
}

fn handle_connection(mut stream: UnixStream, driver: &dyn Driver) -> Result<()> {
    let reader_stream = stream.try_clone()?;
    let reader = BufReader::new(reader_stream);

    for line_result in reader.lines() {
        let line = line_result?;
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

        let mut encoded = serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"status":"error","code":"serialization_error","message":"failed to encode response"}"#
                .to_owned()
        });
        encoded.push('\n');
        stream.write_all(encoded.as_bytes())?;
        stream.flush()?;
    }

    Ok(())
}
