//! Lightweight stdio JSON-RPC replay worker (`waybound-daemon --replay`).
//!
//! Runs with zero browser, zero display server, and zero accessibility drivers (~5 MB RAM),
//! replaying a captured [`waybound_core::SessionFingerprint`] over `BoringSSL` + HTTP/2.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use waybound_core::{CapturedCookie, SessionFingerprint};
use waybound_http::{HandoffClient, HandoffOptions, HandoffResponse};

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum ReplayRequest {
    Init {
        fingerprint: Box<SessionFingerprint>,
        #[serde(default)]
        options: HandoffOptions,
    },
    Request {
        http_method: String,
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
        #[serde(default)]
        body: Option<String>,
    },
    Cookies,
    Shutdown,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ReplayResponse {
    Ok,
    Response { response: HandoffResponse },
    Cookies { cookies: Vec<CapturedCookie> },
    Error { code: String, message: String },
}

fn write_reply(out: &mut impl Write, reply: &ReplayResponse) -> io::Result<()> {
    let encoded =
        serde_json::to_string(reply).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    out.write_all(encoded.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Runs the line-delimited JSON-RPC replay loop over stdin/stdout until `shutdown` or EOF.
pub fn run_replay_stdio() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(error = %err, "failed to create tokio runtime for replay worker");
            return ExitCode::FAILURE;
        }
    };

    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut client: Option<HandoffClient> = None;

    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req = match serde_json::from_str::<ReplayRequest>(trimmed) {
            Ok(r) => r,
            Err(err) => {
                if write_reply(
                    &mut stdout,
                    &ReplayResponse::Error {
                        code: "invalid_request".to_owned(),
                        message: err.to_string(),
                    },
                )
                .is_err()
                {
                    break;
                }
                continue;
            }
        };

        let (reply, should_exit) = match req {
            ReplayRequest::Init {
                fingerprint,
                options,
            } => match HandoffClient::new(*fingerprint, &options) {
                Ok(c) => {
                    client = Some(c);
                    (ReplayResponse::Ok, false)
                }
                Err(err) => (
                    ReplayResponse::Error {
                        code: "init_failed".to_owned(),
                        message: err.to_string(),
                    },
                    false,
                ),
            },
            ReplayRequest::Request {
                http_method,
                url,
                headers,
                body,
            } => {
                let Some(ref c) = client else {
                    if write_reply(
                        &mut stdout,
                        &ReplayResponse::Error {
                            code: "not_initialized".to_owned(),
                            message: "call init with a SessionFingerprint before sending requests"
                                .to_owned(),
                        },
                    )
                    .is_err()
                    {
                        break;
                    }
                    continue;
                };
                match rt.block_on(c.request(&http_method, &url, &headers, body)) {
                    Ok(response) => (ReplayResponse::Response { response }, false),
                    Err(err) => (
                        ReplayResponse::Error {
                            code: "request_failed".to_owned(),
                            message: err.to_string(),
                        },
                        false,
                    ),
                }
            }
            ReplayRequest::Cookies => {
                let cookies = client
                    .as_ref()
                    .map_or_else(Vec::new, HandoffClient::cookies);
                (ReplayResponse::Cookies { cookies }, false)
            }
            ReplayRequest::Shutdown => (ReplayResponse::Ok, true),
        };

        if write_reply(&mut stdout, &reply).is_err() || should_exit {
            break;
        }
    }

    ExitCode::SUCCESS
}
