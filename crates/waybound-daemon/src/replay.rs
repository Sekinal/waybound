//! Lightweight stdio JSON-RPC replay worker (`waybound-daemon --replay`).
//!
//! Runs with zero browser, zero display server, and zero accessibility drivers (~5 MB RAM),
//! replaying a captured [`waybound_core::SessionFingerprint`] over `BoringSSL` + HTTP/2.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use waybound_core::{CapturedCookie, SessionFingerprint};
use waybound_http::{HandoffClient, HandoffOptions, HandoffResponse, MAX_REQUEST_BYTES};

/// Maximum encoded Base64 length corresponding to [`MAX_REQUEST_BYTES`].
const MAX_REQUEST_BASE64_BYTES: usize = MAX_REQUEST_BYTES.div_ceil(3) * 4;

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
        #[serde(default)]
        body_base64: Option<String>,
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

fn decode_request_body(
    body: Option<String>,
    body_base64: Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    match (body, body_base64) {
        (Some(_), Some(_)) => Err("specify at most one of 'body' or 'body_base64'".to_owned()),
        (None, Some(b64)) => {
            if b64.len() > MAX_REQUEST_BASE64_BYTES {
                return Err(format!(
                    "request body_base64 exceeded {MAX_REQUEST_BYTES}-byte decoded limit"
                ));
            }
            let decoded = waybound_http::base64::decode(&b64)
                .map_err(|err| format!("invalid body_base64: {err}"))?;
            if decoded.len() > MAX_REQUEST_BYTES {
                return Err(format!(
                    "request body exceeded {MAX_REQUEST_BYTES}-byte limit"
                ));
            }
            Ok(Some(decoded))
        }
        (Some(text), None) => {
            let bytes = text.into_bytes();
            if bytes.len() > MAX_REQUEST_BYTES {
                return Err(format!(
                    "request body exceeded {MAX_REQUEST_BYTES}-byte limit"
                ));
            }
            Ok(Some(bytes))
        }
        (None, None) => Ok(None),
    }
}

fn write_reply(out: &mut impl Write, reply: &ReplayResponse) -> io::Result<()> {
    let encoded =
        serde_json::to_string(reply).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    out.write_all(encoded.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

fn handle_replay_request(
    rt: &tokio::runtime::Runtime,
    client: &mut Option<HandoffClient>,
    req: ReplayRequest,
) -> (ReplayResponse, bool) {
    match req {
        ReplayRequest::Init {
            fingerprint,
            options,
        } => match HandoffClient::new(*fingerprint, &options) {
            Ok(c) => {
                *client = Some(c);
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
            body_base64,
        } => {
            let Some(ref c) = *client else {
                return (
                    ReplayResponse::Error {
                        code: "not_initialized".to_owned(),
                        message: "call init with a SessionFingerprint before sending requests"
                            .to_owned(),
                    },
                    false,
                );
            };
            match decode_request_body(body, body_base64) {
                Ok(body_bytes) => {
                    match rt.block_on(c.request(&http_method, &url, &headers, body_bytes)) {
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
                Err(message) => (
                    ReplayResponse::Error {
                        code: "invalid_request".to_owned(),
                        message,
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
    }
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

        let (reply, should_exit) = match serde_json::from_str::<ReplayRequest>(trimmed) {
            Ok(req) => handle_replay_request(&rt, &mut client, req),
            Err(err) => (
                ReplayResponse::Error {
                    code: "invalid_request".to_owned(),
                    message: err.to_string(),
                },
                false,
            ),
        };

        if write_reply(&mut stdout, &reply).is_err() || should_exit {
            break;
        }
    }

    ExitCode::SUCCESS
}
