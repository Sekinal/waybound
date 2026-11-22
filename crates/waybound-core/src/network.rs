//! Passive wire-level HTTP response types captured via `SSLKEYLOGFILE`.

use serde::{Deserialize, Serialize};

/// An HTTP/1.1, HTTP/2, or HTTP/3 response passively decrypted from the wire
/// without MITM certificates or CDP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedResponse {
    /// Request URL (`https://authority/path`).
    pub url: String,
    /// HTTP status code (e.g., `200`, `403`, `429`).
    pub status: u16,
    /// Value of the `content-type` response header, if present.
    pub content_type: Option<String>,
    /// UTF-8 decoded response body, if captured and valid UTF-8.
    pub body: Option<String>,
}
