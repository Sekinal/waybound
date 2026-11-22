//! Passive wire-level HTTP response and WebSocket types captured via `SSLKEYLOGFILE`.

use serde::{Deserialize, Serialize};

/// A single HTTP header field as seen on the wire.
///
/// Headers are kept as an ordered list rather than a map so repeated fields
/// (for example several `set-cookie` lines) survive intact. HTTP/2 pseudo-headers
/// (`:method`, `:path`, `:status`, ...) are not included; they are exposed through
/// dedicated fields instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeader {
    /// Header name. HTTP/2 names are lowercase on the wire; HTTP/1.1 names keep their
    /// original casing.
    pub name: String,
    /// Header value (lossy UTF-8).
    pub value: String,
}

impl HttpHeader {
    /// Creates a header from a name/value pair.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// An HTTP/1.1, HTTP/2, or HTTP/3 response passively decrypted from the wire
/// without MITM certificates or CDP.
///
/// The `headers` and `request_*` fields were added after the initial schema; they are
/// optional, default to empty, and are omitted from JSON when empty so older clients
/// and previously stored JSON keep working.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedResponse {
    /// Request URL (`https://authority/path`).
    pub url: String,
    /// HTTP status code (e.g., `200`, `403`, `429`).
    pub status: u16,
    /// Value of the `content-type` response header, if present.
    pub content_type: Option<String>,
    /// UTF-8 decoded response body, if captured and valid UTF-8.
    pub body: Option<String>,
    /// Response headers in wire order (repeated names preserved).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HttpHeader>,
    /// Request method (`GET`, `POST`, ...), if the request was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    /// Request headers in wire order (repeated names preserved).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_headers: Vec<HttpHeader>,
    /// UTF-8 decoded request body (for example a POST/PUT payload), if present.
    ///
    /// Follows the same convention as [`Self::body`]: bytes are decompressed according
    /// to `content-encoding`, and only the longest valid UTF-8 prefix is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
}

/// Direction of a captured WebSocket message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketDirection {
    /// Client (browser) to server.
    Sent,
    /// Server to client (browser).
    Received,
}

/// Opcode of a captured WebSocket message (RFC 6455 section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketOpcode {
    /// UTF-8 text message.
    Text,
    /// Binary message.
    Binary,
    /// Connection close control frame.
    Close,
    /// Ping control frame.
    Ping,
    /// Pong control frame.
    Pong,
}

/// A WebSocket message passively decrypted from an HTTP/1.1 `101 Switching Protocols`
/// upgraded connection.
///
/// Data messages split across continuation frames are reassembled into one item;
/// each control frame (`close`, `ping`, `pong`) is its own item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedWebSocketFrame {
    /// WebSocket URL (`wss://authority/path`) of the upgrade request.
    pub url: String,
    /// Whether the browser sent or received this message.
    pub direction: WebSocketDirection,
    /// Message opcode.
    pub opcode: WebSocketOpcode,
    /// Payload decoded as UTF-8 (longest valid prefix, as for HTTP bodies).
    ///
    /// For `close` frames this is the close reason. `None` when the payload is empty,
    /// not valid UTF-8, or compressed data that could not be inflated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Full payload length in bytes after unmasking and `permessage-deflate`
    /// decompression (counted even beyond the retained cap); `0` when compressed data
    /// could not be inflated.
    #[serde(default)]
    pub payload_len: u64,
    /// `true` when the message was sent with `permessage-deflate` compression (RSV1).
    #[serde(default, skip_serializing_if = "is_false")]
    pub compressed: bool,
    /// `true` when `payload` was cut at the per-message capture cap.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// Status code carried by a `close` frame, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_code: Option<u16>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_response_json_without_new_fields_deserializes() {
        let json = r#"{"url":"https://a.test/x","status":200,"content_type":null,"body":"hi"}"#;
        let parsed: Result<CapturedResponse, _> = serde_json::from_str(json);
        assert!(parsed.is_ok());
        if let Ok(resp) = parsed {
            assert_eq!(resp.url, "https://a.test/x");
            assert_eq!(resp.body.as_deref(), Some("hi"));
            assert!(resp.headers.is_empty());
            assert!(resp.request_method.is_none());
            assert!(resp.request_headers.is_empty());
            assert!(resp.request_body.is_none());
        }
    }

    #[test]
    fn empty_new_fields_are_omitted_from_json() {
        let resp = CapturedResponse {
            url: "https://a.test/".to_owned(),
            status: 204,
            ..CapturedResponse::default()
        };
        let json = serde_json::to_string(&resp).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"url":"https://a.test/","status":204,"content_type":null,"body":null}"#
        );
    }

    #[test]
    fn headers_and_request_fields_round_trip() {
        let resp = CapturedResponse {
            url: "https://a.test/login".to_owned(),
            status: 200,
            headers: vec![
                HttpHeader::new("set-cookie", "a=1"),
                HttpHeader::new("set-cookie", "b=2"),
            ],
            request_method: Some("POST".to_owned()),
            request_headers: vec![HttpHeader::new("content-type", "application/json")],
            request_body: Some("{}".to_owned()),
            ..CapturedResponse::default()
        };
        let json = serde_json::to_string(&resp).unwrap_or_default();
        assert!(json.contains(r#""headers":[{"name":"set-cookie","value":"a=1"},"#));
        let back: Result<CapturedResponse, _> = serde_json::from_str(&json);
        assert_eq!(back.ok(), Some(resp));
    }

    #[test]
    fn websocket_frame_json_shape() {
        let frame = CapturedWebSocketFrame {
            url: "wss://a.test/ws".to_owned(),
            direction: WebSocketDirection::Sent,
            opcode: WebSocketOpcode::Text,
            payload: Some("hi".to_owned()),
            payload_len: 2,
            compressed: false,
            truncated: false,
            close_code: None,
        };
        let json = serde_json::to_string(&frame).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"url":"wss://a.test/ws","direction":"sent","opcode":"text","payload":"hi","payload_len":2}"#
        );
        let back: Result<CapturedWebSocketFrame, _> = serde_json::from_str(&json);
        assert_eq!(back.ok(), Some(frame));
    }
}
