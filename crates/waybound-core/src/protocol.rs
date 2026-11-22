//! Line-delimited JSON IPC protocol between client SDKs and `waybound-daemon`.

use serde::{Deserialize, Serialize};

use crate::error::WayboundError;
use crate::fingerprint::SessionFingerprint;
use crate::input::{KeyCode, KeyModifier};
use crate::locator::{AccessibilityNode, LocatorQuery};
use crate::network::CapturedResponse;

/// Wire-level request sent from a client SDK to `waybound-daemon`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    /// Health check returning the daemon version.
    Ping,
    /// Return a snapshot of the active accessibility tree.
    SnapshotTree,
    /// Return all accessibility nodes matching `query`.
    LocateAll {
        /// Semantic locator query (`nth` is ignored).
        query: LocatorQuery,
    },
    /// Return the current active tab URL, if available.
    CurrentUrl,
    /// Poll the accessibility tree until an element matching `query` appears or `timeout_ms` elapses.
    WaitFor {
        /// Semantic locator query.
        query: LocatorQuery,
        /// Maximum wait time in milliseconds.
        timeout_ms: u64,
    },
    /// Locate an element matching `query` and move the pointer over it without clicking.
    Hover {
        /// Semantic locator query.
        query: LocatorQuery,
    },
    /// Locate an element matching `query` and click its center.
    Click {
        /// Semantic locator query.
        query: LocatorQuery,
    },
    /// Locate an element matching `query` and double-click its center.
    DblClick {
        /// Semantic locator query.
        query: LocatorQuery,
    },
    /// Locate a `<select>` or combobox matching `query` and select an option by label or 0-based index.
    SelectOption {
        /// Semantic locator query targeting the combobox/select control.
        query: LocatorQuery,
        /// Optional visible option label to type/select.
        #[serde(default)]
        label: Option<String>,
        /// Optional 0-based option index (navigated via `Home` + `ArrowDown` * `index` + `Enter`).
        #[serde(default)]
        index: Option<usize>,
    },
    /// Locate an element matching `query`, focus it, and type `text`.
    Fill {
        /// Semantic locator query.
        query: LocatorQuery,
        /// Text to enter.
        text: String,
    },
    /// Navigate the active browser tab to `url` via OS keyboard shortcut (Cmd/Ctrl+L).
    Navigate {
        /// Destination URL (`http://` or `https://`).
        url: String,
    },
    /// Reload the active browser tab via native OS shortcut (Cmd/Ctrl+R).
    Reload,
    /// Navigate back in browser history via native OS shortcut (Cmd+[ / Alt+Left).
    GoBack,
    /// Navigate forward in browser history via native OS shortcut (Cmd+] / Alt+Right).
    GoForward,
    /// Open a new browser tab via native OS shortcut (Cmd/Ctrl+T), optionally navigating to `url`.
    NewTab {
        /// Optional destination URL to navigate to after opening the tab.
        #[serde(default)]
        url: Option<String>,
    },
    /// Close the active browser tab via native OS shortcut (Cmd/Ctrl+W).
    CloseTab,
    /// Switch to the next browser tab (Ctrl+Tab).
    NextTab,
    /// Switch to the previous browser tab (Ctrl+Shift+Tab).
    PrevTab,
    /// Emit a native scroll event.
    Scroll {
        /// Horizontal scroll delta in pixels.
        delta_x: f64,
        /// Vertical scroll delta in pixels.
        delta_y: f64,
    },
    /// Emit a single key press with optional modifiers.
    Press {
        /// Key to press.
        key: KeyCode,
        /// Optional modifier keys.
        #[serde(default)]
        modifiers: Vec<KeyModifier>,
    },
    /// Return passively captured HTTP responses (optionally filtered by URL substring).
    CapturedResponses {
        /// Optional case-insensitive URL substring filter.
        url_contains: Option<String>,
    },
    /// Wait until a passively captured HTTP response matches `url_contains` or `timeout_ms` elapses.
    WaitForResponse {
        /// Case-insensitive URL substring filter.
        url_contains: String,
        /// Maximum wait time in milliseconds.
        timeout_ms: u64,
    },
    /// Wait until zero HTTP/1.1–2 requests are inflight for at least `idle_ms` (or until `timeout_ms`).
    WaitForNetworkIdle {
        /// Continuous idle duration in milliseconds (e.g. 500).
        idle_ms: u64,
        /// Maximum wait time in milliseconds.
        timeout_ms: u64,
    },
    /// Export the live TLS, HTTP/2, header, and cookie fingerprint captured from the browser session.
    ExportSessionFingerprint,
    /// Capture a native OS PNG screenshot of the browser window to `path`.
    Screenshot {
        /// Destination PNG file path.
        path: String,
    },
    /// Request a graceful daemon shutdown (unwinds RAII browser & socket guards).
    Shutdown,
}

/// Wire-level response returned by `waybound-daemon`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Successful acknowledgement with no payload.
    Ok,
    /// Response to [`Request::Ping`].
    Pong {
        /// Daemon crate version string.
        version: String,
    },
    /// Response to [`Request::SnapshotTree`].
    Tree {
        /// Captured accessibility nodes.
        nodes: Vec<AccessibilityNode>,
    },
    /// Response to [`Request::WaitFor`].
    Node {
        /// First matched accessibility node.
        node: AccessibilityNode,
    },
    /// Response to [`Request::CurrentUrl`].
    Url {
        /// Current URL string, if known.
        url: Option<String>,
    },
    /// Response to [`Request::WaitForResponse`].
    HttpResponse {
        /// Matched captured HTTP response.
        response: CapturedResponse,
    },
    /// Response to [`Request::CapturedResponses`].
    HttpResponses {
        /// Captured HTTP responses matching the filter.
        responses: Vec<CapturedResponse>,
    },
    /// Response to [`Request::ExportSessionFingerprint`].
    SessionFingerprint {
        /// Captured live TLS, HTTP/2, header, and cookie snapshot.
        fingerprint: Box<SessionFingerprint>,
    },
    /// Structured error returned when a request fails.
    Error {
        /// Machine-readable error code.
        code: String,
        /// Human-readable error message.
        message: String,
    },
}

impl From<&WayboundError> for Response {
    fn from(err: &WayboundError) -> Self {
        let code = match err {
            WayboundError::ElementNotFound { .. } => "element_not_found",
            WayboundError::BackendUnavailable { .. } => "backend_unavailable",
            WayboundError::Timeout { .. } => "timeout",
            WayboundError::Io(_) => "io_error",
        };
        Self::Error {
            code: code.to_owned(),
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locator::Role;

    #[test]
    fn request_round_trips_as_json() {
        let req = Request::Click {
            query: LocatorQuery::by_role(Role::Button, Some("Search".to_owned())),
        };
        let encoded = serde_json::to_string(&req);
        assert!(encoded.is_ok());
        if let Ok(json) = encoded {
            let decoded: Result<Request, _> = serde_json::from_str(&json);
            assert!(decoded.is_ok());
            if let Ok(parsed) = decoded {
                assert_eq!(parsed, req);
            }
        }
    }
}
