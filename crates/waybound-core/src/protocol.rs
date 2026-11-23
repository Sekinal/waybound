//! Line-delimited JSON IPC protocol between client SDKs and `waybound-daemon`.

use serde::{Deserialize, Serialize};

use crate::error::WayboundError;
use crate::fingerprint::SessionFingerprint;
use crate::input::{KeyCode, KeyModifier};
use crate::locator::{AccessibilityNode, LocatorQuery};
use crate::network::{CapturedResponse, CapturedWebSocketFrame, NetworkStats};

/// Wire-level request sent from a client SDK to `waybound-daemon`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    /// Health check returning the daemon version.
    Ping,
    /// Return a snapshot of the active accessibility tree.
    SnapshotTree {
        /// Optional maximum number of nodes to return (defaults to 2,000, clamped to `1..=20_000`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_nodes: Option<usize>,
    },
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
    ///
    /// The wire name is `dbl_click`; `dblclick` is accepted as an alias because the
    /// Python SDK up to v0.4.0 sent that spelling.
    #[serde(alias = "dblclick")]
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
    /// Return passively captured WebSocket messages (optionally filtered by URL substring).
    CapturedWebsocketFrames {
        /// Optional case-insensitive URL substring filter.
        #[serde(default)]
        url_contains: Option<String>,
        /// Return only the most recent `limit` matching messages (all when absent).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
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
    /// Return per-session bandwidth and connection counters from the local proxy forwarder.
    NetworkStats,
    /// Capture a native OS PNG screenshot to `path` (the browser window on macOS, the whole
    /// display on Linux, the primary screen on Windows, the device screen on Android).
    Screenshot {
        /// Destination PNG file path.
        path: String,
    },
    /// Request a graceful daemon shutdown (unwinds RAII browser & socket guards).
    Shutdown,
    /// Press the primary button on the element matching `source`, drag it along a planned
    /// pointer path to the element matching `target`, and release it there.
    DragTo {
        /// Semantic locator query for the element to drag.
        source: LocatorQuery,
        /// Semantic locator query for the drop target.
        target: LocatorQuery,
        /// How long to wait for each of `source` and `target` to appear, in milliseconds
        /// (defaults to the daemon's standard action auto-wait).
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Idempotently drive a checkbox / radio / switch to `checked`.
    ///
    /// Auto-waits for the element like `click` (and, when a click is needed, for it to be
    /// enabled), refuses elements without a checked state and unchecking a radio button,
    /// clicks only when the current state differs, then re-reads the node and fails if the
    /// state did not change. A mixed checkbox counts as unchecked, so `checked: false` leaves
    /// it mixed without clicking. Answered with [`Response::Node`] carrying the node as
    /// re-read after the action.
    SetChecked {
        /// Semantic locator query.
        query: LocatorQuery,
        /// Desired checked state (`true` for `check()`, `false` for `uncheck()`).
        checked: bool,
    },
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
    /// Response to [`Request::SnapshotTree`] and [`Request::LocateAll`].
    Tree {
        /// Captured accessibility nodes.
        nodes: Vec<AccessibilityNode>,
        /// `true` when traversal stopped early because the node cap was reached.
        #[serde(default)]
        truncated: bool,
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
    /// Response to [`Request::CapturedWebsocketFrames`].
    WebsocketFrames {
        /// Captured WebSocket messages matching the filter, oldest first.
        frames: Vec<CapturedWebSocketFrame>,
    },
    /// Response to [`Request::NetworkStats`].
    NetworkStats {
        /// Per-session bandwidth and connection counters.
        stats: NetworkStats,
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
            WayboundError::Transient { .. } => "transient",
            WayboundError::UnsupportedInput { .. } => "unsupported_input",
            WayboundError::ElementDisabled { .. } => "element_disabled",
            WayboundError::InvalidElementState { .. } => "invalid_element_state",
            WayboundError::StrictModeViolation { .. } => "strict_mode_violation",
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

    #[test]
    fn websocket_frames_request_and_response_json() {
        let req: Result<Request, _> =
            serde_json::from_str(r#"{"method":"captured_websocket_frames"}"#);
        assert_eq!(
            req.ok(),
            Some(Request::CapturedWebsocketFrames {
                url_contains: None,
                limit: None
            })
        );
        let limited: Result<Request, _> = serde_json::from_str(
            r#"{"method":"captured_websocket_frames","url_contains":"chat","limit":2}"#,
        );
        assert_eq!(
            limited.ok(),
            Some(Request::CapturedWebsocketFrames {
                url_contains: Some("chat".to_owned()),
                limit: Some(2)
            })
        );
        let resp = Response::WebsocketFrames { frames: Vec::new() };
        assert_eq!(
            serde_json::to_string(&resp).unwrap_or_default(),
            r#"{"status":"websocket_frames","frames":[]}"#
        );
    }

    #[test]
    fn drag_to_request_round_trips_as_json() {
        let req = Request::DragTo {
            source: LocatorQuery::by_role(Role::Button, Some("Card".to_owned())),
            target: LocatorQuery::by_role(Role::TextBox, Some("Done".to_owned())),
            timeout_ms: Some(2_500),
        };
        let json = serde_json::to_value(&req).ok();
        assert_eq!(
            json.as_ref()
                .and_then(|v| v.get("method"))
                .and_then(serde_json::Value::as_str),
            Some("drag_to")
        );
        let decoded = json.and_then(|v| serde_json::from_value::<Request>(v).ok());
        assert_eq!(decoded, Some(req));

        // `timeout_ms` is optional on the wire.
        let minimal: Option<Request> = serde_json::from_str(
            r#"{"method":"drag_to","source":{"role":"button","name":"A","exact":false,"nth":0},"target":{"role":"button","name":"B","exact":false,"nth":0}}"#,
        )
        .ok();
        assert!(matches!(
            minimal,
            Some(Request::DragTo {
                timeout_ms: None,
                ..
            })
        ));
    }

    #[test]
    fn dbl_click_accepts_canonical_and_legacy_method_names() {
        let expected = Request::DblClick {
            query: LocatorQuery::by_role(Role::Button, Some("Search".to_owned())),
        };
        let encoded = serde_json::to_value(&expected).unwrap_or_default();
        assert_eq!(encoded["method"], "dbl_click");

        for method in ["dbl_click", "dblclick"] {
            let mut legacy = encoded.clone();
            legacy["method"] = serde_json::Value::String(method.to_owned());
            let decoded: Result<Request, _> = serde_json::from_value(legacy);
            assert_eq!(decoded.ok(), Some(expected.clone()), "method {method}");
        }
    }

    #[test]
    fn transient_and_unsupported_input_errors_have_distinct_codes() {
        let transient = WayboundError::Transient {
            backend: "android_waydroid".to_owned(),
            reason: "ERROR: could not get idle state.".to_owned(),
        };
        assert!(transient.is_transient());
        assert_eq!(
            Response::from(&transient),
            Response::Error {
                code: "transient".to_owned(),
                message:
                    "transient backend failure: android_waydroid (ERROR: could not get idle state.)"
                        .to_owned(),
            }
        );

        let unsupported = WayboundError::UnsupportedInput {
            backend: "android_waydroid".to_owned(),
            reason: "Control+a needs API 31".to_owned(),
        };
        assert!(!unsupported.is_transient());
        assert!(matches!(
            Response::from(&unsupported),
            Response::Error { code, .. } if code == "unsupported_input"
        ));
    }

    #[test]
    fn set_checked_request_uses_snake_case_method() {
        let raw = r#"{"method":"set_checked","query":{"role":"check_box","name":"Agree","exact":false},"checked":true}"#;
        let decoded: Result<Request, _> = serde_json::from_str(raw);
        assert!(matches!(
            decoded,
            Ok(Request::SetChecked { checked: true, .. })
        ));
    }

    #[test]
    fn state_errors_map_to_stable_codes() {
        let disabled = Response::from(&WayboundError::ElementDisabled {
            action: "check".to_owned(),
            query: "q".to_owned(),
        });
        assert!(matches!(disabled, Response::Error { ref code, .. } if code == "element_disabled"));
        let invalid = Response::from(&WayboundError::InvalidElementState {
            detail: "d".to_owned(),
        });
        assert!(
            matches!(invalid, Response::Error { ref code, .. } if code == "invalid_element_state")
        );
        let strict = Response::from(&WayboundError::StrictModeViolation {
            query: "q".to_owned(),
            count: 3,
        });
        assert!(
            matches!(strict, Response::Error { ref code, ref message } if code == "strict_mode_violation" && message.contains('3'))
        );
    }

    #[test]
    fn snapshot_tree_request_and_tree_response_are_backwards_compatible() {
        let legacy_req: Result<Request, _> = serde_json::from_str(r#"{"method":"snapshot_tree"}"#);
        assert_eq!(
            legacy_req.ok(),
            Some(Request::SnapshotTree { max_nodes: None })
        );

        let capped_req: Result<Request, _> =
            serde_json::from_str(r#"{"method":"snapshot_tree","max_nodes":25}"#);
        assert_eq!(
            capped_req.ok(),
            Some(Request::SnapshotTree {
                max_nodes: Some(25)
            })
        );

        assert_eq!(
            serde_json::to_string(&Request::SnapshotTree { max_nodes: None }).unwrap_or_default(),
            r#"{"method":"snapshot_tree"}"#
        );

        let legacy_resp: Result<Response, _> =
            serde_json::from_str(r#"{"status":"tree","nodes":[]}"#);
        assert_eq!(
            legacy_resp.ok(),
            Some(Response::Tree {
                nodes: Vec::new(),
                truncated: false,
            })
        );

        let truncated_resp = Response::Tree {
            nodes: Vec::new(),
            truncated: true,
        };
        assert_eq!(
            serde_json::to_string(&truncated_resp).unwrap_or_default(),
            r#"{"status":"tree","nodes":[],"truncated":true}"#
        );
    }

    #[test]
    fn network_stats_request_and_response_json() {
        let req = Request::NetworkStats;
        let encoded_req = serde_json::to_string(&req).unwrap_or_default();
        assert_eq!(encoded_req, r#"{"method":"network_stats"}"#);
        let decoded_req: Result<Request, _> = serde_json::from_str(&encoded_req);
        assert_eq!(decoded_req.ok(), Some(Request::NetworkStats));

        let stats = NetworkStats {
            bytes_sent: 1_024,
            bytes_received: 8_192,
            connections_total: 12,
            connections_blocked: 3,
        };
        let resp = Response::NetworkStats { stats };
        let encoded_resp = serde_json::to_string(&resp).unwrap_or_default();
        assert_eq!(
            encoded_resp,
            r#"{"status":"network_stats","stats":{"bytes_sent":1024,"bytes_received":8192,"connections_total":12,"connections_blocked":3}}"#
        );
        let decoded_resp: Result<Response, _> = serde_json::from_str(&encoded_resp);
        assert_eq!(decoded_resp.ok(), Some(resp));
    }
}
