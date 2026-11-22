//! Line-delimited JSON IPC protocol between client SDKs and `waybound-daemon`.

use serde::{Deserialize, Serialize};

use crate::error::WayboundError;
use crate::locator::{AccessibilityNode, LocatorQuery};

/// Wire-level request sent from a client SDK to `waybound-daemon`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    /// Health check returning the daemon version.
    Ping,
    /// Return a snapshot of the active accessibility tree.
    SnapshotTree,
    /// Locate an element matching `query` and click its center.
    Click {
        /// Semantic locator query.
        query: LocatorQuery,
    },
    /// Locate an element matching `query`, focus it, and type `text`.
    Fill {
        /// Semantic locator query.
        query: LocatorQuery,
        /// Text to enter.
        text: String,
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
    /// Response to [`Request::SnapshotTree`].
    Tree {
        /// Captured accessibility nodes.
        nodes: Vec<AccessibilityNode>,
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
