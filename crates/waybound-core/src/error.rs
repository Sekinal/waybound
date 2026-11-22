//! Error types for `waybound-core`.

use thiserror::Error;

/// Convenience result alias for `waybound-core`.
pub type Result<T> = std::result::Result<T, WayboundError>;

/// Top-level error enum returned by drivers and session operations.
#[derive(Debug, Error)]
pub enum WayboundError {
    /// No accessibility node matched the requested semantic locator.
    #[error("element not found for query: {query}")]
    ElementNotFound {
        /// Human-readable representation of the locator query.
        query: String,
    },

    /// The requested platform backend is not available on this host.
    #[error("backend unavailable: {backend} ({reason})")]
    BackendUnavailable {
        /// Backend identifier.
        backend: String,
        /// Explanation for why it cannot be initialized.
        reason: String,
    },

    /// An operation timed out waiting for a condition.
    #[error("operation timed out after {timeout_ms}ms: {context}")]
    Timeout {
        /// Timeout duration in milliseconds.
        timeout_ms: u64,
        /// Description of the awaited condition.
        context: String,
    },

    /// Underlying I/O or IPC failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
