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

    /// A backend call failed for a reason expected to clear on its own, such as an
    /// Android `uiautomator dump` taken while the screen is still animating.
    ///
    /// Wait loops treat this as "not ready yet" and keep polling until their deadline.
    #[error("transient backend failure: {backend} ({reason})")]
    Transient {
        /// Backend identifier.
        backend: String,
        /// Explanation of the failure, including the backend's own message.
        reason: String,
    },

    /// The backend cannot express the requested input (for example a modifier chord
    /// on an Android version without `input keycombination`).
    #[error("unsupported input for {backend}: {reason}")]
    UnsupportedInput {
        /// Backend identifier.
        backend: String,
        /// Which part of the input cannot be delivered, and why.
        reason: String,
    },
}

impl WayboundError {
    /// Returns `true` for failures that a retry may heal ([`WayboundError::Transient`]).
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }
}
