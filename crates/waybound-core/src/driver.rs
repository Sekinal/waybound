//! Platform driver trait implemented by OS and container backends.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::input::{InputEvent, MouseButton, Point};
use crate::locator::{AccessibilityNode, Bounds, LocatorQuery};

/// Supported execution backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Native macOS Chrome driven via `AXUIElement` + Quartz events.
    MacOsNative,
    /// Native Windows Chrome driven via `UIAutomation` + native HID.
    WindowsNative,
    /// Linux Chrome driven via a headless Wayland compositor + AT-SPI2.
    LinuxWayland,
    /// Headless containerized Android (Waydroid) on Linux.
    AndroidWaydroid,
}

/// Configuration for launching a browser automation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Target platform backend.
    pub backend: BackendKind,
    /// Optional profile directory path for persistent browser state.
    pub profile_dir: Option<String>,
    /// Optional path where the browser writes TLS session keys for passive capture.
    pub ssl_keylog_file: Option<String>,
    /// Logical viewport width in pixels.
    pub viewport_width: u32,
    /// Logical viewport height in pixels.
    pub viewport_height: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            backend: BackendKind::MacOsNative,
            profile_dir: None,
            ssl_keylog_file: None,
            viewport_width: 1280,
            viewport_height: 800,
        }
    }
}

/// Default maximum number of accessibility nodes returned by [`Driver::snapshot_tree_limited`].
pub const DEFAULT_MAX_NODES: usize = 2_000;
/// Minimum allowed value for `max_nodes` in [`Driver::snapshot_tree_limited`].
pub const MIN_MAX_NODES: usize = 1;
/// Maximum allowed value for `max_nodes` in [`Driver::snapshot_tree_limited`].
pub const MAX_MAX_NODES: usize = 20_000;

/// Resolves an optional `max_nodes` parameter to a safe limit within `1..=20_000`
/// (defaulting to [`DEFAULT_MAX_NODES`]).
#[must_use]
pub fn clamp_max_nodes(max_nodes: Option<usize>) -> usize {
    max_nodes.map_or(DEFAULT_MAX_NODES, |n| n.clamp(MIN_MAX_NODES, MAX_MAX_NODES))
}

/// Result of capturing an accessibility tree snapshot, including truncation metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreeSnapshot {
    /// Captured accessibility nodes.
    pub nodes: Vec<AccessibilityNode>,
    /// `true` when traversal stopped early because the node cap was reached.
    #[serde(default)]
    pub truncated: bool,
}

/// Core platform abstraction for out-of-band browser control.
///
/// Implementations live in dedicated backend crates so any platform-specific
/// FFI (`unsafe`) stays strictly isolated outside `waybound-core`.
pub trait Driver: Send + Sync {
    /// Returns the backend kind implemented by this driver.
    fn backend_kind(&self) -> BackendKind;

    /// Captures a snapshot of the current accessibility tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS accessibility bus cannot be queried.
    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>>;

    /// Captures a snapshot of the current accessibility tree capped at `max_nodes`
    /// (clamped to `1..=20_000`), reporting whether traversal was truncated.
    ///
    /// Backends that enforce a traversal cap should override this method to apply
    /// `max_nodes` directly during traversal and report `truncated` accurately.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS accessibility bus cannot be queried.
    fn snapshot_tree_limited(&self, max_nodes: usize) -> Result<TreeSnapshot> {
        let limit = max_nodes.clamp(MIN_MAX_NODES, MAX_MAX_NODES);
        let mut nodes = self.snapshot_tree()?;
        let truncated = nodes.len() > limit;
        if truncated {
            nodes.truncate(limit);
        }
        Ok(TreeSnapshot { nodes, truncated })
    }

    /// Resolves all accessibility nodes matching `query` (ignoring `query.nth`).
    ///
    /// # Errors
    ///
    /// Returns an error if the OS accessibility bus cannot be queried.
    fn locate_all(&self, query: &LocatorQuery) -> Result<Vec<AccessibilityNode>> {
        let nodes = self.snapshot_tree()?;
        Ok(query.resolve_all(&nodes).into_iter().cloned().collect())
    }

    /// Resolves the `query.nth`-th accessibility node matching `query`, enforcing
    /// `query.strict` when set.
    ///
    /// # Errors
    ///
    /// Returns [`crate::WayboundError::StrictModeViolation`] when `query.strict` is `true`
    /// and more than one node matches, or [`crate::WayboundError::ElementNotFound`] when
    /// fewer than `query.nth + 1` nodes match.
    fn locate(&self, query: &LocatorQuery) -> Result<AccessibilityNode> {
        let nodes = self.snapshot_tree()?;
        query.resolve_checked(&nodes).cloned()
    }

    /// Like [`Driver::locate`], called from a wait loop that has `remaining` time left.
    ///
    /// Backends that retry internally (Android retries transient UI dumps) cap that retry
    /// at `remaining`, so nested retries cannot outlast the caller's deadline by more than
    /// the backend call in flight. The default ignores `remaining`.
    ///
    /// # Errors
    ///
    /// Same as [`Driver::locate`].
    fn locate_within(
        &self,
        query: &LocatorQuery,
        remaining: std::time::Duration,
    ) -> Result<AccessibilityNode> {
        let _ = remaining;
        self.locate(query)
    }

    /// Returns `true` when the node id `id` identifies the same UI element across snapshots
    /// (for example a UIA runtime id), rather than being a positional index.
    fn is_stable_node_id(&self, id: &str) -> bool {
        let _ = id;
        false
    }

    /// Returns the URL currently loaded in the active browser tab, if available.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS accessibility bus cannot be queried.
    fn current_url(&self) -> Result<Option<String>> {
        Ok(None)
    }

    /// Navigates the active browser tab directly via a backend-native mechanism
    /// (for example Android `am start` intents).
    ///
    /// Returns `Ok(true)` if the backend handled navigation directly, or `Ok(false)`
    /// to let the daemon fall back to OS keyboard shortcut navigation (`Cmd/Ctrl+L`).
    ///
    /// # Errors
    ///
    /// Returns an error if native navigation fails.
    fn navigate(&self, _url: &str) -> Result<bool> {
        Ok(false)
    }

    /// Returns the current on-screen pointer position, if the backend can read it.
    ///
    /// Used by `waybound-daemon` as the start of planned pointer paths, so a move begins
    /// where the cursor really is rather than at the last position the daemon sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS input subsystem cannot be queried.
    fn cursor_position(&self) -> Result<Option<Point>> {
        Ok(None)
    }

    /// Returns the visible screen-space bounds of the active web viewport, if known.
    ///
    /// Used by `waybound-daemon` to auto-scroll off-screen elements into view before clicking.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS accessibility bus cannot be queried.
    fn viewport_bounds(&self) -> Result<Option<Bounds>> {
        Ok(None)
    }

    /// Captures a native OS screenshot of the active browser window as PNG to `output_path`.
    ///
    /// # Errors
    ///
    /// Returns an error if screen capture is unsupported or fails.
    fn screenshot(&self, output_path: &Path) -> Result<()> {
        let _ = output_path;
        Err(crate::WayboundError::BackendUnavailable {
            backend: format!("{:?}", self.backend_kind()),
            reason: "native screenshot not implemented for this backend".to_owned(),
        })
    }

    /// Dispatches a native OS input event to the active browser surface.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS input subsystem rejects the event.
    fn dispatch_input(&self, event: &InputEvent) -> Result<()>;

    /// Abandons a press started with [`InputEvent::MouseDown`] without completing it, for
    /// example when a drag is aborted by an error or a daemon shutdown.
    ///
    /// The default sends an ordinary [`InputEvent::MouseUp`]. Backends that replay the
    /// whole gesture on release (Android's single `adb` drag command) override this to drop
    /// the buffered gesture instead, so an abort never performs an unrequested drop.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS input subsystem rejects the release.
    fn cancel_pointer_gesture(&self, button: MouseButton) -> Result<()> {
        self.dispatch_input(&InputEvent::MouseUp { button })
    }
}
