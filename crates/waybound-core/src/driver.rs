//! Platform driver trait implemented by OS and container backends.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::input::InputEvent;
use crate::locator::{AccessibilityNode, LocatorQuery};

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

    /// Resolves the first accessibility node matching `query`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::WayboundError::ElementNotFound`] when no node matches.
    fn locate(&self, query: &LocatorQuery) -> Result<AccessibilityNode> {
        let nodes = self.snapshot_tree()?;
        nodes
            .into_iter()
            .find(|node| query.matches(node))
            .ok_or_else(|| crate::WayboundError::ElementNotFound {
                query: format!("{query:?}"),
            })
    }

    /// Dispatches a native OS input event to the active browser surface.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS input subsystem rejects the event.
    fn dispatch_input(&self, event: &InputEvent) -> Result<()>;
}
