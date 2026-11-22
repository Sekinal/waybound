//! Native macOS backend driver implementing [`waybound_core::Driver`] via
//! `AXUIElement` (`ApplicationServices`) and `CGEvent` (`CoreGraphics`).

#[cfg(target_os = "macos")]
mod ax;
#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
mod input;
#[cfg(target_os = "macos")]
mod screenshot;

use std::path::Path;
use std::sync::Mutex;

use waybound_core::{AccessibilityNode, BackendKind, Driver, InputEvent, Point, Result};

/// Native macOS browser driver targeting a running browser process by PID.
pub struct MacOsDriver {
    pid: i32,
    cursor: Mutex<Point>,
}

impl MacOsDriver {
    /// Creates a new [`MacOsDriver`] bound to the browser process `pid`.
    #[must_use]
    pub const fn new(pid: i32) -> Self {
        Self {
            pid,
            cursor: Mutex::new(Point { x: 0.0, y: 0.0 }),
        }
    }

    /// Returns the target macOS process ID.
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }
}

impl Driver for MacOsDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::MacOsNative
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        #[cfg(target_os = "macos")]
        {
            ax::snapshot_application_tree(self.pid)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "macos_native".to_owned(),
                reason: format!(
                    "MacOsDriver (pid {}) is only supported on macOS hosts",
                    self.pid
                ),
            })
        }
    }

    fn current_url(&self) -> Result<Option<String>> {
        #[cfg(target_os = "macos")]
        {
            ax::read_current_url(self.pid)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(None)
        }
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            screenshot::capture_window_png(self.pid, output_path)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = output_path;
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "macos_native".to_owned(),
                reason: "MacOsDriver screenshot is only supported on macOS hosts".to_owned(),
            })
        }
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let mut guard = self.cursor.lock().map_err(|_| {
                waybound_core::WayboundError::BackendUnavailable {
                    backend: "macos_native".to_owned(),
                    reason: "cursor state mutex poisoned".to_owned(),
                }
            })?;
            input::dispatch_cg_event(event, &mut guard)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (event, &self.cursor);
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "macos_native".to_owned(),
                reason: "MacOsDriver input dispatch is only supported on macOS hosts".to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_pid_and_reports_macos_backend() {
        let driver = MacOsDriver::new(4242);
        assert_eq!(driver.pid(), 4242);
        assert_eq!(driver.backend_kind(), BackendKind::MacOsNative);
    }
}
