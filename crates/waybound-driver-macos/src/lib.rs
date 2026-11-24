//! Native macOS backend driver implementing [`waybound_core::Driver`] via
//! `AXUIElement` (`ApplicationServices`) and `CGEvent` (`CoreGraphics`).

#[cfg(target_os = "macos")]
mod ax;
#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
mod input;
#[cfg(any(target_os = "macos", test))]
mod keymap;
#[cfg(target_os = "macos")]
mod screenshot;
#[cfg(any(target_os = "macos", test))]
mod tree;

use std::path::Path;
use std::sync::Mutex;

use waybound_core::{
    AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Point, Result, TreeSnapshot,
};

/// Native macOS browser driver targeting a running browser process by PID.
///
/// Every accessibility operation checks the browser's `AXEnhancedUserInterface` /
/// `AXManualAccessibility` flags (which make Chromium build its accessibility tree) and turns
/// on any that are off. Dropping the driver turns back off the ones it turned on (best
/// effort); that cannot happen if the daemon is killed with `SIGKILL` or crashes.
pub struct MacOsDriver {
    pid: i32,
    cursor: Mutex<Point>,
    #[cfg(target_os = "macos")]
    ax: ax::AxState,
}

impl MacOsDriver {
    /// Creates a new [`MacOsDriver`] bound to the browser process `pid`.
    #[must_use]
    pub const fn new(pid: i32) -> Self {
        Self {
            pid,
            cursor: Mutex::new(Point { x: 0.0, y: 0.0 }),
            #[cfg(target_os = "macos")]
            ax: ax::AxState::new(pid),
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
            ax::snapshot_application_tree(self.pid, &self.ax)
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

    fn snapshot_tree_limited(&self, max_nodes: usize) -> Result<TreeSnapshot> {
        #[cfg(target_os = "macos")]
        {
            ax::snapshot_application_tree_limited(self.pid, &self.ax, max_nodes)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = max_nodes;
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
            ax::read_current_url(self.pid, &self.ax)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(None)
        }
    }

    fn viewport_bounds(&self) -> Result<Option<Bounds>> {
        #[cfg(target_os = "macos")]
        {
            ax::read_viewport_bounds(self.pid, &self.ax)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(None)
        }
    }

    fn cursor_position(&self) -> Result<Option<Point>> {
        #[cfg(target_os = "macos")]
        {
            Ok(input::current_cursor_position())
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
            // Clicks and keystrokes go to the frontmost application, so make sure that is
            // the target browser before sending either. A drag's press counts too, but never
            // its release: a focus failure must not stop a held button from being let go.
            if matches!(
                event,
                InputEvent::KeyPress { .. }
                    | InputEvent::KeyDown { .. }
                    | InputEvent::MouseClick { .. }
                    | InputEvent::MouseDown { .. }
            ) {
                ax::ensure_frontmost(self.pid)?;
            }
            let mut guard = match self.cursor.lock() {
                Ok(guard) => guard,
                // A release must still go out after an earlier panic poisoned the cursor
                // state; the tracked position is only a fallback for the real one anyway.
                Err(poisoned)
                    if matches!(event, InputEvent::MouseUp { .. } | InputEvent::KeyUp { .. }) =>
                {
                    poisoned.into_inner()
                }
                Err(_) => {
                    return Err(waybound_core::WayboundError::BackendUnavailable {
                        backend: "macos_native".to_owned(),
                        reason: "cursor state mutex poisoned".to_owned(),
                    });
                }
            };
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
