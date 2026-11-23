//! Native Windows backend driver implementing [`waybound_core::Driver`] via
//! `UIAutomation` (in-process COM `IUIAutomation`, with a PowerShell fallback selected by
//! `WAYBOUND_WINDOWS_UIA=powershell`) and Win32 `SendInput` (`user32.dll`).

pub mod input;
pub mod screenshot;
pub mod uia;
#[cfg(target_os = "windows")]
mod uia_com;
pub mod uia_model;

use std::path::Path;

#[cfg(not(target_os = "windows"))]
use waybound_core::WayboundError;
use waybound_core::{AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Result};

/// Native Windows browser driver targeting a running browser process via
/// `UIAutomation` and Win32 `SendInput`.
#[derive(Debug, Clone, Default)]
pub struct WindowsDriver {
    pid: Option<i32>,
}

impl WindowsDriver {
    /// Creates a new [`WindowsDriver`] optionally bound to browser process `pid`.
    #[must_use]
    pub const fn new(pid: Option<i32>) -> Self {
        Self { pid }
    }

    /// Returns the target Windows process ID, if one was configured.
    #[must_use]
    pub const fn pid(&self) -> Option<i32> {
        self.pid
    }
}

#[cfg(not(target_os = "windows"))]
fn unavailable_error() -> WayboundError {
    WayboundError::BackendUnavailable {
        backend: "windows".to_owned(),
        reason: "requires Windows host".to_owned(),
    }
}

impl Driver for WindowsDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::WindowsNative
    }

    /// UIA runtime ids stay stable for an element's lifetime; positional fallback ids do not.
    fn is_stable_node_id(&self, id: &str) -> bool {
        !id.starts_with(uia::POSITIONAL_ID_PREFIX)
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        #[cfg(target_os = "windows")]
        {
            uia::query_uia_tree(self.pid).map(|snapshot| snapshot.nodes)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(unavailable_error())
        }
    }

    fn snapshot_tree_limited(&self, max_nodes: usize) -> Result<waybound_core::TreeSnapshot> {
        #[cfg(target_os = "windows")]
        {
            uia::query_uia_tree_limited(self.pid, max_nodes).map(|snapshot| {
                waybound_core::TreeSnapshot {
                    nodes: snapshot.nodes,
                    truncated: snapshot.truncated,
                }
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = max_nodes;
            Err(unavailable_error())
        }
    }

    fn current_url(&self) -> Result<Option<String>> {
        #[cfg(target_os = "windows")]
        {
            uia::query_uia_tree(self.pid).map(|snapshot| snapshot.current_url)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(unavailable_error())
        }
    }

    fn viewport_bounds(&self) -> Result<Option<Bounds>> {
        #[cfg(target_os = "windows")]
        {
            uia::query_uia_tree(self.pid).map(|snapshot| snapshot.viewport_bounds)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(unavailable_error())
        }
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            screenshot::capture_screenshot(output_path)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = output_path;
            Err(unavailable_error())
        }
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            input::win32_input::dispatch_input_event(event)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = event;
            Err(unavailable_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_pid_and_reports_windows_backend() {
        let driver = WindowsDriver::new(Some(1337));
        assert_eq!(driver.pid(), Some(1337));
        assert_eq!(driver.backend_kind(), BackendKind::WindowsNative);
    }

    #[test]
    fn positional_fallback_ids_are_not_stable() {
        let driver = WindowsDriver::default();
        assert!(driver.is_stable_node_id("42-7-1001"));
        assert!(!driver.is_stable_node_id("uia-pos-3"));
    }

    #[test]
    fn default_driver_has_no_pid() {
        let driver = WindowsDriver::default();
        assert_eq!(driver.pid(), None);
        assert_eq!(driver.backend_kind(), BackendKind::WindowsNative);
    }

    #[test]
    fn empty_uia_snapshot_parses_to_zero_nodes() -> Result<()> {
        let snapshot = uia::parse_uia_snapshot_json(r#"{"nodes":[]}"#)?;
        assert_eq!(snapshot.nodes.len(), 0);
        assert_eq!(snapshot.current_url, None);
        assert_eq!(snapshot.viewport_bounds, None);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_host_returns_backend_unavailable() {
        let driver = WindowsDriver::new(None);
        let check = |err: WayboundError| match err {
            WayboundError::BackendUnavailable { backend, reason } => {
                assert_eq!(backend, "windows");
                assert_eq!(reason, "requires Windows host");
            }
            other => assert_eq!(format!("{other:?}"), "BackendUnavailable"),
        };

        if let Err(e) = driver.snapshot_tree() {
            check(e);
        } else {
            assert_eq!(1, 0);
        }

        if let Err(e) = driver.current_url() {
            check(e);
        } else {
            assert_eq!(1, 0);
        }

        if let Err(e) = driver.viewport_bounds() {
            check(e);
        } else {
            assert_eq!(1, 0);
        }

        if let Err(e) = driver.screenshot(Path::new("out.png")) {
            check(e);
        } else {
            assert_eq!(1, 0);
        }

        let evt = InputEvent::PointerMove {
            to: waybound_core::Point { x: 10.0, y: 20.0 },
        };
        if let Err(e) = driver.dispatch_input(&evt) {
            check(e);
        } else {
            assert_eq!(1, 0);
        }
    }
}
