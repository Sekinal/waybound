//! Pure-Rust Linux backend driver implementing [`waybound_core::Driver`] via
//! AT-SPI2 for accessibility inspection, `xdotool`/`ydotool` for native input
//! injection, `import`/`scrot`/`grim` for screenshots, and optional `Xvfb`
//! headless display management.

#![forbid(unsafe_code)]

pub mod atspi;
pub mod input;
mod process;
pub mod screenshot;
pub mod xvfb;

pub use atspi::AtspiSnapshot;
pub use input::DisplayServer;
pub use xvfb::{HeadlessDisplayConfig, HeadlessDisplaySession};

use std::path::Path;

use waybound_core::{AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Result};

/// Native Linux browser driver targeting unmodified Chrome/Chromium over AT-SPI2
/// and OS-level X11/Wayland input and screen capture utilities.
#[derive(Debug, Clone)]
pub struct LinuxDriver {
    pid: Option<i32>,
    display: Option<String>,
    display_server: Option<DisplayServer>,
}

impl LinuxDriver {
    /// Creates a new [`LinuxDriver`] optionally scoped to browser process `pid`.
    #[must_use]
    pub const fn new(pid: Option<i32>) -> Self {
        Self {
            pid,
            display: None,
            display_server: None,
        }
    }

    /// Creates a new [`LinuxDriver`] targeting an optional browser `pid` and explicit
    /// X11 `DISPLAY` string (such as `":99"` for a headless `Xvfb` session).
    #[must_use]
    pub const fn with_display(pid: Option<i32>, display: Option<String>) -> Self {
        Self {
            pid,
            display,
            display_server: None,
        }
    }

    /// Overrides the detected [`DisplayServer`] protocol for this driver instance.
    #[must_use]
    pub const fn with_display_server(mut self, server: DisplayServer) -> Self {
        self.display_server = Some(server);
        self
    }

    /// Returns the configured target browser PID, if any.
    #[must_use]
    pub const fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// Returns the configured X11 `DISPLAY` override, if any.
    #[must_use]
    pub fn display(&self) -> Option<&str> {
        self.display.as_deref()
    }

    /// Resolves the effective [`DisplayServer`] for input dispatch and screenshots.
    ///
    /// Uses an explicit override when configured, defaults to [`DisplayServer::X11`]
    /// when an explicit X11 `DISPLAY` is set, and otherwise auto-detects from the
    /// process environment.
    #[must_use]
    pub fn resolved_display_server(&self) -> DisplayServer {
        if let Some(server) = self.display_server {
            return server;
        }
        if self.display.is_some() {
            return DisplayServer::X11;
        }
        DisplayServer::detect()
    }
}

impl Driver for LinuxDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::LinuxWayland
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.nodes)
    }

    fn current_url(&self) -> Result<Option<String>> {
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.current_url)
    }

    fn viewport_bounds(&self) -> Result<Option<Bounds>> {
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.viewport_bounds)
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        screenshot::capture_screenshot(
            output_path,
            self.resolved_display_server(),
            self.display.as_deref(),
        )
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        input::dispatch_input(
            event,
            self.resolved_display_server(),
            self.display.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_driver_with_pid_display_and_backend_kind() {
        let driver = LinuxDriver::new(Some(4242));
        assert_eq!(driver.pid(), Some(4242));
        assert_eq!(driver.display(), None);
        assert_eq!(driver.backend_kind(), BackendKind::LinuxWayland);

        let with_disp = LinuxDriver::with_display(None, Some(":99".to_owned()));
        assert_eq!(with_disp.pid(), None);
        assert_eq!(with_disp.display(), Some(":99"));
        assert_eq!(with_disp.backend_kind(), BackendKind::LinuxWayland);
    }

    #[test]
    fn explicit_display_defaults_to_x11_unless_server_overridden() {
        let x11_driver = LinuxDriver::with_display(None, Some(":99".to_owned()));
        assert_eq!(x11_driver.resolved_display_server(), DisplayServer::X11);

        let wayland_driver = LinuxDriver::with_display(None, Some(":99".to_owned()))
            .with_display_server(DisplayServer::Wayland);
        assert_eq!(
            wayland_driver.resolved_display_server(),
            DisplayServer::Wayland
        );
    }
}
