//! Pure-Rust Linux backend driver implementing [`waybound_core::Driver`] via
//! AT-SPI2 for accessibility inspection, `xdotool`/`ydotool` for native input
//! injection, `import`/`scrot`/`grim` for screenshots, and optional `Xvfb`
//! headless display management.

#![forbid(unsafe_code)]

pub mod atspi;
pub mod atspi_native;
pub mod input;
mod process;
pub mod screenshot;
pub mod x11_native;
pub mod xvfb;

pub use atspi::AtspiSnapshot;
pub use input::DisplayServer;
pub use xvfb::{HeadlessDisplayConfig, HeadlessDisplaySession};

use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::debug;
use waybound_core::{AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Result};

/// Native Linux browser driver targeting unmodified Chrome/Chromium.
///
/// Uses pure-Rust AT-SPI2 D-Bus (`zbus`) and X11 `XTEST`/`GetImage` (`x11rb`),
/// with automatic fallback to `pyatspi`/`xdotool`/`ydotool`/`scrot`/`grim`.
#[derive(Debug, Clone)]
pub struct LinuxDriver {
    pid: Option<i32>,
    display: Option<String>,
    display_server: Option<DisplayServer>,
    x11: Arc<Mutex<Option<x11_native::X11Client>>>,
    atspi: Arc<Mutex<Option<atspi_native::AtspiClient>>>,
    /// Pointer position left by the last `ydotool` move (Wayland fallback only).
    ydotool_cursor: Arc<Mutex<Option<(i32, i32)>>>,
}

impl LinuxDriver {
    /// Creates a new [`LinuxDriver`] optionally scoped to browser process `pid`.
    #[must_use]
    pub fn new(pid: Option<i32>) -> Self {
        Self {
            pid,
            display: None,
            display_server: None,
            x11: Arc::new(Mutex::new(None)),
            atspi: Arc::new(Mutex::new(None)),
            ydotool_cursor: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates a new [`LinuxDriver`] targeting an optional browser `pid` and explicit
    /// X11 `DISPLAY` string (such as `":99"` for a headless `Xvfb` session).
    #[must_use]
    pub fn with_display(pid: Option<i32>, display: Option<String>) -> Self {
        Self {
            pid,
            display,
            display_server: None,
            x11: Arc::new(Mutex::new(None)),
            atspi: Arc::new(Mutex::new(None)),
            ydotool_cursor: Arc::new(Mutex::new(None)),
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

    fn with_x11<T, F>(&self, op: F) -> Option<Result<T>>
    where
        F: FnOnce(&x11_native::X11Client) -> Result<T>,
    {
        if self.resolved_display_server() != DisplayServer::X11 {
            return None;
        }
        let mut guard = self.x11.lock().ok()?;
        if guard.is_none() {
            match x11_native::X11Client::connect(self.display.as_deref()) {
                Ok(client) => *guard = Some(client),
                Err(err) => {
                    debug!(%err, "native X11Client unavailable; falling back to CLI tools");
                    return None;
                }
            }
        }
        guard.as_ref().map(op)
    }

    fn with_atspi<T, F>(&self, op: F) -> Option<Result<T>>
    where
        F: FnOnce(&mut atspi_native::AtspiClient) -> Result<T>,
    {
        let mut guard = self.atspi.lock().ok()?;
        if guard.is_none() {
            match atspi_native::AtspiClient::connect() {
                Ok(client) => *guard = Some(client),
                Err(err) => {
                    debug!(%err, "native AtspiClient unavailable; falling back to pyatspi");
                    return None;
                }
            }
        }
        guard.as_mut().map(op)
    }
}

impl Driver for LinuxDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::LinuxWayland
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        if let Some(Ok(snap)) = self.with_atspi(|client| client.snapshot(self.pid)) {
            return Ok(snap.nodes);
        }
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.nodes)
    }

    fn current_url(&self) -> Result<Option<String>> {
        if let Some(Ok(url)) = self.with_atspi(|client| client.current_url(self.pid)) {
            return Ok(url);
        }
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.current_url)
    }

    fn viewport_bounds(&self) -> Result<Option<Bounds>> {
        if let Some(Ok(bounds)) = self.with_atspi(|client| client.viewport_bounds(self.pid)) {
            return Ok(bounds);
        }
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.viewport_bounds)
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        if self
            .with_x11(|client| client.capture_png(output_path))
            .is_some_and(|r| r.is_ok())
        {
            return Ok(());
        }
        screenshot::capture_screenshot(
            output_path,
            self.resolved_display_server(),
            self.display.as_deref(),
        )
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        if self
            .with_x11(|client| client.dispatch_input(event))
            .is_some_and(|r| r.is_ok())
        {
            return Ok(());
        }
        // A poisoned lock only means an earlier dispatch panicked; the position is still
        // usable, and refusing here could leave a drag's release unsent.
        let mut ydotool_cursor = self
            .ydotool_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        input::dispatch_input(
            event,
            self.resolved_display_server(),
            self.display.as_deref(),
            &mut ydotool_cursor,
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
