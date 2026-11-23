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

use tracing::{debug, warn};
use waybound_compositor::HeadlessCompositor;
use waybound_core::{
    AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Result, WayboundError,
};

/// Native Linux browser driver targeting unmodified Chrome/Chromium.
///
/// Uses pure-Rust AT-SPI2 D-Bus (`zbus`) and either an in-process
/// [`HeadlessCompositor`] (pure-Rust Wayland) or X11 `XTEST`/`GetImage` (`x11rb`),
/// with automatic fallback to `pyatspi`/`xdotool`/`ydotool`/`scrot`/`grim`.
#[derive(Debug, Clone)]
pub struct LinuxDriver {
    pid: Option<i32>,
    display: Option<String>,
    display_server: Option<DisplayServer>,
    compositor: Option<Arc<HeadlessCompositor>>,
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
            compositor: None,
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
            compositor: None,
            x11: Arc::new(Mutex::new(None)),
            atspi: Arc::new(Mutex::new(None)),
            ydotool_cursor: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates a new [`LinuxDriver`] backed directly by an in-process pure-Rust
    /// [`HeadlessCompositor`], routing pointer/keyboard input and screenshots straight
    /// through the Wayland server with zero X11 or external CLI dependencies.
    #[must_use]
    pub fn with_compositor(pid: Option<i32>, compositor: Arc<HeadlessCompositor>) -> Self {
        Self {
            pid,
            display: None,
            display_server: Some(DisplayServer::Wayland),
            compositor: Some(compositor),
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
        let client = guard.as_mut()?;
        let result = op(client);
        if client.is_broken() {
            warn!("AT-SPI2 connection lost; reconnecting on the next request");
            *guard = None;
        }
        drop(guard);
        Some(result)
    }

    /// Runs `op` on the native AT-SPI2 client. `Ok(Some(_))` is its answer; `Ok(None)` asks
    /// the caller to fall back to the `python3` helper. A native timeout is returned as is:
    /// a browser that stopped answering would only hang the helper for 10 s too.
    fn native_atspi<T, F>(&self, op: F) -> Result<Option<T>>
    where
        F: FnOnce(&mut atspi_native::AtspiClient) -> Result<T>,
    {
        match self.with_atspi(op) {
            Some(Ok(value)) => Ok(Some(value)),
            Some(Err(err @ WayboundError::Timeout { .. })) => Err(err),
            Some(Err(err)) => {
                debug!(%err, "native AT-SPI2 failed; falling back to pyatspi");
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

impl Driver for LinuxDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::LinuxWayland
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        if let Some(snap) = self.native_atspi(|client| client.snapshot(self.pid))? {
            return Ok(snap.nodes);
        }
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.nodes)
    }

    fn snapshot_tree_limited(&self, max_nodes: usize) -> Result<waybound_core::TreeSnapshot> {
        if let Some(snap) =
            self.native_atspi(|client| client.snapshot_limited(self.pid, max_nodes))?
        {
            return Ok(waybound_core::TreeSnapshot {
                nodes: snap.nodes,
                truncated: snap.truncated,
            });
        }
        let snapshot =
            atspi::query_atspi_tree_limited(self.pid, self.display.as_deref(), max_nodes)?;
        Ok(waybound_core::TreeSnapshot {
            nodes: snapshot.nodes,
            truncated: snapshot.truncated,
        })
    }

    fn current_url(&self) -> Result<Option<String>> {
        if let Some(url) = self.native_atspi(|client| client.current_url(self.pid))? {
            return Ok(url);
        }
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.current_url)
    }

    fn viewport_bounds(&self) -> Result<Option<Bounds>> {
        if let Some(ref comp) = self.compositor
            && let Ok(windows) = comp.windows()
            && let Some(win) = windows.last()
            && win.width > 0
            && win.height > 0
        {
            return Ok(Some(Bounds {
                x: 0.0,
                y: 0.0,
                width: f64::from(win.width),
                height: f64::from(win.height),
            }));
        }
        if let Some(bounds) = self.native_atspi(|client| client.viewport_bounds(self.pid))? {
            return Ok(bounds);
        }
        let snapshot = atspi::query_atspi_tree(self.pid, self.display.as_deref())?;
        Ok(snapshot.viewport_bounds)
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        if let Some(ref comp) = self.compositor {
            return comp.screenshot_window(None, output_path);
        }
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
        if let Some(ref comp) = self.compositor {
            return comp.dispatch_input(None, event);
        }
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

    #[cfg(unix)]
    #[test]
    fn with_compositor_resolves_wayland_and_routes_screenshot_and_input_errors() {
        use waybound_compositor::CompositorConfig;
        use waybound_core::{Point, WayboundError};

        let runtime_dir =
            std::env::temp_dir().join(format!("wb-driver-wl-test-{}", std::process::id()));
        let config = CompositorConfig {
            runtime_dir: Some(runtime_dir.clone()),
            socket_name: Some("wl-driver-test-0".to_owned()),
            ..CompositorConfig::default()
        };
        let compositor = HeadlessCompositor::start(config);
        assert!(compositor.is_ok());
        let Ok(compositor) = compositor else {
            return;
        };

        let driver = LinuxDriver::with_compositor(Some(9001), Arc::new(compositor));
        assert_eq!(driver.pid(), Some(9001));
        assert_eq!(driver.display(), None);
        assert_eq!(driver.resolved_display_server(), DisplayServer::Wayland);
        assert_eq!(driver.backend_kind(), BackendKind::LinuxWayland);

        let out_png = runtime_dir.join("out.png");
        let shot_err = driver.screenshot(&out_png);
        assert!(matches!(
            shot_err,
            Err(WayboundError::ElementNotFound { .. })
        ));

        let input_err = driver.dispatch_input(&InputEvent::PointerMove {
            to: Point { x: 10.0, y: 20.0 },
        });
        assert!(matches!(
            input_err,
            Err(WayboundError::ElementNotFound { .. })
        ));

        drop(driver);
        let _ = std::fs::remove_dir_all(&runtime_dir);
    }
}
