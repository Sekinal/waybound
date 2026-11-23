//! Pure-Rust headless Wayland compositor for high-density normal-geometry browser concurrency.
//!
//! Runs a self-contained Wayland server with zero C system library dependencies and
//! `#![forbid(unsafe_code)]`, supporting `wl_compositor`, `wl_shm`, `wl_output`,
//! `xdg_wm_base`, `wl_seat`, and `wl_data_device_manager`.

#![forbid(unsafe_code)]

pub mod buffer;
pub mod config;
pub mod keymap;
#[cfg(unix)]
mod server;

use std::path::{Path, PathBuf};

use waybound_core::{InputEvent, Result};

pub use config::{CompositorConfig, WindowInfo};

/// Handle to a running pure-Rust headless Wayland compositor.
///
/// Dropping the handle cleanly stops the background event loop, joins its thread, and
/// removes the Wayland Unix domain socket file.
pub struct HeadlessCompositor {
    #[cfg(unix)]
    inner: server::ServerHandle,
    #[cfg(not(unix))]
    _unsupported: (),
}

impl std::fmt::Debug for HeadlessCompositor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(unix)]
        {
            f.debug_struct("HeadlessCompositor")
                .field("socket_name", &self.inner.socket_name())
                .field("runtime_dir", &self.inner.runtime_dir())
                .finish()
        }
        #[cfg(not(unix))]
        {
            f.debug_struct("HeadlessCompositor").finish()
        }
    }
}

impl HeadlessCompositor {
    /// Starts a headless Wayland compositor on a dedicated background thread.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::InvalidElementState`] if `config` is invalid,
    /// [`waybound_core::WayboundError::BackendUnavailable`] on non-Unix platforms, or
    /// [`waybound_core::WayboundError::Io`] if binding the Unix socket fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn start(config: CompositorConfig) -> Result<Self> {
        #[cfg(unix)]
        {
            let inner = server::ServerHandle::start(config)?;
            Ok(Self { inner })
        }
        #[cfg(not(unix))]
        {
            let _ = config;
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "wayland-compositor".to_owned(),
                reason: "Wayland compositor is only supported on Unix platforms".to_owned(),
            })
        }
    }

    /// Returns the Wayland display socket name (suitable for `WAYLAND_DISPLAY`).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn socket_name(&self) -> &str {
        #[cfg(unix)]
        {
            self.inner.socket_name()
        }
        #[cfg(not(unix))]
        {
            ""
        }
    }

    /// Returns the runtime directory containing the Wayland socket (suitable for `XDG_RUNTIME_DIR`).
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        #[cfg(unix)]
        {
            self.inner.runtime_dir()
        }
        #[cfg(not(unix))]
        {
            Path::new("")
        }
    }

    /// Returns the full filesystem path of the Wayland Unix domain socket.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        #[cfg(unix)]
        {
            self.inner.socket_path().to_path_buf()
        }
        #[cfg(not(unix))]
        {
            PathBuf::new()
        }
    }

    /// Returns metadata for all currently tracked `xdg_toplevel` windows.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::BackendUnavailable`] if the compositor loop
    /// has stopped or is unavailable on this platform.
    pub fn windows(&self) -> Result<Vec<WindowInfo>> {
        #[cfg(unix)]
        {
            self.inner.windows()
        }
        #[cfg(not(unix))]
        {
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "wayland-compositor".to_owned(),
                reason: "Wayland compositor is only supported on Unix platforms".to_owned(),
            })
        }
    }

    /// Captures the latest committed pixel buffer of `window_id` (or the latest window when
    /// `None`) and encodes it as a PNG byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::ElementNotFound`] if no matching window exists,
    /// [`waybound_core::WayboundError::Transient`] if the window has not committed a buffer yet,
    /// or [`waybound_core::WayboundError::Io`] on encoding failure.
    pub fn screenshot_png(&self, window_id: Option<u64>) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            self.inner.screenshot_png(window_id)
        }
        #[cfg(not(unix))]
        {
            let _ = window_id;
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "wayland-compositor".to_owned(),
                reason: "Wayland compositor is only supported on Unix platforms".to_owned(),
            })
        }
    }

    /// Captures a PNG screenshot of `window_id` (or the latest window when `None`) and writes
    /// it to `output_path`.
    ///
    /// # Errors
    ///
    /// Returns an error if screenshot capture or file writing fails.
    pub fn screenshot_window(&self, window_id: Option<u64>, output_path: &Path) -> Result<()> {
        let png_bytes = self.screenshot_png(window_id)?;
        std::fs::write(output_path, png_bytes)?;
        Ok(())
    }

    /// Dispatches a synthetic pointer or keyboard [`InputEvent`] to `window_id` (or the latest
    /// window when `None`).
    ///
    /// # Errors
    ///
    /// Returns an error if no matching window exists, the key is unmapped, or the compositor
    /// event loop has stopped.
    pub fn dispatch_input(&self, window_id: Option<u64>, event: &InputEvent) -> Result<()> {
        #[cfg(unix)]
        {
            self.inner.dispatch_input(window_id, event)
        }
        #[cfg(not(unix))]
        {
            let _ = (window_id, event);
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "wayland-compositor".to_owned(),
                reason: "Wayland compositor is only supported on Unix platforms".to_owned(),
            })
        }
    }

    /// Requests that the client cleanly close `window_id` via `xdg_toplevel::close`.
    ///
    /// # Errors
    ///
    /// Returns [`waybound_core::WayboundError::ElementNotFound`] if `window_id` is not tracked,
    /// or [`waybound_core::WayboundError::BackendUnavailable`] if the compositor event loop has
    /// stopped or is unavailable on this platform.
    pub fn close_window(&self, window_id: u64) -> Result<()> {
        #[cfg(unix)]
        {
            self.inner.close_window(window_id)
        }
        #[cfg(not(unix))]
        {
            let _ = window_id;
            Err(waybound_core::WayboundError::BackendUnavailable {
                backend: "wayland-compositor".to_owned(),
                reason: "Wayland compositor is only supported on Unix platforms".to_owned(),
            })
        }
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::*;

    /// Encodes a Wayland wire message header + u32 arguments in native endianness.
    fn encode_wl_msg(object_id: u32, opcode: u16, args: &[u32]) -> Vec<u8> {
        let size = u16::try_from(8 + args.len() * 4).unwrap_or(8);
        let mut out = Vec::with_capacity(usize::from(size));
        out.extend_from_slice(&object_id.to_ne_bytes());
        let word1 = (u32::from(size) << 16) | u32::from(opcode);
        out.extend_from_slice(&word1.to_ne_bytes());
        for &arg in args {
            out.extend_from_slice(&arg.to_ne_bytes());
        }
        out
    }

    #[test]
    fn advertises_required_wayland_globals_and_cleans_up_socket() {
        let runtime_dir = std::env::temp_dir().join(format!("wb-wl-test-{}", std::process::id()));
        let config = CompositorConfig {
            runtime_dir: Some(runtime_dir.clone()),
            socket_name: Some("wl-test-0".to_owned()),
            ..CompositorConfig::default()
        };

        let compositor = HeadlessCompositor::start(config);
        assert!(compositor.is_ok());
        let Ok(compositor) = compositor else {
            return;
        };

        let socket_path = compositor.socket_path();
        assert!(socket_path.exists());
        assert_eq!(compositor.socket_name(), "wl-test-0");
        assert_eq!(compositor.windows().ok(), Some(Vec::new()));
        assert!(matches!(
            compositor.close_window(999),
            Err(waybound_core::WayboundError::ElementNotFound { .. })
        ));

        // Perform a raw Wayland wire handshake:
        //   wl_display(1).get_registry(opcode=1, new_id=2)
        //   wl_display(1).sync(opcode=0, new_id=3)
        let stream = UnixStream::connect(&socket_path);
        assert!(stream.is_ok());
        if let Ok(mut stream) = stream {
            assert!(
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .is_ok()
            );
            let mut req = encode_wl_msg(1, 1, &[2]);
            req.extend_from_slice(&encode_wl_msg(1, 0, &[3]));
            assert!(stream.write_all(&req).is_ok());

            let mut buf = Vec::new();
            let mut chunk = [0_u8; 4096];
            let mut saw_sync_done = false;
            let mut globals = Vec::new();

            while !saw_sync_done {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);

                let mut pos = 0;
                while pos + 8 <= buf.len() {
                    let obj_id =
                        u32::from_ne_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
                    let word1 = u32::from_ne_bytes([
                        buf[pos + 4],
                        buf[pos + 5],
                        buf[pos + 6],
                        buf[pos + 7],
                    ]);
                    let msg_size = usize::try_from(word1 >> 16).unwrap_or(0);
                    let opcode = (word1 & 0xFFFF) as u16;
                    if msg_size < 8 || pos + msg_size > buf.len() {
                        break;
                    }
                    let payload = &buf[pos + 8..pos + msg_size];
                    // wl_registry(2)::global(opcode=0): name(u32), interface(string), version(u32)
                    if obj_id == 2 && opcode == 0 && payload.len() >= 8 {
                        let str_len =
                            u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        let str_len_usize = usize::try_from(str_len).unwrap_or(0);
                        if str_len_usize > 0 && 8 + str_len_usize <= payload.len() {
                            let iface_bytes = &payload[8..8 + str_len_usize - 1];
                            if let Ok(iface) = std::str::from_utf8(iface_bytes) {
                                globals.push(iface.to_owned());
                            }
                        }
                    }
                    // wl_callback(3)::done(opcode=0)
                    if obj_id == 3 && opcode == 0 {
                        saw_sync_done = true;
                    }
                    pos += msg_size;
                }
                if pos > 0 {
                    let _ = buf.drain(..pos);
                }
            }

            assert!(saw_sync_done, "expected wl_callback::done from compositor");
            for required in [
                "wl_compositor",
                "wl_shm",
                "wl_output",
                "xdg_wm_base",
                "wl_seat",
                "wl_data_device_manager",
            ] {
                assert!(
                    globals.iter().any(|g| g == required),
                    "missing required global {required}; got {globals:?}"
                );
            }
        }

        drop(compositor);
        assert!(
            !socket_path.exists(),
            "Wayland socket should be removed on Drop"
        );
        let _ = std::fs::remove_dir_all(&runtime_dir);
    }
}
