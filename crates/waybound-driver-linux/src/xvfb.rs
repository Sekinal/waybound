//! Headless Xvfb virtual framebuffer configuration and RAII session guard.

use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, warn};
use waybound_core::{Result, WayboundError};

use crate::process::BACKEND_NAME;

const MAX_DIMENSION: u32 = 16_384;
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(20);
/// Kept below the Python SDK's default 5 s daemon startup timeout, so a display that never
/// becomes ready surfaces as this descriptive error rather than a generic SDK timeout.
const STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(3);
/// How long `stop` waits after `SIGTERM` before falling back to `SIGKILL`.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long to wait for the socket once our `Xvfb` holds the lock (some builds only listen on
/// an abstract socket, so its absence is not fatal).
const SOCKET_GRACE: Duration = Duration::from_secs(1);
/// Directory holding X11 server lock files (`.X<n>-lock`) and sockets (`.X11-unix/X<n>`).
const X11_TMP_DIR: &str = "/tmp";

/// Returns the lock file path an X server for `display_num` writes.
fn x11_lock_path(display_num: u16) -> PathBuf {
    Path::new(X11_TMP_DIR).join(format!(".X{display_num}-lock"))
}

/// Returns the Unix socket path an X server for `display_num` listens on.
fn x11_socket_path(display_num: u16) -> PathBuf {
    Path::new(X11_TMP_DIR)
        .join(".X11-unix")
        .join(format!("X{display_num}"))
}

/// Sends `SIGTERM` to `child` and waits up to `grace` for it to exit; `false` if it did not.
///
/// The signal is sent with `rustix` (this crate forbids `unsafe`). `child` has not been
/// reaped, so its pid cannot have been reused. Returns `false` (the caller falls back to
/// `SIGKILL`) where `SIGTERM` is unavailable or could not be sent.
fn terminate_gracefully(child: &mut Child, grace: Duration) -> bool {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return true;
    }
    if !send_sigterm(child) {
        return false;
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => thread::sleep(STARTUP_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    false
}

/// Sends `SIGTERM` to `child` (unreaped, so its pid cannot have been reused).
#[cfg(unix)]
fn send_sigterm(child: &Child) -> bool {
    i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .is_some_and(|pid| {
            rustix::process::kill_process(pid, rustix::process::Signal::TERM).is_ok()
        })
}

/// No `SIGTERM` elsewhere: the caller falls back to killing the child.
#[cfg(not(unix))]
const fn send_sigterm(_child: &Child) -> bool {
    false
}

/// Parses the owning pid from X11 lock file contents (a space-padded decimal pid).
fn parse_lock_owner(contents: &str) -> Option<u32> {
    contents.trim().parse::<u32>().ok()
}

/// Outcome of one readiness probe of a freshly spawned `Xvfb`.
#[derive(Debug, PartialEq, Eq)]
enum Readiness {
    /// Our `Xvfb` owns the display lock and its socket exists.
    Ready,
    /// Our `Xvfb` owns the display lock but its filesystem socket is not there (yet).
    LockedWithoutSocket,
    /// Not ready yet (no readable lock file).
    Pending,
    /// The display lock belongs to another process.
    OwnedBy(u32),
}

fn probe_readiness(lock_contents: Option<&str>, socket_exists: bool, our_pid: u32) -> Readiness {
    match lock_contents.and_then(parse_lock_owner) {
        Some(owner) if owner != our_pid => Readiness::OwnedBy(owner),
        Some(_) if socket_exists => Readiness::Ready,
        Some(_) => Readiness::LockedWithoutSocket,
        None => Readiness::Pending,
    }
}

/// Configuration for a headless `Xvfb` virtual framebuffer display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadlessDisplayConfig {
    /// X11 display number (for example `99` for `:99`).
    pub display_num: u16,
    /// Framebuffer width in pixels.
    pub width: u32,
    /// Framebuffer height in pixels.
    pub height: u32,
    /// Color depth in bits per pixel (`8`, `16`, `24`, or `32`).
    pub color_depth: u8,
}

impl Default for HeadlessDisplayConfig {
    fn default() -> Self {
        Self {
            display_num: 99,
            width: 1280,
            height: 800,
            color_depth: 24,
        }
    }
}

impl HeadlessDisplayConfig {
    /// Returns the X11 `DISPLAY` identifier string (e.g. `":99"`).
    #[must_use]
    pub fn display_name(&self) -> String {
        format!(":{}", self.display_num)
    }

    /// Validates framebuffer dimensions and color depth before spawning `Xvfb`.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if dimensions are zero or exceed
    /// `16384`, or if `color_depth` is not one of `8`, `16`, `24`, `32`.
    pub fn validate(&self) -> Result<()> {
        if self.width == 0 || self.height == 0 {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "Xvfb dimensions must be non-zero (got {}x{})",
                    self.width, self.height
                ),
            });
        }
        if self.width > MAX_DIMENSION || self.height > MAX_DIMENSION {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "Xvfb dimensions {}x{} exceed maximum {MAX_DIMENSION}",
                    self.width, self.height
                ),
            });
        }
        if !matches!(self.color_depth, 8 | 16 | 24 | 32) {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "unsupported Xvfb color depth {} (expected 8, 16, 24, or 32)",
                    self.color_depth
                ),
            });
        }
        Ok(())
    }
}

/// Builds the argument vector passed to `Xvfb` for `config`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `config` fails validation.
pub fn build_xvfb_args(config: &HeadlessDisplayConfig) -> Result<Vec<String>> {
    config.validate()?;
    Ok(vec![
        config.display_name(),
        "-screen".to_owned(),
        "0".to_owned(),
        format!("{}x{}x{}", config.width, config.height, config.color_depth),
        "-nolisten".to_owned(),
        "tcp".to_owned(),
        "-ac".to_owned(),
    ])
}

/// RAII handle owning a spawned headless `Xvfb` process and terminating it on [`Drop`].
#[derive(Debug)]
pub struct HeadlessDisplaySession {
    config: HeadlessDisplayConfig,
    child: Option<Child>,
}

impl HeadlessDisplaySession {
    /// Spawns `Xvfb` with the validated `config` and returns an RAII session guard.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `config` is invalid, `Xvfb`
    /// cannot be spawned, exits on startup (for example because another server already owns
    /// the display), or does not take the display's lock file within 5 seconds.
    pub fn start(config: HeadlessDisplayConfig) -> Result<Self> {
        let args = build_xvfb_args(&config)?;
        debug!(?args, "starting headless Xvfb display");

        let mut cmd = waybound_core::process::command("Xvfb");
        let _ = cmd
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to spawn `Xvfb`: {err}"),
            })?;

        // Wait until *this* Xvfb owns the display: another process may have started a server
        // on the same number a moment earlier, in which case ours exits (or never gets the
        // lock) and connecting to the display would silently drive someone else's server.
        let display_name = config.display_name();
        let deadline = Instant::now() + STARTUP_READY_TIMEOUT;
        let mut locked_since: Option<Instant> = None;
        let failure = loop {
            if let Some(status) = child.try_wait()? {
                let owner = std::fs::read_to_string(x11_lock_path(config.display_num))
                    .ok()
                    .and_then(|c| parse_lock_owner(&c));
                break owner.map_or_else(
                    || format!("`Xvfb` exited prematurely on startup with {status}"),
                    |pid| {
                        format!(
                            "`Xvfb` exited on startup with {status}; display {display_name} is \
                             already owned by pid {pid}"
                        )
                    },
                );
            }
            let lock = std::fs::read_to_string(x11_lock_path(config.display_num)).ok();
            let socket = x11_socket_path(config.display_num).exists();
            let readiness = probe_readiness(lock.as_deref(), socket, child.id());
            if readiness == Readiness::LockedWithoutSocket {
                let since = *locked_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= SOCKET_GRACE {
                    debug!(display = %display_name, "Xvfb holds the display lock; no filesystem socket found");
                    return Ok(Self {
                        config,
                        child: Some(child),
                    });
                }
            }
            match readiness {
                Readiness::Ready => {
                    return Ok(Self {
                        config,
                        child: Some(child),
                    });
                }
                Readiness::OwnedBy(pid) if Instant::now() >= deadline => {
                    break format!(
                        "Xvfb display {display_name} is owned by another process (pid {pid})"
                    );
                }
                _ if Instant::now() >= deadline => {
                    break format!(
                        "`Xvfb` did not become ready on display {display_name} within {}s",
                        STARTUP_READY_TIMEOUT.as_secs()
                    );
                }
                _ => thread::sleep(STARTUP_POLL_INTERVAL),
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: failure,
        })
    }

    /// Returns the X11 `DISPLAY` string owned by this session (e.g. `":99"`).
    #[must_use]
    pub fn display(&self) -> String {
        self.config.display_name()
    }

    /// Returns the [`HeadlessDisplayConfig`] used to launch this session.
    #[must_use]
    pub const fn config(&self) -> HeadlessDisplayConfig {
        self.config
    }

    /// Terminates the underlying `Xvfb` process if it is still running.
    ///
    /// Sends `SIGTERM` first so Xvfb removes its `/tmp/.X<n>-lock` file and socket (a killed
    /// Xvfb leaves them behind and they look like a live display to the next allocator), and
    /// only falls back to `SIGKILL` if it has not exited within 2 seconds.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if !terminate_gracefully(&mut child, STOP_GRACE)
                && let Err(err) = child.kill()
            {
                warn!(display = %self.config.display_name(), %err, "failed to kill Xvfb");
            }
            let _ = child.wait();
        }
    }
}

impl Drop for HeadlessDisplaySession {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_xvfb_args_for_valid_config() -> Result<()> {
        let cfg = HeadlessDisplayConfig {
            display_num: 99,
            width: 1920,
            height: 1080,
            color_depth: 24,
        };
        assert_eq!(cfg.display_name(), ":99");
        let args = build_xvfb_args(&cfg)?;
        assert_eq!(
            args,
            vec![
                ":99",
                "-screen",
                "0",
                "1920x1080x24",
                "-nolisten",
                "tcp",
                "-ac"
            ]
        );
        Ok(())
    }

    #[test]
    fn readiness_requires_our_lock_and_socket() {
        assert_eq!(parse_lock_owner("      4242\n"), Some(4242));
        assert_eq!(parse_lock_owner("garbage"), None);
        assert_eq!(probe_readiness(None, false, 7), Readiness::Pending);
        assert_eq!(
            probe_readiness(Some("    7\n"), false, 7),
            Readiness::LockedWithoutSocket
        );
        assert_eq!(probe_readiness(Some("    7\n"), true, 7), Readiness::Ready);
        assert_eq!(
            probe_readiness(Some("    9\n"), true, 7),
            Readiness::OwnedBy(9)
        );
        assert_eq!(probe_readiness(Some(""), true, 7), Readiness::Pending);
        assert_eq!(x11_lock_path(101), PathBuf::from("/tmp/.X101-lock"));
        assert_eq!(x11_socket_path(101), PathBuf::from("/tmp/.X11-unix/X101"));
    }

    #[cfg(unix)]
    #[test]
    fn terminate_gracefully_uses_sigterm_and_reports_a_child_that_ignores_it() {
        let polite = waybound_core::process::command("sleep").arg("30").spawn();
        assert!(polite.is_ok());
        if let Ok(mut child) = polite {
            let started = Instant::now();
            assert!(terminate_gracefully(&mut child, Duration::from_secs(5)));
            assert!(started.elapsed() < Duration::from_secs(5));
        }

        let stubborn = waybound_core::process::command("sh")
            .args(["-c", "trap '' TERM; while :; do sleep 0.05; done"])
            .spawn();
        assert!(stubborn.is_ok());
        if let Ok(mut child) = stubborn {
            thread::sleep(Duration::from_millis(200)); // let the shell install its trap
            assert!(!terminate_gracefully(
                &mut child,
                Duration::from_millis(300)
            ));
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn rejects_invalid_xvfb_dimensions_and_color_depth() {
        let zero_width = HeadlessDisplayConfig {
            width: 0,
            ..HeadlessDisplayConfig::default()
        };
        assert!(build_xvfb_args(&zero_width).is_err());

        let huge_height = HeadlessDisplayConfig {
            height: 20_000,
            ..HeadlessDisplayConfig::default()
        };
        assert!(build_xvfb_args(&huge_height).is_err());

        let bad_depth = HeadlessDisplayConfig {
            color_depth: 12,
            ..HeadlessDisplayConfig::default()
        };
        assert!(build_xvfb_args(&bad_depth).is_err());
    }
}
