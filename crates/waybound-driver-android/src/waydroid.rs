//! Multi-instance headless Waydroid session orchestrator for Linux hosts.
//!
//! Manages isolated per-instance headless Weston Wayland sockets, `XDG_DATA_HOME`
//! directories, ADB connection waiting, optional proxy/timezone setup, and RAII
//! teardown on [`Drop`].

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};
use waybound_core::{Result, WayboundError};

#[cfg(target_os = "linux")]
use crate::adb;

const BACKEND_NAME: &str = "android_waydroid";
#[cfg(target_os = "linux")]
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Configuration for launching a headless Waydroid Android container instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaydroidConfig {
    /// Short alphanumeric instance identifier (e.g., `"wb-01"`).
    pub instance_id: String,
    /// Isolated per-instance data directory (`XDG_DATA_HOME`).
    pub data_dir: PathBuf,
    /// Local ADB TCP port used to connect to the container (e.g., `5555`).
    pub adb_port: u16,
    /// Whether to start a dedicated headless `weston` Wayland compositor for this instance.
    pub headless: bool,
    /// Optional HTTP proxy `host:port` configured inside Android via `settings put global http_proxy`.
    pub android_http_proxy: Option<String>,
    /// Optional IANA timezone applied via `setprop persist.sys.timezone`.
    pub timezone: Option<String>,
}

impl WaydroidConfig {
    /// Validates the instance ID and ADB port before launching any OS processes.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `instance_id` contains unsafe
    /// characters or `adb_port == 0`.
    pub fn validate(&self) -> Result<()> {
        if self.instance_id.is_empty()
            || self.instance_id.len() > 32
            || !self
                .instance_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "invalid waydroid instance_id {:?} (must be 1..=32 ASCII [a-zA-Z0-9_-])",
                    self.instance_id
                ),
            });
        }
        if self.adb_port == 0 {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: "waydroid adb_port must be non-zero".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the Wayland socket name dedicated to this instance.
    #[must_use]
    pub fn wayland_socket_name(&self) -> String {
        format!("wayland-waybound-{}", self.instance_id)
    }

    /// Returns the ADB target serial (`127.0.0.1:<adb_port>`).
    #[must_use]
    pub fn adb_serial(&self) -> String {
        format!("127.0.0.1:{}", self.adb_port)
    }
}

/// Builds the `weston` argument vector for a headless compositor socket.
#[must_use]
pub fn build_weston_args(socket_name: &str) -> Vec<String> {
    vec![
        "--backend=headless-backend.so".to_owned(),
        format!("--socket={socket_name}"),
        "--width=1080".to_owned(),
        "--height=2400".to_owned(),
    ]
}

/// RAII handle owning a running Waydroid session and optional headless Weston compositor.
pub struct WaydroidSession {
    config: WaydroidConfig,
    weston: Option<Child>,
    waydroid_proc: Option<Child>,
}

impl WaydroidSession {
    /// Starts an isolated Waydroid session on Linux and waits for ADB readiness.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] on non-Linux hosts or if
    /// `weston`/`waydroid` cannot be started, or [`WayboundError::Timeout`] if
    /// ADB does not become reachable within 30 seconds.
    #[allow(clippy::needless_pass_by_value)]
    pub fn start(config: WaydroidConfig) -> Result<Self> {
        config.validate()?;

        #[cfg(not(target_os = "linux"))]
        {
            Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "Waydroid container launch ({}) requires a Linux host with kernel binder support; pass --serial <adb_serial> to drive an existing remote/local Android device",
                    config.instance_id
                ),
            })
        }

        #[cfg(target_os = "linux")]
        {
            Self::start_linux(config)
        }
    }

    /// Returns the ADB serial (`127.0.0.1:<port>`) for connecting [`crate::AndroidDriver`].
    #[must_use]
    pub fn serial(&self) -> String {
        self.config.adb_serial()
    }

    #[cfg(target_os = "linux")]
    fn start_linux(config: WaydroidConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let socket_name = config.wayland_socket_name();

        let weston = if config.headless {
            let args = build_weston_args(&socket_name);
            debug!(?args, "starting headless weston compositor");
            let child = Command::new("weston")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|err| WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: format!("failed to spawn headless weston: {err}"),
                })?;
            thread::sleep(Duration::from_millis(350));
            Some(child)
        } else {
            None
        };

        let mut cmd = Command::new("waydroid");
        let _ = cmd
            .args(["session", "start"])
            .env("WAYLAND_DISPLAY", &socket_name)
            .env("XDG_DATA_HOME", &config.data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let waydroid_proc = match cmd.spawn() {
            Ok(child) => Some(child),
            Err(err) => {
                if let Some(mut w) = weston {
                    let _ = w.kill();
                    let _ = w.wait();
                }
                return Err(WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: format!("failed to start waydroid session: {err}"),
                });
            }
        };

        let session = Self {
            config,
            weston,
            waydroid_proc,
        };

        let serial = session.serial();
        wait_for_adb_device(&serial)?;
        apply_android_settings(&serial, &session.config)?;

        info!(
            instance = %session.config.instance_id,
            serial = %serial,
            "started headless waydroid session"
        );
        Ok(session)
    }
}

impl Drop for WaydroidSession {
    fn drop(&mut self) {
        let _ = Command::new("waydroid")
            .args(["session", "stop"])
            .env("XDG_DATA_HOME", &self.config.data_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Some(child) = &mut self.waydroid_proc {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(child) = &mut self.weston {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_adb_device(serial: &str) -> Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        let _ = Command::new("adb")
            .args(["connect", serial])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Ok(output) = Command::new("adb")
            .args(["-s", serial, "get-state"])
            .stdin(Stdio::null())
            .output()
            && output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == "device"
        {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }

    Err(WayboundError::Timeout {
        timeout_ms: u64::try_from(STARTUP_TIMEOUT.as_millis()).unwrap_or(30_000),
        context: format!("waydroid ADB device {serial} did not become ready"),
    })
}

#[cfg(target_os = "linux")]
fn apply_android_settings(serial: &str, config: &WaydroidConfig) -> Result<()> {
    if let Some(proxy) = &config.android_http_proxy {
        let escaped = adb::shell_single_quote(proxy);
        let cmd = format!("settings put global http_proxy {escaped}");
        let args = adb::build_adb_args(Some(serial), &["shell", &cmd]);
        let out = Command::new("adb")
            .args(&args)
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            warn!(serial, status = %out.status, "failed to configure Android http_proxy");
        }
    }
    if let Some(tz) = &config.timezone {
        let escaped = adb::shell_single_quote(tz);
        let cmd = format!("setprop persist.sys.timezone {escaped}");
        let args = adb::build_adb_args(Some(serial), &["shell", &cmd]);
        let out = Command::new("adb")
            .args(&args)
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            warn!(serial, status = %out.status, "failed to configure Android timezone");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_instance_id_and_builds_names() {
        let cfg = WaydroidConfig {
            instance_id: "wb-01".to_owned(),
            data_dir: PathBuf::from("/tmp/wb-01"),
            adb_port: 5555,
            headless: true,
            android_http_proxy: None,
            timezone: Some("America/New_York".to_owned()),
        };
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.wayland_socket_name(), "wayland-waybound-wb-01");
        assert_eq!(cfg.adb_serial(), "127.0.0.1:5555");
        assert_eq!(
            build_weston_args("wayland-waybound-wb-01"),
            vec![
                "--backend=headless-backend.so",
                "--socket=wayland-waybound-wb-01",
                "--width=1080",
                "--height=2400",
            ]
        );
    }

    #[test]
    fn rejects_unsafe_instance_ids_and_zero_port() {
        let bad_id = WaydroidConfig {
            instance_id: "../evil".to_owned(),
            data_dir: PathBuf::from("/tmp/x"),
            adb_port: 5555,
            headless: true,
            android_http_proxy: None,
            timezone: None,
        };
        assert!(bad_id.validate().is_err());

        let zero_port = WaydroidConfig {
            instance_id: "ok-1".to_owned(),
            data_dir: PathBuf::from("/tmp/x"),
            adb_port: 0,
            headless: true,
            android_http_proxy: None,
            timezone: None,
        };
        assert!(zero_port.validate().is_err());
    }
}
