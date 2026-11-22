//! Unmodified official Google Chrome launcher with RAII process cleanup.
//!
//! Launches the stock browser binary with zero automation flags and no
//! remote-debugging ports, optionally configuring a profile directory and
//! `SSLKEYLOGFILE` for passive wire-level TLS inspection.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use waybound_core::{Result, WayboundError};

/// Options for launching a stock Google Chrome process.
#[derive(Debug, Clone)]
pub struct ChromeLaunchOptions {
    /// Optional explicit Chrome binary path.
    pub binary_path: Option<PathBuf>,
    /// Optional user data directory (`--user-data-dir`).
    pub profile_dir: Option<PathBuf>,
    /// Optional path written to the `SSLKEYLOGFILE` environment variable.
    pub ssl_keylog_file: Option<PathBuf>,
    /// Optional initial URL opened at launch.
    pub initial_url: Option<String>,
}

/// RAII handle owning a spawned Google Chrome process.
pub struct LaunchedChrome {
    child: Child,
    pid: i32,
}

impl LaunchedChrome {
    /// Returns the OS process ID of the launched Chrome instance.
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }
}

impl Drop for LaunchedChrome {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Resolves the official branded Google Chrome binary on the current platform.
#[must_use]
pub fn resolve_chrome_binary(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.exists().then(|| path.to_path_buf());
    }

    if let Ok(env_path) = env::var("WAYBOUND_CHROME_BIN") {
        let candidate = PathBuf::from(env_path);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        ]
    } else {
        &[
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
        ]
    };

    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

/// Spawns an unmodified Google Chrome process with zero automation/CDP flags.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Chrome cannot be found or spawned.
pub fn launch_chrome(options: &ChromeLaunchOptions) -> Result<LaunchedChrome> {
    let binary = resolve_chrome_binary(options.binary_path.as_deref()).ok_or_else(|| {
        WayboundError::BackendUnavailable {
            backend: "chrome_launcher".to_owned(),
            reason: "official Google Chrome binary not found (set WAYBOUND_CHROME_BIN to override)"
                .to_owned(),
        }
    })?;

    let mut cmd = Command::new(&binary);
    let _ = cmd
        .arg("--force-renderer-accessibility")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(profile_dir) = &options.profile_dir {
        std::fs::create_dir_all(profile_dir).map_err(WayboundError::Io)?;
        let first_run = profile_dir.join("First Run");
        if !first_run.exists() {
            let _ = std::fs::File::create(&first_run);
        }
        let _ = cmd.arg(format!("--user-data-dir={}", profile_dir.display()));
    }
    if let Some(keylog) = &options.ssl_keylog_file {
        let _ = cmd.env("SSLKEYLOGFILE", keylog);
    }
    if let Some(url) = &options.initial_url {
        let _ = cmd.arg(url);
    }

    let child = cmd.spawn().map_err(WayboundError::Io)?;
    let pid = i32::try_from(child.id()).map_err(|_| WayboundError::BackendUnavailable {
        backend: "chrome_launcher".to_owned(),
        reason: "spawned Chrome PID exceeded i32 range".to_owned(),
    })?;

    tracing::info!(pid, binary = %binary.display(), "launched unmodified Google Chrome");
    Ok(LaunchedChrome { child, pid })
}
