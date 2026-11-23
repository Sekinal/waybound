//! Unmodified official Google Chrome launcher with RAII process cleanup.
//!
//! Launches the stock browser binary with zero CDP/WebDriver automation flags
//! (only `--force-renderer-accessibility` so the OS accessibility tree is
//! eagerly populated), optionally configuring a profile directory and
//! `SSLKEYLOGFILE` for passive wire-level TLS inspection.

use std::env;
use std::fmt;
use std::fs::DirBuilder;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use waybound_core::{Result, WayboundError};

/// Options for launching a stock Google Chrome process.
#[derive(Debug, Clone)]
pub struct ChromeLaunchOptions {
    /// Optional explicit Chrome binary path.
    pub binary_path: Option<PathBuf>,
    /// Optional user data directory (`--user-data-dir`). When `None`, a private temporary
    /// profile is created and removed again when the browser handle is dropped.
    pub profile_dir: Option<PathBuf>,
    /// Optional path written to the `SSLKEYLOGFILE` environment variable.
    pub ssl_keylog_file: Option<PathBuf>,
    /// Optional initial URL opened at launch.
    pub initial_url: Option<String>,
    /// Optional `--proxy-server` endpoint (e.g., `http://127.0.0.1:<port>` or `socks5://...`).
    pub proxy_server: Option<String>,
    /// Optional OS-level timezone (`TZ` env var, e.g., `America/New_York`).
    pub timezone: Option<String>,
    /// Optional OS-level locale (`LANG` / `LC_ALL` env vars, e.g., `en_US.UTF-8`).
    pub locale: Option<String>,
    /// Optional X11 `DISPLAY` environment variable (e.g., `:99` for headless Xvfb on Linux).
    pub display: Option<String>,
    /// Optional Wayland display `(WAYLAND_DISPLAY, XDG_RUNTIME_DIR)` for headless compositor mode.
    pub wayland_display: Option<(String, PathBuf)>,
    /// Whether to bring the launched browser window to the foreground on macOS.
    pub focus: bool,
}

/// RAII handle owning a spawned Google Chrome process.
///
/// The `Child` is shared with [`BrowserProbe`], whose `try_wait` may *reap* the process. After
/// a reap the kernel can reuse the pid, so the raw [`LaunchedChrome::pid`] must never be
/// signalled: any future signal must go through the `Child` under the mutex, after checking
/// `try_wait` (as `Drop` does via `Child::kill`, which is a no-op on a reaped child).
pub struct LaunchedChrome {
    child: Arc<Mutex<Child>>,
    pid: i32,
    /// Temporary profile owned by this launch (removed on drop), if one was created.
    temp_profile: Option<PathBuf>,
}

impl LaunchedChrome {
    /// Returns the OS process ID of the launched Chrome instance.
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    /// Returns a cheap, shareable probe reporting whether this browser process still runs.
    #[must_use]
    pub fn probe(&self) -> BrowserProbe {
        BrowserProbe {
            child: Arc::clone(&self.child),
        }
    }
}

/// Liveness probe for a launched browser, shared with the request server so `ping` can
/// report a browser that exited (crashed, or handed off to another instance holding the
/// profile's `SingletonLock`) while the daemon itself is still up.
///
/// [`BrowserProbe::is_alive`] uses `Child::try_wait`, which reaps an exited browser; see
/// [`LaunchedChrome`] for why its raw pid must not be signalled afterwards.
#[derive(Clone)]
pub struct BrowserProbe {
    child: Arc<Mutex<Child>>,
}

impl BrowserProbe {
    /// Returns `true` while the launched browser process has not exited.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.child
            .lock()
            .is_ok_and(|mut child| matches!(child.try_wait(), Ok(None)))
    }
}

impl fmt::Debug for BrowserProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserProbe").finish_non_exhaustive()
    }
}

impl Drop for LaunchedChrome {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(dir) = self.temp_profile.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

static TEMP_PROFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates a fresh temporary profile directory (private, mode `0700`, on Unix).
///
/// `create` (not `create_dir_all`) is used so a pre-existing path, including one planted
/// by another local user, is an error rather than silently reused.
fn create_temp_profile_dir() -> std::io::Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let unique = TEMP_PROFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!(
        "waybound-profile-{}-{nanos:09}-{unique}",
        std::process::id()
    ));
    #[cfg(unix)]
    DirBuilder::new().mode(0o700).create(&dir)?;
    #[cfg(not(unix))]
    DirBuilder::new().create(&dir)?;
    Ok(dir)
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

    let candidates: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            PathBuf::from(
                "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            ),
        ]
    } else if cfg!(target_os = "windows") {
        let mut win_paths = vec![
            PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        ];
        if let Ok(local_app_data) = env::var("LOCALAPPDATA") {
            win_paths.push(
                PathBuf::from(local_app_data)
                    .join("Google")
                    .join("Chrome")
                    .join("Application")
                    .join("chrome.exe"),
            );
        }
        win_paths
    } else {
        vec![
            PathBuf::from("/usr/bin/google-chrome"),
            PathBuf::from("/usr/bin/google-chrome-stable"),
            PathBuf::from("/usr/bin/chromium"),
            PathBuf::from("/usr/bin/chromium-browser"),
        ]
    };

    candidates.into_iter().find(|p| p.exists())
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

    let mut cmd = waybound_core::process::command(&binary);
    let _ = cmd
        .arg("--force-renderer-accessibility")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Always pass `--user-data-dir`. Without it, a Chrome that is already running takes
    // over the launch (the new process forwards its arguments and exits), so the proxy,
    // `SSLKEYLOGFILE`, timezone and locale would be ignored and the driver would be left
    // targeting a dead pid inside the user's real profile.
    let (profile_dir, temp_profile) = if let Some(dir) = &options.profile_dir {
        std::fs::create_dir_all(dir).map_err(WayboundError::Io)?;
        (dir.clone(), None)
    } else {
        let dir = create_temp_profile_dir().map_err(WayboundError::Io)?;
        (dir.clone(), Some(dir))
    };
    let first_run = profile_dir.join("First Run");
    if !first_run.exists() {
        let _ = std::fs::File::create(&first_run);
    }
    let _ = cmd.arg(format!("--user-data-dir={}", profile_dir.display()));
    if let Some(keylog) = &options.ssl_keylog_file {
        let _ = cmd.env("SSLKEYLOGFILE", keylog);
    }
    if let Some(proxy_server) = &options.proxy_server {
        let _ = cmd.arg(format!("--proxy-server={proxy_server}"));
    }
    if let Some((wayland_display, runtime_dir)) = &options.wayland_display {
        let _ = cmd
            .arg("--ozone-platform=wayland")
            .arg("--disable-gpu")
            .arg("--disable-gpu-compositing")
            .arg("--disable-dev-shm-usage")
            .env("WAYLAND_DISPLAY", wayland_display)
            .env("XDG_RUNTIME_DIR", runtime_dir)
            .env_remove("DISPLAY");
    } else if let Some(display) = &options.display {
        let _ = cmd.env("DISPLAY", display);
    }
    if let Some(tz) = &options.timezone {
        let _ = cmd.env("TZ", tz);
    }
    if let Some(locale) = &options.locale {
        let _ = cmd.env("LANG", locale).env("LC_ALL", locale);
    }
    if let Some(url) = &options.initial_url {
        let _ = cmd.arg(url);
    }

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            if let Some(dir) = temp_profile {
                let _ = std::fs::remove_dir_all(dir);
            }
            return Err(WayboundError::Io(err));
        }
    };
    let pid = i32::try_from(child.id()).map_err(|_| WayboundError::BackendUnavailable {
        backend: "chrome_launcher".to_owned(),
        reason: "spawned Chrome PID exceeded i32 range".to_owned(),
    })?;

    tracing::info!(pid, binary = %binary.display(), "launched unmodified Google Chrome");
    if options.focus && cfg!(target_os = "macos") {
        focus_macos_pid(pid);
    }
    Ok(LaunchedChrome {
        child: Arc::new(Mutex::new(child)),
        pid,
        temp_profile,
    })
}

fn focus_macos_pid(pid: i32) {
    let script = format!(
        "tell application \"System Events\" to set frontmost of first process whose unix id is {pid} to true"
    );
    let _ = std::thread::Builder::new()
        .name("waybound-focus".to_owned())
        .spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(600));
            let _ = waybound_core::process::command("/usr/bin/osascript")
                .args(["-e", &script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        });
}

// The stand-in browser is a shell script, so these tests only run on Unix.
#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    use super::*;

    fn options(binary: &Path, profile_dir: Option<PathBuf>) -> ChromeLaunchOptions {
        ChromeLaunchOptions {
            binary_path: Some(binary.to_path_buf()),
            profile_dir,
            ssl_keylog_file: None,
            initial_url: None,
            proxy_server: None,
            timezone: None,
            locale: None,
            focus: false,
            display: None,
            wayland_display: None,
        }
    }

    /// Writes a stand-in "browser" that records its arguments and then idles.
    #[allow(clippy::literal_string_with_formatting_args)]
    fn fake_browser(dir: &Path) -> PathBuf {
        let script = dir.join("fake-chrome.sh");
        let body = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\nprintf 'WAYLAND_DISPLAY=%s\\nXDG_RUNTIME_DIR=%s\\nDISPLAY=%s\\n' \"${WAYLAND_DISPLAY:-}\" \"${XDG_RUNTIME_DIR:-}\" \"${DISPLAY:-}\" > \"$0.env\"\nexec sleep 30\n";
        assert!(std::fs::write(&script, body).is_ok());
        assert!(std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).is_ok());
        script
    }

    fn recorded_profile_dir(script: &Path) -> Option<PathBuf> {
        let args_file = PathBuf::from(format!("{}.args", script.display()));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(args) = std::fs::read_to_string(&args_file)
                && let Some(dir) = args
                    .lines()
                    .find_map(|line| line.strip_prefix("--user-data-dir="))
            {
                return Some(PathBuf::from(dir));
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn launch_without_profile_dir_uses_private_temp_profile_and_cleans_up() {
        let scratch = create_temp_profile_dir().unwrap_or_default();
        assert!(scratch.is_dir(), "could not create scratch dir");
        let script = fake_browser(&scratch);

        let launched = launch_chrome(&options(&script, None));
        assert!(launched.is_ok());
        let profile = recorded_profile_dir(&script);
        assert!(profile.is_some(), "--user-data-dir was not passed");

        if let Some(dir) = &profile {
            let mode = std::fs::metadata(dir).map(|m| m.permissions().mode() & 0o777);
            assert_eq!(mode.ok(), Some(0o700));
            assert!(dir.join("First Run").exists());
        }

        drop(launched);
        if let Some(dir) = &profile {
            assert!(!dir.exists(), "temporary profile was not removed on drop");
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn probe_reports_a_browser_that_exits() {
        let scratch = create_temp_profile_dir().unwrap_or_default();
        assert!(scratch.is_dir(), "could not create scratch dir");
        let script = scratch.join("short-lived.sh");
        assert!(std::fs::write(&script, "#!/bin/sh\nexit 0\n").is_ok());
        assert!(std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).is_ok());
        let long_lived = fake_browser(&scratch);

        let running = launch_chrome(&options(&long_lived, Some(scratch.join("p1"))));
        let exiting = launch_chrome(&options(&script, Some(scratch.join("p2"))));
        assert!(running.is_ok() && exiting.is_ok());
        if let (Ok(running), Ok(exiting)) = (running, exiting) {
            let probe = running.probe();
            assert!(probe.is_alive());
            let gone = exiting.probe();
            let deadline = Instant::now() + Duration::from_secs(5);
            while gone.is_alive() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(!gone.is_alive(), "exited browser still reported alive");
            drop(running);
            assert!(!probe.is_alive(), "killed browser still reported alive");
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn launch_with_explicit_profile_dir_keeps_it_on_drop() {
        let scratch = create_temp_profile_dir().unwrap_or_default();
        assert!(scratch.is_dir(), "could not create scratch dir");
        let script = fake_browser(&scratch);
        let explicit = scratch.join("profile");

        let launched = launch_chrome(&options(&script, Some(explicit.clone())));
        assert!(launched.is_ok());
        assert_eq!(recorded_profile_dir(&script), Some(explicit.clone()));

        drop(launched);
        assert!(
            explicit.exists(),
            "an explicit profile must never be deleted"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn launch_with_wayland_display_sets_ozone_flags_and_env() {
        let scratch = create_temp_profile_dir().unwrap_or_default();
        assert!(scratch.is_dir(), "could not create scratch dir");
        let script = fake_browser(&scratch);
        let runtime_dir = scratch.join("xdg");
        assert!(std::fs::create_dir_all(&runtime_dir).is_ok());

        let mut opts = options(&script, None);
        opts.display = Some(":99".to_owned());
        opts.wayland_display = Some(("wayland-wb-0".to_owned(), runtime_dir.clone()));

        let launched = launch_chrome(&opts);
        assert!(launched.is_ok());
        // Wait for fake script to write both .args and .env.
        assert!(recorded_profile_dir(&script).is_some());

        let args_text =
            std::fs::read_to_string(format!("{}.args", script.display())).unwrap_or_default();
        let args: Vec<&str> = args_text.lines().collect();
        assert!(args.contains(&"--ozone-platform=wayland"));
        assert!(args.contains(&"--disable-gpu"));
        assert!(args.contains(&"--disable-gpu-compositing"));
        assert!(args.contains(&"--disable-dev-shm-usage"));

        let env_file = PathBuf::from(format!("{}.env", script.display()));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut env_text = String::new();
        while Instant::now() < deadline {
            if let Ok(content) = std::fs::read_to_string(&env_file)
                && !content.is_empty()
            {
                env_text = content;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            env_text.contains("WAYLAND_DISPLAY=wayland-wb-0\n"),
            "missing WAYLAND_DISPLAY in {env_text:?}"
        );
        assert!(
            env_text.contains(&format!("XDG_RUNTIME_DIR={}\n", runtime_dir.display())),
            "missing XDG_RUNTIME_DIR in {env_text:?}"
        );
        assert!(
            env_text.contains("DISPLAY=\n"),
            "DISPLAY should be unset in Wayland mode, got {env_text:?}"
        );

        drop(launched);
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
