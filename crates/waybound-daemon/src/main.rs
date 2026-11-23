//! Control daemon binary for `waybound`.
//!
//! Orchestrates platform backends and serves semantic automation requests to
//! client SDKs over a local Unix domain socket.

mod launcher;
mod mock_driver;
mod net_tap;
mod peer;
mod proxy;
#[cfg(feature = "replay")]
mod replay;
mod server;

use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tracing_subscriber::EnvFilter;
use waybound_compositor::{CompositorConfig, HeadlessCompositor};
use waybound_core::Driver;
use waybound_driver_android::{AndroidDriver, WaydroidConfig, WaydroidSession};
use waybound_driver_linux::{HeadlessDisplayConfig, HeadlessDisplaySession, LinuxDriver};
use waybound_driver_macos::MacOsDriver;
use waybound_driver_windows::WindowsDriver;

use crate::launcher::{ChromeLaunchOptions, launch_chrome};
use crate::mock_driver::MockDriver;
use crate::net_tap::{ResponseStore, start_passive_tap};
use crate::proxy::{PassiveTapConfig, ProxyForwarder, UpstreamProxy};
use crate::server::ServerOptions;
use waybound_net::{
    FingerprintRecorder, HostBlocker, InflightCounter, KeyLogStore, expand_block_presets,
};

#[allow(clippy::struct_excessive_bools)]
struct CliArgs {
    socket_path: Option<PathBuf>,
    tcp_addr: Option<String>,
    backend: String,
    pid: Option<i32>,
    serial: Option<String>,
    display: Option<String>,
    headless_xvfb: bool,
    headless_wayland: bool,
    launch_chrome: bool,
    launch_waydroid: bool,
    instance_id: Option<String>,
    adb_port: Option<u16>,
    profile_dir: Option<PathBuf>,
    ssl_keylog_file: Option<PathBuf>,
    initial_url: Option<String>,
    proxy: Option<String>,
    /// Whether `proxy` came from `--proxy` (world-readable argv) rather than `WAYBOUND_PROXY`.
    proxy_from_argv: bool,
    block_hosts: Vec<String>,
    block_presets: Vec<String>,
    timezone: Option<String>,
    locale: Option<String>,
    focus: bool,
    no_motion: bool,
    replay: bool,
    exit_with_parent: ParentWatch,
}

/// Which process `--exit-with-parent` / `WAYBOUND_EXIT_WITH_PARENT` watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentWatch {
    /// Not requested.
    Off,
    /// Watch whatever the parent is when the watchdog starts (`--exit-with-parent`, or a
    /// non-pid value such as `1` in the environment variable).
    Current,
    /// Watch this pid (the SDK passes its own pid, so a parent that died before the watchdog
    /// started is still noticed).
    Pid(u32),
}

/// Parses the `WAYBOUND_EXIT_WITH_PARENT` value.
fn parse_parent_watch(raw: Option<&str>) -> ParentWatch {
    match raw.map(str::trim) {
        None | Some("" | "0") => ParentWatch::Off,
        Some(value) => match value.parse::<u32>() {
            Ok(pid) if pid > 1 => ParentWatch::Pid(pid),
            _ => ParentWatch::Current,
        },
    }
}

/// Parses `WAYBOUND_REAP_PGID`: a process group the SDK started for this daemon's helpers
/// (a pool slot's Xvfb, D-Bus and AT-SPI2), to be stopped when the daemon shuts down. Only a
/// positive group id other than 0, 1 and the daemon's own group (the SDK makes the daemon a
/// session leader, so its group id is its pid) is accepted.
fn parse_reap_pgid(raw: Option<&str>, own_pid: u32) -> Option<i32> {
    let pgid = raw?.trim().parse::<i32>().ok()?;
    let valid = pgid > 1 && u32::try_from(pgid).is_ok_and(|p| p != own_pid);
    valid.then_some(pgid)
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_args() -> Result<CliArgs, String> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from(args: impl IntoIterator<Item = String>) -> Result<CliArgs, String> {
    let mut cli = CliArgs {
        socket_path: env::var("WAYBOUND_SOCKET").ok().map(PathBuf::from),
        tcp_addr: env::var("WAYBOUND_TCP_ADDR").ok(),
        backend: "mock".to_owned(),
        pid: None,
        serial: None,
        display: None,
        headless_xvfb: false,
        headless_wayland: false,
        launch_chrome: false,
        launch_waydroid: false,
        instance_id: None,
        adb_port: None,
        profile_dir: None,
        ssl_keylog_file: None,
        initial_url: None,
        proxy: env::var("WAYBOUND_PROXY").ok(),
        proxy_from_argv: false,
        block_hosts: Vec::new(),
        block_presets: Vec::new(),
        timezone: None,
        locale: None,
        focus: false,
        no_motion: false,
        replay: false,
        exit_with_parent: parse_parent_watch(env::var("WAYBOUND_EXIT_WITH_PARENT").ok().as_deref()),
    };

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => cli.socket_path = Some(PathBuf::from(next_arg(&mut args, "--socket")?)),
            "--tcp" => cli.tcp_addr = Some(next_arg(&mut args, "--tcp")?),
            "--backend" => cli.backend = next_arg(&mut args, "--backend")?,
            "--pid" => {
                let val = next_arg(&mut args, "--pid")?;
                let parsed = val
                    .parse::<i32>()
                    .map_err(|_| format!("invalid --pid value: {val}"))?;
                if parsed <= 0 {
                    return Err(format!("--pid must be positive, got {parsed}"));
                }
                cli.pid = Some(parsed);
            }
            "--serial" => cli.serial = Some(next_arg(&mut args, "--serial")?),
            "--display" => cli.display = Some(next_arg(&mut args, "--display")?),
            "--headless-xvfb" => cli.headless_xvfb = true,
            "--headless-wayland" => cli.headless_wayland = true,
            "--launch-chrome" => cli.launch_chrome = true,
            "--launch-waydroid" => cli.launch_waydroid = true,
            "--instance-id" => cli.instance_id = Some(next_arg(&mut args, "--instance-id")?),
            "--adb-port" => {
                let val = next_arg(&mut args, "--adb-port")?;
                let parsed = val
                    .parse::<u16>()
                    .map_err(|_| format!("invalid --adb-port value: {val}"))?;
                cli.adb_port = Some(parsed);
            }
            "--profile-dir" => {
                cli.profile_dir = Some(PathBuf::from(next_arg(&mut args, "--profile-dir")?));
            }
            "--ssl-keylog" => {
                cli.ssl_keylog_file = Some(PathBuf::from(next_arg(&mut args, "--ssl-keylog")?));
            }
            "--url" => cli.initial_url = Some(next_arg(&mut args, "--url")?),
            "--proxy" => {
                cli.proxy = Some(next_arg(&mut args, "--proxy")?);
                cli.proxy_from_argv = true;
            }
            "--block-host" => cli.block_hosts.push(next_arg(&mut args, "--block-host")?),
            "--block-hosts" => {
                let csv = next_arg(&mut args, "--block-hosts")?;
                for host in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    cli.block_hosts.push(host.to_owned());
                }
            }
            "--block-preset" => cli
                .block_presets
                .push(next_arg(&mut args, "--block-preset")?),
            "--timezone" => cli.timezone = Some(next_arg(&mut args, "--timezone")?),
            "--locale" => cli.locale = Some(next_arg(&mut args, "--locale")?),
            "--focus" => cli.focus = true,
            "--no-motion" => cli.no_motion = true,
            "--exit-with-parent" => cli.exit_with_parent = ParentWatch::Current,
            "--replay" => cli.replay = true,
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    if cli.headless_xvfb && cli.headless_wayland {
        return Err("--headless-xvfb and --headless-wayland are mutually exclusive".to_owned());
    }

    if !cli.block_presets.is_empty() {
        let expanded = expand_block_presets(&cli.block_presets)?;
        cli.block_hosts.extend(expanded);
    }

    Ok(cli)
}

static WAYLAND_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII guard that removes a temporary directory when dropped.
struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_wayland_runtime_dir() -> std::io::Result<PathBuf> {
    let unique = WAYLAND_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!(
        "waybound-wl-daemon-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

#[cfg(unix)]
fn default_user_socket_path() -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(format!("/tmp/waybound-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir.join("w.sock"))
}

fn setup_proxy(
    raw: Option<String>,
    block_hosts: &[String],
    ssl_keylog: Option<&PathBuf>,
    responses: &Arc<ResponseStore>,
    inflight: &InflightCounter,
    fingerprint: &FingerprintRecorder,
) -> Result<(Option<String>, Option<ProxyForwarder>), String> {
    let blocker = HostBlocker::new(block_hosts);
    let tap = ssl_keylog.map(|path| {
        let store = Arc::clone(responses);
        let ws_store = Arc::clone(responses);
        PassiveTapConfig {
            keylog: KeyLogStore::new(path),
            inflight: inflight.clone(),
            fingerprint: fingerprint.clone(),
            on_response: Arc::new(move |seq, resp| {
                store.upsert(seq, resp);
            }),
            on_websocket: Some(Arc::new(move |frame| {
                ws_store.push_websocket_frame(frame);
            })),
        }
    });

    let needs_local_relay =
        !blocker.is_empty() || tap.is_some() || raw.as_deref().is_some_and(|p| p.contains('@'));

    if !needs_local_relay {
        return Ok((raw, None));
    }

    let upstream = match raw {
        Some(raw_proxy) => Some(UpstreamProxy::parse(&raw_proxy)?),
        None => None,
    };
    let fwd =
        ProxyForwarder::start_with_options(upstream, blocker, tap).map_err(|e| e.to_string())?;
    Ok((Some(fwd.chrome_proxy_arg()), Some(fwd)))
}

struct BackendBundle {
    // Drop Chrome before the driver/compositor and runtime dir so Chrome never sees the
    // Wayland socket disappear while it is still running.
    launched_browser: Option<launcher::LaunchedChrome>,
    driver: Arc<dyn Driver>,
    use_motion: bool,
    proxy_forwarder: Option<ProxyForwarder>,
    _waydroid: Option<WaydroidSession>,
    _xvfb: Option<HeadlessDisplaySession>,
    _wayland_runtime_dir: Option<TempDirGuard>,
}

impl BackendBundle {
    fn server_options(
        &self,
        inflight: InflightCounter,
        fingerprint: FingerprintRecorder,
    ) -> ServerOptions {
        ServerOptions {
            use_motion: self.use_motion,
            inflight,
            fingerprint,
            proxy_stats: self
                .proxy_forwarder
                .as_ref()
                .map(ProxyForwarder::stats_handle),
            browser: self
                .launched_browser
                .as_ref()
                .map(launcher::LaunchedChrome::probe),
        }
    }
}

fn launch_desktop_chrome(
    cli: &CliArgs,
    display: Option<String>,
    wayland_display: Option<(String, PathBuf)>,
    responses: &Arc<ResponseStore>,
    inflight: &InflightCounter,
    fingerprint: &FingerprintRecorder,
) -> Result<(i32, launcher::LaunchedChrome, Option<ProxyForwarder>), String> {
    let (chrome_proxy_server, proxy_fwd) = setup_proxy(
        cli.proxy.clone(),
        &cli.block_hosts,
        cli.ssl_keylog_file.as_ref(),
        responses,
        inflight,
        fingerprint,
    )?;
    let opts = ChromeLaunchOptions {
        binary_path: None,
        profile_dir: cli.profile_dir.clone(),
        ssl_keylog_file: cli.ssl_keylog_file.clone(),
        initial_url: cli.initial_url.clone(),
        proxy_server: chrome_proxy_server,
        timezone: cli.timezone.clone(),
        locale: cli.locale.clone(),
        display,
        wayland_display,
        focus: cli.focus,
    };
    let chrome = launch_chrome(&opts).map_err(|e| e.to_string())?;
    let pid = chrome.pid();
    Ok((pid, chrome, proxy_fwd))
}

/// Builds the `Xvfb` configuration for `--headless-xvfb`.
///
/// `--display :N` selects the virtual display number, so several daemons on one host
/// (for example a Python `BrowserPool`) can each own a distinct `Xvfb` server instead of
/// all colliding on the default `:99`.
fn headless_display_config(display: Option<&str>) -> Result<HeadlessDisplayConfig, String> {
    let mut config = HeadlessDisplayConfig::default();
    if let Some(raw) = display {
        let invalid =
            || format!("--display {raw:?} must look like :N when combined with --headless-xvfb");
        let without_colon = raw.strip_prefix(':').unwrap_or(raw);
        let (number, screen) = match without_colon.split_once('.') {
            Some((number, screen)) => (number, Some(screen)),
            None => (without_colon, None),
        };
        let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !all_digits(number) || screen.is_some_and(|s| !all_digits(s)) {
            return Err(invalid());
        }
        config.display_num = number.parse::<u16>().map_err(|_| invalid())?;
    }
    Ok(config)
}

#[allow(clippy::too_many_lines)]
fn build_backend(
    cli: CliArgs,
    responses: &Arc<ResponseStore>,
    inflight: &InflightCounter,
    fingerprint: &FingerprintRecorder,
) -> Result<BackendBundle, String> {
    match cli.backend.as_str() {
        "mock" => Ok(BackendBundle {
            driver: Arc::new(MockDriver::sample_page()),
            use_motion: false,
            launched_browser: None,
            proxy_forwarder: None,
            _waydroid: None,
            _xvfb: None,
            _wayland_runtime_dir: None,
        }),
        "android" => {
            let (serial, waydroid_session, proxy_fwd) = if cli.launch_waydroid {
                let (local_proxy, fwd) = setup_proxy(
                    cli.proxy,
                    &cli.block_hosts,
                    cli.ssl_keylog_file.as_ref(),
                    responses,
                    inflight,
                    fingerprint,
                )?;
                let android_proxy = local_proxy.map(|p| {
                    p.strip_prefix("http://")
                        .map_or_else(|| p.clone(), ToOwned::to_owned)
                });
                let instance_id = cli
                    .instance_id
                    .unwrap_or_else(|| format!("wb-{}", std::process::id()));
                let data_dir = cli
                    .profile_dir
                    .unwrap_or_else(|| PathBuf::from(format!("/tmp/waybound-wd-{instance_id}")));
                let wd_cfg = WaydroidConfig {
                    instance_id,
                    data_dir,
                    adb_port: cli.adb_port.unwrap_or(5555),
                    headless: true,
                    android_http_proxy: android_proxy,
                    timezone: cli.timezone,
                };
                let session = WaydroidSession::start(wd_cfg).map_err(|e| e.to_string())?;
                let s = session.serial();
                (Some(s), Some(session), fwd)
            } else {
                (cli.serial, None, None)
            };

            let android = AndroidDriver::new(serial);
            if let Some(url) = &cli.initial_url {
                android.open_url(url).map_err(|e| e.to_string())?;
            }
            tracing::info!(serial = ?android.serial(), "starting android/waydroid driver");
            Ok(BackendBundle {
                driver: Arc::new(android),
                use_motion: !cli.no_motion,
                launched_browser: None,
                proxy_forwarder: proxy_fwd,
                _waydroid: waydroid_session,
                _xvfb: None,
                _wayland_runtime_dir: None,
            })
        }
        "macos" => {
            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (pid, chrome, proxy_fwd) =
                    launch_desktop_chrome(&cli, None, None, responses, inflight, fingerprint)?;
                (pid, Some(chrome), proxy_fwd)
            } else if let Some(pid) = cli.pid {
                (pid, None, None)
            } else {
                return Err(
                    "--backend macos requires either --pid <pid> or --launch-chrome".to_owned(),
                );
            };
            tracing::info!(pid = target_pid, "starting macos native driver");
            Ok(BackendBundle {
                driver: Arc::new(MacOsDriver::new(target_pid)),
                use_motion: !cli.no_motion,
                launched_browser: launched,
                proxy_forwarder: fwd,
                _waydroid: None,
                _xvfb: None,
                _wayland_runtime_dir: None,
            })
        }
        "linux" => {
            let (xvfb_session, display_env, compositor, wayland_runtime_guard) =
                if cli.headless_wayland {
                    let runtime_dir = create_wayland_runtime_dir().map_err(|e| e.to_string())?;
                    let guard = TempDirGuard(runtime_dir.clone());
                    let comp = Arc::new(
                        HeadlessCompositor::start(CompositorConfig {
                            runtime_dir: Some(runtime_dir),
                            ..CompositorConfig::default()
                        })
                        .map_err(|e| e.to_string())?,
                    );
                    (None, None, Some(comp), Some(guard))
                } else if cli.headless_xvfb {
                    let config = headless_display_config(cli.display.as_deref())?;
                    let session =
                        HeadlessDisplaySession::start(config).map_err(|e| e.to_string())?;
                    let disp = session.display();
                    (Some(session), Some(disp), None, None)
                } else {
                    (None, cli.display.clone(), None, None)
                };

            let wayland_display = compositor
                .as_ref()
                .map(|c| (c.socket_name().to_owned(), c.runtime_dir().to_path_buf()));

            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (pid, chrome, proxy_fwd) = launch_desktop_chrome(
                    &cli,
                    display_env.clone(),
                    wayland_display,
                    responses,
                    inflight,
                    fingerprint,
                )?;
                (Some(pid), Some(chrome), proxy_fwd)
            } else {
                (cli.pid, None, None)
            };

            let driver: Arc<dyn Driver> = compositor.map_or_else(
                || {
                    tracing::info!(pid = ?target_pid, ?display_env, "starting linux desktop driver");
                    Arc::new(LinuxDriver::with_display(target_pid, display_env))
                },
                |comp| {
                    tracing::info!(
                        pid = ?target_pid,
                        socket = %comp.socket_name(),
                        "starting linux headless wayland driver"
                    );
                    Arc::new(LinuxDriver::with_compositor(target_pid, comp))
                },
            );

            Ok(BackendBundle {
                driver,
                use_motion: !cli.no_motion,
                launched_browser: launched,
                proxy_forwarder: fwd,
                _waydroid: None,
                _xvfb: xvfb_session,
                _wayland_runtime_dir: wayland_runtime_guard,
            })
        }
        "windows" => {
            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (pid, chrome, proxy_fwd) =
                    launch_desktop_chrome(&cli, None, None, responses, inflight, fingerprint)?;
                (Some(pid), Some(chrome), proxy_fwd)
            } else {
                (cli.pid, None, None)
            };

            tracing::info!(pid = ?target_pid, "starting windows native driver");
            Ok(BackendBundle {
                driver: Arc::new(WindowsDriver::new(target_pid)),
                use_motion: !cli.no_motion,
                launched_browser: launched,
                proxy_forwarder: fwd,
                _waydroid: None,
                _xvfb: None,
                _wayland_runtime_dir: None,
            })
        }
        other => Err(format!(
            "unknown backend {other:?} (expected 'mock', 'macos', 'linux', 'windows', or 'android')"
        )),
    }
}

/// How often `--exit-with-parent` checks whether the process that started the daemon is gone.
const PARENT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// With `--exit-with-parent` (or `WAYBOUND_EXIT_WITH_PARENT=<pid>`), request the normal
/// graceful shutdown (the same path as `SIGTERM`: held buttons released, Chrome and Xvfb
/// stopped) as soon as the watched parent is no longer our parent, i.e. the SDK process that
/// launched the daemon died, however it died (`SIGKILL` included). The SDK starts the daemon
/// in its own process group, so signals sent to the caller's group no longer reach it.
#[cfg(unix)]
fn watch_parent(shutdown: Arc<AtomicBool>, watch: ParentWatch) {
    let original = match watch {
        ParentWatch::Off => return,
        ParentWatch::Current => std::os::unix::process::parent_id(),
        ParentWatch::Pid(pid) => pid,
    };
    let spawned = thread::Builder::new()
        .name("waybound-parent-watch".to_owned())
        .spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                if std::os::unix::process::parent_id() != original {
                    tracing::info!(original, "parent process exited; shutting down");
                    shutdown.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(PARENT_POLL_INTERVAL);
            }
        });
    if let Err(err) = spawned {
        tracing::warn!(error = %err, "failed to start the parent watchdog");
    }
}

/// Windows has no reparenting to observe; `--exit-with-parent` is accepted and ignored.
#[cfg(not(unix))]
fn watch_parent(_shutdown: Arc<AtomicBool>, _watch: ParentWatch) {
    tracing::warn!("--exit-with-parent is not supported on this platform; ignoring it");
}

#[cfg(unix)]
const TERMINATION_SIGNALS: &[i32] = &[
    signal_hook::consts::SIGTERM,
    signal_hook::consts::SIGINT,
    signal_hook::consts::SIGHUP,
];
#[cfg(not(unix))]
const TERMINATION_SIGNALS: &[i32] = &[signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT];

fn run_replay_mode() -> ExitCode {
    #[cfg(feature = "replay")]
    {
        replay::run_replay_stdio()
    }
    #[cfg(not(feature = "replay"))]
    {
        tracing::error!(
            "waybound-daemon was built without `--features replay`; rebuild with `cargo build -p waybound-daemon --features replay`"
        );
        ExitCode::FAILURE
    }
}

/// Grace period between `SIGTERM` and `SIGKILL` when stopping `WAYBOUND_REAP_PGID`.
const REAP_GRACE: Duration = Duration::from_secs(2);

/// Sends `signal` (a `kill` name such as `TERM`, or `0` to probe) to every process in `pgid`.
/// The daemon forbids `unsafe`, so this goes through the `kill` utility.
#[cfg(unix)]
fn signal_group(signal: &str, pgid: i32) -> bool {
    waybound_core::process::command("kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{pgid}"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Stops the helper process group named by `WAYBOUND_REAP_PGID`: `SIGTERM` (Xvfb then removes
/// its lock file), then `SIGKILL` for whatever is left after a short grace period.
#[cfg(unix)]
fn reap_process_group(pgid: i32) {
    if !signal_group("TERM", pgid) {
        return; // the group is already gone (or `kill` is unavailable)
    }
    let deadline = Instant::now() + REAP_GRACE;
    while Instant::now() < deadline {
        if !signal_group("0", pgid) {
            tracing::info!(pgid, "stopped helper process group");
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    tracing::warn!(pgid, "helper process group ignored SIGTERM; killing it");
    let _ = signal_group("KILL", pgid);
}

#[cfg(not(unix))]
fn reap_process_group(_pgid: i32) {}

fn main() -> ExitCode {
    // Read before `run` so it applies however `run` returns; validated against our own pid.
    let reap_pgid = parse_reap_pgid(
        env::var("WAYBOUND_REAP_PGID").ok().as_deref(),
        std::process::id(),
    );
    let code = run();
    if let Some(pgid) = reap_pgid {
        reap_process_group(pgid);
    }
    code
}

#[allow(clippy::too_many_lines)]
fn run() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            tracing::error!(error = %msg, "invalid CLI arguments");
            return ExitCode::FAILURE;
        }
    };

    if cli.replay {
        return run_replay_mode();
    }

    if cli.proxy_from_argv && cli.proxy.as_deref().is_some_and(|p| p.contains('@')) {
        // Never log the value itself.
        tracing::warn!(
            "--proxy carries credentials on the command line, where every local user can read \
             them; pass the proxy in the WAYBOUND_PROXY environment variable instead"
        );
    }

    let tcp_addr = cli.tcp_addr.clone();
    let socket_path_arg = cli.socket_path.clone();

    // Termination signals take the same graceful path as the `shutdown` request, so the
    // RAII guards below (Chrome, tshark, proxy forwarder, Waydroid, Xvfb, socket file) are
    // dropped. Registered before any child process is spawned.
    let shutdown = Arc::new(AtomicBool::new(false));
    for signal in TERMINATION_SIGNALS {
        if let Err(err) = signal_hook::flag::register(*signal, Arc::clone(&shutdown)) {
            tracing::warn!(signal, error = %err, "failed to install signal handler");
        }
    }

    if cli.exit_with_parent != ParentWatch::Off {
        watch_parent(Arc::clone(&shutdown), cli.exit_with_parent);
    }

    let responses = Arc::new(ResponseStore::default());
    let inflight = InflightCounter::default();
    let fingerprint = FingerprintRecorder::new();
    // When `--launch-chrome` is set, the built-in zero-MITM local pass-through proxy handles
    // passive TLS 1.3 + HTTP/1.1–2 decryption in-process (zero tshark, zero CAP_NET_RAW).
    // Only fall back to external `tshark` when attaching to an already-running browser PID.
    let _net_tap = if cli.launch_chrome {
        None
    } else {
        cli.ssl_keylog_file.as_ref().and_then(|keylog| {
            match start_passive_tap(keylog, Arc::clone(&responses)) {
                Ok(tap) => Some(tap),
                Err(err) => {
                    tracing::warn!(error = %err, "passive network tap unavailable; continuing without capture");
                    None
                }
            }
        })
    };

    let bundle = match build_backend(cli, &responses, &inflight, &fingerprint) {
        Ok(bundle) => bundle,
        Err(msg) => {
            tracing::error!(error = %msg, "failed to initialize backend");
            return ExitCode::FAILURE;
        }
    };

    let options = bundle.server_options(inflight, fingerprint);

    if let Some(addr) = tcp_addr {
        if let Err(err) = server::serve_tcp(&addr, &bundle.driver, responses, options, shutdown) {
            tracing::error!(error = %err, "daemon tcp server terminated with error");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    #[cfg(unix)]
    {
        let socket_path = match socket_path_arg {
            Some(p) => p,
            None => match default_user_socket_path() {
                Ok(p) => p,
                Err(err) => {
                    tracing::error!(error = %err, "failed to create private socket directory");
                    return ExitCode::FAILURE;
                }
            },
        };
        if let Err(err) =
            server::serve_unix(&socket_path, &bundle.driver, responses, options, shutdown)
        {
            tracing::error!(error = %err, "daemon terminated with error");
            return ExitCode::FAILURE;
        }
        ExitCode::SUCCESS
    }

    #[cfg(not(unix))]
    {
        let _ = socket_path_arg;
        if let Err(err) = server::serve_tcp(
            "127.0.0.1:49222",
            &bundle.driver,
            responses,
            options,
            shutdown,
        ) {
            tracing::error!(error = %err, "daemon tcp server terminated with error");
            return ExitCode::FAILURE;
        }
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_expands_repeatable_block_presets_and_merges_with_hosts() {
        let parsed = parse_args_from([
            "--block-preset".to_owned(),
            "analytics".to_owned(),
            "--block-preset".to_owned(),
            "ads".to_owned(),
            "--block-host".to_owned(),
            "custom.tracker.test".to_owned(),
        ]);
        assert!(parsed.is_ok());
        if let Ok(cli) = parsed {
            let blocker = HostBlocker::new(&cli.block_hosts);
            assert!(blocker.is_blocked("www.google-analytics.com"));
            assert!(blocker.is_blocked("pagead2.googlesyndication.com"));
            assert!(blocker.is_blocked("custom.tracker.test"));
            assert!(!blocker.is_blocked("example.com"));
        }
    }

    #[test]
    fn parse_args_rejects_unknown_block_preset() {
        let err = parse_args_from(["--block-preset".to_owned(), "nonexistent".to_owned()]);
        assert!(
            matches!(err, Err(msg) if msg.contains("nonexistent") && msg.contains("analytics"))
        );
    }

    #[test]
    fn parse_args_accepts_headless_wayland_and_rejects_xvfb_combination() {
        let parsed = parse_args_from([
            "--backend".to_owned(),
            "linux".to_owned(),
            "--headless-wayland".to_owned(),
        ]);
        assert!(parsed.is_ok());
        if let Ok(cli) = parsed {
            assert!(cli.headless_wayland);
            assert!(!cli.headless_xvfb);
            assert_eq!(cli.backend, "linux");
        }

        let conflict = parse_args_from([
            "--headless-xvfb".to_owned(),
            "--headless-wayland".to_owned(),
        ]);
        assert!(matches!(conflict, Err(msg) if msg.contains("mutually exclusive")));
    }

    #[test]
    fn parent_watch_and_reap_pgid_are_validated() {
        assert_eq!(parse_parent_watch(None), ParentWatch::Off);
        assert_eq!(parse_parent_watch(Some("0")), ParentWatch::Off);
        assert_eq!(parse_parent_watch(Some("1")), ParentWatch::Current);
        assert_eq!(parse_parent_watch(Some("yes")), ParentWatch::Current);
        assert_eq!(parse_parent_watch(Some(" 4242 ")), ParentWatch::Pid(4242));

        assert_eq!(parse_reap_pgid(None, 10), None);
        assert_eq!(parse_reap_pgid(Some("0"), 10), None);
        assert_eq!(parse_reap_pgid(Some("1"), 10), None);
        assert_eq!(parse_reap_pgid(Some("-5"), 10), None);
        assert_eq!(parse_reap_pgid(Some("10"), 10), None); // our own group
        assert_eq!(parse_reap_pgid(Some("x"), 10), None);
        assert_eq!(parse_reap_pgid(Some("777"), 10), Some(777));
    }

    #[cfg(unix)]
    #[test]
    fn reap_process_group_stops_every_member() {
        use std::os::unix::process::CommandExt;

        let leader = waybound_core::process::command("sh")
            .args(["-c", "sleep 30 & sleep 30"])
            .process_group(0)
            .spawn();
        assert!(leader.is_ok());
        if let Ok(mut leader) = leader {
            let pgid = i32::try_from(leader.id()).unwrap_or(0);
            thread::sleep(Duration::from_millis(200));
            assert!(signal_group("0", pgid));
            reap_process_group(pgid);
            let _ = leader.wait();
            assert!(!signal_group("0", pgid), "group members survived");
        }
    }

    #[test]
    fn headless_display_defaults_to_99_and_honours_display_flag() {
        assert_eq!(headless_display_config(None).map(|c| c.display_num), Ok(99));
        assert_eq!(
            headless_display_config(Some(":105")).map(|c| c.display_num),
            Ok(105)
        );
        assert_eq!(
            headless_display_config(Some(":7.0")).map(|c| c.display_num),
            Ok(7)
        );
        assert_eq!(
            headless_display_config(Some("42")).map(|c| c.display_num),
            Ok(42)
        );
        assert!(headless_display_config(Some("localhost:1")).is_err());
        assert!(headless_display_config(Some(":")).is_err());
        assert!(headless_display_config(Some(":+5")).is_err());
        assert!(headless_display_config(Some(":1.junk")).is_err());
        assert!(headless_display_config(Some(":1.")).is_err());
        assert!(headless_display_config(Some(":70000")).is_err());
    }
}
