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
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    /// Capture interface for the attach-mode `tshark` tap (`--net-iface` / `WAYBOUND_NET_IFACE`).
    net_iface: Option<String>,
    block_hosts: Vec<String>,
    block_presets: Vec<String>,
    timezone: Option<String>,
    locale: Option<String>,
    password_store: Option<String>,
    focus: bool,
    no_motion: bool,
    replay: bool,
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_args() -> Result<CliArgs, String> {
    parse_args_from(env::args().skip(1))
}

fn password_store_arg(val: String) -> Result<String, String> {
    if launcher::PASSWORD_STORES.contains(&val.as_str()) {
        Ok(val)
    } else {
        Err(format!(
            "invalid --password-store value: {val} (expected one of {:?})",
            launcher::PASSWORD_STORES
        ))
    }
}

#[allow(clippy::too_many_lines)]
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
        net_iface: env::var("WAYBOUND_NET_IFACE").ok(),
        block_hosts: Vec::new(),
        block_presets: Vec::new(),
        timezone: None,
        locale: None,
        password_store: None,
        focus: false,
        no_motion: false,
        replay: false,
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
            "--net-iface" => cli.net_iface = Some(next_arg(&mut args, "--net-iface")?),
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
            "--password-store" => {
                cli.password_store = Some(password_store_arg(next_arg(
                    &mut args,
                    "--password-store",
                )?)?);
            }
            "--focus" => cli.focus = true,
            "--no-motion" => cli.no_motion = true,
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

/// Whether the daemon launches the browser itself and so routes it through the loopback
/// forwarder, whose in-process tap decrypts `--ssl-keylog` traffic (and applies `--proxy`).
fn launches_browser(cli: &CliArgs) -> bool {
    match cli.backend.as_str() {
        "macos" | "linux" | "windows" => cli.launch_chrome,
        "android" => cli.launch_waydroid,
        _ => false,
    }
}

/// What to do with `--ssl-keylog` when the daemon does not launch the browser itself.
#[derive(Debug, PartialEq, Eq)]
enum KeylogCapture<'a> {
    /// No keylog, or the in-process tap of a launched browser handles it.
    NotNeeded,
    /// A host `tshark` capture cannot see this backend's traffic; the keylog is ignored.
    Ignored(&'static str),
    /// Attaching to a desktop browser: run the `tshark` fallback with this keylog.
    Tshark(&'a Path),
}

/// Decides how `--ssl-keylog` is captured.
///
/// # Errors
///
/// Rejects `--ssl-keylog` with an explicit `--proxy` when attaching: the daemon cannot route an
/// already-running browser through the proxy and `tshark` only sees direct HTTPS on port 443,
/// so the capture would silently stay empty. An inherited `WAYBOUND_PROXY` is not rejected (it
/// is environment-wide configuration that is simply not applied when attaching).
fn keylog_capture(cli: &CliArgs) -> Result<KeylogCapture<'_>, String> {
    let Some(keylog) = cli.ssl_keylog_file.as_deref() else {
        return Ok(KeylogCapture::NotNeeded);
    };
    if launches_browser(cli) {
        return Ok(KeylogCapture::NotNeeded);
    }
    match cli.backend.as_str() {
        "android" => {
            return Ok(KeylogCapture::Ignored(
                "an attached Android device's traffic does not cross this host's capture \
                 interface; use --launch-waydroid for in-process capture",
            ));
        }
        "macos" | "linux" | "windows" => {}
        _ => {
            return Ok(KeylogCapture::Ignored(
                "this backend has no browser to capture",
            ));
        }
    }
    if cli.proxy_from_argv && cli.proxy.is_some() {
        return Err(
            "--ssl-keylog with --proxy requires the daemon to launch the browser \
                    (--launch-chrome): when attaching, the proxy is not applied and the tshark \
                    fallback cannot see proxied traffic"
                .to_owned(),
        );
    }
    Ok(KeylogCapture::Tshark(keylog))
}

/// Starts the `tshark` fallback when [`keylog_capture`] asks for it. Errors are logged; the
/// caller exits, since a session whose capture calls can never succeed is worse than none.
fn start_keylog_capture(
    cli: &CliArgs,
    responses: &Arc<ResponseStore>,
) -> Result<Option<net_tap::PassiveTap>, ()> {
    let attaches_desktop = matches!(cli.backend.as_str(), "macos" | "linux" | "windows");
    if cli.proxy.is_some() && attaches_desktop && !launches_browser(cli) {
        tracing::warn!("the proxy setting is not applied when attaching to a running browser");
    }
    match keylog_capture(cli) {
        Ok(KeylogCapture::NotNeeded) => Ok(None),
        Ok(KeylogCapture::Ignored(why)) => {
            tracing::warn!("--ssl-keylog is ignored: {why}");
            Ok(None)
        }
        Ok(KeylogCapture::Tshark(keylog)) => {
            start_passive_tap(keylog, cli.net_iface.as_deref(), Arc::clone(responses))
                .map(Some)
                .map_err(|err| {
                    tracing::error!(error = %err, "passive network tap (tshark) failed to start");
                })
        }
        Err(msg) => {
            tracing::error!(error = %msg, "unusable passive capture configuration");
            Err(())
        }
    }
}

struct BackendBundle {
    // Drop Chrome before the driver/compositor and runtime dir so Chrome never sees the
    // Wayland socket disappear while it is still running.
    _launched: Option<launcher::LaunchedChrome>,
    driver: Arc<dyn Driver>,
    use_motion: bool,
    proxy_forwarder: Option<ProxyForwarder>,
    _waydroid: Option<WaydroidSession>,
    _xvfb: Option<HeadlessDisplaySession>,
    _wayland_runtime_dir: Option<TempDirGuard>,
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
        password_store: cli.password_store.clone(),
    };
    let chrome = launch_chrome(&opts).map_err(|e| e.to_string())?;
    let pid = chrome.pid();
    Ok((pid, chrome, proxy_fwd))
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
            _launched: None,
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
                _launched: None,
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
                _launched: launched,
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
                    let session = HeadlessDisplaySession::start(HeadlessDisplayConfig::default())
                        .map_err(|e| e.to_string())?;
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
                _launched: launched,
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
                _launched: launched,
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

#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
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

    let responses = Arc::new(ResponseStore::default());
    let inflight = InflightCounter::default();
    let fingerprint = FingerprintRecorder::new();
    // When the daemon launches the browser, the built-in zero-MITM local pass-through proxy
    // handles passive decryption in-process (zero tshark, zero CAP_NET_RAW). Only fall back to
    // external `tshark` when attaching to a running desktop browser; running both would feed
    // the same store from two sequence counters. If that fallback cannot start, exit rather
    // than serve a session whose capture calls could never succeed.
    let Ok(_net_tap) = start_keylog_capture(&cli, &responses) else {
        return ExitCode::FAILURE;
    };

    let bundle = match build_backend(cli, &responses, &inflight, &fingerprint) {
        Ok(bundle) => bundle,
        Err(msg) => {
            tracing::error!(error = %msg, "failed to initialize backend");
            return ExitCode::FAILURE;
        }
    };

    let proxy_stats = bundle
        .proxy_forwarder
        .as_ref()
        .map(ProxyForwarder::stats_handle);
    let options = ServerOptions {
        use_motion: bundle.use_motion,
        inflight,
        fingerprint,
        proxy_stats,
    };

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

    /// Attach-mode arguments with a keylog, independent of the caller's environment.
    fn attach_cli(backend: &str) -> CliArgs {
        let parsed = parse_args_from(
            [
                "--backend",
                backend,
                "--pid",
                "42",
                "--ssl-keylog",
                "/tmp/keys.log",
            ]
            .map(str::to_owned),
        );
        assert!(parsed.is_ok());
        let mut cli = parsed.unwrap_or_else(|_| unreachable!());
        cli.proxy = None;
        cli.proxy_from_argv = false;
        cli.net_iface = None;
        cli
    }

    #[test]
    fn tshark_only_when_attaching_to_a_desktop_browser_with_a_keylog() {
        let keylog = Path::new("/tmp/keys.log");
        assert_eq!(
            keylog_capture(&attach_cli("macos")),
            Ok(KeylogCapture::Tshark(keylog))
        );

        let mut no_keylog = attach_cli("macos");
        no_keylog.ssl_keylog_file = None;
        assert_eq!(keylog_capture(&no_keylog), Ok(KeylogCapture::NotNeeded));

        let mut launched = attach_cli("linux");
        launched.launch_chrome = true;
        launched.proxy = Some("socks5://proxy.test:1080".to_owned());
        launched.proxy_from_argv = true;
        assert_eq!(keylog_capture(&launched), Ok(KeylogCapture::NotNeeded));

        let mut waydroid = attach_cli("android");
        waydroid.launch_waydroid = true;
        assert_eq!(keylog_capture(&waydroid), Ok(KeylogCapture::NotNeeded));
    }

    #[test]
    fn keylog_is_ignored_for_android_attach_and_mock() {
        assert!(matches!(
            keylog_capture(&attach_cli("android")),
            Ok(KeylogCapture::Ignored(_))
        ));
        assert!(matches!(
            keylog_capture(&attach_cli("mock")),
            Ok(KeylogCapture::Ignored(_))
        ));
    }

    #[test]
    fn only_an_explicit_proxy_rejects_attach_with_keylog() {
        let mut inherited = attach_cli("macos");
        inherited.proxy = Some("http://proxy.test:8080".to_owned());
        assert!(matches!(
            keylog_capture(&inherited),
            Ok(KeylogCapture::Tshark(_))
        ));

        let mut explicit = inherited;
        explicit.proxy_from_argv = true;
        assert!(keylog_capture(&explicit).is_err());
    }
}
