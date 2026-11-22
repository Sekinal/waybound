//! Control daemon binary for `waybound`.
//!
//! Orchestrates platform backends and serves semantic automation requests to
//! client SDKs over a local Unix domain socket.

mod launcher;
mod mock_driver;
mod net_tap;
mod peer;
mod proxy;
mod server;

use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tracing_subscriber::EnvFilter;
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
use waybound_net::{HostBlocker, InflightCounter, KeyLogStore};

#[allow(clippy::struct_excessive_bools)]
struct CliArgs {
    socket_path: Option<PathBuf>,
    tcp_addr: Option<String>,
    backend: String,
    pid: Option<i32>,
    serial: Option<String>,
    display: Option<String>,
    headless_xvfb: bool,
    launch_chrome: bool,
    launch_waydroid: bool,
    instance_id: Option<String>,
    adb_port: Option<u16>,
    profile_dir: Option<PathBuf>,
    ssl_keylog_file: Option<PathBuf>,
    initial_url: Option<String>,
    proxy: Option<String>,
    block_hosts: Vec<String>,
    timezone: Option<String>,
    locale: Option<String>,
    focus: bool,
    no_motion: bool,
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_args() -> Result<CliArgs, String> {
    let mut cli = CliArgs {
        socket_path: env::var("WAYBOUND_SOCKET").ok().map(PathBuf::from),
        tcp_addr: env::var("WAYBOUND_TCP_ADDR").ok(),
        backend: "mock".to_owned(),
        pid: None,
        serial: None,
        display: None,
        headless_xvfb: false,
        launch_chrome: false,
        launch_waydroid: false,
        instance_id: None,
        adb_port: None,
        profile_dir: None,
        ssl_keylog_file: None,
        initial_url: None,
        proxy: env::var("WAYBOUND_PROXY").ok(),
        block_hosts: Vec::new(),
        timezone: None,
        locale: None,
        focus: false,
        no_motion: false,
    };

    let mut args = env::args().skip(1);
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
            "--proxy" => cli.proxy = Some(next_arg(&mut args, "--proxy")?),
            "--block-host" => cli.block_hosts.push(next_arg(&mut args, "--block-host")?),
            "--block-hosts" => {
                let csv = next_arg(&mut args, "--block-hosts")?;
                for host in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    cli.block_hosts.push(host.to_owned());
                }
            }
            "--timezone" => cli.timezone = Some(next_arg(&mut args, "--timezone")?),
            "--locale" => cli.locale = Some(next_arg(&mut args, "--locale")?),
            "--focus" => cli.focus = true,
            "--no-motion" => cli.no_motion = true,
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(cli)
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
) -> Result<(Option<String>, Option<ProxyForwarder>), String> {
    let blocker = HostBlocker::new(block_hosts);
    let tap = ssl_keylog.map(|path| {
        let store = Arc::clone(responses);
        PassiveTapConfig {
            keylog: KeyLogStore::new(path),
            inflight: inflight.clone(),
            on_response: Arc::new(move |seq, resp| {
                store.upsert(seq, resp);
            }),
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
    driver: Arc<dyn Driver>,
    use_motion: bool,
    _launched: Option<launcher::LaunchedChrome>,
    _proxy_forwarder: Option<ProxyForwarder>,
    _waydroid: Option<WaydroidSession>,
    _xvfb: Option<HeadlessDisplaySession>,
}

fn launch_desktop_chrome(
    cli: &CliArgs,
    display: Option<String>,
    responses: &Arc<ResponseStore>,
    inflight: &InflightCounter,
) -> Result<(i32, launcher::LaunchedChrome, Option<ProxyForwarder>), String> {
    let (chrome_proxy_server, proxy_fwd) = setup_proxy(
        cli.proxy.clone(),
        &cli.block_hosts,
        cli.ssl_keylog_file.as_ref(),
        responses,
        inflight,
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
        focus: cli.focus,
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
) -> Result<BackendBundle, String> {
    match cli.backend.as_str() {
        "mock" => Ok(BackendBundle {
            driver: Arc::new(MockDriver::sample_page()),
            use_motion: false,
            _launched: None,
            _proxy_forwarder: None,
            _waydroid: None,
            _xvfb: None,
        }),
        "android" => {
            let (serial, waydroid_session, proxy_fwd) = if cli.launch_waydroid {
                let (local_proxy, fwd) = setup_proxy(
                    cli.proxy,
                    &cli.block_hosts,
                    cli.ssl_keylog_file.as_ref(),
                    responses,
                    inflight,
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
                _proxy_forwarder: proxy_fwd,
                _waydroid: waydroid_session,
                _xvfb: None,
            })
        }
        "macos" => {
            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (pid, chrome, proxy_fwd) =
                    launch_desktop_chrome(&cli, None, responses, inflight)?;
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
                _proxy_forwarder: fwd,
                _waydroid: None,
                _xvfb: None,
            })
        }
        "linux" => {
            let (xvfb_session, display_env) = if cli.headless_xvfb {
                let session = HeadlessDisplaySession::start(HeadlessDisplayConfig::default())
                    .map_err(|e| e.to_string())?;
                let disp = session.display();
                (Some(session), Some(disp))
            } else {
                (None, cli.display.clone())
            };

            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (pid, chrome, proxy_fwd) =
                    launch_desktop_chrome(&cli, display_env.clone(), responses, inflight)?;
                (Some(pid), Some(chrome), proxy_fwd)
            } else {
                (cli.pid, None, None)
            };

            tracing::info!(pid = ?target_pid, ?display_env, "starting linux desktop driver");
            Ok(BackendBundle {
                driver: Arc::new(LinuxDriver::with_display(target_pid, display_env)),
                use_motion: !cli.no_motion,
                _launched: launched,
                _proxy_forwarder: fwd,
                _waydroid: None,
                _xvfb: xvfb_session,
            })
        }
        "windows" => {
            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (pid, chrome, proxy_fwd) =
                    launch_desktop_chrome(&cli, None, responses, inflight)?;
                (Some(pid), Some(chrome), proxy_fwd)
            } else {
                (cli.pid, None, None)
            };

            tracing::info!(pid = ?target_pid, "starting windows native driver");
            Ok(BackendBundle {
                driver: Arc::new(WindowsDriver::new(target_pid)),
                use_motion: !cli.no_motion,
                _launched: launched,
                _proxy_forwarder: fwd,
                _waydroid: None,
                _xvfb: None,
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

    let bundle = match build_backend(cli, &responses, &inflight) {
        Ok(bundle) => bundle,
        Err(msg) => {
            tracing::error!(error = %msg, "failed to initialize backend");
            return ExitCode::FAILURE;
        }
    };

    let options = ServerOptions {
        use_motion: bundle.use_motion,
        inflight,
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
