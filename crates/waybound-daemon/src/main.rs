//! Control daemon binary for `waybound`.
//!
//! Orchestrates platform backends and serves semantic automation requests to
//! client SDKs over a local Unix domain socket.

mod launcher;
mod mock_driver;
mod net_tap;
mod proxy;
mod server;

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;
use waybound_core::Driver;
use waybound_driver_android::{AndroidDriver, WaydroidConfig, WaydroidSession};
use waybound_driver_macos::MacOsDriver;

use crate::launcher::{ChromeLaunchOptions, launch_chrome};
use crate::mock_driver::MockDriver;
use crate::net_tap::{ResponseStore, start_passive_tap};
use crate::proxy::{ProxyForwarder, UpstreamProxy};
use crate::server::ServerOptions;

#[allow(clippy::struct_excessive_bools)]
struct CliArgs {
    socket_path: Option<PathBuf>,
    backend: String,
    pid: Option<i32>,
    serial: Option<String>,
    launch_chrome: bool,
    launch_waydroid: bool,
    instance_id: Option<String>,
    adb_port: Option<u16>,
    profile_dir: Option<PathBuf>,
    ssl_keylog_file: Option<PathBuf>,
    initial_url: Option<String>,
    proxy: Option<String>,
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
        backend: "mock".to_owned(),
        pid: None,
        serial: None,
        launch_chrome: false,
        launch_waydroid: false,
        instance_id: None,
        adb_port: None,
        profile_dir: None,
        ssl_keylog_file: None,
        initial_url: None,
        proxy: env::var("WAYBOUND_PROXY").ok(),
        timezone: None,
        locale: None,
        focus: false,
        no_motion: false,
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => cli.socket_path = Some(PathBuf::from(next_arg(&mut args, "--socket")?)),
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
            "--timezone" => cli.timezone = Some(next_arg(&mut args, "--timezone")?),
            "--locale" => cli.locale = Some(next_arg(&mut args, "--locale")?),
            "--focus" => cli.focus = true,
            "--no-motion" => cli.no_motion = true,
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(cli)
}

fn default_user_socket_path() -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(format!("/tmp/waybound-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir.join("w.sock"))
}

fn setup_proxy(raw: Option<String>) -> Result<(Option<String>, Option<ProxyForwarder>), String> {
    match raw {
        Some(raw_proxy) if raw_proxy.contains('@') => {
            let upstream = UpstreamProxy::parse(&raw_proxy)?;
            let fwd = ProxyForwarder::start(upstream).map_err(|e| e.to_string())?;
            Ok((Some(fwd.chrome_proxy_arg()), Some(fwd)))
        }
        Some(raw_proxy) => Ok((Some(raw_proxy), None)),
        None => Ok((None, None)),
    }
}

type BackendBundle = (
    Arc<dyn Driver>,
    bool,
    Option<launcher::LaunchedChrome>,
    Option<ProxyForwarder>,
    Option<WaydroidSession>,
);

fn build_backend(cli: CliArgs) -> Result<BackendBundle, String> {
    match cli.backend.as_str() {
        "mock" => Ok((Arc::new(MockDriver::sample_page()), false, None, None, None)),
        "android" => {
            let (serial, waydroid_session, proxy_fwd) = if cli.launch_waydroid {
                let (local_proxy, fwd) = setup_proxy(cli.proxy)?;
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
            Ok((
                Arc::new(android),
                !cli.no_motion,
                None,
                proxy_fwd,
                waydroid_session,
            ))
        }
        "macos" => {
            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (chrome_proxy_server, proxy_fwd) = setup_proxy(cli.proxy)?;
                let opts = ChromeLaunchOptions {
                    binary_path: None,
                    profile_dir: cli.profile_dir,
                    ssl_keylog_file: cli.ssl_keylog_file,
                    initial_url: cli.initial_url,
                    proxy_server: chrome_proxy_server,
                    timezone: cli.timezone,
                    locale: cli.locale,
                    focus: cli.focus,
                };
                let chrome = launch_chrome(&opts).map_err(|e| e.to_string())?;
                let pid = chrome.pid();
                (pid, Some(chrome), proxy_fwd)
            } else if let Some(pid) = cli.pid {
                (pid, None, None)
            } else {
                return Err(
                    "--backend macos requires either --pid <pid> or --launch-chrome".to_owned(),
                );
            };
            tracing::info!(pid = target_pid, "starting macos native driver");
            Ok((
                Arc::new(MacOsDriver::new(target_pid)),
                !cli.no_motion,
                launched,
                fwd,
                None,
            ))
        }
        other => Err(format!(
            "unknown backend {other:?} (expected 'mock', 'macos', or 'android')"
        )),
    }
}

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

    let socket_path = match cli.socket_path.clone() {
        Some(p) => p,
        None => match default_user_socket_path() {
            Ok(p) => p,
            Err(err) => {
                tracing::error!(error = %err, "failed to create private socket directory");
                return ExitCode::FAILURE;
            }
        },
    };

    let responses = Arc::new(ResponseStore::default());
    let _net_tap = cli.ssl_keylog_file.as_ref().and_then(|keylog| {
        match start_passive_tap(keylog, Arc::clone(&responses)) {
            Ok(tap) => Some(tap),
            Err(err) => {
                tracing::warn!(error = %err, "passive network tap unavailable; continuing without capture");
                None
            }
        }
    });

    let (driver, use_motion, _launched, _proxy_forwarder, _waydroid) = match build_backend(cli) {
        Ok(bundle) => bundle,
        Err(msg) => {
            tracing::error!(error = %msg, "failed to initialize backend");
            return ExitCode::FAILURE;
        }
    };

    let options = ServerOptions { use_motion };
    if let Err(err) = server::serve_unix(&socket_path, &driver, responses, options) {
        tracing::error!(error = %err, "daemon terminated with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
