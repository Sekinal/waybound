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
use waybound_driver_macos::MacOsDriver;

use crate::launcher::{ChromeLaunchOptions, launch_chrome};
use crate::mock_driver::MockDriver;
use crate::net_tap::{ResponseStore, start_passive_tap};
use crate::proxy::{ProxyForwarder, UpstreamProxy};
use crate::server::ServerOptions;

struct CliArgs {
    socket_path: Option<PathBuf>,
    backend: String,
    pid: Option<i32>,
    launch_chrome: bool,
    profile_dir: Option<PathBuf>,
    ssl_keylog_file: Option<PathBuf>,
    initial_url: Option<String>,
    proxy: Option<String>,
    timezone: Option<String>,
    locale: Option<String>,
    focus: bool,
    no_motion: bool,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut socket_path = env::var("WAYBOUND_SOCKET").ok().map(PathBuf::from);
    let mut backend = "mock".to_owned();
    let mut pid = None;
    let mut launch_chrome_flag = false;
    let mut profile_dir = None;
    let mut ssl_keylog_file = None;
    let mut initial_url = None;
    let mut proxy = env::var("WAYBOUND_PROXY").ok();
    let mut timezone = None;
    let mut locale = None;
    let mut focus = false;
    let mut no_motion = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--socket requires a path argument".to_owned())?;
                socket_path = Some(PathBuf::from(path));
            }
            "--backend" => {
                let val = args
                    .next()
                    .ok_or_else(|| "--backend requires a value ('mock' or 'macos')".to_owned())?;
                backend = val;
            }
            "--pid" => {
                let val = args
                    .next()
                    .ok_or_else(|| "--pid requires a positive integer".to_owned())?;
                let parsed = val
                    .parse::<i32>()
                    .map_err(|_| format!("invalid --pid value: {val}"))?;
                if parsed <= 0 {
                    return Err(format!("--pid must be positive, got {parsed}"));
                }
                pid = Some(parsed);
            }
            "--launch-chrome" => launch_chrome_flag = true,
            "--profile-dir" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--profile-dir requires a path argument".to_owned())?;
                profile_dir = Some(PathBuf::from(path));
            }
            "--ssl-keylog" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--ssl-keylog requires a path argument".to_owned())?;
                ssl_keylog_file = Some(PathBuf::from(path));
            }
            "--url" => {
                let val = args
                    .next()
                    .ok_or_else(|| "--url requires a URL argument".to_owned())?;
                initial_url = Some(val);
            }
            "--proxy" => {
                let val = args
                    .next()
                    .ok_or_else(|| "--proxy requires a proxy URL argument".to_owned())?;
                proxy = Some(val);
            }
            "--timezone" => {
                let val = args.next().ok_or_else(|| {
                    "--timezone requires an IANA timezone (e.g., America/New_York)".to_owned()
                })?;
                timezone = Some(val);
            }
            "--locale" => {
                let val = args
                    .next()
                    .ok_or_else(|| "--locale requires a locale (e.g., en_US.UTF-8)".to_owned())?;
                locale = Some(val);
            }
            "--focus" => focus = true,
            "--no-motion" => no_motion = true,
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(CliArgs {
        socket_path,
        backend,
        pid,
        launch_chrome: launch_chrome_flag,
        profile_dir,
        ssl_keylog_file,
        initial_url,
        proxy,
        timezone,
        locale,
        focus,
        no_motion,
    })
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

    let socket_path = match cli.socket_path {
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
    // Start passive wire tap before launching Chrome so initial TLS handshakes are captured.
    let _net_tap = cli.ssl_keylog_file.as_ref().and_then(|keylog| {
        match start_passive_tap(keylog, Arc::clone(&responses)) {
            Ok(tap) => Some(tap),
            Err(err) => {
                tracing::warn!(error = %err, "passive network tap unavailable; continuing without capture");
                None
            }
        }
    });

    // Keep `_launched` and `_proxy_forwarder` alive for the full lifetime of the daemon.
    let (driver, use_motion, _launched, _proxy_forwarder): (
        Arc<dyn Driver>,
        bool,
        Option<launcher::LaunchedChrome>,
        Option<ProxyForwarder>,
    ) = match cli.backend.as_str() {
        "mock" => (Arc::new(MockDriver::sample_page()), false, None, None),
        "macos" => {
            let (target_pid, launched, fwd) = if cli.launch_chrome {
                let (chrome_proxy_server, proxy_fwd) = match setup_proxy(cli.proxy) {
                    Ok(pair) => pair,
                    Err(msg) => {
                        tracing::error!(error = %msg, "failed to configure proxy");
                        return ExitCode::FAILURE;
                    }
                };
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
                match launch_chrome(&opts) {
                    Ok(chrome) => {
                        let pid = chrome.pid();
                        (pid, Some(chrome), proxy_fwd)
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "failed to launch Google Chrome");
                        return ExitCode::FAILURE;
                    }
                }
            } else if let Some(pid) = cli.pid {
                (pid, None, None)
            } else {
                tracing::error!("--backend macos requires either --pid <pid> or --launch-chrome");
                return ExitCode::FAILURE;
            };

            tracing::info!(pid = target_pid, "starting macos native driver");
            (
                Arc::new(MacOsDriver::new(target_pid)),
                !cli.no_motion,
                launched,
                fwd,
            )
        }
        other => {
            tracing::error!(
                backend = other,
                "unknown backend (expected 'mock' or 'macos')"
            );
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
