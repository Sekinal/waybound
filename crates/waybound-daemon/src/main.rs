//! Control daemon binary for `waybound`.
//!
//! Orchestrates platform backends and serves semantic automation requests to
//! client SDKs over a local Unix domain socket.

mod mock_driver;
mod server;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;
use waybound_core::Driver;
use waybound_driver_macos::MacOsDriver;

use crate::mock_driver::MockDriver;

struct CliArgs {
    socket_path: PathBuf,
    backend: String,
    pid: Option<i32>,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut socket_path = env::var("WAYBOUND_SOCKET")
        .map_or_else(|_| PathBuf::from("/tmp/waybound.sock"), PathBuf::from);
    let mut backend = "mock".to_owned();
    let mut pid = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--socket requires a path argument".to_owned())?;
                socket_path = PathBuf::from(path);
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
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(CliArgs {
        socket_path,
        backend,
        pid,
    })
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
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

    let driver: Arc<dyn Driver> = match cli.backend.as_str() {
        "mock" => Arc::new(MockDriver::sample_page()),
        "macos" => {
            let Some(pid) = cli.pid else {
                tracing::error!("--backend macos requires --pid <browser_pid>");
                return ExitCode::FAILURE;
            };
            tracing::info!(pid, "starting macos native driver");
            Arc::new(MacOsDriver::new(pid))
        }
        other => {
            tracing::error!(
                backend = other,
                "unknown backend (expected 'mock' or 'macos')"
            );
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = server::serve_unix(&cli.socket_path, &driver) {
        tracing::error!(error = %err, "daemon terminated with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
