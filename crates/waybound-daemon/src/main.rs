//! Control daemon binary for `waybound`.
//!
//! Orchestrates platform backends and serves semantic automation requests to
//! client SDKs over a local Unix domain socket.

mod mock_driver;
mod server;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

use crate::mock_driver::MockDriver;

fn parse_socket_path() -> PathBuf {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket"
            && let Some(path) = args.next()
        {
            return PathBuf::from(path);
        }
    }
    env::var("WAYBOUND_SOCKET").map_or_else(|_| PathBuf::from("/tmp/waybound.sock"), PathBuf::from)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let socket_path = parse_socket_path();
    let driver = MockDriver::sample_page();

    if let Err(err) = server::serve_unix(&socket_path, &driver) {
        tracing::error!(error = %err, "daemon terminated with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
