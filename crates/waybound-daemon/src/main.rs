//! Control daemon binary for `waybound`.
//!
//! Orchestrates platform backends and serves semantic automation requests to
//! client SDKs over local IPC.

use tracing_subscriber::EnvFilter;
use waybound_core::SessionConfig;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let default_config = SessionConfig::default();
    tracing::info!(
        backend = ?default_config.backend,
        viewport = format_args!("{}x{}", default_config.viewport_width, default_config.viewport_height),
        "waybound-daemon initialized"
    );
}
