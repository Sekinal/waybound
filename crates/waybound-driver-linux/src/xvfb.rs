//! Headless Xvfb virtual framebuffer configuration and RAII session guard.

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use tracing::{debug, warn};
use waybound_core::{Result, WayboundError};

use crate::process::BACKEND_NAME;

const MAX_DIMENSION: u32 = 16_384;
const STARTUP_SETTLE_DELAY: Duration = Duration::from_millis(100);

/// Configuration for a headless `Xvfb` virtual framebuffer display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadlessDisplayConfig {
    /// X11 display number (for example `99` for `:99`).
    pub display_num: u16,
    /// Framebuffer width in pixels.
    pub width: u32,
    /// Framebuffer height in pixels.
    pub height: u32,
    /// Color depth in bits per pixel (`8`, `16`, `24`, or `32`).
    pub color_depth: u8,
}

impl Default for HeadlessDisplayConfig {
    fn default() -> Self {
        Self {
            display_num: 99,
            width: 1280,
            height: 800,
            color_depth: 24,
        }
    }
}

impl HeadlessDisplayConfig {
    /// Returns the X11 `DISPLAY` identifier string (e.g. `":99"`).
    #[must_use]
    pub fn display_name(&self) -> String {
        format!(":{}", self.display_num)
    }

    /// Validates framebuffer dimensions and color depth before spawning `Xvfb`.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if dimensions are zero or exceed
    /// `16384`, or if `color_depth` is not one of `8`, `16`, `24`, `32`.
    pub fn validate(&self) -> Result<()> {
        if self.width == 0 || self.height == 0 {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "Xvfb dimensions must be non-zero (got {}x{})",
                    self.width, self.height
                ),
            });
        }
        if self.width > MAX_DIMENSION || self.height > MAX_DIMENSION {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "Xvfb dimensions {}x{} exceed maximum {MAX_DIMENSION}",
                    self.width, self.height
                ),
            });
        }
        if !matches!(self.color_depth, 8 | 16 | 24 | 32) {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "unsupported Xvfb color depth {} (expected 8, 16, 24, or 32)",
                    self.color_depth
                ),
            });
        }
        Ok(())
    }
}

/// Builds the argument vector passed to `Xvfb` for `config`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `config` fails validation.
pub fn build_xvfb_args(config: &HeadlessDisplayConfig) -> Result<Vec<String>> {
    config.validate()?;
    Ok(vec![
        config.display_name(),
        "-screen".to_owned(),
        "0".to_owned(),
        format!("{}x{}x{}", config.width, config.height, config.color_depth),
        "-nolisten".to_owned(),
        "tcp".to_owned(),
        "-ac".to_owned(),
    ])
}

/// RAII handle owning a spawned headless `Xvfb` process and terminating it on [`Drop`].
#[derive(Debug)]
pub struct HeadlessDisplaySession {
    config: HeadlessDisplayConfig,
    child: Option<Child>,
}

impl HeadlessDisplaySession {
    /// Spawns `Xvfb` with the validated `config` and returns an RAII session guard.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `config` is invalid, `Xvfb`
    /// cannot be spawned, or `Xvfb` exits immediately on startup.
    pub fn start(config: HeadlessDisplayConfig) -> Result<Self> {
        let args = build_xvfb_args(&config)?;
        debug!(?args, "starting headless Xvfb display");

        let mut cmd = Command::new("Xvfb");
        let _ = cmd
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to spawn `Xvfb`: {err}"),
            })?;

        thread::sleep(STARTUP_SETTLE_DELAY);
        if let Some(status) = child.try_wait()? {
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("`Xvfb` exited prematurely on startup with {status}"),
            });
        }

        Ok(Self {
            config,
            child: Some(child),
        })
    }

    /// Returns the X11 `DISPLAY` string owned by this session (e.g. `":99"`).
    #[must_use]
    pub fn display(&self) -> String {
        self.config.display_name()
    }

    /// Returns the [`HeadlessDisplayConfig`] used to launch this session.
    #[must_use]
    pub const fn config(&self) -> HeadlessDisplayConfig {
        self.config
    }

    /// Terminates the underlying `Xvfb` process if it is still running.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Err(err) = child.kill() {
                warn!(display = %self.config.display_name(), %err, "failed to kill Xvfb");
            }
            let _ = child.wait();
        }
    }
}

impl Drop for HeadlessDisplaySession {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_xvfb_args_for_valid_config() -> Result<()> {
        let cfg = HeadlessDisplayConfig {
            display_num: 99,
            width: 1920,
            height: 1080,
            color_depth: 24,
        };
        assert_eq!(cfg.display_name(), ":99");
        let args = build_xvfb_args(&cfg)?;
        assert_eq!(
            args,
            vec![
                ":99",
                "-screen",
                "0",
                "1920x1080x24",
                "-nolisten",
                "tcp",
                "-ac"
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_xvfb_dimensions_and_color_depth() {
        let zero_width = HeadlessDisplayConfig {
            width: 0,
            ..HeadlessDisplayConfig::default()
        };
        assert!(build_xvfb_args(&zero_width).is_err());

        let huge_height = HeadlessDisplayConfig {
            height: 20_000,
            ..HeadlessDisplayConfig::default()
        };
        assert!(build_xvfb_args(&huge_height).is_err());

        let bad_depth = HeadlessDisplayConfig {
            color_depth: 12,
            ..HeadlessDisplayConfig::default()
        };
        assert!(build_xvfb_args(&bad_depth).is_err());
    }
}
