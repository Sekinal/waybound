//! Configuration and window metadata types for the headless Wayland compositor.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use waybound_core::{Result, WayboundError};

use crate::buffer::MAX_BUFFER_DIMENSION;

/// Default virtual output width in logical pixels.
pub const DEFAULT_WIDTH: u32 = 1920;

/// Default virtual output height in logical pixels.
pub const DEFAULT_HEIGHT: u32 = 1080;

/// Default virtual output refresh rate in millihertz (60 Hz).
pub const DEFAULT_REFRESH_MHZ: u32 = 60_000;

/// Default integer output scale factor.
pub const DEFAULT_SCALE: i32 = 1;

/// Configuration for [`crate::HeadlessCompositor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositorConfig {
    /// Virtual output width in pixels.
    pub width: u32,
    /// Virtual output height in pixels.
    pub height: u32,
    /// Virtual output refresh rate in millihertz (for example `60_000` for 60 Hz).
    pub refresh_mhz: u32,
    /// Integer output scale factor (must be at least `1`).
    pub scale: i32,
    /// Optional Wayland socket filename inside `runtime_dir` (for example `"wayland-waybound-0"`).
    /// When `None`, a unique socket name is generated automatically.
    pub socket_name: Option<String>,
    /// Optional directory where the Wayland Unix socket is created (`XDG_RUNTIME_DIR`).
    /// When `None`, `XDG_RUNTIME_DIR` or the system temporary directory is used.
    pub runtime_dir: Option<PathBuf>,
}

impl Default for CompositorConfig {
    fn default() -> Self {
        Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            refresh_mhz: DEFAULT_REFRESH_MHZ,
            scale: DEFAULT_SCALE,
            socket_name: None,
            runtime_dir: None,
        }
    }
}

impl CompositorConfig {
    /// Validates output dimensions, refresh rate, and scale factor.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::InvalidElementState`] if any dimension, refresh rate, or
    /// scale value is out of range.
    pub fn validate(&self) -> Result<()> {
        if self.width == 0 || self.width > MAX_BUFFER_DIMENSION {
            return Err(WayboundError::InvalidElementState {
                detail: format!(
                    "compositor width {} must be in 1..={MAX_BUFFER_DIMENSION}",
                    self.width
                ),
            });
        }
        if self.height == 0 || self.height > MAX_BUFFER_DIMENSION {
            return Err(WayboundError::InvalidElementState {
                detail: format!(
                    "compositor height {} must be in 1..={MAX_BUFFER_DIMENSION}",
                    self.height
                ),
            });
        }
        if self.refresh_mhz == 0 {
            return Err(WayboundError::InvalidElementState {
                detail: "compositor refresh_mhz must be greater than zero".to_owned(),
            });
        }
        if self.scale < 1 {
            return Err(WayboundError::InvalidElementState {
                detail: format!("compositor scale {} must be at least 1", self.scale),
            });
        }
        Ok(())
    }
}

/// Snapshot metadata for a tracked `xdg_toplevel` window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowInfo {
    /// Compositor-assigned monotonic window identifier.
    pub id: u64,
    /// Current `xdg_toplevel` title reported by the client.
    pub title: String,
    /// Current `xdg_toplevel` `app_id` reported by the client.
    pub app_id: String,
    /// Width of the most recently committed buffer (or configured width if none yet).
    pub width: u32,
    /// Height of the most recently committed buffer (or configured height if none yet).
    pub height: u32,
    /// Whether the window has committed at least one readable pixel buffer.
    pub has_buffer: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_1080p_60hz() {
        let cfg = CompositorConfig::default();
        assert_eq!(cfg.width, 1920);
        assert_eq!(cfg.height, 1080);
        assert_eq!(cfg.refresh_mhz, 60_000);
        assert_eq!(cfg.scale, 1);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_rejects_invalid_values() {
        assert!(
            CompositorConfig {
                width: 0,
                ..CompositorConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CompositorConfig {
                height: MAX_BUFFER_DIMENSION + 1,
                ..CompositorConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CompositorConfig {
                refresh_mhz: 0,
                ..CompositorConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CompositorConfig {
                scale: 0,
                ..CompositorConfig::default()
            }
            .validate()
            .is_err()
        );
    }
}
