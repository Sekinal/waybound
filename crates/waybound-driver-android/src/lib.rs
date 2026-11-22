//! Pure-Rust Android / Waydroid backend driver implementing [`waybound_core::Driver`]
//! via ADB (`uiautomator dump`, `input`, `screencap`, and `am start`).

pub mod adb;
pub mod waydroid;
pub mod xml;

pub use waydroid::{WaydroidConfig, WaydroidSession};

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use waybound_core::{
    AccessibilityNode, BackendKind, Driver, InputEvent, Point, Result, WayboundError,
};

/// Android / Waydroid browser driver communicating with an unmodified Android Chrome
/// instance over `adb`.
pub struct AndroidDriver {
    serial: Option<String>,
    cursor: Mutex<Point>,
    pending_drag: Mutex<Option<adb::PendingDrag>>,
    /// Device API level, probed on the first drag release and cached once read.
    sdk_level: OnceLock<u32>,
}

impl AndroidDriver {
    /// Creates a new [`AndroidDriver`] targeting an optional ADB device `serial`
    /// (for example `"127.0.0.1:5555"` or `"emulator-5554"`).
    ///
    /// When `serial` is `None`, `adb` targets the default connected device.
    #[must_use]
    pub const fn new(serial: Option<String>) -> Self {
        Self {
            serial,
            cursor: Mutex::new(Point { x: 0.0, y: 0.0 }),
            pending_drag: Mutex::new(None),
            sdk_level: OnceLock::new(),
        }
    }

    /// Returns the configured ADB device serial, if any.
    #[must_use]
    pub fn serial(&self) -> Option<&str> {
        self.serial.as_deref()
    }

    /// Opens an `http://` or `https://` URL in Android Chrome via `adb shell am start`.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `url` has an unsupported scheme
    /// or if `adb` fails to launch the intent.
    pub fn open_url(&self, url: &str) -> Result<()> {
        adb::open_chrome_url(self.serial.as_deref(), url)
    }
}

impl AndroidDriver {
    /// Returns the device API level, probing it once; a failed probe is retried next time.
    fn sdk_level(&self) -> Option<u32> {
        if let Some(level) = self.sdk_level.get() {
            return Some(*level);
        }
        let probed = adb::probe_sdk_level(self.serial.as_deref());
        if let Some(level) = probed {
            let _ = self.sdk_level.set(level);
        }
        probed
    }
}

impl Driver for AndroidDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::AndroidWaydroid
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        let raw_xml = adb::dump_ui_xml(self.serial.as_deref())?;
        Ok(xml::parse_uiautomator_xml(&raw_xml))
    }

    fn current_url(&self) -> Result<Option<String>> {
        let raw_xml = adb::dump_ui_xml(self.serial.as_deref())?;
        Ok(xml::extract_chrome_url(&raw_xml))
    }

    fn navigate(&self, url: &str) -> Result<bool> {
        self.open_url(url)?;
        Ok(true)
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        adb::capture_png(self.serial.as_deref(), output_path)
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        let mut guard = self
            .cursor
            .lock()
            .map_err(|_| WayboundError::BackendUnavailable {
                backend: "android_waydroid".to_owned(),
                reason: "cursor state mutex poisoned".to_owned(),
            })?;
        // A poisoned drag state only means an earlier dispatch panicked; the buffered press
        // is still valid, and refusing here would leave a release unsent.
        let mut pending = self
            .pending_drag
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        adb::dispatch_input(
            self.serial.as_deref(),
            event,
            &mut guard,
            &mut pending,
            || self.sdk_level(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_serial_and_reports_android_backend() {
        let driver = AndroidDriver::new(Some("127.0.0.1:5555".to_owned()));
        assert_eq!(driver.serial(), Some("127.0.0.1:5555"));
        assert_eq!(driver.backend_kind(), BackendKind::AndroidWaydroid);

        let default_driver = AndroidDriver::new(None);
        assert_eq!(default_driver.serial(), None);
        assert_eq!(default_driver.backend_kind(), BackendKind::AndroidWaydroid);
    }

    #[test]
    fn open_url_rejects_non_http_schemes_without_invoking_adb() {
        let driver = AndroidDriver::new(None);
        assert!(driver.open_url("file:///etc/passwd").is_err());
        assert!(driver.open_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn pointer_move_updates_cursor_without_invoking_adb() {
        let driver = AndroidDriver::new(None);
        let res = driver.dispatch_input(&InputEvent::PointerMove {
            to: Point { x: 120.0, y: 340.0 },
        });
        assert!(res.is_ok());
    }
}
