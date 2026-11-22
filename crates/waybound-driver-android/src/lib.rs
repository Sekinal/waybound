//! Pure-Rust Android / Waydroid backend driver implementing [`waybound_core::Driver`]
//! via ADB (`uiautomator dump`, `input`, `screencap`, and `am start`).

pub mod adb;
pub mod waydroid;
pub mod xml;

pub use waydroid::{WaydroidConfig, WaydroidSession};

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use waybound_core::{
    AccessibilityNode, BackendKind, Driver, InputEvent, LocatorQuery, Point, Result, WayboundError,
};

/// Android / Waydroid browser driver communicating with an unmodified Android Chrome
/// instance over `adb`.
pub struct AndroidDriver {
    serial: Option<String>,
    cursor: Mutex<Point>,
    /// Serialises `uiautomator dump`: two concurrent dumps on one device make each other
    /// fail (`UiAutomationService ... already registered`).
    dump_lock: Mutex<()>,
    /// Device API level decides how modifier chords are sent; probed once on first use.
    chords: adb::ChordSupportCache,
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
            dump_lock: Mutex::new(()),
            chords: adb::ChordSupportCache::new(),
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

    /// Dumps the UI hierarchy, retrying transient `uiautomator` failures.
    ///
    /// The retry budget is [`adb::snapshot_retry_budget`] of `caller_remaining`.
    ///
    /// The dump lock is taken per attempt, so another connection can dump between this
    /// call's retries instead of queueing behind the whole loop.
    fn dump_xml(&self, caller_remaining: Option<Duration>) -> Result<String> {
        let serial = self.serial.as_deref();
        adb::retry_dump(
            &adb::SystemClock,
            adb::snapshot_retry_budget(caller_remaining),
            || {
                let _guard =
                    self.dump_lock
                        .lock()
                        .map_err(|_| WayboundError::BackendUnavailable {
                            backend: "android_waydroid".to_owned(),
                            reason: "uiautomator dump mutex poisoned".to_owned(),
                        })?;
                adb::dump_ui_xml(serial)
            },
        )
    }
}

impl Driver for AndroidDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::AndroidWaydroid
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        let raw_xml = self.dump_xml(None)?;
        Ok(xml::parse_uiautomator_xml(&raw_xml))
    }

    fn locate_within(
        &self,
        query: &LocatorQuery,
        remaining: Duration,
    ) -> Result<AccessibilityNode> {
        let raw_xml = self.dump_xml(Some(remaining))?;
        let nodes = xml::parse_uiautomator_xml(&raw_xml);
        query
            .resolve_one(&nodes)
            .cloned()
            .ok_or_else(|| WayboundError::ElementNotFound {
                query: format!("{query:?}"),
            })
    }

    fn current_url(&self) -> Result<Option<String>> {
        let raw_xml = self.dump_xml(None)?;
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
        adb::dispatch_input(self.serial.as_deref(), event, &mut guard, &self.chords)
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
