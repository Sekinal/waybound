//! Pure-Rust ADB (`adb [-s <serial>] ...`) command runner for Android / Waydroid.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tracing::debug;
use waybound_core::{InputEvent, KeyCode, Point, Result, WayboundError};

const BACKEND_NAME: &str = "android_waydroid";
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const ADB_TIMEOUT: Duration = Duration::from_secs(15);
const ADB_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Default swipe origin used when scrolling before any `PointerMove` has been dispatched.
const DEFAULT_SCROLL_ORIGIN: Point = Point { x: 540.0, y: 960.0 };
const SCROLL_SWIPE_DURATION_MS: u64 = 250;
/// Shortest touch drag gesture; `input swipe` with a tiny duration reads as a fling.
const MIN_DRAG_DURATION_MS: u64 = 300;
/// Longest touch drag gesture, bounded well below [`ADB_TIMEOUT`].
const MAX_DRAG_DURATION_MS: u64 = 10_000;
/// First Android API level whose `input` tool has `draganddrop` (Android 8.0 / Oreo; absent
/// from the Nougat sources).
pub const DRAG_AND_DROP_MIN_SDK: u32 = 26;

/// Android `KeyEvent` keycodes for non-character keys.
const KEYCODE_ENTER: u32 = 66;
const KEYCODE_TAB: u32 = 61;
const KEYCODE_ESCAPE: u32 = 111;
const KEYCODE_BACKSPACE: u32 = 67;

/// Captures the current Android UI accessibility hierarchy XML via
/// `adb [-s <serial>] exec-out uiautomator dump /dev/tty`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `adb` fails to execute,
/// exits non-zero, or does not return a `uiautomator` XML hierarchy.
pub fn dump_ui_xml(serial: Option<&str>) -> Result<String> {
    let mut last_err = None;
    for target in ["/dev/stdout", "/dev/tty"] {
        let args = build_adb_args(serial, &["exec-out", "uiautomator", "dump", target]);
        let output = run_adb(&args)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            last_err = Some(format!(
                "adb uiautomator dump {target} failed ({}): {}",
                output.status,
                truncate_for_log(stderr.trim())
            ));
            continue;
        }
        let xml = String::from_utf8_lossy(&output.stdout).into_owned();
        if xml.contains("<hierarchy") || xml.contains("<node") {
            return Ok(xml);
        }
        last_err = Some(format!(
            "adb uiautomator dump {target} did not contain XML hierarchy (stdout: {})",
            truncate_for_log(&xml)
        ));
    }

    Err(WayboundError::BackendUnavailable {
        backend: BACKEND_NAME.to_owned(),
        reason: last_err.unwrap_or_else(|| "adb uiautomator dump failed".to_owned()),
    })
}

/// A touch drag that has been pressed but not yet released.
///
/// `adb shell input` cannot hold a finger down across separate commands, so a
/// [`InputEvent::MouseDown`] only records where and when the gesture started; the
/// matching [`InputEvent::MouseUp`] then emits the whole drag as one `input draganddrop`
/// (or `input swipe` on old devices) from that point to the last
/// [`InputEvent::PointerDrag`] position.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PendingDrag {
    /// Where the finger went down.
    pub from: Point,
    /// When the press was recorded.
    pub pressed_at: Instant,
}

/// Dispatches a platform-agnostic [`InputEvent`] to an Android device via `adb shell input`.
///
/// Tracks `last_cursor` across [`InputEvent::PointerMove`], [`InputEvent::MouseClick`],
/// and [`InputEvent::Scroll`] events, and buffers press / drag / release sequences in
/// `pending_drag` (see [`PendingDrag`]). `sdk_level` is only called when a drag is
/// released, to choose between `draganddrop` and `swipe`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `adb` fails to execute or exits non-zero.
pub fn dispatch_input(
    serial: Option<&str>,
    event: &InputEvent,
    last_cursor: &mut Point,
    pending_drag: &mut Option<PendingDrag>,
    sdk_level: impl FnOnce() -> Option<u32>,
) -> Result<()> {
    dispatch_input_with(event, last_cursor, pending_drag, sdk_level, |shell_args| {
        let arg_refs: Vec<&str> = shell_args.iter().map(String::as_str).collect();
        let args = build_adb_args(serial, &arg_refs);
        let output = run_adb(&args)?;
        ensure_success(&output, "input dispatch")
    })
}

/// [`dispatch_input`] with the `adb shell` runner injected, so gesture buffering and error
/// handling can be tested without a device.
///
/// A buffered drag is only cleared once its gesture command succeeded, so a failed release
/// is reported and a retried release sends the gesture again.
///
/// # Errors
///
/// Returns whatever `run` returns for the command it is given.
pub fn dispatch_input_with(
    event: &InputEvent,
    last_cursor: &mut Point,
    pending_drag: &mut Option<PendingDrag>,
    sdk_level: impl FnOnce() -> Option<u32>,
    mut run: impl FnMut(&[String]) -> Result<()>,
) -> Result<()> {
    match event {
        InputEvent::MouseDown { .. } => {
            *pending_drag = Some(PendingDrag {
                from: *last_cursor,
                pressed_at: Instant::now(),
            });
            Ok(())
        }
        InputEvent::MouseUp { .. } => {
            let Some(drag) = *pending_drag else {
                // No finger is down on the device, so there is nothing to lift.
                debug!("ignoring adb release without a pending press");
                return Ok(());
            };
            let held_ms = u64::try_from(drag.pressed_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            let args = build_drag_args(
                drag.from,
                *last_cursor,
                held_ms,
                supports_drag_and_drop(sdk_level()),
            );
            run(&args)?;
            *pending_drag = None;
            Ok(())
        }
        other => build_input_shell_args(other, last_cursor).map_or(Ok(()), |args| run(&args)),
    }
}

/// Reads the device API level (`ro.build.version.sdk`), or `None` if it cannot be read.
#[must_use]
pub fn probe_sdk_level(serial: Option<&str>) -> Option<u32> {
    let args = build_adb_args(serial, &["shell", "getprop", "ro.build.version.sdk"]);
    let output = run_adb(&args).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_sdk_level(&String::from_utf8_lossy(&output.stdout))
}

/// Parses `getprop ro.build.version.sdk` output.
#[must_use]
pub fn parse_sdk_level(raw: &str) -> Option<u32> {
    raw.trim().parse().ok()
}

/// Whether a device at API level `sdk` has `input draganddrop` (unknown levels do not).
#[must_use]
pub const fn supports_drag_and_drop(sdk: Option<u32>) -> bool {
    matches!(sdk, Some(level) if level >= DRAG_AND_DROP_MIN_SDK)
}

/// Captures a PNG screenshot of the Android display to `output_path` via
/// `adb [-s <serial>] exec-out screencap -p`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `adb` fails or does not return
/// valid non-empty PNG bytes, or [`WayboundError::Io`] if writing `output_path` fails.
pub fn capture_png(serial: Option<&str>, output_path: &Path) -> Result<()> {
    let args = build_adb_args(serial, &["exec-out", "screencap", "-p"]);
    let output = run_adb(&args)?;
    ensure_success(&output, "screencap")?;

    validate_png_bytes(&output.stdout)?;
    std::fs::write(output_path, &output.stdout)?;
    Ok(())
}

/// Opens an `http://` or `https://` URL in Android Chrome via
/// `adb [-s <serial>] shell am start -a android.intent.action.VIEW -d <url> com.android.chrome`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `url` is not a valid `http`/`https` URL
/// or if `adb` fails to launch the intent.
pub fn open_chrome_url(serial: Option<&str>, url: &str) -> Result<()> {
    validate_http_url(url)?;
    let escaped_url = shell_single_quote(url);
    let args = build_adb_args(
        serial,
        &[
            "shell",
            "am",
            "start",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            &escaped_url,
            "com.android.chrome",
        ],
    );
    let output = run_adb(&args)?;
    ensure_success(&output, "am start chrome")
}

/// Builds the full argument vector for `adb`, prepending `["-s", serial]` when present.
#[must_use]
pub fn build_adb_args(serial: Option<&str>, subcommand: &[&str]) -> Vec<String> {
    let extra = if serial.is_some() { 2 } else { 0 };
    let mut args = Vec::with_capacity(extra + subcommand.len());
    if let Some(id) = serial {
        args.push("-s".to_owned());
        args.push(id.to_owned());
    }
    for &part in subcommand {
        args.push(part.to_owned());
    }
    args
}

/// Builds the `adb shell input` arguments for a touch drag from `from` to `to` lasting
/// `duration_ms` (clamped to a range Chrome reads as a drag, not a fling).
///
/// With `drag_and_drop`, uses `input draganddrop`, which holds for the system long-press
/// timeout before moving, so HTML5 and touch-sortable drags start instead of the page
/// scrolling. Otherwise (Android < 8.0) falls back to a plain `input swipe`.
#[must_use]
pub fn build_drag_args(
    from: Point,
    to: Point,
    duration_ms: u64,
    drag_and_drop: bool,
) -> Vec<String> {
    vec![
        "shell".to_owned(),
        "input".to_owned(),
        if drag_and_drop {
            "draganddrop"
        } else {
            "swipe"
        }
        .to_owned(),
        coord_to_i32(from.x).to_string(),
        coord_to_i32(from.y).to_string(),
        coord_to_i32(to.x).to_string(),
        coord_to_i32(to.y).to_string(),
        duration_ms
            .clamp(MIN_DRAG_DURATION_MS, MAX_DRAG_DURATION_MS)
            .to_string(),
    ]
}

/// Builds the `adb shell input ...` arguments for an [`InputEvent`], updating `last_cursor`.
///
/// Returns `None` for events that only update local pointer state (such as `PointerMove`
/// and `PointerDrag`). [`InputEvent::MouseDown`] and [`InputEvent::MouseUp`] also return
/// `None` here: [`dispatch_input`] turns a press / release pair into one gesture.
#[must_use]
pub fn build_input_shell_args(event: &InputEvent, last_cursor: &mut Point) -> Option<Vec<String>> {
    match event {
        InputEvent::PointerMove { to } | InputEvent::PointerDrag { to, .. } => {
            *last_cursor = *to;
            None
        }
        InputEvent::MouseDown { .. } | InputEvent::MouseUp { .. } => None,
        InputEvent::MouseClick { button: _, hold_ms } => {
            let x = coord_to_i32(last_cursor.x);
            let y = coord_to_i32(last_cursor.y);
            if *hold_ms > 0 {
                Some(vec![
                    "shell".to_owned(),
                    "input".to_owned(),
                    "swipe".to_owned(),
                    x.to_string(),
                    y.to_string(),
                    x.to_string(),
                    y.to_string(),
                    hold_ms.to_string(),
                ])
            } else {
                Some(vec![
                    "shell".to_owned(),
                    "input".to_owned(),
                    "tap".to_owned(),
                    x.to_string(),
                    y.to_string(),
                ])
            }
        }
        InputEvent::Scroll { delta_x, delta_y } => {
            let origin = if last_cursor.x == 0.0 && last_cursor.y == 0.0 {
                DEFAULT_SCROLL_ORIGIN
            } else {
                *last_cursor
            };
            let x1 = coord_to_i32(origin.x);
            let y1 = coord_to_i32(origin.y);
            // Negative delta_y scrolls down (revealing content below), which on touchscreens
            // requires swiping the finger upward (y2 < y1).
            let x2 = coord_to_i32(origin.x + *delta_x);
            let y2 = coord_to_i32(origin.y + *delta_y);
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "swipe".to_owned(),
                x1.to_string(),
                y1.to_string(),
                x2.to_string(),
                y2.to_string(),
                SCROLL_SWIPE_DURATION_MS.to_string(),
            ])
        }
        InputEvent::KeyPress { key, .. } => Some(build_key_shell_args(key)),
    }
}

fn build_key_shell_args(key: &KeyCode) -> Vec<String> {
    match key {
        KeyCode::Enter | KeyCode::Char('\n' | '\r') => keyevent_args(KEYCODE_ENTER),
        KeyCode::Tab | KeyCode::Char('\t') => keyevent_args(KEYCODE_TAB),
        KeyCode::Escape => keyevent_args(KEYCODE_ESCAPE),
        KeyCode::Backspace => keyevent_args(KEYCODE_BACKSPACE),
        KeyCode::ArrowLeft => keyevent_args(21),
        KeyCode::ArrowRight => keyevent_args(22),
        KeyCode::ArrowUp => keyevent_args(19),
        KeyCode::ArrowDown => keyevent_args(20),
        KeyCode::Space => keyevent_args(62),
        KeyCode::Delete => keyevent_args(112),
        KeyCode::Home => keyevent_args(122),
        KeyCode::End => keyevent_args(123),
        KeyCode::PageUp => keyevent_args(92),
        KeyCode::PageDown => keyevent_args(93),
        KeyCode::Char(ch) => {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            vec![
                "shell".to_owned(),
                "input".to_owned(),
                "text".to_owned(),
                escape_android_input_text(s),
            ]
        }
    }
}

fn keyevent_args(keycode: u32) -> Vec<String> {
    vec![
        "shell".to_owned(),
        "input".to_owned(),
        "keyevent".to_owned(),
        keycode.to_string(),
    ]
}

/// Safely escapes text for Android's `adb shell input text <arg>`.
///
/// Encodes ASCII spaces as `%s` (as required by Android's `input text` tool) and
/// wraps the result in POSIX single quotes so `/system/bin/sh` never interprets
/// shell metacharacters.
#[must_use]
pub fn escape_android_input_text(text: &str) -> String {
    let with_spaces = text.replace(' ', "%s");
    shell_single_quote(&with_spaces)
}

/// Wraps `raw` in POSIX single quotes for safe passing through `/system/bin/sh`.
#[must_use]
pub fn shell_single_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Validates that `url` uses an `http://` or `https://` scheme and contains no
/// whitespace or ASCII control characters.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if validation fails.
pub fn validate_http_url(url: &str) -> Result<()> {
    if url.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("invalid URL (empty or contains whitespace/control chars): {url}"),
        });
    }

    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));

    let Some(after_scheme) = rest else {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("unsupported URL scheme (expected http:// or https://): {url}"),
        });
    };

    if after_scheme.is_empty() || after_scheme.starts_with('/') {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("URL is missing host: {url}"),
        });
    }

    Ok(())
}

/// Verifies that `bytes` is non-empty and begins with the 8-byte PNG signature.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `bytes` is empty or lacks the PNG header.
pub fn validate_png_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() < PNG_MAGIC.len() || !bytes.starts_with(&PNG_MAGIC) {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "adb screencap did not return valid PNG data ({} bytes)",
                bytes.len()
            ),
        });
    }
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn coord_to_i32(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(0.0, f64::from(i32::MAX)) as i32
}

fn run_adb(args: &[String]) -> Result<Output> {
    debug!(?args, "executing adb command");
    let mut cmd = Command::new("adb");
    let _ = cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("failed to execute adb: {err}"),
        })?;

    let stdout_handle = child.stdout.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut pipe| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + ADB_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(WayboundError::Timeout {
                        timeout_ms: u64::try_from(ADB_TIMEOUT.as_millis()).unwrap_or(15_000),
                        context: format!("adb command timed out: {args:?}"),
                    });
                }
                thread::sleep(ADB_POLL_INTERVAL);
            }
            Err(err) => return Err(WayboundError::Io(err)),
        }
    };

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn ensure_success(output: &Output, context: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(WayboundError::BackendUnavailable {
        backend: BACKEND_NAME.to_owned(),
        reason: format!(
            "adb {context} failed with status {}: {}",
            output.status,
            truncate_for_log(stderr.trim())
        ),
    })
}

fn truncate_for_log(s: &str) -> String {
    const MAX_LEN: usize = 200;
    let mut out: String = s.chars().take(MAX_LEN).collect();
    if s.chars().count() > MAX_LEN {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use waybound_core::MouseButton;

    use super::*;

    #[test]
    fn build_adb_args_with_and_without_serial() {
        assert_eq!(
            build_adb_args(None, &["exec-out", "screencap", "-p"]),
            vec!["exec-out", "screencap", "-p"]
        );
        assert_eq!(
            build_adb_args(Some("emulator-5554"), &["exec-out", "screencap", "-p"]),
            vec!["-s", "emulator-5554", "exec-out", "screencap", "-p"]
        );
    }

    #[test]
    fn shell_single_quote_escapes_metacharacters_and_quotes() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
        assert_eq!(
            shell_single_quote("https://example.com/?a=1&b=$(id);rm"),
            "'https://example.com/?a=1&b=$(id);rm'"
        );
    }

    #[test]
    fn escape_android_input_text_encodes_spaces_and_shell_chars() {
        assert_eq!(escape_android_input_text(" "), "'%s'");
        assert_eq!(escape_android_input_text("hello world"), "'hello%sworld'");
        assert_eq!(escape_android_input_text("a;b&c$d"), "'a;b&c$d'");
        assert_eq!(escape_android_input_text("'"), "''\\'''");
    }

    #[test]
    fn build_input_shell_args_handles_pointer_tap_hold_and_scroll() {
        let mut cursor = Point { x: 0.0, y: 0.0 };

        // PointerMove updates cursor without invoking adb.
        let move_args = build_input_shell_args(
            &InputEvent::PointerMove {
                to: Point { x: 320.4, y: 640.6 },
            },
            &mut cursor,
        );
        assert!(move_args.is_none());
        assert_eq!(cursor, Point { x: 320.4, y: 640.6 });

        // Instant click -> input tap
        let tap_args = build_input_shell_args(
            &InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 0,
            },
            &mut cursor,
        );
        assert_eq!(
            tap_args,
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "tap".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
            ])
        );

        // Long press (hold_ms > 0) -> input swipe at same coordinates
        let hold_args = build_input_shell_args(
            &InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 120,
            },
            &mut cursor,
        );
        assert_eq!(
            hold_args,
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "swipe".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
                "120".to_owned(),
            ])
        );

        // Negative delta_y scrolls down by swiping upward from cursor (641 -> 441).
        let scroll_args = build_input_shell_args(
            &InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: -200.0,
            },
            &mut cursor,
        );
        assert_eq!(
            scroll_args,
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "swipe".to_owned(),
                "320".to_owned(),
                "641".to_owned(),
                "320".to_owned(),
                "441".to_owned(),
                "250".to_owned(),
            ])
        );
    }

    #[test]
    fn build_drag_args_picks_gesture_and_clamps_duration() {
        let from = Point { x: 100.4, y: 200.6 };
        let to = Point { x: 300.0, y: 50.0 };
        assert_eq!(
            build_drag_args(from, to, 850, false),
            vec!["shell", "input", "swipe", "100", "201", "300", "50", "850"]
        );
        assert_eq!(
            build_drag_args(from, to, 850, true),
            vec![
                "shell",
                "input",
                "draganddrop",
                "100",
                "201",
                "300",
                "50",
                "850"
            ]
        );
        assert_eq!(build_drag_args(from, to, 5, true)[7], "300");
        assert_eq!(build_drag_args(from, to, u64::MAX, false)[7], "10000");
    }

    #[test]
    fn parses_sdk_level_and_gates_drag_and_drop() {
        assert_eq!(parse_sdk_level("33\r\n"), Some(33));
        assert_eq!(parse_sdk_level(""), None);
        assert_eq!(parse_sdk_level("error: no devices"), None);
        assert!(supports_drag_and_drop(Some(26)));
        assert!(supports_drag_and_drop(Some(34)));
        assert!(!supports_drag_and_drop(Some(25)));
        assert!(!supports_drag_and_drop(None));
    }

    fn failing_adb(_: &[String]) -> Result<()> {
        Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: "injected adb failure".to_owned(),
        })
    }

    #[test]
    fn failed_drag_release_is_reported_and_retried() {
        let mut cursor = Point { x: 10.0, y: 20.0 };
        let mut pending = None;
        let left = MouseButton::Left;
        let sent: std::cell::RefCell<Vec<Vec<String>>> = std::cell::RefCell::new(Vec::new());
        let record = |args: &[String]| {
            sent.borrow_mut().push(args.to_vec());
            Ok(())
        };

        let down = InputEvent::MouseDown { button: left };
        let drag = InputEvent::PointerDrag {
            to: Point { x: 90.0, y: 40.0 },
            button: left,
        };
        let up = InputEvent::MouseUp { button: left };
        assert!(dispatch_input_with(&down, &mut cursor, &mut pending, || Some(30), record).is_ok());
        assert!(dispatch_input_with(&drag, &mut cursor, &mut pending, || Some(30), record).is_ok());

        // The gesture fails: the error surfaces and the drag stays buffered.
        let failed = dispatch_input_with(&up, &mut cursor, &mut pending, || Some(30), failing_adb);
        assert!(failed.is_err());
        assert!(pending.is_some());

        // The retry sends the same gesture and only then forgets the drag.
        assert!(dispatch_input_with(&up, &mut cursor, &mut pending, || Some(30), record).is_ok());
        assert!(pending.is_none());
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(
            sent.borrow()[0][..7],
            ["shell", "input", "draganddrop", "10", "20", "90", "40"]
        );

        // Old devices fall back to a swipe.
        assert!(dispatch_input_with(&down, &mut cursor, &mut pending, || Some(25), record).is_ok());
        assert!(dispatch_input_with(&up, &mut cursor, &mut pending, || Some(25), record).is_ok());
        assert_eq!(sent.borrow().len(), 2);
        assert_eq!(sent.borrow()[1][2], "swipe");
    }

    #[test]
    fn press_drag_and_release_buffer_without_invoking_adb() {
        let mut cursor = Point { x: 10.0, y: 20.0 };
        let mut pending = None;
        let left = MouseButton::Left;
        let no_sdk_probe = || -> Option<u32> { None };

        // A release with nothing pressed has nothing to send (`failing_adb` would error).
        let up = InputEvent::MouseUp { button: left };
        assert!(
            dispatch_input_with(&up, &mut cursor, &mut pending, no_sdk_probe, failing_adb).is_ok()
        );

        let down = InputEvent::MouseDown { button: left };
        assert!(
            dispatch_input_with(&down, &mut cursor, &mut pending, no_sdk_probe, failing_adb)
                .is_ok()
        );
        assert_eq!(pending.map(|d| d.from), Some(Point { x: 10.0, y: 20.0 }));

        let drag = InputEvent::PointerDrag {
            to: Point { x: 90.0, y: 40.0 },
            button: left,
        };
        assert!(
            dispatch_input_with(&drag, &mut cursor, &mut pending, no_sdk_probe, failing_adb)
                .is_ok()
        );
        assert_eq!(cursor, Point { x: 90.0, y: 40.0 });
        assert!(pending.is_some());
    }

    #[test]
    fn build_input_shell_args_handles_key_events() {
        let mut cursor = Point { x: 0.0, y: 0.0 };

        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Enter,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "66".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Tab,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "61".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Escape,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "111".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Backspace,
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "keyevent".to_owned(),
                "67".to_owned(),
            ])
        );
        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Char(';'),
                    modifiers: vec![],
                    hold_ms: 0,
                },
                &mut cursor,
            ),
            Some(vec![
                "shell".to_owned(),
                "input".to_owned(),
                "text".to_owned(),
                "';'".to_owned(),
            ])
        );
    }

    #[test]
    fn validate_http_url_accepts_http_https_and_rejects_others() {
        assert!(validate_http_url("https://example.com/path?a=1&b=2").is_ok());
        assert!(validate_http_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_http_url("HTTPS://EXAMPLE.COM").is_ok());

        assert!(validate_http_url("").is_err());
        assert!(validate_http_url("javascript:alert(1)").is_err());
        assert!(validate_http_url("file:///etc/passwd").is_err());
        assert!(validate_http_url("https://example.com/has space").is_err());
        assert!(validate_http_url("https://").is_err());
    }

    #[test]
    fn validate_png_bytes_checks_magic_header() {
        let mut valid = PNG_MAGIC.to_vec();
        valid.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        assert!(validate_png_bytes(&valid).is_ok());

        assert!(validate_png_bytes(&[]).is_err());
        assert!(validate_png_bytes(b"not a png").is_err());
    }
}
