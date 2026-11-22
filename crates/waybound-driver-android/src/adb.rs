//! Pure-Rust ADB (`adb [-s <serial>] ...`) command runner for Android / Waydroid.

use std::path::Path;
use std::process::{Command, Output};

use tracing::debug;
use waybound_core::{InputEvent, KeyCode, Point, Result, WayboundError};

const BACKEND_NAME: &str = "android_waydroid";
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Default swipe origin used when scrolling before any `PointerMove` has been dispatched.
const DEFAULT_SCROLL_ORIGIN: Point = Point { x: 540.0, y: 960.0 };
const SCROLL_SWIPE_DURATION_MS: u64 = 250;

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
    let args = build_adb_args(serial, &["exec-out", "uiautomator", "dump", "/dev/tty"]);
    let output = run_adb(&args)?;
    ensure_success(&output, "uiautomator dump")?;

    let xml = String::from_utf8_lossy(&output.stdout).into_owned();
    if !xml.contains("<hierarchy") && !xml.contains("<node") {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "adb uiautomator dump did not contain XML hierarchy (stdout: {})",
                truncate_for_log(&xml)
            ),
        });
    }

    Ok(xml)
}

/// Dispatches a platform-agnostic [`InputEvent`] to an Android device via `adb shell input`.
///
/// Tracks `last_cursor` across [`InputEvent::PointerMove`], [`InputEvent::MouseClick`],
/// and [`InputEvent::Scroll`] events.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `adb` fails to execute or exits non-zero.
pub fn dispatch_input(
    serial: Option<&str>,
    event: &InputEvent,
    last_cursor: &mut Point,
) -> Result<()> {
    let Some(shell_args) = build_input_shell_args(event, last_cursor) else {
        return Ok(());
    };

    let arg_refs: Vec<&str> = shell_args.iter().map(String::as_str).collect();
    let args = build_adb_args(serial, &arg_refs);
    let output = run_adb(&args)?;
    ensure_success(&output, "input dispatch")
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

/// Builds the `adb shell input ...` arguments for an [`InputEvent`], updating `last_cursor`.
///
/// Returns `None` for events that only update local pointer state (such as `PointerMove`).
#[must_use]
pub fn build_input_shell_args(event: &InputEvent, last_cursor: &mut Point) -> Option<Vec<String>> {
    match event {
        InputEvent::PointerMove { to } => {
            *last_cursor = *to;
            None
        }
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
            let x2 = coord_to_i32(origin.x - *delta_x);
            let y2 = coord_to_i32(origin.y - *delta_y);
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
        InputEvent::KeyPress { key, modifiers: _ } => Some(build_key_shell_args(key)),
    }
}

fn build_key_shell_args(key: &KeyCode) -> Vec<String> {
    match key {
        KeyCode::Enter | KeyCode::Char('\n' | '\r') => keyevent_args(KEYCODE_ENTER),
        KeyCode::Tab | KeyCode::Char('\t') => keyevent_args(KEYCODE_TAB),
        KeyCode::Escape => keyevent_args(KEYCODE_ESCAPE),
        KeyCode::Backspace => keyevent_args(KEYCODE_BACKSPACE),
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
    let _ = cmd.args(args);
    cmd.output()
        .map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("failed to execute adb: {err}"),
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

        // Scroll -> input swipe from cursor to cursor - delta
        let scroll_args = build_input_shell_args(
            &InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: 200.0,
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
    fn build_input_shell_args_handles_key_events() {
        let mut cursor = Point { x: 0.0, y: 0.0 };

        assert_eq!(
            build_input_shell_args(
                &InputEvent::KeyPress {
                    key: KeyCode::Enter,
                    modifiers: vec![],
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
