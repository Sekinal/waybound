//! Linux input dispatch via `xdotool` (X11/Xvfb) and `ydotool` (Wayland).

use tracing::debug;
use waybound_core::{InputEvent, KeyCode, KeyModifier, MouseButton, Result, WayboundError};

use crate::process::{BACKEND_NAME, DEFAULT_TIMEOUT, run_with_timeout, truncate_for_log};

/// Active Linux display server protocol used to select input and capture tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayServer {
    /// X11 or headless Xvfb display server (`xdotool`, `import`/`scrot`).
    X11,
    /// Wayland compositor (`ydotool`, `grim`).
    Wayland,
}

impl DisplayServer {
    /// Detects the active display server from `WAYLAND_DISPLAY` and `DISPLAY`.
    #[must_use]
    pub fn detect() -> Self {
        let wayland = std::env::var("WAYLAND_DISPLAY").ok();
        let x11 = std::env::var("DISPLAY").ok();
        Self::detect_from_env(wayland.as_deref(), x11.as_deref())
    }

    /// Pure detection helper accepting explicit environment variable values.
    #[must_use]
    pub fn detect_from_env(wayland_display: Option<&str>, x11_display: Option<&str>) -> Self {
        if wayland_display.is_some_and(|v| !v.trim().is_empty()) {
            return Self::Wayland;
        }
        if x11_display.is_some_and(|v| !v.trim().is_empty()) {
            return Self::X11;
        }
        Self::X11
    }
}

/// Formats a floating-point screen coordinate as a clamped integer string without casts.
fn format_coord(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_owned();
    }
    let clamped = value.round().clamp(-1_000_000.0, 1_000_000.0);
    if clamped == 0.0 {
        "0".to_owned()
    } else {
        format!("{clamped:.0}")
    }
}

/// Computes a bounded positive scroll step count from a logical delta.
fn scroll_steps(delta: f64) -> u32 {
    if !delta.is_finite() || delta == 0.0 {
        return 0;
    }
    let mag = delta.abs().round().clamp(1.0, 50.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        mag as u32
    }
}

/// Converts a logical scroll delta into a signed integer wheel tick count for `ydotool`.
fn signed_wheel_ticks(delta: f64) -> i32 {
    let steps = scroll_steps(delta);
    let signed = i32::try_from(steps).unwrap_or(50);
    if delta < 0.0 { -signed } else { signed }
}

const fn xdotool_button(button: MouseButton) -> &'static str {
    match button {
        MouseButton::Left => "1",
        MouseButton::Middle => "2",
        MouseButton::Right => "3",
    }
}

const fn xdotool_modifier(modifier: KeyModifier) -> &'static str {
    match modifier {
        KeyModifier::Meta => "super",
        KeyModifier::Control => "ctrl",
        KeyModifier::Alt => "alt",
        KeyModifier::Shift => "shift",
    }
}

fn xdotool_keysym(ch: char) -> String {
    match ch {
        ' ' => "space".to_owned(),
        '-' => "minus".to_owned(),
        '=' => "equal".to_owned(),
        '[' => "bracketleft".to_owned(),
        ']' => "bracketright".to_owned(),
        '\\' => "backslash".to_owned(),
        ';' => "semicolon".to_owned(),
        '\'' => "apostrophe".to_owned(),
        ',' => "comma".to_owned(),
        '.' => "period".to_owned(),
        '/' => "slash".to_owned(),
        '`' => "grave".to_owned(),
        c if c.is_ascii_alphanumeric() => c.to_string(),
        c => format!("U{:04X}", u32::from(c)),
    }
}

/// Builds the sequence of `xdotool` argument vectors for an [`InputEvent`].
#[must_use]
pub fn build_xdotool_commands(event: &InputEvent) -> Vec<Vec<String>> {
    match event {
        // `xdotool mousemove` goes through XTEST, which tracks held buttons itself, so a
        // move during a drag needs no special form.
        InputEvent::PointerMove { to } | InputEvent::PointerDrag { to, .. } => vec![vec![
            "mousemove".to_owned(),
            format_coord(to.x),
            format_coord(to.y),
        ]],
        InputEvent::MouseDown { button } => vec![vec![
            "mousedown".to_owned(),
            xdotool_button(*button).to_owned(),
        ]],
        InputEvent::MouseUp { button } => vec![vec![
            "mouseup".to_owned(),
            xdotool_button(*button).to_owned(),
        ]],
        InputEvent::MouseClick { button, hold_ms } => {
            let btn = xdotool_button(*button).to_owned();
            if *hold_ms == 0 {
                vec![vec!["click".to_owned(), btn]]
            } else {
                let sleep_secs = format!("{}.{:03}", hold_ms / 1_000, hold_ms % 1_000);
                vec![vec![
                    "mousedown".to_owned(),
                    btn.clone(),
                    "sleep".to_owned(),
                    sleep_secs,
                    "mouseup".to_owned(),
                    btn,
                ]]
            }
        }
        InputEvent::Scroll { delta_x, delta_y } => {
            let mut cmds = Vec::new();
            let y_steps = scroll_steps(*delta_y);
            if y_steps > 0 {
                // Negative delta_y scrolls down (X11 button 5); positive scrolls up (button 4).
                let btn = if *delta_y < 0.0 { "5" } else { "4" };
                cmds.push(vec![
                    "click".to_owned(),
                    "--repeat".to_owned(),
                    y_steps.to_string(),
                    "--delay".to_owned(),
                    "12".to_owned(),
                    btn.to_owned(),
                ]);
            }
            let x_steps = scroll_steps(*delta_x);
            if x_steps > 0 {
                let btn = if *delta_x < 0.0 { "6" } else { "7" };
                cmds.push(vec![
                    "click".to_owned(),
                    "--repeat".to_owned(),
                    x_steps.to_string(),
                    "--delay".to_owned(),
                    "12".to_owned(),
                    btn.to_owned(),
                ]);
            }
            cmds
        }
        InputEvent::KeyPress { key, modifiers, .. } => {
            if modifiers.is_empty()
                && let KeyCode::Char(ch) = key
                && !ch.is_control()
            {
                return vec![vec![
                    "type".to_owned(),
                    "--delay".to_owned(),
                    "0".to_owned(),
                    "--".to_owned(),
                    ch.to_string(),
                ]];
            }

            let mut parts: Vec<String> = modifiers
                .iter()
                .map(|m| xdotool_modifier(*m).to_owned())
                .collect();
            let key_part = match key {
                KeyCode::Enter => "Return".to_owned(),
                KeyCode::Tab => "Tab".to_owned(),
                KeyCode::Escape => "Escape".to_owned(),
                KeyCode::Backspace => "BackSpace".to_owned(),
                KeyCode::ArrowLeft => "Left".to_owned(),
                KeyCode::ArrowRight => "Right".to_owned(),
                KeyCode::ArrowUp => "Up".to_owned(),
                KeyCode::ArrowDown => "Down".to_owned(),
                KeyCode::Space => "space".to_owned(),
                KeyCode::Delete => "Delete".to_owned(),
                KeyCode::Home => "Home".to_owned(),
                KeyCode::End => "End".to_owned(),
                KeyCode::PageUp => "Prior".to_owned(),
                KeyCode::PageDown => "Next".to_owned(),
                KeyCode::Char(ch) => xdotool_keysym(*ch),
            };
            parts.push(key_part);

            vec![vec![
                "key".to_owned(),
                "--clearmodifiers".to_owned(),
                parts.join("+"),
            ]]
        }
    }
}

const fn ydotool_button_codes(button: MouseButton) -> (&'static str, &'static str, &'static str) {
    match button {
        MouseButton::Left => ("0xC0", "0x40", "0x80"),
        MouseButton::Right => ("0xC1", "0x41", "0x81"),
        MouseButton::Middle => ("0xC2", "0x42", "0x82"),
    }
}

const fn ydotool_modifier_keycode(modifier: KeyModifier) -> u16 {
    match modifier {
        KeyModifier::Meta => 125,
        KeyModifier::Control => 29,
        KeyModifier::Alt => 56,
        KeyModifier::Shift => 42,
    }
}

/// Maps common ASCII characters to Linux `input-event-codes.h` keycodes.
const fn linux_char_keycode(ch: char) -> Option<u16> {
    match ch.to_ascii_lowercase() {
        '1' => Some(2),
        '2' => Some(3),
        '3' => Some(4),
        '4' => Some(5),
        '5' => Some(6),
        '6' => Some(7),
        '7' => Some(8),
        '8' => Some(9),
        '9' => Some(10),
        '0' => Some(11),
        '-' => Some(12),
        '=' => Some(13),
        'q' => Some(16),
        'w' => Some(17),
        'e' => Some(18),
        'r' => Some(19),
        't' => Some(20),
        'y' => Some(21),
        'u' => Some(22),
        'i' => Some(23),
        'o' => Some(24),
        'p' => Some(25),
        '[' => Some(26),
        ']' => Some(27),
        'a' => Some(30),
        's' => Some(31),
        'd' => Some(32),
        'f' => Some(33),
        'g' => Some(34),
        'h' => Some(35),
        'j' => Some(36),
        'k' => Some(37),
        'l' => Some(38),
        ';' => Some(39),
        '\'' => Some(40),
        '`' => Some(41),
        '\\' => Some(43),
        'z' => Some(44),
        'x' => Some(45),
        'c' => Some(46),
        'v' => Some(47),
        'b' => Some(48),
        'n' => Some(49),
        'm' => Some(50),
        ',' => Some(51),
        '.' => Some(52),
        '/' => Some(53),
        ' ' => Some(57),
        _ => None,
    }
}

/// Builds a `ydotool click` that only presses (`down`) or only releases `button`.
fn ydotool_button_command(button: MouseButton, down: bool) -> Vec<String> {
    let (_, down_code, up_code) = ydotool_button_codes(button);
    let code = if down { down_code } else { up_code };
    vec!["click".to_owned(), code.to_owned()]
}

/// Rounds a logical coordinate to the whole pixel `ydotool` is given.
#[allow(clippy::cast_possible_truncation)]
fn coord_px(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(-1_000_000.0, 1_000_000.0) as i32
}

/// Builds the sequence of `ydotool` argument vectors for an [`InputEvent`].
///
/// `cursor` is the pointer position (whole pixels) the previous commands left the pointer
/// at. `ydotool mousemove --absolute` is implemented as a jump to the `(0, 0)` corner
/// followed by a relative move, so it is only used for plain moves; moves with a button
/// held ([`InputEvent::PointerDrag`]) are relative to `cursor`, or else the drag would be
/// dragged through the top-left corner (and could trip GNOME's hot corner). Relative moves
/// go through the compositor's pointer acceleration, so with an accelerated profile the
/// drop can land short of or past the target.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] for a drag move while the pointer
/// position is unknown (no absolute move was sent yet).
pub fn build_ydotool_commands(
    event: &InputEvent,
    cursor: &mut Option<(i32, i32)>,
) -> Result<Vec<Vec<String>>> {
    match event {
        InputEvent::PointerMove { to } => {
            let (x, y) = (coord_px(to.x), coord_px(to.y));
            *cursor = Some((x, y));
            Ok(vec![vec![
                "mousemove".to_owned(),
                "--absolute".to_owned(),
                "-x".to_owned(),
                x.to_string(),
                "-y".to_owned(),
                y.to_string(),
            ]])
        }
        InputEvent::PointerDrag { to, .. } => {
            let Some((from_x, from_y)) = *cursor else {
                return Err(WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: "ydotool drag needs a known pointer position; move the pointer \
                             before pressing"
                        .to_owned(),
                });
            };
            let (x, y) = (coord_px(to.x), coord_px(to.y));
            *cursor = Some((x, y));
            let (dx, dy) = (x - from_x, y - from_y);
            if dx == 0 && dy == 0 {
                // Already there: nothing to move.
                return Ok(Vec::new());
            }
            Ok(vec![vec![
                "mousemove".to_owned(),
                "-x".to_owned(),
                dx.to_string(),
                "-y".to_owned(),
                dy.to_string(),
            ]])
        }
        other => Ok(ydotool_stateless_commands(other)),
    }
}

/// `ydotool` commands for events that do not depend on the pointer position.
fn ydotool_stateless_commands(event: &InputEvent) -> Vec<Vec<String>> {
    match event {
        // Pointer moves need the tracked position; see `build_ydotool_commands`.
        InputEvent::PointerMove { .. } | InputEvent::PointerDrag { .. } => Vec::new(),
        InputEvent::MouseDown { button } => vec![ydotool_button_command(*button, true)],
        InputEvent::MouseUp { button } => vec![ydotool_button_command(*button, false)],
        InputEvent::MouseClick { button, hold_ms } => {
            let (click_code, down_code, up_code) = ydotool_button_codes(*button);
            if *hold_ms == 0 {
                vec![vec!["click".to_owned(), click_code.to_owned()]]
            } else {
                vec![vec![
                    "click".to_owned(),
                    "--next-delay".to_owned(),
                    hold_ms.to_string(),
                    down_code.to_owned(),
                    up_code.to_owned(),
                ]]
            }
        }
        InputEvent::Scroll { delta_x, delta_y } => {
            let wx = signed_wheel_ticks(*delta_x);
            let wy = -signed_wheel_ticks(*delta_y);
            if wx == 0 && wy == 0 {
                Vec::new()
            } else {
                vec![vec![
                    "mousemove".to_owned(),
                    "--wheel".to_owned(),
                    "-x".to_owned(),
                    wx.to_string(),
                    "-y".to_owned(),
                    wy.to_string(),
                ]]
            }
        }
        InputEvent::KeyPress { key, modifiers, .. } => {
            if modifiers.is_empty()
                && let KeyCode::Char(ch) = key
                && !ch.is_control()
            {
                return vec![vec![
                    "type".to_owned(),
                    "--key-delay".to_owned(),
                    "0".to_owned(),
                    "--".to_owned(),
                    ch.to_string(),
                ]];
            }

            let primary_code = match key {
                KeyCode::Enter => Some(28),
                KeyCode::Tab => Some(15),
                KeyCode::Escape => Some(1),
                KeyCode::Backspace => Some(14),
                KeyCode::ArrowLeft => Some(105),
                KeyCode::ArrowRight => Some(106),
                KeyCode::ArrowUp => Some(103),
                KeyCode::ArrowDown => Some(108),
                KeyCode::Space => Some(57),
                KeyCode::Delete => Some(111),
                KeyCode::Home => Some(102),
                KeyCode::End => Some(107),
                KeyCode::PageUp => Some(104),
                KeyCode::PageDown => Some(109),
                KeyCode::Char(ch) => linux_char_keycode(*ch),
            };

            let Some(code) = primary_code else {
                if let KeyCode::Char(ch) = key {
                    return vec![vec![
                        "type".to_owned(),
                        "--key-delay".to_owned(),
                        "0".to_owned(),
                        "--".to_owned(),
                        ch.to_string(),
                    ]];
                }
                return Vec::new();
            };

            let mut args = vec!["key".to_owned()];
            for modifier in modifiers {
                args.push(format!("{}:1", ydotool_modifier_keycode(*modifier)));
            }
            args.push(format!("{code}:1"));
            args.push(format!("{code}:0"));
            for modifier in modifiers.iter().rev() {
                args.push(format!("{}:0", ydotool_modifier_keycode(*modifier)));
            }
            vec![args]
        }
    }
}

/// Pastes a single non-ASCII Unicode character via `xclip -selection clipboard` + `Ctrl+v`.
///
/// `xdotool type` dynamically remaps temporary X11 keycodes for non-ASCII / CJK characters
/// and frees them before Chromium finishes processing the event, silently dropping characters.
/// Returns `Ok(true)` if `xclip` succeeded, or `Ok(false)` if `xclip` is unavailable.
pub(crate) fn try_paste_unicode_x11(ch: char, display: Option<&str>) -> Result<bool> {
    use std::io::Write;
    use std::process::Stdio;
    use std::thread;
    use std::time::Duration;

    let mut cmd = waybound_core::process::command("xclip");
    let _ = cmd
        .args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(disp) = display {
        let _ = cmd.env("DISPLAY", disp);
    }

    let Ok(mut child) = cmd.spawn() else {
        return Ok(false);
    };

    if let Some(mut stdin) = child.stdin.take() {
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        if stdin.write_all(s.as_bytes()).is_err() {
            return Ok(false);
        }
    }

    let Ok(status) = child.wait() else {
        return Ok(false);
    };
    if !status.success() {
        return Ok(false);
    }

    thread::sleep(Duration::from_millis(15));
    let mut envs: Vec<(&str, &str)> = Vec::new();
    if let Some(disp) = display {
        envs.push(("DISPLAY", disp));
    }
    let paste_args = vec![
        "key".to_owned(),
        "--clearmodifiers".to_owned(),
        "ctrl+v".to_owned(),
    ];
    let output = run_with_timeout(
        "xdotool",
        &paste_args,
        &envs,
        DEFAULT_TIMEOUT,
        "Linux X11 Unicode paste",
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "`xdotool` paste failed ({}): {}",
                output.status,
                truncate_for_log(&stderr)
            ),
        });
    }
    Ok(true)
}

/// Dispatches an [`InputEvent`] via `xdotool` (X11/Xvfb) or `ydotool` (Wayland).
///
/// `ydotool_cursor` carries the pointer position between `ydotool` calls (see
/// [`build_ydotool_commands`]).
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if the input binary is missing or
/// exits non-zero, or [`WayboundError::Timeout`] if dispatch exceeds 10 seconds.
pub fn dispatch_input(
    event: &InputEvent,
    server: DisplayServer,
    display: Option<&str>,
    ydotool_cursor: &mut Option<(i32, i32)>,
) -> Result<()> {
    if server == DisplayServer::X11
        && let InputEvent::KeyPress {
            key: KeyCode::Char(ch),
            modifiers,
            ..
        } = event
        && modifiers.is_empty()
        && !ch.is_ascii()
        && !ch.is_control()
        && try_paste_unicode_x11(*ch, display)?
    {
        return Ok(());
    }

    let mut next_cursor = *ydotool_cursor;
    let (program, commands) = match server {
        DisplayServer::X11 => ("xdotool", build_xdotool_commands(event)),
        // Plan against a copy: the tracked position only advances once the move succeeded.
        DisplayServer::Wayland => ("ydotool", build_ydotool_commands(event, &mut next_cursor)?),
    };

    let mut envs: Vec<(&str, &str)> = Vec::new();
    if server == DisplayServer::X11
        && let Some(disp) = display
    {
        envs.push(("DISPLAY", disp));
    }

    for args in &commands {
        debug!(program, ?args, ?server, "dispatching Linux input command");
        let output = run_with_timeout(
            program,
            args,
            &envs,
            DEFAULT_TIMEOUT,
            "Linux input dispatch",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!(
                    "`{program}` failed ({}): {}",
                    output.status,
                    truncate_for_log(&stderr)
                ),
            });
        }
    }

    *ydotool_cursor = next_cursor;
    Ok(())
}

#[cfg(test)]
mod tests {
    use waybound_core::Point;

    use super::*;

    /// Builds `ydotool` commands from an unknown starting pointer position.
    fn ydo(event: &InputEvent) -> Vec<Vec<String>> {
        build_ydotool_commands(event, &mut None).unwrap_or_default()
    }

    #[test]
    fn detects_display_server_from_environment_vars() {
        assert_eq!(
            DisplayServer::detect_from_env(Some("wayland-0"), Some(":0")),
            DisplayServer::Wayland
        );
        assert_eq!(
            DisplayServer::detect_from_env(None, Some(":99")),
            DisplayServer::X11
        );
        assert_eq!(
            DisplayServer::detect_from_env(Some("   "), Some(":0")),
            DisplayServer::X11
        );
        assert_eq!(
            DisplayServer::detect_from_env(None, None),
            DisplayServer::X11
        );
    }

    #[test]
    fn builds_xdotool_commands_for_pointer_click_scroll_and_keys() {
        assert_eq!(
            build_xdotool_commands(&InputEvent::PointerMove {
                to: Point { x: 120.6, y: 45.2 },
            }),
            vec![vec!["mousemove", "121", "45"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::MouseClick {
                button: MouseButton::Right,
                hold_ms: 0,
            }),
            vec![vec!["click", "3"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 250,
            }),
            vec![vec!["mousedown", "1", "sleep", "0.250", "mouseup", "1"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: -3.0,
            }),
            vec![vec!["click", "--repeat", "3", "--delay", "12", "5"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Char('a'),
                modifiers: Vec::new(),
                hold_ms: 0,
            }),
            vec![vec!["type", "--delay", "0", "--", "a"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Char('l'),
                modifiers: vec![KeyModifier::Control],
                hold_ms: 0,
            }),
            vec![vec!["key", "--clearmodifiers", "ctrl+l"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Enter,
                modifiers: vec![KeyModifier::Meta, KeyModifier::Shift],
                hold_ms: 0,
            }),
            vec![vec!["key", "--clearmodifiers", "super+shift+Return"]]
        );
    }

    #[test]
    fn builds_ydotool_commands_for_pointer_click_scroll_and_keys() {
        assert_eq!(
            ydo(&InputEvent::PointerMove {
                to: Point { x: 300.0, y: 500.0 },
            }),
            vec![vec!["mousemove", "--absolute", "-x", "300", "-y", "500"]]
        );

        assert_eq!(
            ydo(&InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 0,
            }),
            vec![vec!["click", "0xC0"]]
        );

        assert_eq!(
            ydo(&InputEvent::MouseClick {
                button: MouseButton::Middle,
                hold_ms: 150,
            }),
            vec![vec!["click", "--next-delay", "150", "0x42", "0x82"]]
        );

        assert_eq!(
            ydo(&InputEvent::Scroll {
                delta_x: 2.0,
                delta_y: 4.0,
            }),
            vec![vec!["mousemove", "--wheel", "-x", "2", "-y", "-4"]]
        );

        assert_eq!(
            ydo(&InputEvent::KeyPress {
                key: KeyCode::Char('l'),
                modifiers: vec![KeyModifier::Control],
                hold_ms: 0,
            }),
            vec![vec!["key", "29:1", "38:1", "38:0", "29:0"]]
        );

        assert_eq!(
            ydo(&InputEvent::KeyPress {
                key: KeyCode::Char('z'),
                modifiers: Vec::new(),
                hold_ms: 0,
            }),
            vec![vec!["type", "--key-delay", "0", "--", "z"]]
        );
    }

    #[test]
    fn builds_press_drag_and_release_commands() {
        let down = InputEvent::MouseDown {
            button: MouseButton::Left,
        };
        let drag = InputEvent::PointerDrag {
            to: Point { x: 410.4, y: 88.6 },
            button: MouseButton::Left,
        };
        let up = InputEvent::MouseUp {
            button: MouseButton::Left,
        };

        assert_eq!(build_xdotool_commands(&down), vec![vec!["mousedown", "1"]]);
        assert_eq!(
            build_xdotool_commands(&drag),
            vec![vec!["mousemove", "410", "89"]]
        );
        assert_eq!(build_xdotool_commands(&up), vec![vec!["mouseup", "1"]]);

        assert_eq!(ydo(&down), vec![vec!["click", "0x40"]]);
        assert_eq!(ydo(&up), vec![vec!["click", "0x80"]]);
        assert_eq!(
            ydo(&InputEvent::MouseUp {
                button: MouseButton::Right,
            }),
            vec![vec!["click", "0x81"]]
        );
    }

    #[test]
    fn ydotool_drag_moves_are_relative_to_the_tracked_pointer() {
        let mut cursor = None;
        let left = MouseButton::Left;
        let drag_to = |x: f64, y: f64| InputEvent::PointerDrag {
            to: Point { x, y },
            button: left,
        };

        // Without a known position a drag cannot be placed, and says so.
        assert!(build_ydotool_commands(&drag_to(5.0, 5.0), &mut cursor).is_err());

        // One absolute move positions the pointer before the press.
        let positioned = build_ydotool_commands(
            &InputEvent::PointerMove {
                to: Point { x: 200.4, y: 100.6 },
            },
            &mut cursor,
        );
        assert_eq!(
            positioned.ok(),
            Some(vec![
                vec!["mousemove", "--absolute", "-x", "200", "-y", "101"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            ])
        );
        assert_eq!(cursor, Some((200, 101)));

        // Held moves are relative deltas and never go through `--absolute`.
        let first = build_ydotool_commands(&drag_to(210.0, 101.0), &mut cursor).ok();
        assert_eq!(
            first,
            Some(vec![
                vec!["mousemove", "-x", "10", "-y", "0"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            ])
        );
        let second = build_ydotool_commands(&drag_to(150.2, 60.0), &mut cursor).ok();
        assert_eq!(
            second,
            Some(vec![
                vec!["mousemove", "-x", "-60", "-y", "-41"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            ])
        );
        assert_eq!(cursor, Some((150, 60)));

        // Repeating the position sends nothing.
        assert_eq!(
            build_ydotool_commands(&drag_to(150.0, 60.0), &mut cursor).ok(),
            Some(Vec::new())
        );
    }

    #[test]
    fn handles_non_finite_coordinates_and_zero_scroll_gracefully() {
        assert_eq!(
            build_xdotool_commands(&InputEvent::PointerMove {
                to: Point {
                    x: f64::NAN,
                    y: f64::INFINITY,
                },
            }),
            vec![vec!["mousemove", "0", "0"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: 0.0,
            })
            .len(),
            0
        );

        assert_eq!(
            ydo(&InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: f64::NAN,
            })
            .len(),
            0
        );
    }
}
