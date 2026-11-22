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
        InputEvent::PointerMove { to } => vec![vec![
            "mousemove".to_owned(),
            "--sync".to_owned(),
            format_coord(to.x),
            format_coord(to.y),
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
                let btn = if *delta_y < 0.0 { "4" } else { "5" };
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
        InputEvent::KeyPress { key, modifiers } => {
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

/// Builds the sequence of `ydotool` argument vectors for an [`InputEvent`].
#[must_use]
pub fn build_ydotool_commands(event: &InputEvent) -> Vec<Vec<String>> {
    match event {
        InputEvent::PointerMove { to } => vec![vec![
            "mousemove".to_owned(),
            "--absolute".to_owned(),
            "-x".to_owned(),
            format_coord(to.x),
            "-y".to_owned(),
            format_coord(to.y),
        ]],
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
        InputEvent::KeyPress { key, modifiers } => {
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

/// Dispatches an [`InputEvent`] via `xdotool` (X11/Xvfb) or `ydotool` (Wayland).
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if the input binary is missing or
/// exits non-zero, or [`WayboundError::Timeout`] if dispatch exceeds 10 seconds.
pub fn dispatch_input(
    event: &InputEvent,
    server: DisplayServer,
    display: Option<&str>,
) -> Result<()> {
    let (program, commands) = match server {
        DisplayServer::X11 => ("xdotool", build_xdotool_commands(event)),
        DisplayServer::Wayland => ("ydotool", build_ydotool_commands(event)),
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use waybound_core::Point;

    use super::*;

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
            vec![vec!["mousemove", "--sync", "121", "45"]]
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
                delta_y: 3.0,
            }),
            vec![vec!["click", "--repeat", "3", "--delay", "12", "5"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Char('a'),
                modifiers: Vec::new(),
            }),
            vec![vec!["type", "--delay", "0", "--", "a"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Char('l'),
                modifiers: vec![KeyModifier::Control],
            }),
            vec![vec!["key", "--clearmodifiers", "ctrl+l"]]
        );

        assert_eq!(
            build_xdotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Enter,
                modifiers: vec![KeyModifier::Meta, KeyModifier::Shift],
            }),
            vec![vec!["key", "--clearmodifiers", "super+shift+Return"]]
        );
    }

    #[test]
    fn builds_ydotool_commands_for_pointer_click_scroll_and_keys() {
        assert_eq!(
            build_ydotool_commands(&InputEvent::PointerMove {
                to: Point { x: 300.0, y: 500.0 },
            }),
            vec![vec!["mousemove", "--absolute", "-x", "300", "-y", "500"]]
        );

        assert_eq!(
            build_ydotool_commands(&InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 0,
            }),
            vec![vec!["click", "0xC0"]]
        );

        assert_eq!(
            build_ydotool_commands(&InputEvent::MouseClick {
                button: MouseButton::Middle,
                hold_ms: 150,
            }),
            vec![vec!["click", "--next-delay", "150", "0x42", "0x82"]]
        );

        assert_eq!(
            build_ydotool_commands(&InputEvent::Scroll {
                delta_x: 2.0,
                delta_y: 4.0,
            }),
            vec![vec!["mousemove", "--wheel", "-x", "2", "-y", "-4"]]
        );

        assert_eq!(
            build_ydotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Char('l'),
                modifiers: vec![KeyModifier::Control],
            }),
            vec![vec!["key", "29:1", "38:1", "38:0", "29:0"]]
        );

        assert_eq!(
            build_ydotool_commands(&InputEvent::KeyPress {
                key: KeyCode::Char('z'),
                modifiers: Vec::new(),
            }),
            vec![vec!["type", "--key-delay", "0", "--", "z"]]
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
            vec![vec!["mousemove", "--sync", "0", "0"]]
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
            build_ydotool_commands(&InputEvent::Scroll {
                delta_x: 0.0,
                delta_y: f64::NAN,
            })
            .len(),
            0
        );
    }
}
