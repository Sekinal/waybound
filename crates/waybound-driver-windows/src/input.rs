//! Win32 input coordinate normalization, virtual-key mapping, and `SendInput` dispatch.

use waybound_core::{KeyCode, KeyModifier};

/// Maximum coordinate value in Win32 `MOUSEEVENTF_ABSOLUTE` normalized space (`0..=65535`).
pub const ABSOLUTE_COORD_MAX: i32 = 65_535;

/// Converts a logical screen pixel coordinate `pos` along an axis of length `screen_extent`
/// into Win32 `MOUSEEVENTF_ABSOLUTE` `[0, 65535]` coordinates without overflow or `NaN`.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn to_absolute_coord(pos: f64, screen_extent: i32) -> i32 {
    if !pos.is_finite() || screen_extent <= 1 {
        return 0;
    }

    let max_pixel = f64::from(screen_extent - 1);
    let clamped = pos.clamp(0.0, max_pixel);
    let scaled = (clamped * f64::from(ABSOLUTE_COORD_MAX) / max_pixel).round();

    if !scaled.is_finite() {
        return 0;
    }

    scaled.clamp(0.0, f64::from(ABSOLUTE_COORD_MAX)) as i32
}

/// Maps a [`KeyCode`] to its corresponding Win32 Virtual-Key (`VK_*`) code, if one exists.
///
/// Non-ASCII or punctuation characters without a layout-independent virtual-key code return
/// `None` so callers can emit them via `KEYEVENTF_UNICODE` UTF-16 code units instead.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn key_to_vk(key: KeyCode) -> Option<u16> {
    match key {
        KeyCode::Enter => Some(0x0D),     // VK_RETURN
        KeyCode::Tab => Some(0x09),       // VK_TAB
        KeyCode::Escape => Some(0x1B),    // VK_ESCAPE
        KeyCode::Backspace => Some(0x08), // VK_BACK
        KeyCode::Char(c) => match c {
            'a'..='z' => Some(u16::from(c.to_ascii_uppercase() as u8)),
            'A'..='Z' | '0'..='9' => Some(u16::from(c as u8)),
            ' ' => Some(0x20), // VK_SPACE
            '-' => Some(0xBD), // VK_OEM_MINUS
            '=' => Some(0xBB), // VK_OEM_PLUS
            ',' => Some(0xBC), // VK_OEM_COMMA
            '.' => Some(0xBE), // VK_OEM_PERIOD
            '/' => Some(0xBF), // VK_OEM_2
            ';' => Some(0xBA), // VK_OEM_1
            _ => None,
        },
    }
}

/// Maps a [`KeyModifier`] to its corresponding Win32 Virtual-Key (`VK_*`) code.
#[must_use]
pub const fn modifier_to_vk(modifier: KeyModifier) -> u16 {
    match modifier {
        KeyModifier::Control => 0x11, // VK_CONTROL
        KeyModifier::Alt => 0x12,     // VK_MENU
        KeyModifier::Shift => 0x10,   // VK_SHIFT
        KeyModifier::Meta => 0x5B,    // VK_LWIN
    }
}

/// Audited Win32 `user32.dll` `SendInput` FFI backend (Windows only).
#[cfg(target_os = "windows")]
pub mod win32_input {
    use std::thread;
    use std::time::Duration;

    use waybound_core::{InputEvent, KeyCode, KeyModifier, MouseButton, Result, WayboundError};

    use super::{key_to_vk, modifier_to_vk, to_absolute_coord};

    const INPUT_MOUSE: u32 = 0;
    const INPUT_KEYBOARD: u32 = 1;

    const MOUSEEVENTF_MOVE: u32 = 0x0001;
    const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
    const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
    const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
    const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
    const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
    const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
    const MOUSEEVENTF_WHEEL: u32 = 0x0800;
    const MOUSEEVENTF_HWHEEL: u32 = 0x1000;
    const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;

    const KEYEVENTF_KEYUP: u32 = 0x0002;
    const KEYEVENTF_UNICODE: u32 = 0x0004;

    const SM_CXSCREEN: i32 = 0;
    const SM_CYSCREEN: i32 = 1;

    const WHEEL_DELTA: f64 = 120.0;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MouseInput {
        dx: i32,
        dy: i32,
        mouse_data: u32,
        dw_flags: u32,
        time: u32,
        dw_extra_info: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct KeybdInput {
        w_vk: u16,
        w_scan: u16,
        dw_flags: u32,
        time: u32,
        dw_extra_info: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct HardwareInput {
        u_msg: u32,
        w_param_l: u16,
        w_param_h: u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union InputUnion {
        mi: MouseInput,
        ki: KeybdInput,
        hi: HardwareInput,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Input {
        r#type: u32,
        u: InputUnion,
    }

    // SAFETY: Standard Win32 `user32.dll` ABI declarations for `SendInput` and `GetSystemMetrics`.
    #[link(name = "user32")]
    unsafe extern "system" {
        fn SendInput(c_inputs: u32, p_inputs: *const Input, cb_size: i32) -> u32;
        fn GetSystemMetrics(n_index: i32) -> i32;
    }

    fn send_inputs(inputs: &[Input]) -> Result<()> {
        if inputs.is_empty() {
            return Ok(());
        }
        let count = u32::try_from(inputs.len()).map_err(|_| WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: "input batch exceeds u32::MAX".to_owned(),
        })?;
        let cb_size =
            i32::try_from(size_of::<Input>()).map_err(|_| WayboundError::BackendUnavailable {
                backend: "windows".to_owned(),
                reason: "INPUT struct size exceeds i32::MAX".to_owned(),
            })?;

        // SAFETY: `inputs.as_ptr()` points to a valid contiguous array of `count` `Input`
        // structs whose `#[repr(C)]` layout matches Win32 `INPUT` of size `cb_size`.
        let sent = unsafe { SendInput(count, inputs.as_ptr(), cb_size) };
        if sent != count {
            return Err(WayboundError::BackendUnavailable {
                backend: "windows".to_owned(),
                reason: format!("SendInput dispatched {sent} of {count} events"),
            });
        }
        Ok(())
    }

    const fn mouse_input(dx: i32, dy: i32, mouse_data: u32, dw_flags: u32) -> Input {
        Input {
            r#type: INPUT_MOUSE,
            u: InputUnion {
                mi: MouseInput {
                    dx,
                    dy,
                    mouse_data,
                    dw_flags,
                    time: 0,
                    dw_extra_info: 0,
                },
            },
        }
    }

    const fn keybd_vk_input(vk: u16, key_up: bool) -> Input {
        Input {
            r#type: INPUT_KEYBOARD,
            u: InputUnion {
                ki: KeybdInput {
                    w_vk: vk,
                    w_scan: 0,
                    dw_flags: if key_up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dw_extra_info: 0,
                },
            },
        }
    }

    const fn keybd_unicode_input(code_unit: u16, key_up: bool) -> Input {
        Input {
            r#type: INPUT_KEYBOARD,
            u: InputUnion {
                ki: KeybdInput {
                    w_vk: 0,
                    w_scan: code_unit,
                    dw_flags: if key_up {
                        KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
                    } else {
                        KEYEVENTF_UNICODE
                    },
                    time: 0,
                    dw_extra_info: 0,
                },
            },
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn scroll_delta_to_dword(delta: f64) -> u32 {
        if !delta.is_finite() {
            return 0;
        }
        let scaled = (delta * WHEEL_DELTA).round().clamp(-32_760.0, 32_760.0) as i32;
        scaled.cast_unsigned()
    }

    /// Emits arbitrary Unicode text via Win32 `KEYEVENTF_UNICODE` UTF-16 code units.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `SendInput` rejects the event batch.
    pub fn send_unicode_text(text: &str) -> Result<()> {
        let mut batch = Vec::with_capacity(text.len().saturating_mul(2));
        for unit in text.encode_utf16() {
            batch.push(keybd_unicode_input(unit, false));
            batch.push(keybd_unicode_input(unit, true));
        }
        send_inputs(&batch)
    }

    /// Dispatches a platform-agnostic [`InputEvent`] via Win32 `SendInput`.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if `SendInput` fails to inject all events.
    pub fn dispatch_input_event(event: &InputEvent) -> Result<()> {
        tracing::debug!(?event, "dispatching Win32 input event");

        match event {
            InputEvent::PointerMove { to } => {
                // SAFETY: `GetSystemMetrics` is a pure Win32 query accepting integer metric IDs.
                let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
                // SAFETY: `GetSystemMetrics` is a pure Win32 query accepting integer metric IDs.
                let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };

                let abs_x = to_absolute_coord(to.x, width);
                let abs_y = to_absolute_coord(to.y, height);
                send_inputs(&[mouse_input(
                    abs_x,
                    abs_y,
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                )])
            }
            InputEvent::MouseClick { button, hold_ms } => {
                let (down_flag, up_flag) = match button {
                    MouseButton::Left => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
                    MouseButton::Right => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
                    MouseButton::Middle => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
                };

                send_inputs(&[mouse_input(0, 0, 0, down_flag)])?;
                if *hold_ms > 0 {
                    thread::sleep(Duration::from_millis(*hold_ms));
                }
                send_inputs(&[mouse_input(0, 0, 0, up_flag)])
            }
            InputEvent::Scroll { delta_x, delta_y } => {
                let mut batch = Vec::with_capacity(2);
                if delta_y.is_finite() && delta_y.abs() > f64::EPSILON {
                    // Win32 vertical wheel positive is upward, whereas web/logical delta_y positive scrolls down.
                    batch.push(mouse_input(
                        0,
                        0,
                        scroll_delta_to_dword(-*delta_y),
                        MOUSEEVENTF_WHEEL,
                    ));
                }
                if delta_x.is_finite() && delta_x.abs() > f64::EPSILON {
                    batch.push(mouse_input(
                        0,
                        0,
                        scroll_delta_to_dword(*delta_x),
                        MOUSEEVENTF_HWHEEL,
                    ));
                }
                send_inputs(&batch)
            }
            InputEvent::KeyPress { key, modifiers, .. } => {
                let has_shortcut_modifier = modifiers.iter().any(|m| {
                    matches!(
                        m,
                        KeyModifier::Control | KeyModifier::Alt | KeyModifier::Meta
                    )
                });

                if !has_shortcut_modifier
                    && modifiers.is_empty()
                    && let KeyCode::Char(c) = key
                    && !c.is_control()
                {
                    let mut utf16 = [0u16; 2];
                    let encoded = c.encode_utf16(&mut utf16);
                    let mut batch = Vec::with_capacity(encoded.len() * 2);
                    for &unit in encoded.iter() {
                        batch.push(keybd_unicode_input(unit, false));
                        batch.push(keybd_unicode_input(unit, true));
                    }
                    return send_inputs(&batch);
                }

                let mut batch = Vec::with_capacity(modifiers.len() * 2 + 4);
                for &modifier in modifiers {
                    batch.push(keybd_vk_input(modifier_to_vk(modifier), false));
                }

                if let Some(vk) = key_to_vk(key.clone()) {
                    batch.push(keybd_vk_input(vk, false));
                    batch.push(keybd_vk_input(vk, true));
                } else if let KeyCode::Char(c) = key {
                    let mut utf16 = [0u16; 2];
                    let encoded = c.encode_utf16(&mut utf16);
                    for &unit in encoded.iter() {
                        batch.push(keybd_unicode_input(unit, false));
                        batch.push(keybd_unicode_input(unit, true));
                    }
                }

                for &modifier in modifiers.iter().rev() {
                    batch.push(keybd_vk_input(modifier_to_vk(modifier), true));
                }

                send_inputs(&batch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_absolute_coordinates_across_screen_bounds() {
        assert_eq!(to_absolute_coord(0.0, 1920), 0);
        assert_eq!(to_absolute_coord(1919.0, 1920), ABSOLUTE_COORD_MAX);
        assert_eq!(to_absolute_coord(959.5, 1920), 32_768);
        assert_eq!(to_absolute_coord(-100.0, 1920), 0);
        assert_eq!(to_absolute_coord(5000.0, 1920), ABSOLUTE_COORD_MAX);
    }

    #[test]
    fn handles_non_finite_and_degenerate_extents_safely() {
        assert_eq!(to_absolute_coord(f64::NAN, 1920), 0);
        assert_eq!(to_absolute_coord(f64::INFINITY, 1920), 0);
        assert_eq!(to_absolute_coord(f64::NEG_INFINITY, 1920), 0);
        assert_eq!(to_absolute_coord(100.0, 0), 0);
        assert_eq!(to_absolute_coord(100.0, 1), 0);
        assert_eq!(to_absolute_coord(100.0, -1080), 0);
    }

    #[test]
    fn maps_special_and_ascii_virtual_keys() {
        assert_eq!(key_to_vk(KeyCode::Enter), Some(0x0D));
        assert_eq!(key_to_vk(KeyCode::Tab), Some(0x09));
        assert_eq!(key_to_vk(KeyCode::Escape), Some(0x1B));
        assert_eq!(key_to_vk(KeyCode::Backspace), Some(0x08));
        assert_eq!(key_to_vk(KeyCode::Char('a')), Some(0x41));
        assert_eq!(key_to_vk(KeyCode::Char('Z')), Some(0x5A));
        assert_eq!(key_to_vk(KeyCode::Char('7')), Some(0x37));
        assert_eq!(key_to_vk(KeyCode::Char(' ')), Some(0x20));
        assert_eq!(key_to_vk(KeyCode::Char('€')), None);
    }

    #[test]
    fn maps_all_key_modifiers_to_win32_vk() {
        assert_eq!(modifier_to_vk(KeyModifier::Control), 0x11);
        assert_eq!(modifier_to_vk(KeyModifier::Alt), 0x12);
        assert_eq!(modifier_to_vk(KeyModifier::Shift), 0x10);
        assert_eq!(modifier_to_vk(KeyModifier::Meta), 0x5B);
    }
}
