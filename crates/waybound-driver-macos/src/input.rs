//! Safe CoreGraphics (`CGEvent`) native input dispatcher for macOS.

#![cfg(target_os = "macos")]

use std::ptr;
use std::thread;
use std::time::Duration;

use waybound_core::{InputEvent, KeyCode, KeyModifier, MouseButton, Point, Result, WayboundError};

use crate::ffi::{
    CGEventCreate, CGEventCreateKeyboardEvent, CGEventCreateMouseEvent,
    CGEventCreateScrollWheelEvent2, CGEventGetLocation, CGEventKeyboardSetUnicodeString,
    CGEventPost, CGEventSetFlags, CgEventType, CgMouseButton, CgPoint,
    K_CG_EVENT_FLAG_MASK_ALTERNATE, K_CG_EVENT_FLAG_MASK_COMMAND, K_CG_EVENT_FLAG_MASK_CONTROL,
    K_CG_EVENT_FLAG_MASK_SHIFT, K_CG_HID_EVENT_TAP, K_CG_SCROLL_EVENT_UNIT_PIXEL, OwnedCf,
};
use crate::keymap::ansi_keycode;

/// Dispatches a native macOS `CGEvent` for `event`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if CoreGraphics refuses to allocate an event.
pub fn dispatch_cg_event(event: &InputEvent, last_cursor: &mut Point) -> Result<()> {
    match event {
        InputEvent::PointerMove { to } => {
            *last_cursor = *to;
            post_mouse(CgEventType::MouseMoved, *to, CgMouseButton::Left)
        }
        InputEvent::MouseClick { button, hold_ms } => {
            let ButtonEvents {
                down,
                up,
                button: cg_button,
                ..
            } = button_events(*button);
            // Click where the pointer really is; the tracked position is only a fallback.
            if let Some(actual) = current_cursor_position() {
                *last_cursor = actual;
            }
            post_mouse(down, *last_cursor, cg_button)?;
            if *hold_ms > 0 {
                thread::sleep(Duration::from_millis((*hold_ms).min(1_000)));
            }
            post_mouse(up, *last_cursor, cg_button)
        }
        InputEvent::Scroll { delta_x, delta_y } => post_scroll(*delta_x, *delta_y),
        InputEvent::KeyPress {
            key,
            modifiers,
            hold_ms,
        } => post_key(key, modifiers, *hold_ms),
        InputEvent::MouseDown { button } => {
            let events = button_events(*button);
            if let Some(actual) = current_cursor_position() {
                *last_cursor = actual;
            }
            post_mouse(events.down, *last_cursor, events.button)
        }
        InputEvent::MouseUp { button } => {
            let events = button_events(*button);
            if let Some(actual) = current_cursor_position() {
                *last_cursor = actual;
            }
            post_mouse(events.up, *last_cursor, events.button)
        }
        InputEvent::PointerDrag { to, button } => {
            // While a button is held, AppKit and Chrome only treat motion as a drag when it
            // arrives as `*MouseDragged`; a plain `MouseMoved` would never start one.
            let events = button_events(*button);
            *last_cursor = *to;
            post_mouse(events.dragged, *to, events.button)
        }
    }
}

/// The CoreGraphics event types and button constant used for one logical mouse button.
#[derive(Debug, Clone, Copy)]
struct ButtonEvents {
    down: CgEventType,
    up: CgEventType,
    dragged: CgEventType,
    button: CgMouseButton,
}

const fn button_events(button: MouseButton) -> ButtonEvents {
    match button {
        MouseButton::Left => ButtonEvents {
            down: CgEventType::LeftMouseDown,
            up: CgEventType::LeftMouseUp,
            dragged: CgEventType::LeftMouseDragged,
            button: CgMouseButton::Left,
        },
        MouseButton::Right => ButtonEvents {
            down: CgEventType::RightMouseDown,
            up: CgEventType::RightMouseUp,
            dragged: CgEventType::RightMouseDragged,
            button: CgMouseButton::Right,
        },
        MouseButton::Middle => ButtonEvents {
            down: CgEventType::OtherMouseDown,
            up: CgEventType::OtherMouseUp,
            dragged: CgEventType::OtherMouseDragged,
            button: CgMouseButton::Center,
        },
    }
}

fn post_mouse(event_type: CgEventType, point: Point, button: CgMouseButton) -> Result<()> {
    let cg_point = CgPoint {
        x: point.x,
        y: point.y,
    };
    // SAFETY: `CGEventCreateMouseEvent` accepts a null source and returns a `+1` retained `CGEventRef` or null.
    let ev = unsafe {
        OwnedCf::from_owned(CGEventCreateMouseEvent(
            ptr::null(),
            event_type as u32,
            cg_point,
            button as u32,
        ))
    }
    .ok_or_else(|| WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason: "CGEventCreateMouseEvent returned null".to_owned(),
    })?;

    // SAFETY: `ev` is a valid non-null `CGEventRef`.
    unsafe { CGEventPost(K_CG_HID_EVENT_TAP, ev.as_ptr()) };
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn post_scroll(delta_x: f64, delta_y: f64) -> Result<()> {
    let dy = delta_y
        .round()
        .clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32;
    let dx = delta_x
        .round()
        .clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32;

    // SAFETY: `CGEventCreateScrollWheelEvent2` is non-variadic (macOS 10.13+, safe on ARM64 PCS)
    // and returns a `+1` retained `CGEventRef` or null.
    let ev = unsafe {
        OwnedCf::from_owned(CGEventCreateScrollWheelEvent2(
            ptr::null(),
            K_CG_SCROLL_EVENT_UNIT_PIXEL,
            2,
            dy,
            dx,
            0,
        ))
    }
    .ok_or_else(|| WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason: "CGEventCreateScrollWheelEvent2 returned null".to_owned(),
    })?;

    // SAFETY: `ev` is a valid non-null `CGEventRef`.
    unsafe { CGEventPost(K_CG_HID_EVENT_TAP, ev.as_ptr()) };
    Ok(())
}

/// Virtual keycode of the Command key (`kVK_Command`).
const VK_COMMAND: u16 = 0x37;
/// Virtual keycode of the Shift key (`kVK_Shift`).
const VK_SHIFT: u16 = 0x38;
/// Virtual keycode of the Option key (`kVK_Option`).
const VK_OPTION: u16 = 0x3A;
/// Virtual keycode of the Control key (`kVK_Control`).
const VK_CONTROL: u16 = 0x3B;

const fn modifier_flag(modifier: KeyModifier) -> u64 {
    match modifier {
        KeyModifier::Meta => K_CG_EVENT_FLAG_MASK_COMMAND,
        KeyModifier::Control => K_CG_EVENT_FLAG_MASK_CONTROL,
        KeyModifier::Alt => K_CG_EVENT_FLAG_MASK_ALTERNATE,
        KeyModifier::Shift => K_CG_EVENT_FLAG_MASK_SHIFT,
    }
}

const fn modifier_keycode(modifier: KeyModifier) -> u16 {
    match modifier {
        KeyModifier::Meta => VK_COMMAND,
        KeyModifier::Control => VK_CONTROL,
        KeyModifier::Alt => VK_OPTION,
        KeyModifier::Shift => VK_SHIFT,
    }
}

/// Reads the current pointer location in global display coordinates.
#[must_use]
pub fn current_cursor_position() -> Option<Point> {
    // SAFETY: `CGEventCreate` accepts a null source and returns a `+1` retained `CGEventRef` or null.
    let ev = unsafe { OwnedCf::from_owned(CGEventCreate(ptr::null())) }?;
    // SAFETY: `ev` is a valid non-null `CGEventRef`; `CGEventGetLocation` returns a `CGPoint` by value.
    let location = unsafe { CGEventGetLocation(ev.as_ptr()) };
    (location.x.is_finite() && location.y.is_finite()).then_some(Point {
        x: location.x,
        y: location.y,
    })
}

fn post_key(key: &KeyCode, modifiers: &[KeyModifier], hold_ms: u64) -> Result<()> {
    let mut held: Vec<KeyModifier> = Vec::with_capacity(modifiers.len() + 1);
    for modifier in modifiers {
        if !held.contains(modifier) {
            held.push(*modifier);
        }
    }

    match key {
        KeyCode::Enter => post_chord(0x24, None, &held, hold_ms),
        KeyCode::Tab => post_chord(0x30, None, &held, hold_ms),
        KeyCode::Escape => post_chord(0x35, None, &held, hold_ms),
        KeyCode::Backspace => post_chord(0x33, None, &held, hold_ms),
        KeyCode::ArrowLeft => post_chord(0x7B, None, &held, hold_ms),
        KeyCode::ArrowRight => post_chord(0x7C, None, &held, hold_ms),
        KeyCode::ArrowUp => post_chord(0x7E, None, &held, hold_ms),
        KeyCode::ArrowDown => post_chord(0x7D, None, &held, hold_ms),
        KeyCode::Space => post_chord(0x31, Some(' '), &held, hold_ms),
        KeyCode::Delete => post_chord(0x75, None, &held, hold_ms),
        KeyCode::Home => post_chord(0x73, None, &held, hold_ms),
        KeyCode::End => post_chord(0x77, None, &held, hold_ms),
        KeyCode::PageUp => post_chord(0x74, None, &held, hold_ms),
        KeyCode::PageDown => post_chord(0x79, None, &held, hold_ms),
        KeyCode::Char(ch) => match (ansi_keycode(*ch), held.is_empty()) {
            // Plain typing: the real ANSI key (so `KeyboardEvent.code` is right), Shift held
            // for capitals and shifted symbols, and the character pinned via the Unicode
            // string so it is correct on non-US keyboard layouts too.
            (Some((keycode, shifted)), true) => {
                if shifted {
                    held.push(KeyModifier::Shift);
                }
                post_chord(keycode, Some(*ch), &held, hold_ms)
            }
            // Shortcut: let the system derive the character from the key and modifiers.
            (Some((keycode, shifted)), false) => {
                if shifted && !held.contains(&KeyModifier::Shift) {
                    held.push(KeyModifier::Shift);
                }
                post_chord(keycode, None, &held, hold_ms)
            }
            // Non-ASCII text has no ANSI key; deliver it as a Unicode string.
            (None, true) => post_chord(0, Some(*ch), &held, hold_ms),
            // Never fall back to keycode 0 here: that is the A key, so an unmapped shortcut
            // would silently become e.g. Cmd+A (select all).
            (None, false) => Err(WayboundError::BackendUnavailable {
                backend: "macos_native".to_owned(),
                reason: format!("no virtual keycode for shortcut key {ch:?}"),
            }),
        },
    }
}

/// Presses `modifiers`, taps `keycode`, then releases the modifiers in reverse order,
/// mirroring the event sequence a physical keyboard produces.
fn post_chord(
    keycode: u16,
    unicode: Option<char>,
    modifiers: &[KeyModifier],
    hold_ms: u64,
) -> Result<()> {
    let mut flags = 0u64;
    let mut pressed: Vec<KeyModifier> = Vec::with_capacity(modifiers.len());
    let mut result = Ok(());

    for modifier in modifiers {
        flags |= modifier_flag(*modifier);
        if let Err(err) = post_key_event(modifier_keycode(*modifier), true, flags, None) {
            flags &= !modifier_flag(*modifier);
            result = Err(err);
            break;
        }
        pressed.push(*modifier);
    }

    if result.is_ok() {
        result = post_key_event(keycode, true, flags, unicode);
        if result.is_ok() {
            if hold_ms > 0 {
                thread::sleep(Duration::from_millis(hold_ms.min(1_000)));
            }
            result = post_key_event(keycode, false, flags, unicode);
        }
    }

    // Always release what was pressed, even after an error, so no modifier is left stuck.
    for modifier in pressed.iter().rev() {
        flags &= !modifier_flag(*modifier);
        let released = post_key_event(modifier_keycode(*modifier), false, flags, None);
        if result.is_ok() {
            result = released;
        }
    }
    result
}

fn post_key_event(keycode: u16, down: bool, flags: u64, unicode: Option<char>) -> Result<()> {
    // SAFETY: `CGEventCreateKeyboardEvent` accepts a null source and returns a `+1` retained
    // `CGEventRef` or null.
    let ev = unsafe {
        OwnedCf::from_owned(CGEventCreateKeyboardEvent(
            ptr::null(),
            keycode,
            u8::from(down),
        ))
    }
    .ok_or_else(|| WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason: "CGEventCreateKeyboardEvent returned null".to_owned(),
    })?;

    let mut utf16 = [0u16; 2];
    let encoded = unicode.map(|ch| ch.encode_utf16(&mut utf16));

    // SAFETY: `ev` is a valid non-null `CGEventRef`, and `encoded` (when present) is a valid
    // UTF-16 slice of length `encoded.len()` that outlives the call.
    unsafe {
        // Set flags unconditionally: an event created with a null source inherits the
        // current hardware modifier state, so a physically held key would otherwise leak in.
        CGEventSetFlags(ev.as_ptr(), flags);
        if let Some(units) = encoded {
            CGEventKeyboardSetUnicodeString(ev.as_ptr(), units.len(), units.as_ptr());
        }
        CGEventPost(K_CG_HID_EVENT_TAP, ev.as_ptr());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drags_use_the_dragged_event_type_for_each_button() {
        assert_eq!(button_events(MouseButton::Left).dragged as u32, 6);
        assert_eq!(button_events(MouseButton::Right).dragged as u32, 7);
        assert_eq!(button_events(MouseButton::Middle).dragged as u32, 27);
        assert_eq!(button_events(MouseButton::Left).down as u32, 1);
        assert_eq!(button_events(MouseButton::Left).up as u32, 2);
        assert_eq!(button_events(MouseButton::Middle).button as u32, 2);
    }

    #[test]
    fn reads_a_finite_cursor_position_without_permissions() {
        let position = current_cursor_position();
        assert!(position.is_some_and(|p| p.x.is_finite() && p.y.is_finite()));
    }
}
