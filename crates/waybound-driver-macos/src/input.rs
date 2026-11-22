//! Safe CoreGraphics (`CGEvent`) native input dispatcher for macOS.

#![cfg(target_os = "macos")]

use std::ptr;

use waybound_core::{InputEvent, KeyCode, MouseButton, Point, Result, WayboundError};

use crate::ffi::{
    CGEventCreateKeyboardEvent, CGEventCreateMouseEvent, CGEventCreateScrollWheelEvent2,
    CGEventKeyboardSetUnicodeString, CGEventPost, CgEventType, CgMouseButton, CgPoint,
    K_CG_HID_EVENT_TAP, K_CG_SCROLL_EVENT_UNIT_PIXEL, OwnedCf,
};

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
        InputEvent::MouseClick { button } => {
            let (down, up, cg_button) = match button {
                MouseButton::Left => (
                    CgEventType::LeftMouseDown,
                    CgEventType::LeftMouseUp,
                    CgMouseButton::Left,
                ),
                MouseButton::Right => (
                    CgEventType::RightMouseDown,
                    CgEventType::RightMouseUp,
                    CgMouseButton::Right,
                ),
                MouseButton::Middle => (
                    CgEventType::OtherMouseDown,
                    CgEventType::OtherMouseUp,
                    CgMouseButton::Center,
                ),
            };
            post_mouse(down, *last_cursor, cg_button)?;
            post_mouse(up, *last_cursor, cg_button)
        }
        InputEvent::Scroll { delta_x, delta_y } => post_scroll(*delta_x, *delta_y),
        InputEvent::KeyPress { key } => post_key(key),
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

fn post_key(key: &KeyCode) -> Result<()> {
    match key {
        KeyCode::Enter => post_virtual_key(0x24),
        KeyCode::Tab => post_virtual_key(0x30),
        KeyCode::Escape => post_virtual_key(0x35),
        KeyCode::Backspace => post_virtual_key(0x33),
        KeyCode::Char(ch) => post_unicode_char(*ch),
    }
}

fn post_virtual_key(keycode: u16) -> Result<()> {
    for down in [1u8, 0u8] {
        // SAFETY: `CGEventCreateKeyboardEvent` returns a `+1` retained `CGEventRef` or null.
        let ev =
            unsafe { OwnedCf::from_owned(CGEventCreateKeyboardEvent(ptr::null(), keycode, down)) }
                .ok_or_else(|| WayboundError::BackendUnavailable {
                    backend: "macos_native".to_owned(),
                    reason: "CGEventCreateKeyboardEvent returned null".to_owned(),
                })?;
        // SAFETY: `ev` is a valid non-null `CGEventRef`.
        unsafe { CGEventPost(K_CG_HID_EVENT_TAP, ev.as_ptr()) };
    }
    Ok(())
}

fn post_unicode_char(ch: char) -> Result<()> {
    let mut utf16 = [0u16; 2];
    let encoded = ch.encode_utf16(&mut utf16);

    for down in [1u8, 0u8] {
        // SAFETY: `CGEventCreateKeyboardEvent` returns a `+1` retained `CGEventRef` or null.
        let ev = unsafe { OwnedCf::from_owned(CGEventCreateKeyboardEvent(ptr::null(), 0, down)) }
            .ok_or_else(|| WayboundError::BackendUnavailable {
            backend: "macos_native".to_owned(),
            reason: "CGEventCreateKeyboardEvent returned null".to_owned(),
        })?;
        // SAFETY: `ev` is valid and `encoded` is a valid UTF-16 slice of length `encoded.len()`.
        unsafe {
            CGEventKeyboardSetUnicodeString(ev.as_ptr(), encoded.len(), encoded.as_ptr());
            CGEventPost(K_CG_HID_EVENT_TAP, ev.as_ptr());
        }
    }
    Ok(())
}
