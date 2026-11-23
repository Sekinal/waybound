//! OS-level input event primitives.

use serde::{Deserialize, Serialize};

/// 2D coordinate in logical screen pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    /// Horizontal coordinate.
    pub x: f64,
    /// Vertical coordinate.
    pub y: f64,
}

/// Mouse button identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    /// Primary button.
    Left,
    /// Secondary/context button.
    Right,
    /// Wheel click button.
    Middle,
}

/// Modifier keys that can be held during a key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyModifier {
    /// Command (macOS) / Super (Linux) / Win (Windows).
    Meta,
    /// Control key.
    Control,
    /// Alt / Option key.
    Alt,
    /// Shift key.
    Shift,
}

/// Logical keyboard key identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyCode {
    /// Return / Enter key.
    Enter,
    /// Tab key.
    Tab,
    /// Escape key.
    Escape,
    /// Backspace key.
    Backspace,
    /// Left arrow key.
    ArrowLeft,
    /// Right arrow key.
    ArrowRight,
    /// Up arrow key.
    ArrowUp,
    /// Down arrow key.
    ArrowDown,
    /// Space bar.
    Space,
    /// Forward delete key.
    Delete,
    /// Home key.
    Home,
    /// End key.
    End,
    /// Page Up key.
    PageUp,
    /// Page Down key.
    PageDown,
    /// Arbitrary Unicode character.
    Char(char),
}

/// Platform-agnostic native input event sent to a backend driver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputEvent {
    /// Move pointer to an absolute logical coordinate.
    PointerMove {
        /// Target pointer position.
        to: Point,
    },
    /// Press and release a mouse button at the current pointer position.
    MouseClick {
        /// Button to click.
        button: MouseButton,
        /// Optional hold duration in milliseconds between mouse-down and mouse-up.
        #[serde(default)]
        hold_ms: u64,
    },
    /// Scroll by a logical delta.
    Scroll {
        /// Horizontal scroll delta.
        delta_x: f64,
        /// Vertical scroll delta.
        delta_y: f64,
    },
    /// Press and release a key, optionally with modifier keys held.
    KeyPress {
        /// Key to emit.
        key: KeyCode,
        /// Active modifiers for this keystroke.
        #[serde(default)]
        modifiers: Vec<KeyModifier>,
        /// Optional hold duration in milliseconds between key-down and key-up.
        #[serde(default)]
        hold_ms: u64,
    },
    /// Press `button` at the current pointer position and keep it held.
    ///
    /// Must be paired with a later [`InputEvent::MouseUp`] for the same button.
    MouseDown {
        /// Button to press.
        button: MouseButton,
    },
    /// Release a `button` previously pressed with [`InputEvent::MouseDown`].
    ///
    /// Releasing a button that is not held is harmless and must succeed, so callers can
    /// always send it on cleanup paths.
    MouseUp {
        /// Button to release.
        button: MouseButton,
    },
    /// Move the pointer to an absolute logical coordinate while `button` is held down.
    ///
    /// A separate variant from [`InputEvent::PointerMove`] because some platforms need a
    /// different native event for drags (macOS `kCGEventLeftMouseDragged`), and because a
    /// backend that does not know this variant fails to deserialize it instead of silently
    /// treating it as a plain hover move.
    PointerDrag {
        /// Target pointer position.
        to: Point,
        /// Button held during the move.
        #[serde(default = "default_drag_button")]
        button: MouseButton,
    },
}

const fn default_drag_button() -> MouseButton {
    MouseButton::Left
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(event: &InputEvent) -> Option<InputEvent> {
        serde_json::to_string(event)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    #[test]
    fn drag_events_round_trip_as_json() {
        let events = [
            InputEvent::MouseDown {
                button: MouseButton::Left,
            },
            InputEvent::PointerDrag {
                to: Point { x: 12.5, y: -3.0 },
                button: MouseButton::Right,
            },
            InputEvent::MouseUp {
                button: MouseButton::Middle,
            },
        ];
        for event in &events {
            assert_eq!(round_trip(event).as_ref(), Some(event));
        }
    }

    #[test]
    fn drag_events_use_stable_wire_tags() {
        let down = serde_json::to_value(InputEvent::MouseDown {
            button: MouseButton::Left,
        })
        .ok();
        assert_eq!(
            down,
            Some(serde_json::json!({"kind": "mouse_down", "button": "left"}))
        );
        let parsed: Option<InputEvent> =
            serde_json::from_str(r#"{"kind":"pointer_drag","to":{"x":1.0,"y":2.0}}"#).ok();
        assert_eq!(
            parsed,
            Some(InputEvent::PointerDrag {
                to: Point { x: 1.0, y: 2.0 },
                button: MouseButton::Left,
            })
        );
    }

    #[test]
    fn existing_events_stay_wire_compatible() {
        let parsed: Option<InputEvent> =
            serde_json::from_str(r#"{"kind":"pointer_move","to":{"x":3.0,"y":4.0}}"#).ok();
        assert_eq!(
            parsed,
            Some(InputEvent::PointerMove {
                to: Point { x: 3.0, y: 4.0 },
            })
        );
        let click: Option<InputEvent> =
            serde_json::from_str(r#"{"kind":"mouse_click","button":"left"}"#).ok();
        assert_eq!(
            click,
            Some(InputEvent::MouseClick {
                button: MouseButton::Left,
                hold_ms: 0,
            })
        );
        let encoded = serde_json::to_value(InputEvent::PointerMove {
            to: Point { x: 3.0, y: 4.0 },
        })
        .ok();
        assert_eq!(
            encoded,
            Some(serde_json::json!({"kind": "pointer_move", "to": {"x": 3.0, "y": 4.0}}))
        );
    }
}
