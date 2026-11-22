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
}
