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
    },
    /// Scroll by a logical delta.
    Scroll {
        /// Horizontal scroll delta.
        delta_x: f64,
        /// Vertical scroll delta.
        delta_y: f64,
    },
    /// Press and release a key.
    KeyPress {
        /// Key to emit.
        key: KeyCode,
    },
}
