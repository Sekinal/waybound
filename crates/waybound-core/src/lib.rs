//! Core domain types and platform driver traits for `waybound`.
//!
//! All OS-specific display, accessibility, and input backends implement the
//! traits defined here, keeping the orchestration daemon and client SDKs
//! completely platform-agnostic.

pub mod driver;
pub mod error;
pub mod input;
pub mod locator;
pub mod motion;
pub mod network;
pub mod process;
pub mod protocol;

pub use driver::{BackendKind, Driver, SessionConfig};
pub use error::{Result, WayboundError};
pub use input::{InputEvent, KeyCode, KeyModifier, MouseButton, Point};
pub use locator::{AccessibilityNode, Bounds, LocatorQuery, Role};
pub use motion::{
    MotionConfig, MotionStep, ScrollStep, SplitMix64, hover_pause_before_click, key_delay,
    key_hold_ms, mouse_hold_ms, pick_click_point, plan_human_pointer_path, plan_pointer_path,
    plan_scroll_burst,
};
pub use network::CapturedResponse;
pub use protocol::{Request, Response};
