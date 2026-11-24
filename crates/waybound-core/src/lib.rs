//! Core domain types and platform driver traits for `waybound`.
//!
//! All OS-specific display, accessibility, and input backends implement the
//! traits defined here, keeping the orchestration daemon and client SDKs
//! completely platform-agnostic.

pub mod driver;
pub mod error;
pub mod fingerprint;
pub mod input;
pub mod locator;
pub mod motion;
pub mod network;
pub mod process;
pub mod protocol;

pub use driver::{
    BackendKind, DEFAULT_MAX_NODES, Driver, MAX_MAX_NODES, MIN_MAX_NODES, SessionConfig,
    TreeSnapshot, clamp_max_nodes,
};
pub use error::{Result, WayboundError};
pub use fingerprint::{
    CapturedCookie, HeaderEntry, Http2Fingerprint, Http2Setting, Http2StreamDependency,
    SessionFingerprint, TlsFingerprint,
};
pub use input::{InputEvent, KeyCode, KeyModifier, MouseButton, Point};
pub use locator::{AccessibilityNode, Bounds, LocatorQuery, Role};
pub use motion::{
    KeystrokeStep, MotionConfig, MotionStep, MotorProfile, ScrollStep, ScrollStyle, SplitMix64,
    action_pause_for, double_click_gap_for, erfc_approx, hover_pause_before_click, hover_pause_for,
    key_delay, key_hold_for, key_hold_ms, minimum_jerk, mouse_hold_for, mouse_hold_ms,
    pick_click_point, pick_click_point_from, plan_click_slip, plan_human_pointer_path,
    plan_human_pointer_path_with_profile, plan_pointer_path, plan_scroll_burst,
    plan_scroll_burst_with_profile, plan_typing_sequence, reading_pause_for,
    sigma_lognormal_progress,
};
pub use network::{
    CapturedResponse, CapturedWebSocketFrame, HttpHeader, NetworkStats, WebSocketDirection,
    WebSocketOpcode,
};
pub use protocol::{Request, Response, WindowSummary, WireRequest, parse_wire_request};
