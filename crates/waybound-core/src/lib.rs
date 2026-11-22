//! Core domain types and platform driver traits for `waybound`.
//!
//! All OS-specific display, accessibility, and input backends implement the
//! traits defined here, keeping the orchestration daemon and client SDKs
//! completely platform-agnostic.

pub mod driver;
pub mod error;
pub mod input;
pub mod locator;
pub mod protocol;

pub use driver::{BackendKind, Driver, SessionConfig};
pub use error::{Result, WayboundError};
pub use input::{InputEvent, KeyCode, MouseButton, Point};
pub use locator::{AccessibilityNode, Bounds, LocatorQuery, Role};
pub use protocol::{Request, Response};
