//! Deterministic in-memory driver for hermetic IPC and SDK testing.

use std::sync::Mutex;

use waybound_core::{AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Result, Role};

/// In-memory driver exposing a deterministic accessibility tree and recording input events.
pub struct MockDriver {
    nodes: Vec<AccessibilityNode>,
    events: Mutex<Vec<InputEvent>>,
}

impl MockDriver {
    /// Creates a `MockDriver` populated with a sample search page tree.
    #[must_use]
    pub fn sample_page() -> Self {
        Self {
            nodes: vec![
                AccessibilityNode {
                    id: "input-origin".to_owned(),
                    role: Role::TextBox,
                    name: Some("Origin".to_owned()),
                    value: Some(String::new()),
                    bounds: Bounds {
                        x: 100.0,
                        y: 120.0,
                        width: 240.0,
                        height: 36.0,
                    },
                    focused: false,
                },
                AccessibilityNode {
                    id: "btn-search".to_owned(),
                    role: Role::Button,
                    name: Some("Search Flights".to_owned()),
                    value: None,
                    bounds: Bounds {
                        x: 360.0,
                        y: 120.0,
                        width: 140.0,
                        height: 36.0,
                    },
                    focused: false,
                },
            ],
            events: Mutex::new(Vec::new()),
        }
    }
}

impl Driver for MockDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::MacOsNative
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        Ok(self.nodes.clone())
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event.clone());
        }
        Ok(())
    }
}
