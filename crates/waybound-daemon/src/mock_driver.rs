//! Deterministic in-memory driver for hermetic IPC and SDK testing.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use waybound_core::{
    AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, Result, Role, WayboundError,
};

/// Minimal valid 1x1 transparent PNG bytes for hermetic screenshot tests.
const ONE_BY_ONE_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

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

    /// Returns every input event dispatched to this driver so far.
    #[cfg(test)]
    pub fn recorded_events(&self) -> Vec<InputEvent> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.clone())
    }
}

impl Driver for MockDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::MacOsNative
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        Ok(self.nodes.clone())
    }

    fn current_url(&self) -> Result<Option<String>> {
        Ok(Some("https://mock.waybound.local/".to_owned()))
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        fs::write(output_path, ONE_BY_ONE_PNG).map_err(WayboundError::Io)
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event.clone());
        }
        Ok(())
    }
}
