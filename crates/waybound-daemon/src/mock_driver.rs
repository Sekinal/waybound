//! Deterministic in-memory driver for hermetic IPC and SDK testing.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use waybound_core::{
    AccessibilityNode, BackendKind, Bounds, Driver, InputEvent, MouseButton, Point, Result, Role,
    WayboundError,
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
///
/// Left clicks landing on an enabled node with a checked state toggle that state, so
/// `check()` / `uncheck()` can be exercised end to end.
pub struct MockDriver {
    nodes: Mutex<Vec<AccessibilityNode>>,
    pointer: Mutex<Option<Point>>,
    events: Mutex<Vec<InputEvent>>,
}

const fn bounds(x: f64, y: f64, width: f64, height: f64) -> Bounds {
    Bounds {
        x,
        y,
        width,
        height,
    }
}

impl MockDriver {
    /// Creates a `MockDriver` populated with a sample search page tree.
    #[must_use]
    pub fn sample_page() -> Self {
        let nodes = vec![
            AccessibilityNode::new(
                "input-origin".to_owned(),
                Role::TextBox,
                Some("Origin".to_owned()),
                Some(String::new()),
                bounds(100.0, 120.0, 240.0, 36.0),
            ),
            AccessibilityNode::new(
                "btn-search".to_owned(),
                Role::Button,
                Some("Search Flights".to_owned()),
                None,
                bounds(360.0, 120.0, 140.0, 36.0),
            ),
            AccessibilityNode {
                checked: Some(false),
                ..AccessibilityNode::new(
                    "chk-nonstop".to_owned(),
                    Role::CheckBox,
                    Some("Nonstop only".to_owned()),
                    None,
                    bounds(100.0, 180.0, 20.0, 20.0),
                )
            },
            AccessibilityNode {
                checked: Some(true),
                disabled: true,
                ..AccessibilityNode::new(
                    "chk-insurance".to_owned(),
                    Role::CheckBox,
                    Some("Travel insurance".to_owned()),
                    None,
                    bounds(100.0, 220.0, 20.0, 20.0),
                )
            },
            AccessibilityNode {
                expanded: Some(false),
                ..AccessibilityNode::new(
                    "combo-cabin".to_owned(),
                    Role::ComboBox,
                    Some("Cabin".to_owned()),
                    Some("Economy".to_owned()),
                    bounds(360.0, 180.0, 140.0, 36.0),
                )
            },
        ];
        Self {
            nodes: Mutex::new(nodes),
            pointer: Mutex::new(None),
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

    /// Toggles the checked state of the enabled checkable node under `at`, if any.
    fn toggle_at(&self, at: Point) {
        let Ok(mut nodes) = self.nodes.lock() else {
            return;
        };
        let probe = bounds(at.x, at.y, 0.0, 0.0);
        if let Some(node) = nodes
            .iter_mut()
            .find(|n| n.checked.is_some() && n.bounds.contains_center(&probe))
            && !node.disabled
        {
            node.checked = node.checked.map(|c| !c);
        }
    }
}

impl Driver for MockDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::MacOsNative
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        Ok(self.nodes.lock().map_or_else(|_| Vec::new(), |g| g.clone()))
    }

    fn current_url(&self) -> Result<Option<String>> {
        Ok(Some("https://mock.waybound.local/".to_owned()))
    }

    fn screenshot(&self, output_path: &Path) -> Result<()> {
        fs::write(output_path, ONE_BY_ONE_PNG).map_err(WayboundError::Io)
    }

    fn dispatch_input(&self, event: &InputEvent) -> Result<()> {
        match event {
            InputEvent::PointerMove { to } => {
                if let Ok(mut guard) = self.pointer.lock() {
                    *guard = Some(*to);
                }
            }
            InputEvent::MouseClick {
                button: MouseButton::Left,
                ..
            } => {
                let at = self.pointer.lock().map_or(None, |g| *g);
                if let Some(point) = at {
                    self.toggle_at(point);
                }
            }
            _ => {}
        }
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event.clone());
        }
        Ok(())
    }
}
