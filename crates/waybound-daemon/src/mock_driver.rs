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
/// `check()` / `uncheck()` can be exercised end to end. Tests can additionally make clicks
/// inert, hide the tree for a few snapshots after a click, enable a node after a number of
/// snapshots, or rename a node when it toggles.
pub struct MockDriver {
    state: Mutex<MockState>,
    events: Mutex<Vec<InputEvent>>,
}

#[derive(Default)]
struct MockState {
    nodes: Vec<AccessibilityNode>,
    pointer: Option<Point>,
    /// Clicks are recorded but change nothing.
    inert_clicks: bool,
    /// Number of empty snapshots served after each toggling click.
    hide_after_click: usize,
    /// Remaining empty snapshots.
    hidden_snapshots: usize,
    /// `(node id, snapshots left)` after which the node becomes enabled.
    enable_after: Option<(String, usize)>,
    /// `(node id, unchecked name, checked name)` renamed whenever it toggles.
    toggle_names: Option<(String, String, String)>,
    /// Report node ids as positional (not stable) like the macOS / AT-SPI / Android drivers.
    positional_ids: bool,
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
        Self::with_nodes(nodes)
    }

    /// Creates a `MockDriver` serving exactly `nodes`.
    #[must_use]
    pub fn with_nodes(nodes: Vec<AccessibilityNode>) -> Self {
        Self {
            state: Mutex::new(MockState {
                nodes,
                ..MockState::default()
            }),
            events: Mutex::new(Vec::new()),
        }
    }

    #[cfg(test)]
    fn configure(&self, apply: impl FnOnce(&mut MockState)) {
        if let Ok(mut guard) = self.state.lock() {
            apply(&mut guard);
        }
    }

    /// Reports node ids as positional, forcing re-identification by role and bounds.
    #[cfg(test)]
    pub fn set_positional_ids(&self) {
        self.configure(|st| st.positional_ids = true);
    }

    /// Makes clicks change nothing (a control that ignores input).
    #[cfg(test)]
    pub fn set_inert_clicks(&self) {
        self.configure(|st| st.inert_clicks = true);
    }

    /// Serves `count` empty snapshots after every toggling click (a re-render).
    #[cfg(test)]
    pub fn hide_after_click(&self, count: usize) {
        self.configure(|st| st.hide_after_click = count);
    }

    /// Enables node `id` once `snapshots` more snapshots have been taken.
    #[cfg(test)]
    pub fn enable_after(&self, id: &str, snapshots: usize) {
        self.configure(|st| st.enable_after = Some((id.to_owned(), snapshots)));
    }

    /// Renames node `id` to `off` / `on` whenever its checked state toggles.
    #[cfg(test)]
    pub fn rename_on_toggle(&self, id: &str, off: &str, on: &str) {
        self.configure(|st| {
            st.toggle_names = Some((id.to_owned(), off.to_owned(), on.to_owned()));
        });
    }

    /// Returns every input event dispatched to this driver so far.
    #[cfg(test)]
    pub fn recorded_events(&self) -> Vec<InputEvent> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.clone())
    }

    /// Toggles the checked state of the enabled checkable node under the pointer, if any.
    fn click(&self) {
        let Ok(mut guard) = self.state.lock() else {
            return;
        };
        let st = &mut *guard;
        let Some(at) = st.pointer else {
            return;
        };
        if st.inert_clicks {
            return;
        }
        let probe = bounds(at.x, at.y, 0.0, 0.0);
        let Some(node) = st
            .nodes
            .iter_mut()
            .find(|n| n.checked.is_some() && n.bounds.contains_center(&probe))
        else {
            return;
        };
        if node.disabled {
            return;
        }
        node.checked = node.checked.map(|c| !c);
        if let Some((id, off, on)) = &st.toggle_names
            && *id == node.id
        {
            let name = if node.checked == Some(true) { on } else { off };
            node.name = Some(name.clone());
        }
        st.hidden_snapshots = st.hide_after_click;
    }
}

impl Driver for MockDriver {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::MacOsNative
    }

    fn stable_node_ids(&self) -> bool {
        self.state.lock().is_ok_and(|st| !st.positional_ids)
    }

    fn snapshot_tree(&self) -> Result<Vec<AccessibilityNode>> {
        let Ok(mut guard) = self.state.lock() else {
            return Ok(Vec::new());
        };
        let st = &mut *guard;
        if let Some((id, left)) = &mut st.enable_after {
            if *left == 0 {
                if let Some(node) = st.nodes.iter_mut().find(|n| n.id == *id) {
                    node.disabled = false;
                }
            } else {
                *left -= 1;
            }
        }
        if st.hidden_snapshots > 0 {
            st.hidden_snapshots -= 1;
            return Ok(Vec::new());
        }
        Ok(st.nodes.clone())
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
                if let Ok(mut guard) = self.state.lock() {
                    guard.pointer = Some(*to);
                }
            }
            InputEvent::MouseClick {
                button: MouseButton::Left,
                ..
            } => self.click(),
            _ => {}
        }
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event.clone());
        }
        Ok(())
    }
}
