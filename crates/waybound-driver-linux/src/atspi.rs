//! Linux AT-SPI2 accessibility tree extraction and role normalization.

use serde::Deserialize;
use tracing::debug;
use waybound_core::{AccessibilityNode, Bounds, Result, Role, WayboundError};

use crate::process::{BACKEND_NAME, DEFAULT_TIMEOUT, run_with_timeout, truncate_for_log};

/// Maximum number of accessibility nodes retained from a single AT-SPI2 snapshot.
pub const MAX_NODES: usize = 4_000;

/// Parsed snapshot of a Linux browser's AT-SPI2 accessibility tree.
#[derive(Debug, Clone, PartialEq)]
pub struct AtspiSnapshot {
    /// Flattened accessibility nodes, capped at [`MAX_NODES`].
    pub nodes: Vec<AccessibilityNode>,
    /// URL of the active web document, if exposed by AT-SPI2.
    pub current_url: Option<String>,
    /// Screen-space bounding rectangle of the active web viewport, if available.
    pub viewport_bounds: Option<Bounds>,
}

/// Maps an AT-SPI2 role name (case-insensitive) to a normalized [`Role`].
#[must_use]
pub fn map_atspi_role(role: &str) -> Role {
    let normalized = role.trim().to_ascii_lowercase().replace(['-', '_'], " ");
    match normalized.as_str() {
        "button" | "push button" => Role::Button,
        "link" => Role::Link,
        "entry" | "password text" | "text" => Role::TextBox,
        "check box" => Role::CheckBox,
        "radio button" => Role::Radio,
        "toggle button" | "switch" => Role::Switch,
        "combo box" => Role::ComboBox,
        "list box" | "list" => Role::ListBox,
        "list item" | "option" => Role::Option,
        "page tab" => Role::Tab,
        "dialog" | "alert" => Role::Dialog,
        "menu item" => Role::MenuItem,
        "document web" | "document frame" => Role::Document,
        "heading" => Role::Heading,
        "static" | "label" | "paragraph" => Role::StaticText,
        _ => Role::Unknown,
    }
}

#[derive(Debug, Deserialize)]
struct RawAtspiSnapshot {
    #[serde(default)]
    nodes: Vec<RawAtspiNode>,
    #[serde(default)]
    current_url: Option<String>,
    #[serde(default)]
    viewport_bounds: Option<Bounds>,
}

#[derive(Debug, Deserialize)]
struct RawAtspiNode {
    id: String,
    role: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    bounds: Bounds,
    #[serde(default)]
    focused: bool,
}

const fn is_valid_bounds(bounds: &Bounds) -> bool {
    bounds.x.is_finite()
        && bounds.y.is_finite()
        && bounds.width.is_finite()
        && bounds.height.is_finite()
        && bounds.width >= 0.0
        && bounds.height >= 0.0
}

fn clean_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

/// Parses an AT-SPI2 snapshot JSON payload into an [`AtspiSnapshot`].
///
/// Enforces [`MAX_NODES`] and validates that all retained bounds contain finite,
/// non-negative dimensions.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `raw` is not valid snapshot JSON.
pub fn parse_atspi_snapshot_json(raw: &str) -> Result<AtspiSnapshot> {
    let parsed: RawAtspiSnapshot =
        serde_json::from_str(raw).map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("failed to parse AT-SPI2 snapshot JSON: {err}"),
        })?;

    let mut nodes = Vec::with_capacity(parsed.nodes.len().min(MAX_NODES));
    for raw_node in parsed.nodes {
        if nodes.len() >= MAX_NODES {
            break;
        }
        if !is_valid_bounds(&raw_node.bounds) {
            continue;
        }
        nodes.push(AccessibilityNode {
            id: raw_node.id,
            role: map_atspi_role(&raw_node.role),
            name: clean_optional_string(raw_node.name),
            value: clean_optional_string(raw_node.value),
            bounds: raw_node.bounds,
            focused: raw_node.focused,
        });
    }

    let viewport_bounds = parsed.viewport_bounds.filter(is_valid_bounds);
    let current_url = clean_optional_string(parsed.current_url);

    Ok(AtspiSnapshot {
        nodes,
        current_url,
        viewport_bounds,
    })
}

/// Embedded Python script querying AT-SPI2 via `gi.repository.Atspi`.
const ATSPI_QUERY_SCRIPT: &str = r#"
import collections
import json
import os
import sys

try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
except Exception as exc:
    sys.stderr.write(f"gi.repository.Atspi unavailable: {exc}\n")
    sys.exit(2)

MAX_NODES = 4000
CHROME_NAMES = ("chrome", "chromium", "google-chrome", "brave")

target_pid_raw = os.environ.get("WAYBOUND_TARGET_PID", "").strip()
target_pid = int(target_pid_raw) if target_pid_raw else None

desktop = Atspi.get_desktop(0)
if desktop is None:
    sys.stderr.write("AT-SPI2 desktop unavailable\n")
    sys.exit(3)

target_app = None
for i in range(desktop.get_child_count()):
    app = desktop.get_child_at_index(i)
    if app is None:
        continue
    try:
        app_pid = app.get_process_id()
    except Exception:
        app_pid = -1
    if target_pid is not None:
        if app_pid == target_pid:
            target_app = app
            break
    else:
        name = (app.get_name() or "").lower()
        if any(token in name for token in CHROME_NAMES):
            target_app = app
            break

if target_app is None:
    print(json.dumps({"nodes": [], "current_url": None, "viewport_bounds": None}))
    sys.exit(0)

def read_text_value(acc):
    try:
        n = Atspi.Text.get_character_count(acc)
        if 0 < n <= 4096:
            return Atspi.Text.get_text(acc, 0, n)
    except Exception:
        pass
    try:
        text_iface = acc.get_text_iface()
        if text_iface is not None:
            n = text_iface.get_character_count()
            if 0 < n <= 4096:
                return text_iface.get_text(0, n)
    except Exception:
        pass
    return None

# Locate the active web document (`document web` with the largest non-zero viewport)
# and also grab the omnibox URL as a fallback if DocURL/URI isn't exposed.
current_url = None
viewport_bounds = None
web_root = None
best_area = -1.0
scan_queue = collections.deque([target_app])
scanned = 0

while scan_queue and scanned < MAX_NODES:
    acc = scan_queue.popleft()
    if acc is None:
        continue
    scanned += 1
    try:
        r = (acc.get_role_name() or "").strip().lower()
    except Exception:
        r = ""
    if r == "entry" and current_url is None:
        try:
            n = acc.get_name() or ""
        except Exception:
            n = ""
        if n == "Address and search bar":
            v = read_text_value(acc)
            if v:
                current_url = str(v)
    if r in ("document web", "document frame"):
        try:
            comp = acc.get_component_iface()
            if comp is not None:
                rect = comp.get_extents(Atspi.CoordType.SCREEN)
                area = max(0.0, float(rect.width)) * max(0.0, float(rect.height))
                if area > best_area:
                    best_area = area
                    web_root = acc
                    if rect.width > 0 and rect.height > 0:
                        viewport_bounds = {
                            "x": float(rect.x),
                            "y": float(rect.y),
                            "width": float(rect.width),
                            "height": float(rect.height),
                        }
        except Exception:
            if web_root is None:
                web_root = acc
        try:
            doc = acc.get_document_iface()
            if doc is not None:
                attrs = doc.get_attributes() or {}
                url = attrs.get("DocURL") or attrs.get("URI")
                if url:
                    current_url = str(url)
        except Exception:
            pass
        continue
    try:
        cc = acc.get_child_count()
    except Exception:
        cc = 0
    for idx in range(cc):
        try:
            child = acc.get_child_at_index(idx)
            if child is not None:
                scan_queue.append(child)
        except Exception:
            continue

nodes = []
queue = collections.deque([web_root if web_root is not None else target_app])

while queue and len(nodes) < MAX_NODES:
    acc = queue.popleft()
    if acc is None:
        continue

    try:
        role_name = acc.get_role_name() or ""
    except Exception:
        role_name = ""

    try:
        name = acc.get_name() or ""
    except Exception:
        name = ""

    value = None
    if role_name.strip().lower() in ("entry", "password text", "text", "combo box"):
        value = read_text_value(acc)

    bx, by, bw, bh = 0.0, 0.0, 0.0, 0.0
    try:
        comp = acc.get_component_iface()
        if comp is not None:
            rect = comp.get_extents(Atspi.CoordType.SCREEN)
            bx = float(rect.x)
            by = float(rect.y)
            bw = max(0.0, float(rect.width))
            bh = max(0.0, float(rect.height))
    except Exception:
        pass

    focused = False
    try:
        states = acc.get_state_set()
        if states is not None:
            focused = bool(states.contains(Atspi.StateType.FOCUSED))
    except Exception:
        focused = False

    if role_name in ("document web", "document frame"):
        if viewport_bounds is None and bw > 0.0 and bh > 0.0:
            viewport_bounds = {"x": bx, "y": by, "width": bw, "height": bh}
        if current_url is None:
            try:
                doc = acc.get_document_iface()
                if doc is not None:
                    attrs = doc.get_attributes() or {}
                    url = attrs.get("DocURL") or attrs.get("URI")
                    if url:
                        current_url = str(url)
            except Exception:
                pass
    elif current_url is None and role_name == "entry" and name == "Address and search bar" and value:
        current_url = str(value)

    nodes.append({
        "id": f"atspi-{len(nodes)}",
        "role": role_name,
        "name": name if name else None,
        "value": value if value else None,
        "bounds": {"x": bx, "y": by, "width": bw, "height": bh},
        "focused": focused,
    })

    try:
        child_count = acc.get_child_count()
    except Exception:
        child_count = 0

    for idx in range(child_count):
        if len(nodes) + len(queue) >= MAX_NODES * 2:
            break
        try:
            child = acc.get_child_at_index(idx)
            if child is not None:
                queue.append(child)
        except Exception:
            continue

print(json.dumps({
    "nodes": nodes,
    "current_url": current_url,
    "viewport_bounds": viewport_bounds,
}))
"#;

/// Queries Chrome's live AT-SPI2 accessibility tree via a bounded `python3` helper.
///
/// When `pid` is `Some`, only the AT-SPI2 application with that process ID is inspected;
/// otherwise the first Chrome/Chromium application on the desktop is queried.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if `python3` or `gi.repository.Atspi`
/// is unavailable or returns invalid JSON, or [`WayboundError::Timeout`] if the query
/// exceeds 10 seconds.
pub fn query_atspi_tree(pid: Option<i32>, display_env: Option<&str>) -> Result<AtspiSnapshot> {
    let args = vec!["-c".to_owned(), ATSPI_QUERY_SCRIPT.to_owned()];
    let pid_str = pid.map(|p| p.to_string());
    let mut envs: Vec<(&str, &str)> = Vec::new();
    if let Some(pid_val) = pid_str.as_deref() {
        envs.push(("WAYBOUND_TARGET_PID", pid_val));
    }
    if let Some(disp) = display_env {
        envs.push(("DISPLAY", disp));
    }

    debug!(?pid, ?display_env, "querying AT-SPI2 accessibility tree");
    let output = run_with_timeout(
        "python3",
        &args,
        &envs,
        DEFAULT_TIMEOUT,
        "AT-SPI2 tree query",
    )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!(
                "AT-SPI2 query failed ({}): {}",
                output.status,
                truncate_for_log(&stderr)
            ),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_atspi_snapshot_json(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_atspi_roles_to_core_variants() {
        let cases = [
            ("push button", Role::Button),
            ("PUSH BUTTON", Role::Button),
            ("link", Role::Link),
            ("entry", Role::TextBox),
            ("password text", Role::TextBox),
            ("text", Role::TextBox),
            ("check box", Role::CheckBox),
            ("radio button", Role::Radio),
            ("toggle button", Role::Switch),
            ("switch", Role::Switch),
            ("combo box", Role::ComboBox),
            ("list box", Role::ListBox),
            ("list", Role::ListBox),
            ("list item", Role::Option),
            ("option", Role::Option),
            ("page tab", Role::Tab),
            ("dialog", Role::Dialog),
            ("alert", Role::Dialog),
            ("menu item", Role::MenuItem),
            ("document web", Role::Document),
            ("document frame", Role::Document),
            ("heading", Role::Heading),
            ("static", Role::StaticText),
            ("label", Role::StaticText),
            ("paragraph", Role::StaticText),
            ("filler", Role::Unknown),
            ("", Role::Unknown),
        ];

        for (raw, expected) in cases {
            assert_eq!(map_atspi_role(raw), expected, "role `{raw}`");
        }
    }

    #[test]
    fn parses_valid_atspi_snapshot_json_with_url_and_viewport() -> Result<()> {
        let raw = r#"{
            "nodes": [
                {
                    "id": "atspi-0",
                    "role": "document web",
                    "name": "Example Domain",
                    "value": null,
                    "bounds": {"x": 0.0, "y": 80.0, "width": 1280.0, "height": 720.0},
                    "focused": false
                },
                {
                    "id": "atspi-1",
                    "role": "push button",
                    "name": "  Sign In  ",
                    "value": "",
                    "bounds": {"x": 100.0, "y": 200.0, "width": 120.0, "height": 40.0},
                    "focused": true
                }
            ],
            "current_url": "https://example.com/",
            "viewport_bounds": {"x": 0.0, "y": 80.0, "width": 1280.0, "height": 720.0}
        }"#;

        let snap = parse_atspi_snapshot_json(raw)?;
        assert_eq!(snap.nodes.len(), 2);
        assert_eq!(snap.nodes[0].role, Role::Document);
        assert_eq!(snap.nodes[1].role, Role::Button);
        assert_eq!(snap.nodes[1].name.as_deref(), Some("Sign In"));
        assert_eq!(snap.nodes[1].value, None);
        assert!(snap.nodes[1].focused);
        assert_eq!(snap.current_url.as_deref(), Some("https://example.com/"));
        assert_eq!(
            snap.viewport_bounds,
            Some(Bounds {
                x: 0.0,
                y: 80.0,
                width: 1280.0,
                height: 720.0,
            })
        );
        Ok(())
    }

    #[test]
    fn enforces_max_nodes_cap_and_filters_negative_bounds() -> Result<()> {
        let mut raw_nodes = Vec::with_capacity(MAX_NODES + 25);
        raw_nodes.push(serde_json::json!({
            "id": "bad-bounds",
            "role": "push button",
            "name": "Invalid",
            "bounds": {"x": 0.0, "y": 0.0, "width": -10.0, "height": 20.0},
            "focused": false
        }));
        for idx in 0..(MAX_NODES + 20) {
            raw_nodes.push(serde_json::json!({
                "id": format!("n-{idx}"),
                "role": "link",
                "name": format!("Item {idx}"),
                "bounds": {"x": 1.0, "y": 2.0, "width": 10.0, "height": 10.0},
                "focused": false
            }));
        }

        let payload = serde_json::json!({
            "nodes": raw_nodes,
            "current_url": "   ",
            "viewport_bounds": {"x": 0.0, "y": 0.0, "width": -1.0, "height": 100.0}
        });

        let snap = parse_atspi_snapshot_json(&payload.to_string())?;
        assert_eq!(snap.nodes.len(), MAX_NODES);
        assert_eq!(snap.nodes[0].id, "n-0");
        assert_eq!(snap.current_url, None);
        assert_eq!(snap.viewport_bounds, None);
        Ok(())
    }

    #[test]
    fn rejects_malformed_snapshot_json() {
        let err = parse_atspi_snapshot_json("{not valid json");
        assert!(err.is_err());
    }
}
