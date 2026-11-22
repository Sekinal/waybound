//! Safe `AXUIElement` tree traversal for macOS Chrome windows.

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr;

use waybound_core::{AccessibilityNode, Bounds, Result, Role, WayboundError};

use crate::ffi::{
    AXIsProcessTrusted, AXUIElementCopyAttributeNames, AXUIElementCopyAttributeValue,
    AXUIElementCreateApplication, AXUIElementGetTypeID, AXUIElementSetAttributeValue,
    AXValueGetTypeID, AXValueGetValue, CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex,
    CFEqual, CFGetTypeID, CgPoint, CgSize, K_AX_ERROR_SUCCESS, K_AX_VALUE_TYPE_CG_POINT,
    K_AX_VALUE_TYPE_CG_SIZE, OwnedCf, cf_string, cf_to_bool, cf_to_i64, cf_to_string,
    cf_to_url_string, kCFBooleanTrue,
};

const MAX_DEPTH: usize = 40;
const MAX_NODES: usize = 2_000;
const MAX_VISITED: usize = 10_000;
const MAX_WEB_AREA_SEARCH: usize = 500;

/// Checks whether the current process has macOS Accessibility permission.
#[must_use]
pub fn is_accessibility_trusted() -> bool {
    // SAFETY: `AXIsProcessTrusted` takes no arguments and is safe to call from any thread.
    unsafe { AXIsProcessTrusted() != 0 }
}

const FRONTMOST_POLL: std::time::Duration = std::time::Duration::from_millis(25);
const FRONTMOST_POLL_ATTEMPTS: usize = 40;

fn is_frontmost(app: &OwnedCf) -> bool {
    copy_attr(app, "AXFrontmost")
        .and_then(|v| cf_to_bool(&v))
        .unwrap_or(false)
}

/// Makes the application `pid` frontmost, or fails without sending anything.
///
/// Events posted to the HID event tap are delivered to whichever application is frontmost,
/// so keyboard input must never be sent before this succeeds: otherwise a URL or form text
/// would be typed into the user's terminal or editor.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permission is missing or
/// the application cannot be brought to the front.
pub fn ensure_frontmost(pid: i32) -> Result<()> {
    let unavailable = |reason: String| WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason,
    };
    if pid <= 0 {
        return Err(unavailable(format!("invalid target pid: {pid}")));
    }
    if !is_accessibility_trusted() {
        return Err(unavailable(
            "macOS Accessibility permission not granted (enable in System Settings > Privacy & Security > Accessibility)".to_owned(),
        ));
    }
    // SAFETY: `AXUIElementCreateApplication` returns a `+1` retained `AXUIElementRef` or null.
    let app = unsafe { OwnedCf::from_owned(AXUIElementCreateApplication(pid)) }
        .ok_or_else(|| unavailable(format!("failed to create AXUIElement for pid {pid}")))?;

    if is_frontmost(&app) {
        return Ok(());
    }

    if let Some(key) = cf_string("AXFrontmost") {
        // SAFETY: `app` and `key` are valid retained CF objects, and `kCFBooleanTrue` is a global CF constant.
        let status =
            unsafe { AXUIElementSetAttributeValue(app.as_ptr(), key.as_ptr(), kCFBooleanTrue) };
        tracing::debug!(pid, status, "requested AXFrontmost on target application");
    }
    for _ in 0..FRONTMOST_POLL_ATTEMPTS {
        if is_frontmost(&app) {
            return Ok(());
        }
        std::thread::sleep(FRONTMOST_POLL);
    }
    Err(unavailable(format!(
        "could not bring target browser (pid {pid}) to the front; refusing to send input to another application"
    )))
}

fn open_window_root(pid: i32) -> Result<OwnedCf> {
    if pid <= 0 {
        return Err(WayboundError::BackendUnavailable {
            backend: "macos_native".to_owned(),
            reason: format!("invalid target pid: {pid}"),
        });
    }
    if !is_accessibility_trusted() {
        return Err(WayboundError::BackendUnavailable {
            backend: "macos_native".to_owned(),
            reason: "macOS Accessibility permission not granted (enable in System Settings > Privacy & Security > Accessibility)".to_owned(),
        });
    }

    // SAFETY: `AXUIElementCreateApplication` returns a `+1` retained `AXUIElementRef` or null.
    let app =
        unsafe { OwnedCf::from_owned(AXUIElementCreateApplication(pid)) }.ok_or_else(|| {
            WayboundError::BackendUnavailable {
                backend: "macos_native".to_owned(),
                reason: format!("failed to create AXUIElement for pid {pid}"),
            }
        })?;

    enable_enhanced_ui(&app);

    // Prefer the active browser window, then the first window in `AXWindows`,
    // falling back to the application root so we work even when Chrome is backgrounded.
    Ok(copy_attr(&app, "AXFocusedWindow")
        .or_else(|| copy_attr(&app, "AXMainWindow"))
        .or_else(|| first_ax_window(&app))
        .unwrap_or(app))
}

/// Captures a bounded snapshot of the web-content (`AXWebArea`) accessibility tree for `pid`.
///
/// Scopes traversal to `AXWebArea` so browser chrome (tabs, toolbar, address bar)
/// does not pollute semantic web locators.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing
/// or the application element cannot be created.
pub fn snapshot_application_tree(pid: i32) -> Result<Vec<AccessibilityNode>> {
    let window_root = open_window_root(pid)?;
    let Some(web_area) = find_web_area(&window_root) else {
        tracing::debug!(pid, "AXWebArea not yet present in browser window");
        return Ok(Vec::new());
    };

    let mut nodes = Vec::new();
    let mut visited = 0;
    // Created once per walk and shared by every probed node.
    let expanded_key = cf_string("AXExpanded");
    walk_node(
        &web_area,
        0,
        &mut visited,
        &mut nodes,
        expanded_key.as_ref(),
    );
    tracing::debug!(
        pid,
        visited,
        captured = nodes.len(),
        "macos AXWebArea snapshot complete"
    );
    Ok(nodes)
}

/// Reads the active tab's URL from `AXWebArea`'s `AXURL` attribute.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing.
pub fn read_current_url(pid: i32) -> Result<Option<String>> {
    let window_root = open_window_root(pid)?;
    let Some(web_area) = find_web_area(&window_root) else {
        return Ok(None);
    };
    Ok(copy_attr(&web_area, "AXURL").and_then(|v| cf_to_url_string(&v)))
}

/// Reads the visible screen-space bounding rectangle of `AXWebArea`.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing.
pub fn read_viewport_bounds(pid: i32) -> Result<Option<Bounds>> {
    let window_root = open_window_root(pid)?;
    let Some(web_area) = find_web_area(&window_root) else {
        return Ok(None);
    };
    let bounds = read_bounds(&web_area);
    Ok((bounds.width > 0.0 && bounds.height > 0.0).then_some(bounds))
}

fn find_web_area(root: &OwnedCf) -> Option<OwnedCf> {
    let mut stack: Vec<(OwnedCf, usize)> = Vec::new();
    // SAFETY: `root` is a valid retained `OwnedCf` pointing to an `AXUIElement`.
    let root_clone = unsafe { OwnedCf::retain(root.as_ptr()) }?;
    stack.push((root_clone, 0));

    let mut visited = 0;
    while let Some((elem, depth)) = stack.pop() {
        if visited >= MAX_WEB_AREA_SEARCH {
            break;
        }
        visited += 1;

        if read_string_attr(&elem, "AXRole").as_deref() == Some("AXWebArea") {
            return Some(elem);
        }

        if depth >= 14 {
            continue;
        }

        let Some(children) = copy_attr(&elem, "AXChildren") else {
            continue;
        };

        // SAFETY: `children` is a live CF object; verify `CFArray` and `AXUIElement` type IDs.
        unsafe {
            if CFGetTypeID(children.as_ptr()) != CFArrayGetTypeID() {
                continue;
            }
            let ax_type_id = AXUIElementGetTypeID();
            let count = CFArrayGetCount(children.as_ptr());
            let mut pushed = 0usize;
            let budget = MAX_WEB_AREA_SEARCH.saturating_sub(visited);
            for idx in (0..count).rev() {
                if pushed >= budget {
                    break;
                }
                let child_raw = CFArrayGetValueAtIndex(children.as_ptr(), idx);
                if !child_raw.is_null()
                    && CFGetTypeID(child_raw) == ax_type_id
                    && let Some(child) = OwnedCf::retain(child_raw)
                {
                    stack.push((child, depth + 1));
                    pushed += 1;
                }
            }
        }
    }

    None
}

fn first_ax_window(app: &OwnedCf) -> Option<OwnedCf> {
    let windows = copy_attr(app, "AXWindows")?;
    // SAFETY: Verify `windows` is a `CFArray` and element 0 is a valid `AXUIElement` before retaining.
    unsafe {
        if CFGetTypeID(windows.as_ptr()) != CFArrayGetTypeID() {
            return None;
        }
        if CFArrayGetCount(windows.as_ptr()) <= 0 {
            return None;
        }
        let first = CFArrayGetValueAtIndex(windows.as_ptr(), 0);
        if first.is_null() || CFGetTypeID(first) != AXUIElementGetTypeID() {
            return None;
        }
        OwnedCf::retain(first)
    }
}

fn enable_enhanced_ui(app: &OwnedCf) {
    for attr in ["AXEnhancedUserInterface", "AXManualAccessibility"] {
        if let Some(key) = cf_string(attr) {
            // SAFETY: `app` and `key` are valid retained CF objects, and `kCFBooleanTrue` is a global CF constant.
            let status =
                unsafe { AXUIElementSetAttributeValue(app.as_ptr(), key.as_ptr(), kCFBooleanTrue) };
            tracing::debug!(attr, status, "set AX attribute on target application");
        }
    }
}

fn copy_attr(element: &OwnedCf, attr_name: &str) -> Option<OwnedCf> {
    copy_attr_key(element, &cf_string(attr_name)?)
}

/// Like [`copy_attr`] with a pre-built attribute name `CFString`.
fn copy_attr_key(element: &OwnedCf, key: &OwnedCf) -> Option<OwnedCf> {
    let mut out = ptr::null();
    // SAFETY: `element` and `key` are valid retained CoreFoundation references, and `out` receives a `+1` ref on success.
    unsafe {
        let status = AXUIElementCopyAttributeValue(element.as_ptr(), key.as_ptr(), &raw mut out);
        if status != K_AX_ERROR_SUCCESS {
            return None;
        }
        OwnedCf::from_owned(out)
    }
}

fn read_string_attr(element: &OwnedCf, attr_name: &str) -> Option<String> {
    let val = copy_attr(element, attr_name)?;
    cf_to_string(&val)
}

fn read_bounds(element: &OwnedCf) -> Bounds {
    let mut point = CgPoint::default();
    let mut has_pos = false;
    if let Some(pos_val) = copy_attr(element, "AXPosition") {
        // SAFETY: Verify runtime type is `AXValue` before extracting `CGPoint` into `point`.
        unsafe {
            if CFGetTypeID(pos_val.as_ptr()) == AXValueGetTypeID() {
                has_pos = AXValueGetValue(
                    pos_val.as_ptr(),
                    K_AX_VALUE_TYPE_CG_POINT,
                    (&raw mut point).cast::<c_void>(),
                ) != 0;
            }
        }
    }

    let mut size = CgSize::default();
    let mut has_size = false;
    if let Some(size_val) = copy_attr(element, "AXSize") {
        // SAFETY: Verify runtime type is `AXValue` before extracting `CGSize` into `size`.
        unsafe {
            if CFGetTypeID(size_val.as_ptr()) == AXValueGetTypeID() {
                has_size = AXValueGetValue(
                    size_val.as_ptr(),
                    K_AX_VALUE_TYPE_CG_SIZE,
                    (&raw mut size).cast::<c_void>(),
                ) != 0;
            }
        }
    }

    if !has_pos || !has_size {
        return Bounds {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 0.0,
        };
    }

    Bounds {
        x: point.x,
        y: point.y,
        width: size.width,
        height: size.height,
    }
}

fn map_ax_role(ax_role: &str, ax_subrole: Option<&str>) -> Role {
    match (ax_role, ax_subrole) {
        ("AXCheckBox", Some("AXSwitch")) | ("AXSwitch", _) => Role::Switch,
        ("AXRadioButton", Some("AXTabButton")) | ("AXTab" | "AXTabGroup", _) => Role::Tab,
        ("AXGroup", Some("AXApplicationDialog")) | ("AXDialog" | "AXSheet", _) => Role::Dialog,
        ("AXGroup", Some("AXLandmarkRegion")) | ("AXRegion", _) => Role::Region,
        ("AXGroup", _) => Role::Group,
        ("AXImage", _) => Role::Img,
        ("AXButton" | "AXPopUpButton" | "AXMenuButton", _) => Role::Button,
        ("AXLink", _) => Role::Link,
        ("AXSearchField", _) => Role::SearchBox,
        ("AXTextField" | "AXTextArea", _) => Role::TextBox,
        ("AXComboBox", _) => Role::ComboBox,
        ("AXList" | "AXOutline", _) => Role::ListBox,
        ("AXMenuItem", _) => Role::MenuItem,
        ("AXRadioButton", _) => Role::Radio,
        ("AXCheckBox", _) => Role::CheckBox,
        ("AXWebArea" | "AXScrollArea", _) => Role::Document,
        ("AXHeading", _) => Role::Heading,
        ("AXStaticText", _) => Role::StaticText,
        _ => Role::Unknown,
    }
}

/// Picks the accessible name used by locators.
///
/// Chrome exposes the text of `AXStaticText` in `AXValue`, not in `AXTitle` or
/// `AXDescription`, so without this fallback plain page text has no name and can never
/// be matched by `get_by_text` / `get_by_role(StaticText, name=...)`.
fn accessible_name(role: Role, name: Option<String>, value: Option<&str>) -> Option<String> {
    if name.is_none() && role == Role::StaticText {
        return value.map(str::to_owned);
    }
    name
}

/// Maps a checkable role's numeric `AXValue` to the node's checked state.
///
/// `AXCheckBox`, `AXRadioButton`, switches, and Chromium's checkbox / radio menu items report
/// `0` (off), `1` (on), or `2` (mixed). Mixed is reported as `Some(false)` (not fully
/// checked). Other roles, and values that are missing or out of range, yield `None`, so a plain
/// menu item without a numeric value has no checked state.
fn checked_from_ax_value(role: Role, raw: Option<i64>) -> Option<bool> {
    if !is_checkable(role) {
        return None;
    }
    match raw? {
        1 => Some(true),
        0 | 2 => Some(false),
        _ => None,
    }
}

const fn is_checkable(role: Role) -> bool {
    matches!(
        role,
        Role::CheckBox | Role::Radio | Role::Switch | Role::MenuItem
    )
}

/// Roles that are actionable controls, for which `AXEnabled` is read.
///
/// Limiting these extra AX round trips to controls keeps snapshots of large pages fast;
/// static text, headings, and containers are never reported disabled.
const fn is_control(role: Role) -> bool {
    matches!(
        role,
        Role::Button
            | Role::Link
            | Role::TextBox
            | Role::SearchBox
            | Role::CheckBox
            | Role::Radio
            | Role::Switch
            | Role::ComboBox
            | Role::ListBox
            | Role::Option
            | Role::Tab
            | Role::MenuItem
            | Role::ListItem
    )
}

/// How `AXExpanded` is read for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpandProbe {
    /// The role is always expandable (combobox): read `AXExpanded` directly.
    Always,
    /// The role may be expandable (disclosure / menu buttons, links, menu and list items):
    /// read `AXExpanded` only when the element lists it in its attribute names, because
    /// answering `false` for any control would report non-expandable ones as collapsed.
    IfAdvertised,
    /// Never expandable: no AX call.
    Never,
}

const fn expand_probe(role: Role) -> ExpandProbe {
    match role {
        Role::ComboBox => ExpandProbe::Always,
        Role::Button | Role::Link | Role::MenuItem | Role::ListItem | Role::Tab => {
            ExpandProbe::IfAdvertised
        }
        _ => ExpandProbe::Never,
    }
}

fn read_bool_attr(element: &OwnedCf, attr_name: &str) -> Option<bool> {
    copy_attr(element, attr_name).and_then(|v| cf_to_bool(&v))
}

/// Returns `true` if `element` lists the attribute named by `key` in
/// `AXUIElementCopyAttributeNames`.
fn advertises_attr(element: &OwnedCf, key: &OwnedCf) -> bool {
    let mut raw_names = ptr::null();
    // SAFETY: `element` is a valid retained `AXUIElementRef`; on success `raw_names` receives a
    // `+1` retained `CFArrayRef` whose ownership is transferred to `OwnedCf`.
    let names = unsafe {
        if AXUIElementCopyAttributeNames(element.as_ptr(), &raw mut raw_names) != K_AX_ERROR_SUCCESS
        {
            return false;
        }
        OwnedCf::from_owned(raw_names)
    };
    let Some(names) = names else {
        return false;
    };
    // SAFETY: `names` is a live CoreFoundation object whose type is checked to be `CFArray`;
    // indices stay within `CFArrayGetCount`, elements are borrowed (`+0`) and only compared with
    // `CFEqual` against the live `key` string while `names` keeps them alive.
    unsafe {
        if CFGetTypeID(names.as_ptr()) != CFArrayGetTypeID() {
            return false;
        }
        let count = CFArrayGetCount(names.as_ptr());
        (0..count).any(|idx| {
            let item = CFArrayGetValueAtIndex(names.as_ptr(), idx);
            !item.is_null() && CFEqual(item, key.as_ptr()) != 0
        })
    }
}

fn read_expanded(element: &OwnedCf, role: Role, expanded_key: Option<&OwnedCf>) -> Option<bool> {
    let key = expanded_key?;
    let read = || copy_attr_key(element, key).and_then(|v| cf_to_bool(&v));
    match expand_probe(role) {
        ExpandProbe::Always => read(),
        ExpandProbe::IfAdvertised if advertises_attr(element, key) => read(),
        ExpandProbe::IfAdvertised | ExpandProbe::Never => None,
    }
}

fn walk_node(
    element: &OwnedCf,
    depth: usize,
    visited: &mut usize,
    out: &mut Vec<AccessibilityNode>,
    expanded_key: Option<&OwnedCf>,
) {
    if depth > MAX_DEPTH || out.len() >= MAX_NODES || *visited >= MAX_VISITED {
        return;
    }
    *visited += 1;

    let role_str = read_string_attr(element, "AXRole").unwrap_or_default();
    let subrole_str = matches!(
        role_str.as_str(),
        "AXCheckBox" | "AXRadioButton" | "AXGroup"
    )
    .then(|| read_string_attr(element, "AXSubrole"))
    .flatten();
    let role = map_ax_role(&role_str, subrole_str.as_deref());
    let name = read_string_attr(element, "AXTitle")
        .filter(|s| !s.is_empty())
        .or_else(|| read_string_attr(element, "AXDescription").filter(|s| !s.is_empty()))
        .or_else(|| read_string_attr(element, "AXPlaceholderValue").filter(|s| !s.is_empty()));
    // `AXValue` is copied once: a string is the node's value, while checkable controls report
    // their state as a `CFNumber` (a `CFBoolean` on some native switches).
    let raw_value = copy_attr(element, "AXValue");
    let value = raw_value
        .as_ref()
        .and_then(cf_to_string)
        .filter(|s| !s.is_empty());
    let checked = checked_from_ax_value(
        role,
        raw_value
            .as_ref()
            .and_then(|v| cf_to_i64(v).or_else(|| cf_to_bool(v).map(i64::from))),
    );
    let name = accessible_name(role, name, value.as_deref());
    let focused = copy_attr(element, "AXFocused")
        .and_then(|v| cf_to_bool(&v))
        .unwrap_or(false);
    let bounds = read_bounds(element);

    if role != Role::Unknown || name.is_some() {
        let disabled = is_control(role) && read_bool_attr(element, "AXEnabled") == Some(false);
        let expanded = read_expanded(element, role, expanded_key);
        let id = format!("ax-{}", out.len());
        out.push(AccessibilityNode {
            id,
            role,
            name,
            value,
            bounds,
            focused,
            checked,
            disabled,
            expanded,
        });
    }

    let Some(children) = copy_attr(element, "AXChildren") else {
        return;
    };

    // SAFETY: `children` is a live CoreFoundation object; verify `CFArray` and `AXUIElement` type IDs.
    let child_refs: Vec<OwnedCf> = unsafe {
        if CFGetTypeID(children.as_ptr()) != CFArrayGetTypeID() {
            return;
        }
        let ax_type_id = AXUIElementGetTypeID();
        let count = CFArrayGetCount(children.as_ptr());
        let budget = MAX_VISITED.saturating_sub(*visited);
        let mut collected = Vec::new();
        for idx in 0..count {
            if collected.len() >= budget {
                break;
            }
            let child_raw = CFArrayGetValueAtIndex(children.as_ptr(), idx);
            if !child_raw.is_null()
                && CFGetTypeID(child_raw) == ax_type_id
                && let Some(child) = OwnedCf::retain(child_raw)
            {
                collected.push(child);
            }
        }
        collected
    };

    for child in &child_refs {
        if out.len() >= MAX_NODES || *visited >= MAX_VISITED {
            break;
        }
        walk_node(child, depth + 1, visited, out, expanded_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_text_falls_back_to_value_for_its_name() {
        assert_eq!(
            accessible_name(Role::StaticText, None, Some("Total: $419")).as_deref(),
            Some("Total: $419")
        );
        // An explicit title wins.
        assert_eq!(
            accessible_name(Role::StaticText, Some("Label".to_owned()), Some("x")).as_deref(),
            Some("Label")
        );
        // Other roles keep value and name separate (a text box's value is user input).
        assert_eq!(accessible_name(Role::TextBox, None, Some("typed")), None);
    }

    #[test]
    fn ax_value_maps_to_checked_state_for_checkable_roles_only() {
        assert_eq!(checked_from_ax_value(Role::CheckBox, Some(0)), Some(false));
        assert_eq!(checked_from_ax_value(Role::CheckBox, Some(1)), Some(true));
        // Mixed / indeterminate is "not fully checked".
        assert_eq!(checked_from_ax_value(Role::CheckBox, Some(2)), Some(false));
        assert_eq!(checked_from_ax_value(Role::Radio, Some(1)), Some(true));
        assert_eq!(checked_from_ax_value(Role::Switch, Some(0)), Some(false));
        assert_eq!(checked_from_ax_value(Role::CheckBox, Some(7)), None);
        assert_eq!(checked_from_ax_value(Role::CheckBox, None), None);
        assert_eq!(checked_from_ax_value(Role::Button, Some(1)), None);
        // Chromium's checkbox / radio menu items report a numeric value; plain ones do not.
        assert_eq!(checked_from_ax_value(Role::MenuItem, Some(1)), Some(true));
        assert_eq!(checked_from_ax_value(Role::MenuItem, None), None);
    }

    #[test]
    fn expanded_is_only_probed_for_roles_that_can_expand() {
        assert_eq!(expand_probe(Role::ComboBox), ExpandProbe::Always);
        assert_eq!(expand_probe(Role::Button), ExpandProbe::IfAdvertised);
        assert_eq!(expand_probe(Role::Link), ExpandProbe::IfAdvertised);
        assert_eq!(expand_probe(Role::TextBox), ExpandProbe::Never);
        assert_eq!(expand_probe(Role::CheckBox), ExpandProbe::Never);
        assert_eq!(expand_probe(Role::StaticText), ExpandProbe::Never);
    }
}
