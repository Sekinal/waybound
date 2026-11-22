//! Safe `AXUIElement` tree traversal for macOS Chrome windows.

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr;

use waybound_core::{AccessibilityNode, Bounds, Result, Role, WayboundError};

use crate::ffi::{
    AXIsProcessTrusted, AXUIElementCopyAttributeValue, AXUIElementCreateApplication,
    AXUIElementGetTypeID, AXUIElementSetAttributeValue, AXValueGetTypeID, AXValueGetValue,
    CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFGetTypeID, CgPoint, CgSize,
    K_AX_ERROR_SUCCESS, K_AX_VALUE_TYPE_CG_POINT, K_AX_VALUE_TYPE_CG_SIZE, OwnedCf, cf_string,
    cf_to_bool, cf_to_string, kCFBooleanTrue,
};

const MAX_DEPTH: usize = 40;
const MAX_NODES: usize = 2_000;
const MAX_VISITED: usize = 10_000;

/// Checks whether the current process has macOS Accessibility permission.
#[must_use]
pub fn is_accessibility_trusted() -> bool {
    // SAFETY: `AXIsProcessTrusted` takes no arguments and is safe to call from any thread.
    unsafe { AXIsProcessTrusted() != 0 }
}

/// Captures a bounded snapshot of the accessibility tree for `pid`.
///
/// Enables `AXEnhancedUserInterface` on the target application so Chromium/Chrome
/// exposes its `AXWebArea` web-content accessibility tree.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing
/// or the application element cannot be created.
pub fn snapshot_application_tree(pid: i32) -> Result<Vec<AccessibilityNode>> {
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
    let root = copy_attr(&app, "AXFocusedWindow")
        .or_else(|| copy_attr(&app, "AXMainWindow"))
        .or_else(|| first_ax_window(&app))
        .unwrap_or(app);

    let mut nodes = Vec::new();
    let mut visited = 0;
    walk_node(&root, 0, &mut visited, &mut nodes);
    tracing::debug!(
        pid,
        visited,
        captured = nodes.len(),
        "macos AX snapshot complete"
    );
    Ok(nodes)
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
    let key = cf_string(attr_name)?;
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

fn map_ax_role(ax_role: &str) -> Role {
    match ax_role {
        "AXButton" | "AXPopUpButton" | "AXMenuButton" => Role::Button,
        "AXLink" => Role::Link,
        "AXTextField" | "AXTextArea" | "AXComboBox" | "AXSearchField" => Role::TextBox,
        "AXCheckBox" => Role::CheckBox,
        "AXWebArea" | "AXScrollArea" => Role::Document,
        "AXHeading" => Role::Heading,
        "AXStaticText" => Role::StaticText,
        _ => Role::Unknown,
    }
}

fn walk_node(
    element: &OwnedCf,
    depth: usize,
    visited: &mut usize,
    out: &mut Vec<AccessibilityNode>,
) {
    if depth > MAX_DEPTH || out.len() >= MAX_NODES || *visited >= MAX_VISITED {
        return;
    }
    *visited += 1;

    let role_str = read_string_attr(element, "AXRole").unwrap_or_default();
    let role = map_ax_role(&role_str);
    let name = read_string_attr(element, "AXTitle")
        .filter(|s| !s.is_empty())
        .or_else(|| read_string_attr(element, "AXDescription").filter(|s| !s.is_empty()))
        .or_else(|| read_string_attr(element, "AXPlaceholderValue").filter(|s| !s.is_empty()));
    let value = read_string_attr(element, "AXValue").filter(|s| !s.is_empty());
    let focused = copy_attr(element, "AXFocused")
        .and_then(|v| cf_to_bool(&v))
        .unwrap_or(false);
    let bounds = read_bounds(element);

    if role != Role::Unknown || name.is_some() {
        let id = format!("ax-{}", out.len());
        out.push(AccessibilityNode {
            id,
            role,
            name,
            value,
            bounds,
            focused,
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
        walk_node(child, depth + 1, visited, out);
    }
}
