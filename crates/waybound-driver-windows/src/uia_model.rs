//! Platform-independent rules shared by the native COM `UIAutomation` backend.
//!
//! Everything here is pure so it is unit-tested on every OS. Each function mirrors one step
//! of the PowerShell walker in [`crate::uia`] (control type names, which patterns are probed,
//! bounds sanitizing, runtime id formatting, omnibox detection, web root choice, the capped
//! breadth-first walk), so the two backends produce the same nodes for the same tree.

use std::collections::VecDeque;

use waybound_core::{Bounds, WayboundError};

/// `UIA_*ControlTypeId` values from `UIAutomationClient.h`.
pub mod control_type {
    /// `UIA_ButtonControlTypeId`.
    pub const BUTTON: i32 = 50_000;
    /// `UIA_CheckBoxControlTypeId`.
    pub const CHECK_BOX: i32 = 50_002;
    /// `UIA_ComboBoxControlTypeId`.
    pub const COMBO_BOX: i32 = 50_003;
    /// `UIA_EditControlTypeId`.
    pub const EDIT: i32 = 50_004;
    /// `UIA_HyperlinkControlTypeId`.
    pub const HYPERLINK: i32 = 50_005;
    /// `UIA_MenuItemControlTypeId`.
    pub const MENU_ITEM: i32 = 50_011;
    /// `UIA_RadioButtonControlTypeId`.
    pub const RADIO_BUTTON: i32 = 50_013;
    /// `UIA_TreeItemControlTypeId`.
    pub const TREE_ITEM: i32 = 50_024;
    /// `UIA_DocumentControlTypeId`.
    pub const DOCUMENT: i32 = 50_030;
    /// `UIA_SplitButtonControlTypeId`.
    pub const SPLIT_BUTTON: i32 = 50_031;
}

/// Returns the .NET `ControlType.ProgrammaticName` (for example `ControlType.Button`) for a
/// `UIA_*ControlTypeId`, the string the PowerShell walker reports for the same element.
///
/// Ids outside the documented range map to `ControlType.Unknown`, which
/// [`crate::uia::map_uia_control_type`] turns into [`waybound_core::Role::Unknown`].
#[must_use]
pub const fn control_type_programmatic_name(id: i32) -> &'static str {
    match id {
        50_000 => "ControlType.Button",
        50_001 => "ControlType.Calendar",
        50_002 => "ControlType.CheckBox",
        50_003 => "ControlType.ComboBox",
        50_004 => "ControlType.Edit",
        50_005 => "ControlType.Hyperlink",
        50_006 => "ControlType.Image",
        50_007 => "ControlType.ListItem",
        50_008 => "ControlType.List",
        50_009 => "ControlType.Menu",
        50_010 => "ControlType.MenuBar",
        50_011 => "ControlType.MenuItem",
        50_012 => "ControlType.ProgressBar",
        50_013 => "ControlType.RadioButton",
        50_014 => "ControlType.ScrollBar",
        50_015 => "ControlType.Slider",
        50_016 => "ControlType.Spinner",
        50_017 => "ControlType.StatusBar",
        50_018 => "ControlType.Tab",
        50_019 => "ControlType.TabItem",
        50_020 => "ControlType.Text",
        50_021 => "ControlType.ToolBar",
        50_022 => "ControlType.ToolTip",
        50_023 => "ControlType.Tree",
        50_024 => "ControlType.TreeItem",
        50_025 => "ControlType.Custom",
        50_026 => "ControlType.Group",
        50_027 => "ControlType.Thumb",
        50_028 => "ControlType.DataGrid",
        50_029 => "ControlType.DataItem",
        50_030 => "ControlType.Document",
        50_031 => "ControlType.SplitButton",
        50_032 => "ControlType.Window",
        50_033 => "ControlType.Pane",
        50_034 => "ControlType.Header",
        50_035 => "ControlType.HeaderItem",
        50_036 => "ControlType.Table",
        50_037 => "ControlType.TitleBar",
        50_038 => "ControlType.Separator",
        50_039 => "ControlType.SemanticZoom",
        50_040 => "ControlType.AppBar",
        _ => "ControlType.Unknown",
    }
}

/// `true` when the walker reads `TogglePattern.ToggleState` for this control type.
#[must_use]
pub const fn probes_toggle_state(control_type_id: i32) -> bool {
    matches!(
        control_type_id,
        control_type::CHECK_BOX
            | control_type::RADIO_BUTTON
            | control_type::BUTTON
            | control_type::MENU_ITEM
    )
}

/// `true` when the walker reads `SelectionItemPattern.IsSelected` for this control type.
#[must_use]
pub const fn probes_selection_state(control_type_id: i32) -> bool {
    control_type_id == control_type::RADIO_BUTTON
}

/// `true` when the walker reads `ExpandCollapsePattern.ExpandCollapseState` for this control
/// type.
#[must_use]
pub const fn probes_expand_state(control_type_id: i32) -> bool {
    matches!(
        control_type_id,
        control_type::COMBO_BOX
            | control_type::BUTTON
            | control_type::MENU_ITEM
            | control_type::TREE_ITEM
            | control_type::HYPERLINK
            | control_type::SPLIT_BUTTON
    )
}

/// Converts a Win32 `RECT` (`left`, `top`, `right`, `bottom`) into `(x, y, width, height)`.
///
/// Negative extents become `0`, as the PowerShell walker does for an empty .NET `Rect`
/// (UIA reports an off-screen element as an all-zero `RECT` natively and as `Rect.Empty`
/// through .NET, and both end up as a zero-sized node at the origin).
#[must_use]
pub fn rect_to_xywh(left: i32, top: i32, right: i32, bottom: i32) -> (f64, f64, f64, f64) {
    let width = (i64::from(right) - i64::from(left)).max(0);
    let height = (i64::from(bottom) - i64::from(top)).max(0);
    // A difference of two `i32` values always fits in `i32`'s doubled range, which `f64`
    // represents exactly.
    #[allow(clippy::cast_precision_loss)]
    let (width, height) = (width as f64, height as f64);
    (f64::from(left), f64::from(top), width, height)
}

/// Formats a UIA runtime id the way the PowerShell walker does (`$rid -join '-'`).
///
/// Returns `None` for an empty id so the node gets a positional id instead.
#[must_use]
pub fn runtime_id_to_string(parts: &[i32]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    Some(
        parts
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// `true` when an `Edit` element looks like the browser address bar.
///
/// Its value must be non-empty, and either its name contains `Address` or `URL`, or its value starts with `http://` or
/// `https://` (all case-insensitive, like PowerShell's `-match`).
#[must_use]
pub fn is_address_bar_candidate(name: Option<&str>, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let name_matches = name.is_some_and(|n| {
        let lower = n.to_ascii_lowercase();
        lower.contains("address") || lower.contains("url")
    });
    let value_lower = value.to_ascii_lowercase();
    name_matches || value_lower.starts_with("http://") || value_lower.starts_with("https://")
}

/// Picks the web content root among the window's `Document` descendants, given each one's
/// `(x, y, width, height)` in tree order.
///
/// The largest strictly positive area wins (the first one on ties) and its bounds become the
/// viewport. When no document has a positive area, the first document is still used as the
/// root, without viewport bounds. Returns `None` when there are no documents.
#[must_use]
pub fn select_web_root(documents: &[(f64, f64, f64, f64)]) -> Option<(usize, Option<Bounds>)> {
    let mut best: Option<(usize, f64, Bounds)> = None;
    for (idx, &(x, y, width, height)) in documents.iter().enumerate() {
        let finite = [x, y, width, height].iter().all(|v| v.is_finite());
        if !(finite && width > 0.0 && height > 0.0) {
            continue;
        }
        let area = width * height;
        if best
            .as_ref()
            .is_none_or(|(_, best_area, _)| area > *best_area)
        {
            best = Some((
                idx,
                area,
                Bounds {
                    x,
                    y,
                    width,
                    height,
                },
            ));
        }
    }
    match best {
        Some((idx, _, bounds)) => Some((idx, Some(bounds))),
        None if documents.is_empty() => None,
        None => Some((0, None)),
    }
}

/// `(x, y, width, height)` of an element.
pub type XywhRect = (f64, f64, f64, f64);

/// Like [`select_web_root`], over documents found in the raw view, each with its
/// `IsControlElement` flag.
///
/// Documents that are control elements are considered first, so whenever the control view
/// has a document the choice is exactly [`select_web_root`]'s over those. Only when none of
/// them is a control element are the raw-only documents considered. (Chrome's web document
/// can be missing from the control view right after launch while its content is already
/// there; walking the browser window instead returned the browser's own UI.)
#[must_use]
pub fn select_web_root_preferring_control(
    documents: &[(XywhRect, bool)],
) -> Option<(usize, Option<Bounds>)> {
    let control: Vec<usize> = (0..documents.len())
        .filter(|&i| documents.get(i).is_some_and(|(_, is_control)| *is_control))
        .collect();
    let pool: Vec<usize> = if control.is_empty() {
        (0..documents.len()).collect()
    } else {
        control
    };
    let rects: Vec<(f64, f64, f64, f64)> = pool
        .iter()
        .filter_map(|&i| documents.get(i).map(|(rect, _)| *rect))
        .collect();
    let (picked, bounds) = select_web_root(&rects)?;
    pool.get(picked).map(|&idx| (idx, bounds))
}

/// Process names the walker accepts when no target pid is configured, in priority order.
///
/// PowerShell's `Get-Process -Name 'chrome','msedge','chromium'` returns the matching
/// processes sorted by process name and then by id (`ProcessBaseCommand` sorts its matches),
/// so the old walker effectively tried `chrome`, then `chromium`, then `msedge`, each in
/// ascending pid order. This list keeps that alphabetical order.
pub const BROWSER_PROCESS_NAMES: [&str; 3] = ["chrome", "chromium", "msedge"];

/// Reduces a full image path (`C:\...\chrome.exe`) to a lowercase process name (`chrome`).
#[must_use]
pub fn process_name_from_image_path(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let lower = base.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .map_or_else(|| lower.clone(), str::to_owned)
}

/// A top-level UIA element considered as the browser window when no pid is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCandidate {
    /// Lowercase process name of the owning process, if it could be read.
    pub process_name: Option<String>,
    /// Owning process id.
    pub pid: i32,
    /// `true` when the element's control type is `Window` (not a popup, tooltip or pane).
    pub is_window: bool,
}

/// Picks the browser window among top-level elements (given in UIA order).
///
/// The order is: browser name in [`BROWSER_PROCESS_NAMES`] order, then lowest pid (both as
/// the PowerShell walker's `Get-Process` loop did), then an element whose control type is
/// `Window` over any other top-level element of that process (a popup or tooltip can come
/// first in UIA order), then UIA order.
#[must_use]
pub fn pick_browser_window(candidates: &[WindowCandidate]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(idx, c)| {
            let rank = BROWSER_PROCESS_NAMES
                .iter()
                .position(|name| c.process_name.as_deref() == Some(*name))?;
            Some(((rank, c.pid, !c.is_window, idx), idx))
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, idx)| idx)
}

/// What [`bfs_limited`]'s visitor decided for one node.
pub enum Visit<T, N> {
    /// Keep the node and offer its children.
    Node(T, Vec<N>),
    /// Drop the node and its subtree (the PowerShell walker's per-node `catch {}`).
    Skip,
    /// Stop the walk now (deadline); the result is marked truncated.
    Stop,
}

/// Capped breadth-first walk with exactly the PowerShell walker's truncation rule.
///
/// Children are enqueued until `items + queued` reaches `limit`; a child that no longer fits
/// marks the walk truncated, as does [`Visit::Stop`].
pub fn bfs_limited<N, T>(
    root: N,
    limit: usize,
    mut visit: impl FnMut(N) -> Visit<T, N>,
) -> (Vec<T>, bool) {
    let mut queue = VecDeque::from([root]);
    let mut items = Vec::new();
    let mut truncated = false;
    while items.len() < limit {
        let Some(node) = queue.pop_front() else {
            break;
        };
        let (item, children) = match visit(node) {
            Visit::Node(item, children) => (item, children),
            Visit::Skip => continue,
            Visit::Stop => {
                truncated = true;
                break;
            }
        };
        items.push(item);
        for child in children {
            if items.len() + queue.len() >= limit {
                truncated = true;
                break;
            }
            queue.push_back(child);
        }
    }
    if !queue.is_empty() {
        truncated = true;
    }
    (items, truncated)
}

/// `E_FAIL`: unspecified failure. Chrome returns it for elements torn down mid-navigation.
pub const E_FAIL: u32 = 0x8000_4005;
/// `UIA_E_ELEMENTNOTAVAILABLE`: the element no longer exists (stale).
pub const UIA_E_ELEMENTNOTAVAILABLE: u32 = 0x8004_0201;
/// `UIA_E_TIMEOUT`: the provider did not answer within the UIA connection/transaction timeout.
pub const UIA_E_TIMEOUT: u32 = 0x8013_1505;
/// `RPC_E_DISCONNECTED`: the provider process went away mid-call.
pub const RPC_E_DISCONNECTED: u32 = 0x8001_0108;
/// `RPC_E_SERVER_DIED`: the provider process died during the call.
pub const RPC_E_SERVER_DIED: u32 = 0x8001_0007;
/// `RPC_E_SERVER_DIED_DNE`: the provider process died before the call was delivered.
pub const RPC_E_SERVER_DIED_DNE: u32 = 0x8001_0012;
/// `CO_E_OBJNOTCONNECTED`: the remote object was disconnected from its process.
pub const CO_E_OBJNOTCONNECTED: u32 = 0x8004_01FD;
/// `HRESULT_FROM_WIN32(RPC_S_SERVER_UNAVAILABLE)`: the provider process is gone.
pub const RPC_S_SERVER_UNAVAILABLE: u32 = 0x8007_06BA;
/// `HRESULT_FROM_WIN32(RPC_S_CALL_FAILED)`: the cross-process call failed (provider exiting).
pub const RPC_S_CALL_FAILED: u32 = 0x8007_06BE;

/// How a failed `UIAutomation` COM call is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HresultClass {
    /// The element or its process went away; worth retrying (`transient`).
    Stale,
    /// The provider did not answer in time (`timeout`).
    Timeout,
    /// Anything else (`backend_unavailable`).
    Other,
}

/// Classifies a failed COM call by its `HRESULT`.
#[must_use]
pub const fn classify_hresult(code: u32) -> HresultClass {
    match code {
        UIA_E_ELEMENTNOTAVAILABLE
        | RPC_E_DISCONNECTED
        | RPC_E_SERVER_DIED
        | RPC_E_SERVER_DIED_DNE
        | CO_E_OBJNOTCONNECTED
        | RPC_S_SERVER_UNAVAILABLE
        | RPC_S_CALL_FAILED => HresultClass::Stale,
        UIA_E_TIMEOUT => HresultClass::Timeout,
        _ => HresultClass::Other,
    }
}

/// Like [`classify_hresult`], for calls that read the web content tree.
///
/// There `E_FAIL` is also stale: Chrome returns it for a document that is being replaced by a navigation,
/// where the PowerShell walker swallowed the error and returned a partial or empty tree.
#[must_use]
pub const fn classify_tree_hresult(code: u32) -> HresultClass {
    if code == E_FAIL {
        HresultClass::Stale
    } else {
        classify_hresult(code)
    }
}

/// Converts a failed native `UIAutomation` call into a [`WayboundError`].
///
/// [`HresultClass::Stale`] becomes `Transient`, [`HresultClass::Timeout`] becomes `Timeout`
/// and everything else `BackendUnavailable`. The message always carries the `HRESULT` in hex.
#[must_use]
pub fn uia_error(
    class: HresultClass,
    code: u32,
    operation: &str,
    message: &str,
    timeout_ms: u64,
) -> WayboundError {
    let detail = format!(
        "Windows UIAutomation (native COM) {operation} failed: HRESULT 0x{code:08X} ({})",
        message.trim()
    );
    match class {
        HresultClass::Stale => WayboundError::Transient {
            backend: "windows".to_owned(),
            reason: detail,
        },
        HresultClass::Timeout => WayboundError::Timeout {
            timeout_ms,
            context: detail,
        },
        HresultClass::Other => WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: detail,
        },
    }
}

/// Lifecycle of a COM worker thread, shared between the thread and the callers that wait on
/// it. Drives the count of abandoned (hung) workers so it can never leak.
pub mod worker_life {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    /// The worker is running and still owned by the request slot.
    pub const LIVE: u8 = 0;
    /// A caller gave up on the worker; it is counted until its thread exits.
    pub const ABANDONED: u8 = 1;
    /// The worker thread has exited.
    pub const EXITED: u8 = 2;

    /// Marks the worker abandoned and counts it, unless it was already abandoned or has
    /// exited. Returns `true` if this call counted it.
    pub fn abandon(life: &AtomicU8, abandoned_count: &AtomicUsize) -> bool {
        // Count first so a concurrent exit always finds the increment it may undo.
        let _ = abandoned_count.fetch_add(1, Ordering::SeqCst);
        if life
            .compare_exchange(LIVE, ABANDONED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            true
        } else {
            let _ = abandoned_count.fetch_sub(1, Ordering::SeqCst);
            false
        }
    }

    /// Records the worker thread's exit, un-counting it if it had been abandoned.
    pub fn exited(life: &AtomicU8, abandoned_count: &AtomicUsize) {
        if life.swap(EXITED, Ordering::SeqCst) == ABANDONED {
            let _ = abandoned_count.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Which implementation answers `UIAutomation` queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiaBackend {
    /// In-process COM `IUIAutomation` (default); falls back to PowerShell only if COM
    /// initialization fails.
    NativeCom,
    /// In-process COM with no fallback: if COM initialization fails, queries return
    /// `backend_unavailable`. Used by CI to prove the native path ran.
    NativeStrict,
    /// The original `powershell.exe` + .NET `UIAutomationClient` walker.
    PowerShell,
}

impl UiaBackend {
    /// Short name used in logs and error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeCom => "native-com",
            Self::NativeStrict => "native-strict",
            Self::PowerShell => "powershell",
        }
    }
}

/// Environment variable that selects the `UIAutomation` backend.
pub const UIA_BACKEND_ENV: &str = "WAYBOUND_WINDOWS_UIA";

/// Parses the value of [`UIA_BACKEND_ENV`].
///
/// `powershell` (or `ps`) selects the PowerShell walker; `native-strict` (or `strict`)
/// selects native COM without fallback; unset, empty, `native` or `com` select native COM.
/// The second value is `false` for an unrecognized setting, which also selects native COM.
#[must_use]
pub fn parse_uia_backend(raw: Option<&str>) -> (UiaBackend, bool) {
    let Some(value) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return (UiaBackend::NativeCom, true);
    };
    match value.to_ascii_lowercase().as_str() {
        "powershell" | "ps" => (UiaBackend::PowerShell, true),
        "native" | "com" => (UiaBackend::NativeCom, true),
        "native-strict" | "strict" => (UiaBackend::NativeStrict, true),
        _ => (UiaBackend::NativeCom, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uia::map_uia_control_type;
    use waybound_core::Role;

    #[test]
    fn programmatic_names_round_trip_through_role_mapping() {
        let cases = [
            (50_000, Role::Button),
            (50_002, Role::CheckBox),
            (50_003, Role::ComboBox),
            (50_004, Role::TextBox),
            (50_005, Role::Link),
            (50_006, Role::Img),
            (50_007, Role::Option),
            (50_008, Role::ListBox),
            (50_011, Role::MenuItem),
            (50_013, Role::Radio),
            (50_018, Role::Tab),
            (50_019, Role::Tab),
            (50_020, Role::StaticText),
            (50_026, Role::Group),
            (50_030, Role::Document),
            (50_031, Role::Button),
            (50_032, Role::Unknown),
            (50_033, Role::Unknown),
            (50_034, Role::Heading),
            (50_035, Role::Heading),
            (12_345, Role::Unknown),
        ];
        for (id, role) in cases {
            assert_eq!(
                map_uia_control_type(control_type_programmatic_name(id), None),
                role,
                "control type {id}"
            );
        }
        assert_eq!(
            map_uia_control_type(control_type_programmatic_name(50_020), Some("heading")),
            Role::Heading
        );
        assert_eq!(control_type_programmatic_name(99), "ControlType.Unknown");
    }

    #[test]
    fn every_documented_control_type_has_a_name() {
        for id in 50_000..=50_040 {
            assert_ne!(control_type_programmatic_name(id), "ControlType.Unknown");
        }
    }

    #[test]
    fn pattern_probes_match_powershell_gates() {
        assert!(probes_toggle_state(control_type::CHECK_BOX));
        assert!(probes_toggle_state(control_type::BUTTON));
        assert!(probes_toggle_state(control_type::MENU_ITEM));
        assert!(probes_toggle_state(control_type::RADIO_BUTTON));
        assert!(!probes_toggle_state(control_type::EDIT));
        assert!(probes_selection_state(control_type::RADIO_BUTTON));
        assert!(!probes_selection_state(control_type::CHECK_BOX));
        for id in [50_003, 50_000, 50_011, 50_024, 50_005, 50_031] {
            assert!(probes_expand_state(id), "{id}");
        }
        assert!(!probes_expand_state(control_type::CHECK_BOX));
    }

    #[test]
    fn rect_conversion_clamps_negative_extents() {
        assert_eq!(rect_to_xywh(10, 20, 110, 70), (10.0, 20.0, 100.0, 50.0));
        assert_eq!(rect_to_xywh(0, 0, 0, 0), (0.0, 0.0, 0.0, 0.0));
        assert_eq!(rect_to_xywh(50, 50, 10, 10), (50.0, 50.0, 0.0, 0.0));
        assert_eq!(
            rect_to_xywh(-1920, -40, 0, 1040),
            (-1920.0, -40.0, 1920.0, 1080.0)
        );
        assert_eq!(
            rect_to_xywh(i32::MIN, 0, i32::MAX, 1),
            (f64::from(i32::MIN), 0.0, 4_294_967_295.0, 1.0)
        );
    }

    #[test]
    fn runtime_ids_join_like_powershell() {
        assert_eq!(
            runtime_id_to_string(&[42, 7, 1001]).as_deref(),
            Some("42-7-1001")
        );
        assert_eq!(runtime_id_to_string(&[42, -5]).as_deref(), Some("42--5"));
        assert_eq!(runtime_id_to_string(&[]), None);
    }

    #[test]
    fn address_bar_detection_is_case_insensitive() {
        assert!(is_address_bar_candidate(
            Some("Address and search bar"),
            "example.com"
        ));
        assert!(is_address_bar_candidate(Some("url"), "x"));
        assert!(is_address_bar_candidate(None, "HTTPS://example.com"));
        assert!(is_address_bar_candidate(Some("Search"), "http://a"));
        assert!(!is_address_bar_candidate(Some("Search"), "old"));
        assert!(!is_address_bar_candidate(Some("Address"), ""));
    }

    #[test]
    fn web_root_prefers_largest_positive_document() {
        assert_eq!(select_web_root(&[]), None);
        assert_eq!(select_web_root(&[(0.0, 0.0, 0.0, 0.0)]), Some((0, None)));
        let picked = select_web_root(&[
            (0.0, 0.0, 0.0, 0.0),
            (0.0, 80.0, 100.0, 100.0),
            (0.0, 80.0, 1280.0, 720.0),
            (0.0, 0.0, 1280.0, 720.0),
        ]);
        assert_eq!(
            picked,
            Some((
                2,
                Some(Bounds {
                    x: 0.0,
                    y: 80.0,
                    width: 1280.0,
                    height: 720.0,
                })
            ))
        );
        assert_eq!(
            select_web_root(&[(f64::NAN, 0.0, 10.0, 10.0)]),
            Some((0, None))
        );
    }

    #[test]
    fn web_root_prefers_control_view_documents() {
        let big = (0.0, 80.0, 1280.0, 720.0);
        let small = (0.0, 80.0, 100.0, 100.0);
        // A control-view document wins over a larger raw-only one.
        assert_eq!(
            select_web_root_preferring_control(&[(big, false), (small, true)]).map(|r| r.0),
            Some(1)
        );
        // No control-view document: the raw-only ones are used.
        assert_eq!(
            select_web_root_preferring_control(&[(small, false), (big, false)]).map(|r| r.0),
            Some(1)
        );
        // Only zero-sized control documents: the first of them, without viewport.
        assert_eq!(
            select_web_root_preferring_control(&[(big, false), ((0.0, 0.0, 0.0, 0.0), true)]),
            Some((1, None))
        );
        assert_eq!(select_web_root_preferring_control(&[]), None);
    }

    #[test]
    fn browser_window_choice_follows_name_priority() {
        assert_eq!(
            process_name_from_image_path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            "chrome"
        );
        assert_eq!(process_name_from_image_path("MSEDGE.EXE"), "msedge");
        assert_eq!(
            process_name_from_image_path("/usr/bin/chromium"),
            "chromium"
        );
        let c = |name: Option<&str>, pid: i32, is_window: bool| WindowCandidate {
            process_name: name.map(str::to_owned),
            pid,
            is_window,
        };
        let candidates = [
            c(Some("explorer"), 1, true),
            c(Some("msedge"), 5, true),
            c(None, 2, true),
            c(Some("chromium"), 9, true),
            c(Some("chrome"), 40, false), // a chrome popup listed first
            c(Some("chrome"), 40, true),
            c(Some("chrome"), 30, false),
        ];
        // chrome beats chromium and msedge; lowest pid wins even if only a popup.
        assert_eq!(pick_browser_window(&candidates), Some(6));
        // Within one process, a Window beats a popup listed before it.
        assert_eq!(pick_browser_window(&candidates[..6]), Some(5));
        // chromium before msedge (alphabetical, like Get-Process).
        assert_eq!(pick_browser_window(&candidates[..4]), Some(3));
        assert_eq!(pick_browser_window(&candidates[..3]), Some(1));
        assert_eq!(pick_browser_window(&[c(Some("code"), 1, true)]), None);
    }

    /// Tree used by the walk tests: node `n` has the children listed at index `n`.
    fn walk(
        tree: &[Vec<usize>],
        limit: usize,
        skip: Option<usize>,
        stop: Option<usize>,
    ) -> (Vec<usize>, bool) {
        bfs_limited(0usize, limit, |n| {
            if Some(n) == skip {
                return Visit::Skip;
            }
            if Some(n) == stop {
                return Visit::Stop;
            }
            Visit::Node(n, tree.get(n).cloned().unwrap_or_default())
        })
    }

    #[test]
    fn bfs_walk_matches_powershell_truncation() {
        // 0 -> [1, 2], 1 -> [3, 4], 2 -> [5]
        let tree = vec![vec![1, 2], vec![3, 4], vec![5], vec![], vec![], vec![]];
        assert_eq!(
            walk(&tree, 100, None, None),
            (vec![0, 1, 2, 3, 4, 5], false)
        );
        assert_eq!(walk(&tree, 6, None, None), (vec![0, 1, 2, 3, 4, 5], false));
        // At 3, node 1's children no longer fit after 0, 1, 2 are taken or queued.
        assert_eq!(walk(&tree, 3, None, None), (vec![0, 1, 2], true));
        assert_eq!(walk(&tree, 1, None, None), (vec![0], true));
        // A failing node is dropped together with its subtree.
        assert_eq!(walk(&tree, 100, Some(1), None), (vec![0, 2, 5], false));
        // A deadline stop keeps what was read and marks the walk truncated.
        assert_eq!(walk(&tree, 100, None, Some(3)), (vec![0, 1, 2], true));
    }

    #[test]
    fn hresults_map_to_existing_error_codes() {
        let stale = uia_error(
            classify_hresult(UIA_E_ELEMENTNOTAVAILABLE),
            UIA_E_ELEMENTNOTAVAILABLE,
            "tree snapshot",
            " gone ",
            10,
        );
        assert!(matches!(
            &stale,
            WayboundError::Transient { reason, .. }
                if reason.contains("HRESULT 0x80040201") && reason.contains("(gone)")
        ));
        assert!(matches!(
            uia_error(
                classify_hresult(UIA_E_TIMEOUT),
                UIA_E_TIMEOUT,
                "x",
                "",
                10_000
            ),
            WayboundError::Timeout {
                timeout_ms: 10_000,
                ..
            }
        ));
        for code in [
            RPC_S_SERVER_UNAVAILABLE,
            RPC_S_CALL_FAILED,
            RPC_E_DISCONNECTED,
            RPC_E_SERVER_DIED,
            RPC_E_SERVER_DIED_DNE,
            CO_E_OBJNOTCONNECTED,
        ] {
            assert_eq!(classify_hresult(code), HresultClass::Stale, "{code:08X}");
        }
        assert_eq!(classify_hresult(E_FAIL), HresultClass::Other);
        assert_eq!(classify_tree_hresult(E_FAIL), HresultClass::Stale);
        assert_eq!(classify_tree_hresult(UIA_E_TIMEOUT), HresultClass::Timeout);
        assert!(matches!(
            uia_error(classify_hresult(E_FAIL), E_FAIL, "x", "", 1),
            WayboundError::BackendUnavailable { .. }
        ));
    }

    #[test]
    fn abandoned_worker_count_never_leaks() {
        use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
        use worker_life::{ABANDONED, EXITED, LIVE, abandon, exited};

        // Abandoned, then exits: counted, then un-counted.
        let (life, count) = (AtomicU8::new(LIVE), AtomicUsize::new(0));
        assert!(abandon(&life, &count));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(!abandon(&life, &count)); // a second caller does not double count
        assert_eq!(count.load(Ordering::SeqCst), 1);
        exited(&life, &count);
        assert_eq!(
            (life.load(Ordering::SeqCst), count.load(Ordering::SeqCst)),
            (EXITED, 0)
        );

        // Exits first (e.g. init failed after the caller's wait), then a late abandon.
        let (life, count) = (AtomicU8::new(LIVE), AtomicUsize::new(0));
        exited(&life, &count);
        assert!(!abandon(&life, &count));
        assert_eq!(count.load(Ordering::SeqCst), 0);

        // Live worker that exits normally is never counted.
        let (life, count) = (AtomicU8::new(LIVE), AtomicUsize::new(0));
        exited(&life, &count);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_ne!(life.load(Ordering::SeqCst), ABANDONED);
    }

    #[test]
    fn backend_switch_parses_env_values() {
        assert_eq!(parse_uia_backend(None), (UiaBackend::NativeCom, true));
        assert_eq!(parse_uia_backend(Some("  ")), (UiaBackend::NativeCom, true));
        assert_eq!(
            parse_uia_backend(Some("PowerShell")),
            (UiaBackend::PowerShell, true)
        );
        assert_eq!(
            parse_uia_backend(Some("ps")),
            (UiaBackend::PowerShell, true)
        );
        assert_eq!(
            parse_uia_backend(Some("native")),
            (UiaBackend::NativeCom, true)
        );
        assert_eq!(
            parse_uia_backend(Some("bogus")),
            (UiaBackend::NativeCom, false)
        );
        assert_eq!(
            parse_uia_backend(Some("Native-Strict")),
            (UiaBackend::NativeStrict, true)
        );
        assert_eq!(UiaBackend::PowerShell.as_str(), "powershell");
    }
}
