//! Safe `AXUIElement` tree traversal for macOS Chrome windows.
//!
//! The traversal policy (batched decoding, limits, deadline, web-area selection) lives in the
//! pure [`crate::tree`] module; this module implements its [`AxSource`] on top of the
//! Accessibility API and owns every `unsafe` call involved.
//!
//! Failure policy: a slow or hung browser never turns into an error. A deadline or a run of
//! unanswered messages ends the operation with whatever was read so far (possibly an empty tree
//! or no URL), logged with a rate-limited warning, so callers keep polling as they did when the
//! old reader simply lost unanswered attributes. Only `kAXErrorAPIDisabled` (permission revoked)
//! is reported as an error.

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, Once, PoisonError};
use std::time::{Duration, Instant};

use waybound_core::{AccessibilityNode, Bounds, Result, TreeSnapshot, WayboundError};

use crate::ffi::{
    AXIsProcessTrusted, AXUIElementCopyAttributeNames, AXUIElementCopyAttributeValue,
    AXUIElementCopyMultipleAttributeValues, AXUIElementCreateApplication,
    AXUIElementCreateSystemWide, AXUIElementGetTypeID, AXUIElementSetAttributeValue,
    AXUIElementSetMessagingTimeout, AXValueGetType, AXValueGetTypeID, AXValueGetValue, CFEqual,
    CFGetTypeID, CFNullGetTypeID, CgPoint, CgSize, K_AX_ERROR_SUCCESS, K_AX_VALUE_TYPE_AX_ERROR,
    K_AX_VALUE_TYPE_CG_POINT, K_AX_VALUE_TYPE_CG_SIZE, OwnedCf, cf_array, cf_array_items,
    cf_string, cf_to_bool, cf_to_i64, cf_to_string, cf_to_url_string, kCFBooleanFalse,
    kCFBooleanTrue,
};
use crate::tree::{
    ATTR_SETS, ApiDisabled, AttrSet, AxSource, AxStatus, BatchNext, Budget, Candidate,
    ENHANCED_UI_ATTRS, FlagState, FlagValue, Limit, NodeAttrs, Outcome, SNAPSHOT_LIMITS, SetResult,
    Slot, SlotValue, SystemClock, WEB_AREA_SEARCH, WalkLimits, WarnGate, WebAreaSearch, WindowAttr,
    after_batch, api_disabled_error, classify_ax_error, decode_slots, find_web_area, flag_value,
    set_result, walk_tree,
};

/// How long one Accessibility message to the browser may take before failing with
/// `kAXErrorCannotComplete` (the system default is about 6 s).
///
/// Set process-wide through the system-wide element: `AXUIElement.h` documents that a timeout
/// set on any other element applies "only for that object", not to elements obtained from it.
pub const MESSAGING_TIMEOUT: Duration = Duration::from_secs(3);
/// Overall budget of one snapshot, URL read, or viewport read. One message may still be in
/// flight when it passes, so an operation can last up to about this plus [`MESSAGING_TIMEOUT`].
pub const OPERATION_DEADLINE: Duration = Duration::from_secs(10);
/// Unanswered messages in a row after which an operation stops early (and returns what it has).
const MAX_UNRESPONSIVE_STREAK: u32 = 3;

/// Checks whether the current process has macOS Accessibility permission.
#[must_use]
pub fn is_accessibility_trusted() -> bool {
    // SAFETY: `AXIsProcessTrusted` takes no arguments and is safe to call from any thread.
    unsafe { AXIsProcessTrusted() != 0 }
}

/// Sets this process's Accessibility messaging timeout to [`MESSAGING_TIMEOUT`], once.
fn ensure_messaging_timeout() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: `AXUIElementCreateSystemWide` takes no arguments and returns a `+1` retained
        // element (or null), whose ownership moves into `OwnedCf`.
        let Some(system) = (unsafe { OwnedCf::from_owned(AXUIElementCreateSystemWide()) }) else {
            tracing::warn!(
                "could not create the system-wide AX element; keeping the default AX messaging timeout"
            );
            return;
        };
        // SAFETY: `system` is a live `AXUIElementRef`; the timeout is a positive float.
        let status = unsafe {
            AXUIElementSetMessagingTimeout(system.as_ptr(), MESSAGING_TIMEOUT.as_secs_f32())
        };
        if status == K_AX_ERROR_SUCCESS {
            tracing::debug!(
                timeout_ms = MESSAGING_TIMEOUT.as_millis(),
                "set process-wide AX messaging timeout"
            );
        } else {
            tracing::warn!(
                status,
                "AXUIElementSetMessagingTimeout failed; keeping the default"
            );
        }
    });
}

fn unavailable(reason: String) -> WayboundError {
    WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason,
    }
}

/// Validates `pid` and permission, and creates the application element.
fn app_element(pid: i32) -> Result<OwnedCf> {
    if pid <= 0 {
        return Err(unavailable(format!("invalid target pid: {pid}")));
    }
    if !is_accessibility_trusted() {
        return Err(unavailable(
            "macOS Accessibility permission not granted (enable in System Settings > Privacy & Security > Accessibility)".to_owned(),
        ));
    }
    ensure_messaging_timeout();
    // SAFETY: `AXUIElementCreateApplication` returns a `+1` retained `AXUIElementRef` or null.
    unsafe { OwnedCf::from_owned(AXUIElementCreateApplication(pid)) }
        .ok_or_else(|| unavailable(format!("failed to create AXUIElement for pid {pid}")))
}

const FRONTMOST_POLL: Duration = Duration::from_millis(25);
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
    let app = app_element(pid)?;

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

/// Per-driver Accessibility state: the application flags the driver keeps on (restored when the
/// driver is dropped) and the warning rate limit.
#[derive(Debug)]
pub struct AxState {
    pid: i32,
    flags: Mutex<[FlagState; 2]>,
    warnings: Mutex<WarnGate>,
}

impl AxState {
    /// State for the browser process `pid`; nothing is changed until the first AX operation.
    #[must_use]
    pub const fn new(pid: i32) -> Self {
        Self {
            pid,
            flags: Mutex::new([FlagState::new(), FlagState::new()]),
            warnings: Mutex::new(WarnGate::new()),
        }
    }

    /// Whether a warning with `key` may be logged now (rate limit, see [`WarnGate`]).
    fn warn_allowed(&self, key: &str) -> bool {
        self.warnings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .should_warn(key, Instant::now())
    }

    /// Reads `AXEnhancedUserInterface` / `AXManualAccessibility` (one batched message) and turns
    /// on whichever is off, so accessibility comes back after a slow startup or after another
    /// client turned it off. The flags mutex is never held across an AX call.
    fn ensure_enhanced_ui(&self, app: &OwnedCf, tree: &CfTree, budget: &mut Budget<SystemClock>) {
        let (observed, unanswered) = tree.read_flags(app);
        if unanswered {
            // Count it towards the operation's streak; the walk itself decides when to stop.
            let _streak = budget.settle(Outcome::<()>::Unresponsive);
        }

        let now = Instant::now();
        let mut planned = [false; 2];
        {
            let mut flags = self.flags.lock().unwrap_or_else(PoisonError::into_inner);
            for ((flag, value), plan) in flags.iter_mut().zip(observed).zip(&mut planned) {
                *plan = flag.plan(value, now);
            }
        }

        let mut results: [Option<SetResult>; 2] = [None; 2];
        for (((plan, key), attr), result) in planned
            .iter()
            .zip(&tree.flag_keys)
            .zip(ENHANCED_UI_ATTRS)
            .zip(&mut results)
        {
            if !plan {
                continue;
            }
            // SAFETY: `app` and `key` are valid retained CF objects, and `kCFBooleanTrue` is a
            // global CF constant.
            let status =
                unsafe { AXUIElementSetAttributeValue(app.as_ptr(), key.as_ptr(), kCFBooleanTrue) };
            *result = Some(set_result(status));
            tracing::debug!(
                pid = self.pid,
                attr,
                status,
                "turned AX flag on for target application"
            );
        }

        if results.iter().any(Option::is_some) {
            let now = Instant::now();
            let mut flags = self.flags.lock().unwrap_or_else(PoisonError::into_inner);
            for (flag, result) in flags.iter_mut().zip(results) {
                if let Some(result) = result {
                    flag.record_set(result, now);
                }
            }
        }
    }
}

impl Drop for AxState {
    /// Turns back off the flags this driver turned on (best effort). This runs on a normal
    /// shutdown; it cannot run if the daemon is killed with `SIGKILL` or crashes.
    fn drop(&mut self) {
        let flags = *self.flags.get_mut().unwrap_or_else(PoisonError::into_inner);
        if flags.iter().all(|f| f.restore_value().is_none()) || self.pid <= 0 {
            return;
        }
        // SAFETY: `AXUIElementCreateApplication` returns a `+1` retained `AXUIElementRef` or null.
        let Some(app) = (unsafe { OwnedCf::from_owned(AXUIElementCreateApplication(self.pid)) })
        else {
            return;
        };
        for (flag, attr) in flags.iter().zip(ENHANCED_UI_ATTRS) {
            let Some(value) = flag.restore_value() else {
                continue;
            };
            let Some(key) = cf_string(attr) else {
                continue;
            };
            // SAFETY: reading the global CF boolean constants.
            let cf_value = unsafe {
                if value {
                    kCFBooleanTrue
                } else {
                    kCFBooleanFalse
                }
            };
            // SAFETY: `app` and `key` are valid retained CF objects and `cf_value` is a global
            // CF constant. Best effort: the browser may already have exited.
            let status =
                unsafe { AXUIElementSetAttributeValue(app.as_ptr(), key.as_ptr(), cf_value) };
            let prior = flag.prior();
            tracing::debug!(
                pid = self.pid,
                attr,
                value,
                ?prior,
                status,
                "restored AX flag on target application"
            );
        }
    }
}

/// Runs one bounded Accessibility operation against `pid`.
fn run<T>(
    pid: i32,
    state: &AxState,
    f: impl FnOnce(
        &mut CfTree,
        &OwnedCf,
        &mut Budget<SystemClock>,
    ) -> std::result::Result<T, ApiDisabled>,
) -> Result<T> {
    let app = app_element(pid)?;
    let mut tree = CfTree::new()
        .ok_or_else(|| unavailable("failed to allocate AX attribute names".to_owned()))?;
    let mut budget = Budget::new(SystemClock, OPERATION_DEADLINE, MAX_UNRESPONSIVE_STREAK);
    state.ensure_enhanced_ui(&app, &tree, &mut budget);
    f(&mut tree, &app, &mut budget).map_err(|ApiDisabled| api_disabled_error())
}

fn locate_web_area(
    pid: i32,
    state: &AxState,
    tree: &mut CfTree,
    app: &OwnedCf,
    budget: &mut Budget<SystemClock>,
) -> std::result::Result<WebAreaSearch<OwnedCf>, ApiDisabled> {
    let search = find_web_area(tree, app, &WEB_AREA_SEARCH, budget)?;
    let search_stats = search.stats;
    if search_stats.truncated || search_stats.unanswered || search_stats.stopped_by.is_some() {
        let key = format!(
            "search:{:?}:{}:{}:{}",
            search_stats.stopped_by,
            search_stats.truncated,
            search_stats.unanswered,
            search.web_area.is_some()
        );
        if state.warn_allowed(&key) {
            tracing::warn!(
                pid,
                visited = search_stats.visited,
                windows = search_stats.roots,
                stopped_by = ?search_stats.stopped_by,
                limits_hit = search_stats.truncated,
                unanswered = search_stats.unanswered,
                found = search.web_area.is_some(),
                max_visited = WEB_AREA_SEARCH.visited,
                max_depth = WEB_AREA_SEARCH.depth,
                "AXWebArea search ended early; using the best web area found so far (if any)"
            );
        }
    }
    tracing::trace!(
        pid,
        candidates = search.candidates,
        url = ?search.web_area.as_ref().and_then(|c| c.url.as_deref()),
        "selected AXWebArea"
    );
    Ok(search)
}

/// Captures a bounded snapshot of the web-content (`AXWebArea`) accessibility tree for `pid`,
/// with [`SNAPSHOT_LIMITS`].
///
/// Scopes traversal to `AXWebArea` so browser chrome (tabs, toolbar, address bar)
/// does not pollute semantic web locators. A slow or hung browser yields a partial or empty
/// tree (with a rate-limited warning), never an error.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing,
/// the Accessibility API is disabled, or the application element cannot be created.
pub fn snapshot_application_tree(pid: i32, state: &AxState) -> Result<Vec<AccessibilityNode>> {
    snapshot(pid, state, &SNAPSHOT_LIMITS, false).map(|s| s.nodes)
}

/// Captures up to `max_nodes` accessibility nodes for `pid` (clamped to the protocol's
/// `1..=20_000`), reporting in [`TreeSnapshot::truncated`] whether elements may be missing:
/// the node or visit cap was reached, the depth limit cut children, the deadline passed, the
/// browser stopped answering, or an element could not be read.
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing,
/// the Accessibility API is disabled, or the application element cannot be created.
pub fn snapshot_application_tree_limited(
    pid: i32,
    state: &AxState,
    max_nodes: usize,
) -> Result<TreeSnapshot> {
    snapshot(pid, state, &WalkLimits::for_max_nodes(max_nodes), true)
}

/// Shared snapshot implementation. `caller_capped` marks a node cap chosen by the client, whose
/// truncation is expected and therefore only logged at debug level.
fn snapshot(
    pid: i32,
    state: &AxState,
    limits: &WalkLimits,
    caller_capped: bool,
) -> Result<TreeSnapshot> {
    run(pid, state, |tree, app, budget| {
        let search = locate_web_area(pid, state, tree, app, budget)?;
        let Some(web_area) = search.web_area else {
            tracing::debug!(pid, stopped_by = ?search.stats.stopped_by, "AXWebArea not yet present in browser window");
            // Not found in time is "maybe missing"; simply absent (page loading) is not.
            let truncated = search.stats.stopped_by.is_some() || search.stats.unanswered;
            return Ok(TreeSnapshot {
                nodes: Vec::new(),
                truncated,
            });
        };
        let walk = walk_tree(tree, web_area.elem, limits, budget)?;
        let t = walk.truncation;
        let expected = caller_capped
            && t.stopped_by == Some(Limit::Nodes)
            && t.depth_cut == 0
            && t.partial == 0
            && t.skipped == 0;
        if t.is_truncated() {
            if !expected && state.warn_allowed(&t.warn_key()) {
                tracing::warn!(
                    pid,
                    visited = walk.visited,
                    captured = walk.nodes.len(),
                    stopped_by = ?t.stopped_by,
                    unvisited_subtrees = t.unvisited,
                    depth_cut_children = t.depth_cut,
                    partial_nodes = t.partial,
                    skipped_elements = t.skipped,
                    max_nodes = limits.nodes,
                    max_visited = limits.visited,
                    max_depth = limits.depth,
                    "macos AXWebArea snapshot incomplete; missing elements cannot be located until a later snapshot reaches them"
                );
            } else {
                tracing::debug!(pid, stopped_by = ?t.stopped_by, unvisited = t.unvisited, partial = t.partial, skipped = t.skipped, "macos AXWebArea snapshot incomplete");
            }
        }
        tracing::debug!(
            pid,
            visited = walk.visited,
            captured = walk.nodes.len(),
            truncated = t.truncated(),
            reads = budget.reads(),
            "macos AXWebArea snapshot complete"
        );
        Ok(TreeSnapshot {
            nodes: walk.nodes,
            truncated: t.truncated(),
        })
    })
}

/// Reads the active tab's URL from `AXWebArea`'s `AXURL` attribute (`None` if no web area was
/// found in time).
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing or the
/// Accessibility API is disabled.
pub fn read_current_url(pid: i32, state: &AxState) -> Result<Option<String>> {
    run(pid, state, |tree, app, budget| {
        Ok(locate_web_area(pid, state, tree, app, budget)?
            .web_area
            .and_then(|c| c.url))
    })
}

/// Reads the visible screen-space bounding rectangle of `AXWebArea` (`None` if no visible web
/// area was found in time).
///
/// # Errors
///
/// Returns [`WayboundError::BackendUnavailable`] if Accessibility permissions are missing or the
/// Accessibility API is disabled.
pub fn read_viewport_bounds(pid: i32, state: &AxState) -> Result<Option<Bounds>> {
    run(pid, state, |tree, app, budget| {
        Ok(locate_web_area(pid, state, tree, app, budget)?
            .web_area
            .filter(Candidate::visible)
            .map(|c| c.bounds))
    })
}

fn copy_attr(element: &OwnedCf, attr_name: &str) -> Option<OwnedCf> {
    copy_attr_status(element, &cf_string(attr_name)?)
        .ok()
        .flatten()
}

/// Copies one attribute value, returning the `AXError` code on failure.
fn copy_attr_status(element: &OwnedCf, key: &OwnedCf) -> std::result::Result<Option<OwnedCf>, i32> {
    let mut out = ptr::null();
    // SAFETY: `element` and `key` are valid retained CoreFoundation references, and `out` receives a `+1` ref on success.
    unsafe {
        let status = AXUIElementCopyAttributeValue(element.as_ptr(), key.as_ptr(), &raw mut out);
        if status != K_AX_ERROR_SUCCESS {
            return Err(status);
        }
        Ok(OwnedCf::from_owned(out))
    }
}

/// A C type that `AXValueGetValue` writes for one `AXValueType`.
///
/// # Safety
///
/// Implementors must have exactly the size and layout of the C type `AXValueGetValue` writes
/// for [`AxValuePayload::VALUE_TYPE`], so writing it into a `Self` is sound.
unsafe trait AxValuePayload: Default {
    /// The matching `AXValueType` constant.
    const VALUE_TYPE: u32;
}

// SAFETY: `CgPoint` is `#[repr(C)]` with two `f64`s, the layout of `CGPoint` (two 64-bit
// `CGFloat`s) that `kAXValueTypeCGPoint` wraps.
unsafe impl AxValuePayload for CgPoint {
    const VALUE_TYPE: u32 = K_AX_VALUE_TYPE_CG_POINT;
}

// SAFETY: `CgSize` is `#[repr(C)]` with two `f64`s, the layout of `CGSize` that
// `kAXValueTypeCGSize` wraps.
unsafe impl AxValuePayload for CgSize {
    const VALUE_TYPE: u32 = K_AX_VALUE_TYPE_CG_SIZE;
}

/// The `AXError` (`SInt32`) wrapped by an `AXValue` of type `kAXValueTypeAXError`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
struct AxErrorCode(i32);

// SAFETY: `AxErrorCode` is a transparent `i32`, the layout of `AXError` (`SInt32`) that
// `kAXValueTypeAXError` wraps.
unsafe impl AxValuePayload for AxErrorCode {
    const VALUE_TYPE: u32 = K_AX_VALUE_TYPE_AX_ERROR;
}

/// Extracts a `T` from an `AXValue` whose type is `T::VALUE_TYPE`.
fn ax_value<T: AxValuePayload>(value: &OwnedCf) -> Option<T> {
    let mut out = T::default();
    // SAFETY: `value` is a live CF object; its type ID is checked to be `AXValue` and its
    // `AXValueType` to be `T::VALUE_TYPE` before `AXValueGetValue` writes one value of that
    // type, which `AxValuePayload` guarantees has the layout of `T`.
    let ok = unsafe {
        CFGetTypeID(value.as_ptr()) == AXValueGetTypeID()
            && AXValueGetType(value.as_ptr()) == T::VALUE_TYPE
            && AXValueGetValue(
                value.as_ptr(),
                T::VALUE_TYPE,
                (&raw mut out).cast::<c_void>(),
            ) != 0
    };
    ok.then_some(out)
}

/// Classifies one entry of a `AXUIElementCopyMultipleAttributeValues` result.
fn slot_of(value: Option<OwnedCf>) -> Slot<OwnedCf> {
    let Some(value) = value else {
        return Slot::Missing;
    };
    // SAFETY: `value` is a live CF object; `CFNullGetTypeID` takes no arguments.
    if unsafe { CFGetTypeID(value.as_ptr()) == CFNullGetTypeID() } {
        return Slot::Missing;
    }
    if let Some(AxErrorCode(code)) = ax_value::<AxErrorCode>(&value) {
        return Slot::Error(code);
    }
    Slot::Value(value)
}

impl SlotValue for OwnedCf {
    type Elem = Self;

    fn string(&self) -> Option<String> {
        cf_to_string(self)
    }

    fn boolean(&self) -> Option<bool> {
        cf_to_bool(self)
    }

    fn integer(&self) -> Option<i64> {
        cf_to_i64(self)
    }

    fn point(&self) -> Option<(f64, f64)> {
        ax_value::<CgPoint>(self).map(|p| (p.x, p.y))
    }

    fn size(&self) -> Option<(f64, f64)> {
        ax_value::<CgSize>(self).map(|s| (s.width, s.height))
    }

    fn url(&self) -> Option<String> {
        cf_to_url_string(self)
    }

    fn elements(&self) -> Option<Vec<Self>> {
        // SAFETY: `AXUIElementGetTypeID` takes no arguments.
        let ax_type_id = unsafe { AXUIElementGetTypeID() };
        let items = cf_array_items(self)?;
        Some(
            items
                .into_iter()
                .flatten()
                // SAFETY: each item is a live, retained CF object.
                .filter(|item| unsafe { CFGetTypeID(item.as_ptr()) } == ax_type_id)
                .collect(),
        )
    }
}

/// Attribute names read together, built once per operation.
struct AttrNames {
    /// One `CFString` per attribute, in request order (used by per-attribute reads).
    keys: Vec<OwnedCf>,
    /// The same strings in a `CFArray` for the batched call.
    array: OwnedCf,
}

impl AttrNames {
    fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        let keys = names
            .into_iter()
            .map(cf_string)
            .collect::<Option<Vec<_>>>()?;
        let array = cf_array(&keys)?;
        Some(Self { keys, array })
    }

    fn for_set(set: AttrSet) -> Option<Self> {
        Self::new(set.attrs().iter().map(|a| a.name()))
    }
}

/// Reads the attributes named by `names` from `elem` in one batched message, falling back to one
/// message per attribute when the batched call itself is refused. `Err` carries the outcome when
/// the element is gone, unanswered, or the API is disabled.
fn read_slots(
    elem: &OwnedCf,
    names: &AttrNames,
) -> std::result::Result<Vec<Slot<OwnedCf>>, Outcome<()>> {
    let mut raw = ptr::null();
    // SAFETY: `elem` is a live `AXUIElementRef` and `names.array` a live `CFArray` of
    // `CFString`s. Options = 0 (not `kAXCopyMultipleAttributeOptionStopOnError`), so every
    // attribute gets a slot. On success `raw` receives a `+1` retained `CFArray`.
    let code = unsafe {
        AXUIElementCopyMultipleAttributeValues(elem.as_ptr(), names.array.as_ptr(), 0, &raw mut raw)
    };
    match after_batch(code) {
        BatchNext::Decode => {
            // SAFETY: the call succeeded, so `raw` is null or a `+1` `CFArray` we now own.
            let values = unsafe { OwnedCf::from_owned(raw) };
            match values.as_ref().and_then(cf_array_items) {
                Some(items) if items.len() == names.keys.len() => {
                    Ok(items.into_iter().map(slot_of).collect())
                }
                other => {
                    tracing::debug!(
                        returned = other.map(|v| v.len()),
                        requested = names.keys.len(),
                        "batched AX read returned an unexpected array; reading one by one"
                    );
                    read_slots_each(elem, names)
                }
            }
        }
        BatchNext::PerAttribute => {
            tracing::trace!(
                code,
                "batched AX read refused; reading attributes one by one"
            );
            read_slots_each(elem, names)
        }
        BatchNext::Stop(outcome) => Err(outcome),
    }
}

/// Reads the attributes named by `names` from `elem` one message at a time.
fn read_slots_each(
    elem: &OwnedCf,
    names: &AttrNames,
) -> std::result::Result<Vec<Slot<OwnedCf>>, Outcome<()>> {
    let mut slots = Vec::with_capacity(names.keys.len());
    for key in &names.keys {
        match copy_attr_status(elem, key) {
            Ok(value) => slots.push(slot_of(value)),
            Err(code) => match classify_ax_error(code) {
                AxStatus::Unresponsive => return Err(Outcome::Unresponsive),
                AxStatus::ApiDisabled => return Err(Outcome::ApiDisabled),
                AxStatus::Gone => return Err(Outcome::Gone),
                AxStatus::Success | AxStatus::Absent => slots.push(Slot::Error(code)),
            },
        }
    }
    Ok(slots)
}

const fn retype<T>(outcome: &Outcome<()>) -> Outcome<T> {
    match outcome {
        Outcome::Ok(()) | Outcome::Gone => Outcome::Gone,
        Outcome::Unresponsive => Outcome::Unresponsive,
        Outcome::ApiDisabled => Outcome::ApiDisabled,
    }
}

/// The live Accessibility tree as an [`AxSource`].
struct CfTree {
    names: [AttrNames; ATTR_SETS],
    flags: AttrNames,
    flag_keys: Vec<OwnedCf>,
    expanded_key: OwnedCf,
}

impl CfTree {
    fn new() -> Option<Self> {
        let flags = AttrNames::new(ENHANCED_UI_ATTRS)?;
        Some(Self {
            names: [
                AttrNames::for_set(AttrSet::Node)?,
                AttrNames::for_set(AttrSet::Probe)?,
                AttrNames::for_set(AttrSet::Minimal)?,
            ],
            flag_keys: flags.keys.clone(),
            flags,
            expanded_key: cf_string("AXExpanded")?,
        })
    }

    fn names(&self, set: AttrSet) -> Option<&AttrNames> {
        self.names.get(set.index())
    }

    /// Reads both application flags in one message. The `bool` is `true` if the browser did not
    /// answer.
    fn read_flags(&self, app: &OwnedCf) -> ([FlagValue; 2], bool) {
        match read_slots(app, &self.flags) {
            Ok(slots) => {
                let mut values = [FlagValue::Unreadable; 2];
                for (value, slot) in values.iter_mut().zip(&slots) {
                    *value = flag_value(slot);
                }
                (values, false)
            }
            Err(outcome) => (
                [FlagValue::Unreadable; 2],
                matches!(outcome, Outcome::Unresponsive),
            ),
        }
    }

    fn decode(
        set: AttrSet,
        slots: std::result::Result<Vec<Slot<OwnedCf>>, Outcome<()>>,
    ) -> Outcome<NodeAttrs<OwnedCf>> {
        match slots {
            Ok(slots) => decode_slots(set.attrs(), &slots).map_or(Outcome::Gone, Outcome::Ok),
            Err(outcome) => retype(&outcome),
        }
    }
}

impl AxSource for CfTree {
    type Elem = OwnedCf;

    fn read(&mut self, elem: &OwnedCf, set: AttrSet) -> Outcome<NodeAttrs<OwnedCf>> {
        let Some(names) = self.names(set) else {
            return Outcome::Gone;
        };
        Self::decode(set, read_slots(elem, names))
    }

    fn read_each(&mut self, elem: &OwnedCf, set: AttrSet) -> Outcome<NodeAttrs<OwnedCf>> {
        let Some(names) = self.names(set) else {
            return Outcome::Gone;
        };
        Self::decode(set, read_slots_each(elem, names))
    }

    fn advertises_expanded(&mut self, elem: &OwnedCf) -> Outcome<bool> {
        let mut raw_names = ptr::null();
        // SAFETY: `elem` is a valid retained `AXUIElementRef`; on success `raw_names` receives a
        // `+1` retained `CFArrayRef` whose ownership is transferred to `OwnedCf`.
        let code = unsafe { AXUIElementCopyAttributeNames(elem.as_ptr(), &raw mut raw_names) };
        if code != K_AX_ERROR_SUCCESS {
            return match classify_ax_error(code) {
                AxStatus::Unresponsive => Outcome::Unresponsive,
                AxStatus::ApiDisabled => Outcome::ApiDisabled,
                _ => Outcome::Ok(false),
            };
        }
        // SAFETY: see above; the call succeeded.
        let names = unsafe { OwnedCf::from_owned(raw_names) };
        let key = &self.expanded_key;
        let found = names
            .as_ref()
            .and_then(cf_array_items)
            .is_some_and(|items| {
                items.iter().flatten().any(|item| {
                    // SAFETY: both are live CF objects.
                    unsafe { CFEqual(item.as_ptr(), key.as_ptr()) != 0 }
                })
            });
        Outcome::Ok(found)
    }

    fn windows(&mut self, app: &OwnedCf, which: WindowAttr) -> Outcome<Vec<OwnedCf>> {
        let Some(key) = cf_string(which.name()) else {
            return Outcome::Ok(Vec::new());
        };
        match copy_attr_status(app, &key) {
            Ok(None) => Outcome::Ok(Vec::new()),
            Ok(Some(value)) => {
                let elems = match which {
                    WindowAttr::All => value.elements().unwrap_or_default(),
                    WindowAttr::Focused | WindowAttr::Main => {
                        // SAFETY: `value` is a live CF object; `AXUIElementGetTypeID` takes no arguments.
                        let is_elem =
                            unsafe { CFGetTypeID(value.as_ptr()) == AXUIElementGetTypeID() };
                        if is_elem { vec![value] } else { Vec::new() }
                    }
                };
                Outcome::Ok(elems)
            }
            Err(code) => match classify_ax_error(code) {
                AxStatus::Unresponsive => Outcome::Unresponsive,
                AxStatus::ApiDisabled => Outcome::ApiDisabled,
                _ => Outcome::Ok(Vec::new()),
            },
        }
    }

    fn same_element(&self, a: &OwnedCf, b: &OwnedCf) -> bool {
        // SAFETY: both are live CF objects.
        unsafe { CFEqual(a.as_ptr(), b.as_ptr()) != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{AXValueCreate, kCFNull};
    use crate::tree::{AX_ERROR_ATTRIBUTE_UNSUPPORTED, AX_ERROR_NO_VALUE, Attr, NODE_ATTRS};

    fn ax_value_of<T: AxValuePayload>(value: &T) -> Option<OwnedCf> {
        // SAFETY: `value` points to a live `T`, whose layout matches `T::VALUE_TYPE`
        // (`AxValuePayload`); `AXValueCreate` copies it and returns a `+1` retained `AXValue`
        // (or null).
        unsafe {
            OwnedCf::from_owned(AXValueCreate(
                T::VALUE_TYPE,
                ptr::from_ref(value).cast::<c_void>(),
            ))
        }
    }

    fn cf_null() -> Option<OwnedCf> {
        // SAFETY: `kCFNull` is a live global singleton; `retain` takes an extra reference.
        unsafe { OwnedCf::retain(kCFNull) }
    }

    fn cf_bool(value: bool) -> Option<OwnedCf> {
        // SAFETY: the CF boolean constants are live global singletons; `retain` takes an extra
        // reference.
        unsafe {
            OwnedCf::retain(if value {
                kCFBooleanTrue
            } else {
                kCFBooleanFalse
            })
        }
    }

    #[test]
    fn error_values_and_null_are_absent_slots() {
        assert!(matches!(
            slot_of(ax_value_of(&AxErrorCode(AX_ERROR_NO_VALUE))),
            Slot::Error(-25_212)
        ));
        assert!(matches!(slot_of(cf_null()), Slot::Missing));
        assert!(matches!(slot_of(None), Slot::Missing));
        assert!(matches!(slot_of(cf_string("AXButton")), Slot::Value(_)));
        // A CGPoint AXValue is a value, not an error.
        let point = CgPoint { x: 1.0, y: 2.0 };
        assert!(matches!(slot_of(ax_value_of(&point)), Slot::Value(_)));
    }

    #[test]
    fn real_cf_values_decode_like_a_batched_result() {
        // The array `AXUIElementCopyMultipleAttributeValues` would return for NODE_ATTRS with
        // options = 0, built from real CF objects (no Accessibility permission needed).
        let error = || ax_value_of(&AxErrorCode(AX_ERROR_ATTRIBUTE_UNSUPPORTED));
        let point = CgPoint { x: 10.0, y: 20.0 };
        let size = CgSize {
            width: 30.0,
            height: 40.0,
        };
        let owned: Vec<OwnedCf> = NODE_ATTRS
            .iter()
            .filter_map(|attr| match attr {
                Attr::Role => cf_string("AXStaticText"),
                Attr::Value => cf_string("Total: $419"),
                Attr::Position => ax_value_of(&point),
                Attr::Size => ax_value_of(&size),
                Attr::Title => cf_null(),
                Attr::Focused => cf_bool(true),
                _ => error(),
            })
            .collect();
        assert_eq!(owned.len(), NODE_ATTRS.len());
        let array = cf_array(&owned);
        let slots: Vec<Slot<OwnedCf>> = array
            .as_ref()
            .and_then(cf_array_items)
            .unwrap_or_default()
            .into_iter()
            .map(slot_of)
            .collect();
        let decoded = decode_slots(NODE_ATTRS, &slots);
        assert_eq!(
            decoded.map(|a| (
                a.role,
                a.title,
                a.value_text,
                a.position,
                a.size,
                a.focused,
                a.children.is_some()
            )),
            Ok((
                Some("AXStaticText".to_owned()),
                None,
                Some("Total: $419".to_owned()),
                Some((10.0, 20.0)),
                Some((30.0, 40.0)),
                Some(true),
                false
            ))
        );
    }

    #[test]
    fn real_cf_flag_values_decode() {
        assert_eq!(flag_value(&slot_of(cf_bool(true))), FlagValue::On);
        assert_eq!(flag_value(&slot_of(cf_bool(false))), FlagValue::Off);
        assert_eq!(flag_value(&slot_of(cf_null())), FlagValue::Absent);
        assert_eq!(
            flag_value(&slot_of(ax_value_of(&AxErrorCode(
                crate::tree::AX_ERROR_CANNOT_COMPLETE
            )))),
            FlagValue::Unreadable
        );
    }

    #[test]
    fn ax_value_rejects_mismatched_types() {
        let value = ax_value_of(&CgPoint { x: 1.0, y: 2.0 });
        assert!(value.as_ref().is_some_and(|v| v.size().is_none()));
        assert!(
            value
                .as_ref()
                .is_some_and(|v| ax_value::<AxErrorCode>(v).is_none())
        );
        assert_eq!(value.as_ref().and_then(SlotValue::point), Some((1.0, 2.0)));
        assert!(cf_string("x").as_ref().and_then(SlotValue::point).is_none());
    }

    #[test]
    fn attribute_name_arrays_are_built_once_per_set() {
        let tree = CfTree::new();
        assert!(tree.is_some());
        let lens: Option<Vec<usize>> = tree.as_ref().map(|t| {
            t.names
                .iter()
                .chain(std::iter::once(&t.flags))
                .map(|n| cf_array_items(&n.array).map_or(0, |v| v.len()))
                .collect()
        });
        assert_eq!(
            lens,
            Some(vec![
                AttrSet::Node.attrs().len(),
                AttrSet::Probe.attrs().len(),
                AttrSet::Minimal.attrs().len(),
                ENHANCED_UI_ATTRS.len(),
            ])
        );
    }
}
