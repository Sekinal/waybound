//! Platform-independent accessibility-tree logic for the macOS driver.
//!
//! Everything in this module is pure: it never calls the Accessibility API. `ax.rs` implements
//! [`AxSource`] on top of `AXUIElement` and feeds real elements through the functions here, while
//! the unit tests below drive the same code with a fake tree and an injected clock. This keeps the
//! policy (batched attribute decoding, traversal limits and truncation accounting, the messaging
//! failure / deadline budget, and `AXWebArea` selection) testable without Accessibility permission.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use waybound_core::{AccessibilityNode, Bounds, MAX_MAX_NODES, MIN_MAX_NODES, Role, WayboundError};

// ---------------------------------------------------------------------------------------------
// AXError classification (values from HIServices `AXError.h`).
// ---------------------------------------------------------------------------------------------

/// `kAXErrorSuccess`.
pub const AX_ERROR_SUCCESS: i32 = 0;
/// `kAXErrorInvalidUIElement`: the element no longer exists.
pub const AX_ERROR_INVALID_UI_ELEMENT: i32 = -25_202;
/// `kAXErrorCannotComplete`: messaging failed, which includes the messaging timeout elapsing.
pub const AX_ERROR_CANNOT_COMPLETE: i32 = -25_204;
/// `kAXErrorAttributeUnsupported`.
#[cfg(test)]
pub const AX_ERROR_ATTRIBUTE_UNSUPPORTED: i32 = -25_205;
/// `kAXErrorAPIDisabled`: assistive applications are not enabled for this process.
pub const AX_ERROR_API_DISABLED: i32 = -25_211;
/// `kAXErrorNoValue`.
#[cfg(test)]
pub const AX_ERROR_NO_VALUE: i32 = -25_212;

/// What an `AXError` result means for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxStatus {
    /// The call succeeded.
    Success,
    /// The attribute is unsupported, has no value, or the call failed for this element only:
    /// treat the value as absent (the historical behaviour of every read in this driver).
    Absent,
    /// The element was destroyed (for example a node removed while the page re-rendered).
    Gone,
    /// The target application did not answer within the messaging timeout, or messaging failed.
    Unresponsive,
    /// The Accessibility API is disabled for this process (permission revoked).
    ApiDisabled,
}

/// Classifies an `AXError` code returned by an `AXUIElement*` function.
#[must_use]
pub const fn classify_ax_error(code: i32) -> AxStatus {
    match code {
        AX_ERROR_SUCCESS => AxStatus::Success,
        AX_ERROR_CANNOT_COMPLETE => AxStatus::Unresponsive,
        AX_ERROR_API_DISABLED => AxStatus::ApiDisabled,
        AX_ERROR_INVALID_UI_ELEMENT => AxStatus::Gone,
        _ => AxStatus::Absent,
    }
}

/// The result of one accessibility read, as seen by the traversal code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    /// The read succeeded.
    Ok(T),
    /// The element is gone; skip it (and its subtree) without penalising the application.
    Gone,
    /// The application did not answer within the messaging timeout.
    Unresponsive,
    /// The Accessibility API is disabled for this process.
    ApiDisabled,
}

/// Maps a failed (non-success) `AXError` to an [`Outcome`] for a call whose result cannot be
/// treated as "absent" (for example a whole batched read).
#[must_use]
pub const fn failure_outcome<T>(code: i32) -> Option<Outcome<T>> {
    match classify_ax_error(code) {
        AxStatus::Unresponsive => Some(Outcome::Unresponsive),
        AxStatus::ApiDisabled => Some(Outcome::ApiDisabled),
        AxStatus::Gone => Some(Outcome::Gone),
        AxStatus::Success | AxStatus::Absent => None,
    }
}

/// What to do after `AXUIElementCopyMultipleAttributeValues` returned `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchNext {
    /// The call succeeded: decode the returned slots.
    Decode,
    /// The batched call itself failed for a reason specific to it (illegal argument, not
    /// implemented, ...): retry the element with one `AXUIElementCopyAttributeValue` per attribute.
    PerAttribute,
    /// Stop reading this element and report this outcome (no per-attribute retry: retrying a
    /// hung application would multiply the timeout by the number of attributes).
    Stop(Outcome<()>),
}

/// Decides how to continue after a batched attribute read returned `code`.
#[must_use]
pub const fn after_batch(code: i32) -> BatchNext {
    if code == AX_ERROR_SUCCESS {
        return BatchNext::Decode;
    }
    match failure_outcome(code) {
        Some(outcome) => BatchNext::Stop(outcome),
        None => BatchNext::PerAttribute,
    }
}

// ---------------------------------------------------------------------------------------------
// Attributes and batched decoding.
// ---------------------------------------------------------------------------------------------

/// An accessibility attribute read by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attr {
    /// `AXRole`.
    Role,
    /// `AXSubrole`.
    Subrole,
    /// `AXTitle`.
    Title,
    /// `AXDescription`.
    Description,
    /// `AXPlaceholderValue`.
    Placeholder,
    /// `AXValue`.
    Value,
    /// `AXPosition`.
    Position,
    /// `AXSize`.
    Size,
    /// `AXFocused`.
    Focused,
    /// `AXEnabled`.
    Enabled,
    /// `AXExpanded`.
    Expanded,
    /// `AXURL`.
    Url,
    /// `AXChildren`.
    Children,
}

impl Attr {
    /// The attribute's name as passed to the Accessibility API.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Role => "AXRole",
            Self::Subrole => "AXSubrole",
            Self::Title => "AXTitle",
            Self::Description => "AXDescription",
            Self::Placeholder => "AXPlaceholderValue",
            Self::Value => "AXValue",
            Self::Position => "AXPosition",
            Self::Size => "AXSize",
            Self::Focused => "AXFocused",
            Self::Enabled => "AXEnabled",
            Self::Expanded => "AXExpanded",
            Self::Url => "AXURL",
            Self::Children => "AXChildren",
        }
    }
}

/// A fixed list of attributes read together in one batched call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrSet {
    /// Everything a snapshot node needs.
    Node,
    /// What the `AXWebArea` search needs (role, geometry, URL, children).
    Probe,
    /// The minimum that keeps an element and its subtree in a snapshot (role, children), read
    /// attribute by attribute after a batched read of the element went unanswered.
    Minimal,
}

/// Attributes read for every node of a snapshot.
pub const NODE_ATTRS: &[Attr] = &[
    Attr::Role,
    Attr::Subrole,
    Attr::Title,
    Attr::Description,
    Attr::Placeholder,
    Attr::Value,
    Attr::Position,
    Attr::Size,
    Attr::Focused,
    Attr::Enabled,
    Attr::Expanded,
    Attr::Url,
    Attr::Children,
];

/// Attributes read for every element visited while searching for the page's `AXWebArea`.
pub const PROBE_ATTRS: &[Attr] = &[
    Attr::Role,
    Attr::Position,
    Attr::Size,
    Attr::Url,
    Attr::Children,
];

/// Attributes read one by one for an element whose batched read went unanswered.
pub const MINIMAL_ATTRS: &[Attr] = &[Attr::Role, Attr::Children];

/// Number of [`AttrSet`]s (size of per-set caches).
pub const ATTR_SETS: usize = 3;

impl AttrSet {
    /// The attributes in this set, in request order.
    #[must_use]
    pub const fn attrs(self) -> &'static [Attr] {
        match self {
            Self::Node => NODE_ATTRS,
            Self::Probe => PROBE_ATTRS,
            Self::Minimal => MINIMAL_ATTRS,
        }
    }

    /// Index of this set in per-set caches.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Node => 0,
            Self::Probe => 1,
            Self::Minimal => 2,
        }
    }
}

/// One position of the array returned by `AXUIElementCopyMultipleAttributeValues`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot<V> {
    /// A null entry or `kCFNull`: no value.
    Missing,
    /// An `AXValue` of type `kAXValueAXErrorType` carrying this `AXError`: no value.
    Error(i32),
    /// A real attribute value.
    Value(V),
}

/// Typed accessors over one attribute value (a `CFTypeRef` in production, a fake in tests).
///
/// Each accessor returns `None` when the value has a different runtime type, so a wrongly typed
/// value is treated exactly like an absent one.
pub trait SlotValue {
    /// The element type contained in `AXChildren`-style arrays.
    type Elem;
    /// The value as a string (`CFString`).
    fn string(&self) -> Option<String>;
    /// The value as a boolean (`CFBoolean`).
    fn boolean(&self) -> Option<bool>;
    /// The value as an integer (`CFNumber`).
    fn integer(&self) -> Option<i64>;
    /// The value as a point (`AXValue` of type `CGPoint`).
    fn point(&self) -> Option<(f64, f64)>;
    /// The value as a size (`AXValue` of type `CGSize`).
    fn size(&self) -> Option<(f64, f64)>;
    /// The value as a URL string (`CFURL` or `CFString`).
    fn url(&self) -> Option<String>;
    /// The value as an array of accessibility elements.
    fn elements(&self) -> Option<Vec<Self::Elem>>;
}

/// The decoded attributes of one element. `None` means absent (unsupported, no value, an error
/// slot, or a value of an unexpected type).
#[derive(Debug, Clone, PartialEq)]
pub struct NodeAttrs<E> {
    /// `AXRole`.
    pub role: Option<String>,
    /// `AXSubrole`.
    pub subrole: Option<String>,
    /// `AXTitle`.
    pub title: Option<String>,
    /// `AXDescription`.
    pub description: Option<String>,
    /// `AXPlaceholderValue`.
    pub placeholder: Option<String>,
    /// `AXValue` when it is a string.
    pub value_text: Option<String>,
    /// `AXValue` when it is a number (or a boolean, as `0` / `1`).
    pub value_number: Option<i64>,
    /// `AXPosition`.
    pub position: Option<(f64, f64)>,
    /// `AXSize`.
    pub size: Option<(f64, f64)>,
    /// `AXFocused`.
    pub focused: Option<bool>,
    /// `AXEnabled`.
    pub enabled: Option<bool>,
    /// `AXExpanded` (whether or not the element advertises it).
    pub expanded: Option<bool>,
    /// `AXURL`.
    pub url: Option<String>,
    /// `AXChildren`.
    pub children: Option<Vec<E>>,
}

impl<E> Default for NodeAttrs<E> {
    fn default() -> Self {
        Self {
            role: None,
            subrole: None,
            title: None,
            description: None,
            placeholder: None,
            value_text: None,
            value_number: None,
            position: None,
            size: None,
            focused: None,
            enabled: None,
            expanded: None,
            url: None,
            children: None,
        }
    }
}

/// The batched read returned a different number of values than attributes were requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthMismatch {
    /// Number of attributes requested.
    pub expected: usize,
    /// Number of values returned.
    pub actual: usize,
}

/// Decodes the values returned for `attrs` (one slot per attribute, in request order).
///
/// Missing entries and `kAXValueAXErrorType` error values are absent attributes, never values.
///
/// # Errors
///
/// Returns [`LengthMismatch`] if `slots` does not have exactly one entry per attribute, in which
/// case the positions cannot be trusted and the caller must fall back to per-attribute reads.
pub fn decode_slots<V: SlotValue>(
    attrs: &[Attr],
    slots: &[Slot<V>],
) -> Result<NodeAttrs<V::Elem>, LengthMismatch> {
    if attrs.len() != slots.len() {
        return Err(LengthMismatch {
            expected: attrs.len(),
            actual: slots.len(),
        });
    }
    let mut out = NodeAttrs::default();
    for (attr, slot) in attrs.iter().zip(slots) {
        let Slot::Value(v) = slot else {
            continue;
        };
        match attr {
            Attr::Role => out.role = v.string(),
            Attr::Subrole => out.subrole = v.string(),
            Attr::Title => out.title = v.string(),
            Attr::Description => out.description = v.string(),
            Attr::Placeholder => out.placeholder = v.string(),
            Attr::Value => {
                out.value_text = v.string();
                // Checkable controls report their state as a `CFNumber` (a `CFBoolean` on some
                // native switches).
                out.value_number = v.integer().or_else(|| v.boolean().map(i64::from));
            }
            Attr::Position => out.position = v.point(),
            Attr::Size => out.size = v.size(),
            Attr::Focused => out.focused = v.boolean(),
            Attr::Enabled => out.enabled = v.boolean(),
            Attr::Expanded => out.expanded = v.boolean(),
            Attr::Url => out.url = v.url(),
            Attr::Children => out.children = v.elements(),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Node construction.
// ---------------------------------------------------------------------------------------------

/// Maps a macOS `AXRole` / `AXSubrole` pair to a normalized [`Role`].
#[must_use]
pub fn map_ax_role(ax_role: &str, ax_subrole: Option<&str>) -> Role {
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

/// The normalized role of a decoded element. `AXSubrole` is only consulted for the roles whose
/// mapping depends on it.
#[must_use]
pub fn node_role<E>(attrs: &NodeAttrs<E>) -> Role {
    let role = attrs.role.as_deref().unwrap_or_default();
    let subrole = matches!(role, "AXCheckBox" | "AXRadioButton" | "AXGroup")
        .then_some(attrs.subrole.as_deref())
        .flatten();
    map_ax_role(role, subrole)
}

/// Picks the accessible name used by locators.
///
/// Chrome exposes the text of `AXStaticText` in `AXValue`, not in `AXTitle` or
/// `AXDescription`, so without this fallback plain page text has no name and can never
/// be matched by `get_by_text` / `get_by_role(StaticText, name=...)`.
#[must_use]
pub fn accessible_name(role: Role, name: Option<String>, value: Option<&str>) -> Option<String> {
    if name.is_none() && role == Role::StaticText {
        return value.map(str::to_owned);
    }
    name
}

fn non_empty(s: Option<&String>) -> Option<String> {
    s.filter(|s| !s.is_empty()).cloned()
}

/// The node's non-empty string `AXValue`.
fn node_value<E>(attrs: &NodeAttrs<E>) -> Option<String> {
    non_empty(attrs.value_text.as_ref())
}

/// The node's accessible name: the first non-empty of `AXTitle`, `AXDescription`,
/// `AXPlaceholderValue`, then the static-text `AXValue` fallback.
#[must_use]
pub fn node_name<E>(attrs: &NodeAttrs<E>, role: Role) -> Option<String> {
    let name = non_empty(attrs.title.as_ref())
        .or_else(|| non_empty(attrs.description.as_ref()))
        .or_else(|| non_empty(attrs.placeholder.as_ref()));
    accessible_name(role, name, node_value(attrs).as_deref())
}

/// Bounds from `AXPosition` and `AXSize`; all zero unless both are present.
#[must_use]
pub const fn bounds_of(position: Option<(f64, f64)>, size: Option<(f64, f64)>) -> Bounds {
    match (position, size) {
        (Some((x, y)), Some((width, height))) => Bounds {
            x,
            y,
            width,
            height,
        },
        _ => Bounds {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 0.0,
        },
    }
}

/// Maps a checkable role's numeric `AXValue` to the node's checked state.
///
/// `AXCheckBox`, `AXRadioButton`, switches, and Chromium's checkbox / radio menu items report
/// `0` (off), `1` (on), or `2` (mixed). Mixed is reported as `Some(false)` (not fully
/// checked). Other roles, and values that are missing or out of range, yield `None`, so a plain
/// menu item without a numeric value has no checked state.
#[must_use]
pub fn checked_from_ax_value(role: Role, raw: Option<i64>) -> Option<bool> {
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

/// Roles that are actionable controls, for which `AXEnabled` is reported.
///
/// Static text, headings, and containers are never reported disabled.
#[must_use]
pub const fn is_control(role: Role) -> bool {
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

/// How `AXExpanded` is interpreted for a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandProbe {
    /// The role is always expandable (combobox): use `AXExpanded` directly.
    Always,
    /// The role may be expandable (disclosure / menu buttons, links, menu and list items):
    /// use `AXExpanded` only when the element lists it in its attribute names, because
    /// Chromium answers `AXExpanded` for any control, which would report non-expandable ones
    /// as collapsed.
    IfAdvertised,
    /// Never expandable.
    Never,
}

/// The [`ExpandProbe`] policy for `role`.
#[must_use]
pub const fn expand_probe(role: Role) -> ExpandProbe {
    match role {
        Role::ComboBox => ExpandProbe::Always,
        Role::Button | Role::Link | Role::MenuItem | Role::ListItem | Role::Tab => {
            ExpandProbe::IfAdvertised
        }
        _ => ExpandProbe::Never,
    }
}

/// Whether building this node requires asking the element whether it advertises `AXExpanded`
/// (one extra `AXUIElementCopyAttributeNames` call, skipped when there is no value to vet).
#[must_use]
pub fn needs_expanded_advert<E>(role: Role, attrs: &NodeAttrs<E>) -> bool {
    expand_probe(role) == ExpandProbe::IfAdvertised && attrs.expanded.is_some()
}

/// The expanded state reported for a node.
#[must_use]
pub const fn expanded_state(role: Role, value: Option<bool>, advertised: bool) -> Option<bool> {
    match expand_probe(role) {
        ExpandProbe::Always => value,
        ExpandProbe::IfAdvertised if advertised => value,
        ExpandProbe::IfAdvertised | ExpandProbe::Never => None,
    }
}

/// Whether a node with this role and name is included in snapshots.
#[must_use]
pub const fn is_captured(role: Role, name: Option<&String>) -> bool {
    !matches!(role, Role::Unknown) || name.is_some()
}

/// Builds the snapshot node for a decoded element.
#[must_use]
pub fn make_node<E>(
    attrs: &NodeAttrs<E>,
    role: Role,
    name: Option<String>,
    index: usize,
    expanded_advertised: bool,
) -> AccessibilityNode {
    AccessibilityNode {
        id: format!("ax-{index}"),
        role,
        name,
        value: node_value(attrs),
        bounds: bounds_of(attrs.position, attrs.size),
        focused: attrs.focused.unwrap_or(false),
        checked: checked_from_ax_value(role, attrs.value_number),
        disabled: is_control(role) && attrs.enabled == Some(false),
        expanded: expanded_state(role, attrs.expanded, expanded_advertised),
        url: link_url(role, attrs.url.as_deref()),
    }
}

/// The `href` reported for a node: the trimmed, non-empty `AXURL` of links only (other roles,
/// such as the web area itself, never report one).
#[must_use]
pub fn link_url(role: Role, url: Option<&str>) -> Option<String> {
    if role != Role::Link {
        return None;
    }
    let trimmed = url?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

// ---------------------------------------------------------------------------------------------
// Time and failure budget.
// ---------------------------------------------------------------------------------------------

/// A monotonic clock, injectable for tests.
pub trait Clock {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Why an accessibility operation stopped early.
///
/// Only [`Abort::ApiDisabled`] becomes an error for the caller. The other two only stop the
/// operation from wasting more time: whatever was collected so far is returned (possibly
/// nothing), exactly as a slow browser produced a partial or empty tree before, so callers keep
/// polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    /// The operation's overall deadline passed.
    Deadline,
    /// Too many messages in a row went unanswered.
    Unresponsive,
    /// The Accessibility API is disabled for this process (permission missing or revoked).
    ApiDisabled,
}

/// The Accessibility API is disabled for this process: the one failure that never heals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiDisabled;

/// Converts an [`Abort`] into the [`Limit`] recorded for a partial result.
///
/// # Errors
///
/// Returns [`ApiDisabled`] for [`Abort::ApiDisabled`].
pub const fn stop_reason(abort: Abort) -> Result<Limit, ApiDisabled> {
    match abort {
        Abort::Deadline => Ok(Limit::Deadline),
        Abort::Unresponsive => Ok(Limit::Unresponsive),
        Abort::ApiDisabled => Err(ApiDisabled),
    }
}

/// Bounds one accessibility operation (a snapshot, a URL or viewport read) in time and in
/// consecutive unanswered messages, so a hung browser costs a few messaging timeouts instead of
/// one timeout per node.
#[derive(Debug)]
pub struct Budget<C> {
    clock: C,
    started: Instant,
    limit: Duration,
    max_streak: u32,
    streak: u32,
    reads: usize,
}

impl<C: Clock> Budget<C> {
    /// Starts a budget of `limit` from now, stopping after `max_streak` (at least 1) unanswered
    /// reads in a row.
    pub fn new(clock: C, limit: Duration, max_streak: u32) -> Self {
        let started = clock.now();
        Self {
            clock,
            started,
            limit,
            max_streak: max_streak.max(1),
            streak: 0,
            reads: 0,
        }
    }

    /// Reads accounted for so far.
    #[must_use]
    pub const fn reads(&self) -> usize {
        self.reads
    }

    /// Fails once the overall deadline has passed.
    ///
    /// # Errors
    ///
    /// Returns [`Abort::Deadline`] once `limit` has elapsed since the budget started.
    pub fn check(&self) -> Result<(), Abort> {
        if self.clock.now().saturating_duration_since(self.started) >= self.limit {
            return Err(Abort::Deadline);
        }
        Ok(())
    }

    /// Accounts for one read, returning its value (`None` if the element was gone or the read
    /// went unanswered).
    ///
    /// # Errors
    ///
    /// Returns [`Abort::Unresponsive`] once `max_streak` reads in a row went unanswered (and for
    /// every unanswered read after that), and [`Abort::ApiDisabled`] if the API is disabled.
    pub fn settle<T>(&mut self, outcome: Outcome<T>) -> Result<Option<T>, Abort> {
        self.reads += 1;
        match outcome {
            Outcome::Ok(v) => {
                self.streak = 0;
                Ok(Some(v))
            }
            Outcome::Gone => {
                self.streak = 0;
                Ok(None)
            }
            Outcome::Unresponsive => {
                self.streak += 1;
                if self.streak >= self.max_streak {
                    Err(Abort::Unresponsive)
                } else {
                    Ok(None)
                }
            }
            Outcome::ApiDisabled => Err(Abort::ApiDisabled),
        }
    }
}

/// The error returned when the Accessibility API is disabled for this process.
#[must_use]
pub fn api_disabled_error() -> WayboundError {
    WayboundError::BackendUnavailable {
        backend: "macos_native".to_owned(),
        reason: "the Accessibility API is disabled for this process (kAXErrorAPIDisabled); re-grant Accessibility permission in System Settings > Privacy & Security > Accessibility".to_owned(),
    }
}

// ---------------------------------------------------------------------------------------------
// Tree source and snapshot walk.
// ---------------------------------------------------------------------------------------------

/// Which window attribute of the application element to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowAttr {
    /// `AXFocusedWindow`.
    Focused,
    /// `AXMainWindow`.
    Main,
    /// `AXWindows`.
    All,
}

impl WindowAttr {
    /// The attribute's name as passed to the Accessibility API.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Focused => "AXFocusedWindow",
            Self::Main => "AXMainWindow",
            Self::All => "AXWindows",
        }
    }
}

/// An accessibility tree the traversal code can read.
pub trait AxSource {
    /// An element handle.
    type Elem: Clone;
    /// Reads the attributes of `set` from `elem` (one batched round trip when possible).
    fn read(&mut self, elem: &Self::Elem, set: AttrSet) -> Outcome<NodeAttrs<Self::Elem>>;
    /// Reads the attributes of `set` from `elem` one at a time (no batched call).
    fn read_each(&mut self, elem: &Self::Elem, set: AttrSet) -> Outcome<NodeAttrs<Self::Elem>>;
    /// Whether `elem` lists `AXExpanded` in its attribute names.
    fn advertises_expanded(&mut self, elem: &Self::Elem) -> Outcome<bool>;
    /// Reads window element(s) of the application element `app` (zero or one element for
    /// [`WindowAttr::Focused`] / [`WindowAttr::Main`]).
    fn windows(&mut self, app: &Self::Elem, which: WindowAttr) -> Outcome<Vec<Self::Elem>>;
    /// Whether two handles refer to the same accessibility element.
    fn same_element(&self, a: &Self::Elem, b: &Self::Elem) -> bool;
}

/// Traversal limits for a snapshot walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    /// Deepest level (root = 0) whose children are still visited.
    pub depth: usize,
    /// Maximum number of nodes captured into the snapshot.
    pub nodes: usize,
    /// Maximum number of elements read (captured or not).
    pub visited: usize,
}

/// Limits for snapshots of real pages.
///
/// Sized by round trips rather than by guesswork: a node now costs one batched read, plus one
/// `AXUIElementCopyAttributeNames` call for links / buttons / menu and list items / tabs that
/// report `AXExpanded`, so at most 2 round trips. The previous reader made about 10 per node
/// and stopped at 2,000 captured nodes, about 20,000 round trips. 10,000 visited elements is
/// also at most 20,000 round trips, so the new worst case costs no more messages than the old
/// cap did while reaching up to five times as many nodes. The operation deadline
/// ([`Budget`]) remains the effective cap on a slow browser, and returns the partial tree.
pub const SNAPSHOT_LIMITS: WalkLimits = WalkLimits {
    depth: 64,
    nodes: 5_000,
    visited: 10_000,
};

impl WalkLimits {
    /// Limits for a snapshot capped by the caller at `max_nodes` (clamped to
    /// `MIN_MAX_NODES..=MAX_MAX_NODES`, as the protocol does): the node cap is the caller's, and
    /// the visit budget is at least [`SNAPSHOT_LIMITS`]'s and five times the node cap, as on the
    /// previous reader. The operation deadline still bounds the time and reports truncation.
    #[must_use]
    pub fn for_max_nodes(max_nodes: usize) -> Self {
        let nodes = max_nodes.clamp(MIN_MAX_NODES, MAX_MAX_NODES);
        Self {
            depth: SNAPSHOT_LIMITS.depth,
            nodes,
            visited: SNAPSHOT_LIMITS.visited.max(nodes.saturating_mul(5)),
        }
    }
}

/// Why a walk or search stopped before covering everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// [`WalkLimits::nodes`] captured nodes.
    Nodes,
    /// [`WalkLimits::visited`] visited elements.
    Visited,
    /// The operation deadline passed.
    Deadline,
    /// Too many messages in a row went unanswered.
    Unresponsive,
}

/// How much of the tree a walk left out or read only partially.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Truncation {
    /// What stopped the walk early, if anything.
    pub stopped_by: Option<Limit>,
    /// Elements that were discovered but never read because the walk stopped (each may root a
    /// larger unvisited subtree).
    pub unvisited: usize,
    /// Children skipped because their parent was at [`WalkLimits::depth`].
    pub depth_cut: usize,
    /// Elements whose batched read went unanswered and that were kept with only their role and
    /// children (name, value, bounds and states missing).
    pub partial: usize,
    /// Elements that could not be read at all (subtree lost).
    pub skipped: usize,
}

impl Truncation {
    /// Whether any part of the tree was left out or read only partially.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.stopped_by.is_some() || self.depth_cut > 0 || self.partial > 0 || self.skipped > 0
    }

    /// The protocol's `truncated` flag: `true` when elements may be missing from the snapshot,
    /// whatever the reason (node or visit cap, the caller's `max_nodes`, depth, deadline,
    /// unanswered messages, or an element that could not be read). Partially read elements
    /// alone do not set it: every element is present, only some of its attributes are missing.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.stopped_by.is_some() || self.depth_cut > 0 || self.skipped > 0
    }

    /// A key that changes only when the kind of truncation changes (not with the counts), used
    /// to rate-limit warnings.
    #[must_use]
    pub fn warn_key(&self) -> String {
        format!(
            "snapshot:{:?}:{}:{}:{}",
            self.stopped_by,
            self.depth_cut > 0,
            self.partial > 0,
            self.skipped > 0
        )
    }
}

/// The result of a snapshot walk.
#[derive(Debug, Clone, PartialEq)]
pub struct WalkResult {
    /// Captured nodes in document (pre-)order.
    pub nodes: Vec<AccessibilityNode>,
    /// Elements read.
    pub visited: usize,
    /// What was left out.
    pub truncation: Truncation,
}

enum NodeRead<E> {
    Full(NodeAttrs<E>),
    Partial(NodeAttrs<E>),
    Skipped,
    Gone,
}

/// Reads one element for the walk: a batched read, then, if that went unanswered, a
/// per-attribute read of the minimal set so the element and its subtree are kept.
fn read_node<S: AxSource, C: Clock>(
    src: &mut S,
    elem: &S::Elem,
    budget: &mut Budget<C>,
) -> Result<NodeRead<S::Elem>, Abort> {
    let outcome = src.read(elem, AttrSet::Node);
    let unanswered = matches!(outcome, Outcome::Unresponsive);
    if let Some(attrs) = budget.settle(outcome)? {
        return Ok(NodeRead::Full(attrs));
    }
    if !unanswered {
        return Ok(NodeRead::Gone);
    }
    budget.check()?;
    let outcome = src.read_each(elem, AttrSet::Minimal);
    let unanswered = matches!(outcome, Outcome::Unresponsive);
    Ok(match budget.settle(outcome)? {
        Some(attrs) => NodeRead::Partial(attrs),
        None if unanswered => NodeRead::Skipped,
        None => NodeRead::Gone,
    })
}

/// Walks the subtree under `root` in document order, capturing semantic nodes.
///
/// Never fails because the browser is slow: a deadline or a run of unanswered messages ends
/// the walk and returns what was captured so far, recorded in [`WalkResult::truncation`].
///
/// # Errors
///
/// Returns [`ApiDisabled`] if the Accessibility API is disabled.
pub fn walk_tree<S: AxSource, C: Clock>(
    src: &mut S,
    root: S::Elem,
    limits: &WalkLimits,
    budget: &mut Budget<C>,
) -> Result<WalkResult, ApiDisabled> {
    let mut stack = vec![(root, 0usize)];
    let mut nodes = Vec::new();
    let mut visited = 0usize;
    let mut truncation = Truncation::default();

    while let Some((elem, depth)) = stack.pop() {
        let mut limit = if nodes.len() >= limits.nodes {
            Some(Limit::Nodes)
        } else if visited >= limits.visited {
            Some(Limit::Visited)
        } else {
            None
        };
        if limit.is_none()
            && let Err(abort) = budget.check()
        {
            limit = Some(stop_reason(abort)?);
        }
        if limit.is_some() {
            truncation.stopped_by = limit;
            truncation.unvisited = stack.len() + 1;
            break;
        }
        visited += 1;

        let read = match read_node(src, &elem, budget) {
            Ok(read) => read,
            Err(abort) => {
                truncation.stopped_by = Some(stop_reason(abort)?);
                truncation.unvisited = stack.len() + 1;
                break;
            }
        };
        let mut attrs = match read {
            NodeRead::Full(attrs) => attrs,
            NodeRead::Partial(attrs) => {
                truncation.partial += 1;
                attrs
            }
            NodeRead::Skipped => {
                truncation.skipped += 1;
                continue;
            }
            NodeRead::Gone => continue,
        };
        let children = attrs.children.take();
        let role = node_role(&attrs);
        let name = node_name(&attrs, role);
        let mut stop_after = None;
        if is_captured(role, name.as_ref()) {
            let advertised = if needs_expanded_advert(role, &attrs) {
                match budget.settle(src.advertises_expanded(&elem)) {
                    Ok(found) => found.unwrap_or(false),
                    Err(abort) => {
                        stop_after = Some(stop_reason(abort)?);
                        false
                    }
                }
            } else {
                false
            };
            nodes.push(make_node(&attrs, role, name, nodes.len(), advertised));
        }
        if stop_after.is_some() {
            truncation.stopped_by = stop_after;
            truncation.unvisited = stack.len() + children.as_ref().map_or(0, Vec::len);
            break;
        }

        let Some(children) = children else {
            continue;
        };
        if depth >= limits.depth {
            truncation.depth_cut += children.len();
            continue;
        }
        // Reversed so the first child is popped (visited) first.
        stack.extend(children.into_iter().rev().map(|c| (c, depth + 1)));
    }

    Ok(WalkResult {
        nodes,
        visited,
        truncation,
    })
}

// ---------------------------------------------------------------------------------------------
// AXWebArea selection.
// ---------------------------------------------------------------------------------------------

/// Limits for the search for `AXWebArea` candidates under one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchLimits {
    /// Deepest level (window = 0) whose children are still searched.
    pub depth: usize,
    /// Maximum elements read per window.
    pub visited: usize,
}

/// Web-area search limits. Web-area subtrees are never descended into, so this budget is spent
/// only on browser UI (tab strip, toolbars, side panels).
pub const WEB_AREA_SEARCH: SearchLimits = SearchLimits {
    depth: 24,
    visited: 5_000,
};

/// Roles whose subtrees are searched only when the rest of the window has no regular page: the
/// tab strip, toolbars (bookmarks bar) and menus can hold thousands of elements but never the
/// page.
pub const DEFERRED_ROLES: &[&str] = &["AXTabGroup", "AXToolbar", "AXMenuBar", "AXMenu"];

/// Preference class of a web area by its `AXURL`, within one window. Lower is preferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UrlTier {
    /// A regular page, or a web area whose URL could not be read.
    Page,
    /// Browser-internal `WebUI` (`chrome://`, `chrome-untrusted://`, `chrome-extension://`), which
    /// is what side panels and extension popups show. Still chosen if the window has nothing
    /// better, so a tab really showing `chrome://settings` keeps working.
    BrowserUi,
    /// Docked `DevTools` (`devtools://`).
    DevTools,
}

/// Classifies a web area by its URL.
#[must_use]
pub fn url_tier(url: Option<&str>) -> UrlTier {
    let Some(url) = url else {
        return UrlTier::Page;
    };
    let scheme = url
        .split_once(':')
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    match scheme.as_str() {
        "devtools" => UrlTier::DevTools,
        "chrome" | "chrome-untrusted" | "chrome-extension" => UrlTier::BrowserUi,
        _ => UrlTier::Page,
    }
}

/// An `AXWebArea` found while searching.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate<E> {
    /// The web area element.
    pub elem: E,
    /// Its `AXURL`, if readable.
    pub url: Option<String>,
    /// Its screen bounds (all zero if unreadable).
    pub bounds: Bounds,
    /// Index of the searched root it was found under (0 = focused window).
    pub root: usize,
    /// Discovery order across the whole search.
    pub order: usize,
}

impl<E> Candidate<E> {
    /// Whether it has a non-empty on-screen area.
    #[must_use]
    pub fn visible(&self) -> bool {
        self.bounds.width > 0.0 && self.bounds.height > 0.0
    }

    fn area(&self) -> f64 {
        if self.visible() {
            self.bounds.width * self.bounds.height
        } else {
            0.0
        }
    }

    fn tier(&self) -> UrlTier {
        url_tier(self.url.as_deref())
    }
}

/// Orders candidates best-first: the earlier searched window (focused, then main, then the
/// others) always wins; within a window a regular page beats browser `WebUI` (side panels,
/// `chrome://`) beats `DevTools`, then visible beats zero-size (a page is briefly 0x0 while
/// navigating), then the larger area, then discovery order.
#[must_use]
pub fn rank_cmp<E>(a: &Candidate<E>, b: &Candidate<E>) -> Ordering {
    a.root
        .cmp(&b.root)
        .then_with(|| a.tier().cmp(&b.tier()))
        .then_with(|| b.visible().cmp(&a.visible()))
        .then_with(|| b.area().total_cmp(&a.area()))
        .then_with(|| a.order.cmp(&b.order))
}

/// Index of the best candidate.
#[must_use]
pub fn best_candidate<E>(candidates: &[Candidate<E>]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| rank_cmp(a, b))
        .map(|(i, _)| i)
}

/// Statistics of a web-area search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchStats {
    /// Elements read.
    pub visited: usize,
    /// Roots (windows) searched.
    pub roots: usize,
    /// Whether a depth or visit limit cut a window's search short.
    pub truncated: bool,
    /// Set when the deadline or unanswered messages stopped the search; the result is then the
    /// best web area found so far, if any.
    pub stopped_by: Option<Limit>,
    /// Whether some element (or the focused-window attribute) stayed unanswered even after the
    /// per-attribute fallback. Other windows are then not searched: the caller polls again.
    pub unanswered: bool,
}

/// The chosen web area, if any, with search statistics.
#[derive(Debug, Clone, PartialEq)]
pub struct WebAreaSearch<E> {
    /// The best web area found.
    pub web_area: Option<Candidate<E>>,
    /// Number of web areas considered.
    pub candidates: usize,
    /// Search statistics.
    pub stats: SearchStats,
}

struct Search<'a, S: AxSource, C> {
    src: &'a mut S,
    budget: &'a mut Budget<C>,
    limits: &'a SearchLimits,
    candidates: Vec<Candidate<S::Elem>>,
    stats: SearchStats,
    searched: Vec<S::Elem>,
}

impl<S: AxSource, C: Clock> Search<'_, S, C> {
    fn root_has_page(&self, root: usize) -> bool {
        self.candidates
            .iter()
            .any(|c| c.root == root && c.tier() == UrlTier::Page)
    }

    /// Breadth-first search of `root` for web areas. Tab strips / toolbars / menus are only
    /// searched if the rest of the window has no regular page.
    fn search_root(&mut self, root: S::Elem) -> Result<(), Abort> {
        if self
            .searched
            .iter()
            .any(|seen| self.src.same_element(seen, &root))
        {
            return Ok(());
        }
        self.searched.push(root.clone());
        let root_index = self.stats.roots;
        self.stats.roots += 1;

        let mut primary = VecDeque::from([(root, 0usize)]);
        let mut deferred: VecDeque<(S::Elem, usize)> = VecDeque::new();
        let mut visited = 0usize;
        loop {
            let (elem, depth, in_deferred) = if let Some((e, d)) = primary.pop_front() {
                (e, d, false)
            } else if self.root_has_page(root_index) {
                break;
            } else if let Some((e, d)) = deferred.pop_front() {
                (e, d, true)
            } else {
                break;
            };
            if visited >= self.limits.visited {
                self.stats.truncated = true;
                break;
            }
            self.budget.check()?;
            visited += 1;
            self.stats.visited += 1;

            let Some(mut attrs) = self.read_probe(&elem)? else {
                continue;
            };
            let role = attrs.role.as_deref().unwrap_or_default();
            if role == "AXWebArea" {
                // Never descend: nested `AXWebArea`s are iframes of this page.
                let order = self.candidates.len();
                self.candidates.push(Candidate {
                    elem,
                    url: attrs.url.take(),
                    bounds: bounds_of(attrs.position, attrs.size),
                    root: root_index,
                    order,
                });
                continue;
            }
            let defer = in_deferred || DEFERRED_ROLES.contains(&role);
            let Some(children) = attrs.children.take() else {
                continue;
            };
            if depth >= self.limits.depth {
                self.stats.truncated |= !children.is_empty();
                continue;
            }
            let queue = if defer { &mut deferred } else { &mut primary };
            queue.extend(children.into_iter().map(|c| (c, depth + 1)));
        }
        Ok(())
    }

    /// Reads one element for the search: a batched probe, then, if that went unanswered, a
    /// per-attribute read of role and children (as the walk does) so the subtree is still
    /// searched. Still unanswered: recorded in [`SearchStats::unanswered`].
    fn read_probe(&mut self, elem: &S::Elem) -> Result<Option<NodeAttrs<S::Elem>>, Abort> {
        let outcome = self.src.read(elem, AttrSet::Probe);
        let unanswered = matches!(outcome, Outcome::Unresponsive);
        if let Some(attrs) = self.budget.settle(outcome)? {
            return Ok(Some(attrs));
        }
        if !unanswered {
            return Ok(None);
        }
        self.budget.check()?;
        let outcome = self.src.read_each(elem, AttrSet::Minimal);
        let unanswered = matches!(outcome, Outcome::Unresponsive);
        let attrs = self.budget.settle(outcome)?;
        if attrs.is_none() && unanswered {
            self.stats.unanswered = true;
        }
        Ok(attrs)
    }

    fn run(&mut self, app: &S::Elem) -> Result<(), Abort> {
        self.budget.check()?;
        let outcome = self.src.windows(app, WindowAttr::Focused);
        let unanswered = matches!(outcome, Outcome::Unresponsive);
        let focused = self.budget.settle(outcome)?.unwrap_or_default();
        if unanswered {
            // Unknown focused window: never guess another window's page; poll again.
            self.stats.unanswered = true;
            return Ok(());
        }
        for root in focused {
            self.search_root(root)?;
        }
        if !self.candidates.is_empty() || self.stats.unanswered {
            // A focused-window search with unanswered reads may have missed its page: return
            // "no web area this time" rather than picking a page from another window.
            return Ok(());
        }
        for which in [WindowAttr::Main, WindowAttr::All] {
            self.budget.check()?;
            let roots = self
                .budget
                .settle(self.src.windows(app, which))?
                .unwrap_or_default();
            for root in roots {
                self.search_root(root)?;
                if !self.candidates.is_empty() {
                    return Ok(());
                }
            }
        }
        if self.searched.is_empty() {
            // No window is exposed (for example while Chrome is backgrounded on some setups).
            self.search_root(app.clone())?;
        }
        Ok(())
    }
}

/// Chooses the `AXWebArea` that shows the page of the browser's active tab.
///
/// Heuristic: the focused window always wins. Its web areas are ranked by [`rank_cmp`] (a
/// regular page over side panels / `chrome://` over `DevTools`), so `chrome://newtab` in the
/// focused window is chosen over a page in another window. Only if the focused window has no
/// web area at all (and answered every read, after the per-attribute fallback) are the main
/// window and then the other windows searched, taking the first
/// one that has any. With no windows at all the application element itself is searched.
///
/// A deadline or a run of unanswered messages stops the search early; the best web area found
/// so far (possibly none) is returned with [`SearchStats::stopped_by`] set.
///
/// # Errors
///
/// Returns [`ApiDisabled`] if the Accessibility API is disabled.
pub fn find_web_area<S: AxSource, C: Clock>(
    src: &mut S,
    app: &S::Elem,
    limits: &SearchLimits,
    budget: &mut Budget<C>,
) -> Result<WebAreaSearch<S::Elem>, ApiDisabled> {
    let mut search = Search {
        src,
        budget,
        limits,
        candidates: Vec::new(),
        stats: SearchStats::default(),
        searched: Vec::new(),
    };
    if let Err(abort) = search.run(app) {
        search.stats.stopped_by = Some(stop_reason(abort)?);
    }

    let candidates = search.candidates.len();
    let web_area = best_candidate(&search.candidates)
        .filter(|&i| i < candidates)
        .map(|i| search.candidates.swap_remove(i));
    Ok(WebAreaSearch {
        web_area,
        candidates,
        stats: search.stats,
    })
}

// ---------------------------------------------------------------------------------------------
// AXEnhancedUserInterface / AXManualAccessibility bookkeeping.
// ---------------------------------------------------------------------------------------------

/// Application attributes that make Chromium build its native accessibility tree.
///
/// `AXEnhancedUserInterface` is the attribute `VoiceOver` sets; `AXManualAccessibility` is the
/// Chromium / Electron-specific switch that enables accessibility without the side effects of
/// "enhanced UI" (which slows Chrome and makes window managers misbehave). Both are set because
/// older Chrome builds only react to the former.
pub const ENHANCED_UI_ATTRS: [&str; 2] = ["AXEnhancedUserInterface", "AXManualAccessibility"];

/// The observed value of an application flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagValue {
    /// The flag is on.
    On,
    /// The flag is explicitly off.
    Off,
    /// The application reports no value / does not support the attribute (effectively off).
    Absent,
    /// The value could not be read (timeout or unexpected type): unknown.
    Unreadable,
}

/// Decodes one slot of a batched read of the flags.
#[must_use]
pub fn flag_value<V: SlotValue>(slot: &Slot<V>) -> FlagValue {
    match slot {
        Slot::Missing => FlagValue::Absent,
        Slot::Error(code) => match classify_ax_error(*code) {
            AxStatus::Absent => FlagValue::Absent,
            AxStatus::Success | AxStatus::Gone | AxStatus::Unresponsive | AxStatus::ApiDisabled => {
                FlagValue::Unreadable
            }
        },
        Slot::Value(v) => match v.boolean().or_else(|| v.integer().map(|i| i != 0)) {
            Some(true) => FlagValue::On,
            Some(false) => FlagValue::Off,
            None => FlagValue::Unreadable,
        },
    }
}

/// The result of writing `true` to a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetResult {
    /// The write succeeded.
    Set,
    /// The write timed out: it may or may not have been applied.
    TimedOut,
    /// The write was refused.
    Failed,
}

/// Classifies the `AXError` of `AXUIElementSetAttributeValue`.
#[must_use]
pub const fn set_result(code: i32) -> SetResult {
    match classify_ax_error(code) {
        AxStatus::Success => SetResult::Set,
        AxStatus::Unresponsive => SetResult::TimedOut,
        AxStatus::Absent | AxStatus::Gone | AxStatus::ApiDisabled => SetResult::Failed,
    }
}

/// First retry delay after a failed or timed-out write; doubles per failure.
pub const FLAG_RETRY_BASE: Duration = Duration::from_millis(250);
/// Longest retry delay.
pub const FLAG_RETRY_MAX: Duration = Duration::from_secs(5);

/// Retry delay after `failures` consecutive failed writes (at least 1).
#[must_use]
pub fn flag_retry_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(5);
    FLAG_RETRY_BASE
        .saturating_mul(1 << shift)
        .min(FLAG_RETRY_MAX)
}

/// Bookkeeping for one application flag that the driver keeps on while it runs and restores
/// when it is dropped.
///
/// The flag is read at the start of every operation and written again whenever it is off, so
/// accessibility comes back after a slow startup or after another client turned it off. Failed
/// writes back off in time instead of being capped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlagState {
    ours: bool,
    prior: Option<FlagValue>,
    failures: u32,
    retry_at: Option<Instant>,
}

impl FlagState {
    /// A flag that has not been touched yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ours: false,
            prior: None,
            failures: 0,
            retry_at: None,
        }
    }

    /// Decides from the value `observed` at `now` whether to write `true`. A flag that is on is
    /// left alone; an unreadable one too (the application is not answering, so a write would
    /// only cost another timeout).
    pub fn plan(&mut self, observed: FlagValue, now: Instant) -> bool {
        match observed {
            FlagValue::On | FlagValue::Unreadable => false,
            FlagValue::Off | FlagValue::Absent => {
                if self.retry_at.is_some_and(|at| now < at) {
                    return false;
                }
                if !self.ours && self.prior.is_none() {
                    self.prior = Some(observed);
                }
                true
            }
        }
    }

    /// Records the result of a write planned by [`FlagState::plan`]. A write that timed out may
    /// have been applied, so it is treated as ours (and restored on drop), but backs off.
    pub fn record_set(&mut self, result: SetResult, now: Instant) {
        match result {
            SetResult::Set => {
                self.ours = true;
                self.failures = 0;
                self.retry_at = None;
            }
            SetResult::TimedOut | SetResult::Failed => {
                self.ours |= result == SetResult::TimedOut;
                self.failures = self.failures.saturating_add(1);
                self.retry_at = Some(now + flag_retry_delay(self.failures));
            }
        }
    }

    /// The value to write back when the driver goes away: `Some(false)` if the driver (possibly)
    /// turned the flag on and it was readably off before; `None` to leave it alone. A prior
    /// [`FlagValue::Absent`] is not restored: "no value" cannot be told apart from "on but not
    /// readable as a boolean", so writing `false` could turn off someone else's setting.
    #[must_use]
    pub const fn restore_value(self) -> Option<bool> {
        match self.prior {
            Some(FlagValue::Off) if self.ours => Some(false),
            _ => None,
        }
    }

    /// The value observed before the driver first turned the flag on.
    #[must_use]
    pub const fn prior(self) -> Option<FlagValue> {
        self.prior
    }
}

// ---------------------------------------------------------------------------------------------
// Warning rate limit.
// ---------------------------------------------------------------------------------------------

/// Minimum interval between two warnings with the same key.
pub const WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Rate-limits warnings: a key warns the first time it is seen and then at most once per
/// [`WARN_INTERVAL`], so a `wait_for` polling every 75 ms does not log every poll.
#[derive(Debug, Default)]
pub struct WarnGate {
    last: Vec<(String, Instant)>,
}

/// Distinct keys remembered by a [`WarnGate`].
const WARN_GATE_KEYS: usize = 32;

impl WarnGate {
    /// An empty gate.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: Vec::new() }
    }

    /// Whether a warning with `key` should be logged at `now` (and records it if so).
    pub fn should_warn(&mut self, key: &str, now: Instant) -> bool {
        if let Some(entry) = self.last.iter_mut().find(|(k, _)| k == key) {
            if now.saturating_duration_since(entry.1) < WARN_INTERVAL {
                return false;
            }
            entry.1 = now;
            return true;
        }
        if self.last.len() >= WARN_GATE_KEYS {
            let _oldest = self.last.remove(0);
        }
        self.last.push((key.to_owned(), now));
        true
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use waybound_core::LocatorQuery;

    use super::*;

    // ----- fakes -----

    #[derive(Debug, Clone, PartialEq)]
    enum Fake {
        Str(String),
        Bool(bool),
        Int(i64),
        Point(f64, f64),
        Size(f64, f64),
        Url(String),
        Kids(Vec<usize>),
    }

    impl SlotValue for Fake {
        type Elem = usize;
        fn string(&self) -> Option<String> {
            match self {
                Self::Str(s) => Some(s.clone()),
                _ => None,
            }
        }
        fn boolean(&self) -> Option<bool> {
            match self {
                Self::Bool(b) => Some(*b),
                _ => None,
            }
        }
        fn integer(&self) -> Option<i64> {
            match self {
                Self::Int(i) => Some(*i),
                _ => None,
            }
        }
        fn point(&self) -> Option<(f64, f64)> {
            match self {
                Self::Point(x, y) => Some((*x, *y)),
                _ => None,
            }
        }
        fn size(&self) -> Option<(f64, f64)> {
            match self {
                Self::Size(w, h) => Some((*w, *h)),
                _ => None,
            }
        }
        fn url(&self) -> Option<String> {
            match self {
                Self::Url(s) | Self::Str(s) => Some(s.clone()),
                _ => None,
            }
        }
        fn elements(&self) -> Option<Vec<usize>> {
            match self {
                Self::Kids(k) => Some(k.clone()),
                _ => None,
            }
        }
    }

    fn s(v: &str) -> Fake {
        Fake::Str(v.to_owned())
    }

    fn url(v: &str) -> Fake {
        Fake::Url(v.to_owned())
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Debug, Clone, Default)]
    struct FakeNode {
        attrs: Vec<(Attr, Fake)>,
        advertises_expanded: bool,
        /// Every read of this element times out.
        unresponsive: bool,
        /// Only the batched read times out; attribute-by-attribute reads answer.
        batch_unresponsive: bool,
        gone: bool,
    }

    impl FakeNode {
        fn new(role: &str) -> Self {
            Self {
                attrs: vec![(Attr::Role, s(role))],
                ..Self::default()
            }
        }
        fn with(mut self, attr: Attr, value: Fake) -> Self {
            self.attrs.push((attr, value));
            self
        }
        fn kids(self, kids: &[usize]) -> Self {
            self.with(Attr::Children, Fake::Kids(kids.to_vec()))
        }
        fn rect(self, x: f64, y: f64, w: f64, h: f64) -> Self {
            self.with(Attr::Position, Fake::Point(x, y))
                .with(Attr::Size, Fake::Size(w, h))
        }
        fn web(page_url: &str, w: f64, h: f64) -> Self {
            Self::new("AXWebArea")
                .with(Attr::Url, url(page_url))
                .rect(0.0, 0.0, w, h)
        }
    }

    #[derive(Debug, Clone)]
    struct FakeClock(Rc<Cell<Instant>>);

    impl FakeClock {
        fn new() -> Self {
            Self(Rc::new(Cell::new(Instant::now())))
        }
        fn advance(&self, by: Duration) {
            self.0.set(self.0.get() + by);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
    }

    struct FakeTree {
        nodes: Vec<FakeNode>,
        focused: Vec<usize>,
        main: Vec<usize>,
        all: Vec<usize>,
        clock: FakeClock,
        read_cost: Duration,
        reads: Vec<usize>,
        each_reads: Vec<usize>,
        advert_calls: usize,
    }

    impl FakeTree {
        fn new(nodes: Vec<FakeNode>, clock: &FakeClock) -> Self {
            Self {
                nodes,
                focused: Vec::new(),
                main: Vec::new(),
                all: Vec::new(),
                clock: clock.clone(),
                read_cost: Duration::from_millis(1),
                reads: Vec::new(),
                each_reads: Vec::new(),
                advert_calls: 0,
            }
        }

        fn decode(node: &FakeNode, set: AttrSet) -> Outcome<NodeAttrs<usize>> {
            // Mirror `AXUIElementCopyMultipleAttributeValues` with options = 0: one slot per
            // requested attribute, unsupported ones as error values.
            let slots: Vec<Slot<Fake>> = set
                .attrs()
                .iter()
                .map(|attr| {
                    node.attrs
                        .iter()
                        .find(|(a, _)| a == attr)
                        .map_or(Slot::Error(AX_ERROR_ATTRIBUTE_UNSUPPORTED), |(_, v)| {
                            Slot::Value(v.clone())
                        })
                })
                .collect();
            decode_slots(set.attrs(), &slots).map_or(Outcome::Gone, Outcome::Ok)
        }
    }

    impl AxSource for FakeTree {
        type Elem = usize;

        fn read(&mut self, elem: &usize, set: AttrSet) -> Outcome<NodeAttrs<usize>> {
            self.clock.advance(self.read_cost);
            self.reads.push(*elem);
            let Some(node) = self.nodes.get(*elem) else {
                return Outcome::Gone;
            };
            if node.unresponsive || node.batch_unresponsive {
                return Outcome::Unresponsive;
            }
            if node.gone {
                return Outcome::Gone;
            }
            Self::decode(node, set)
        }

        fn read_each(&mut self, elem: &usize, set: AttrSet) -> Outcome<NodeAttrs<usize>> {
            self.clock.advance(self.read_cost);
            self.each_reads.push(*elem);
            let Some(node) = self.nodes.get(*elem) else {
                return Outcome::Gone;
            };
            if node.unresponsive {
                return Outcome::Unresponsive;
            }
            if node.gone {
                return Outcome::Gone;
            }
            Self::decode(node, set)
        }

        fn advertises_expanded(&mut self, elem: &usize) -> Outcome<bool> {
            self.advert_calls += 1;
            Outcome::Ok(self.nodes.get(*elem).is_some_and(|n| n.advertises_expanded))
        }

        fn windows(&mut self, _app: &usize, which: WindowAttr) -> Outcome<Vec<usize>> {
            Outcome::Ok(match which {
                WindowAttr::Focused => self.focused.clone(),
                WindowAttr::Main => self.main.clone(),
                WindowAttr::All => self.all.clone(),
            })
        }

        fn same_element(&self, a: &usize, b: &usize) -> bool {
            a == b
        }
    }

    struct Disabled;

    impl AxSource for Disabled {
        type Elem = usize;
        fn read(&mut self, _: &usize, _: AttrSet) -> Outcome<NodeAttrs<usize>> {
            Outcome::ApiDisabled
        }
        fn read_each(&mut self, _: &usize, _: AttrSet) -> Outcome<NodeAttrs<usize>> {
            Outcome::ApiDisabled
        }
        fn advertises_expanded(&mut self, _: &usize) -> Outcome<bool> {
            Outcome::ApiDisabled
        }
        fn windows(&mut self, _: &usize, _: WindowAttr) -> Outcome<Vec<usize>> {
            Outcome::ApiDisabled
        }
        fn same_element(&self, a: &usize, b: &usize) -> bool {
            a == b
        }
    }

    /// The production streak limit and deadline.
    fn budget(clock: &FakeClock) -> Budget<FakeClock> {
        Budget::new(clock.clone(), Duration::from_secs(10), 3)
    }

    // ----- error classification -----

    #[test]
    fn ax_errors_are_classified() {
        assert_eq!(classify_ax_error(0), AxStatus::Success);
        assert_eq!(classify_ax_error(-25_204), AxStatus::Unresponsive);
        assert_eq!(classify_ax_error(-25_211), AxStatus::ApiDisabled);
        assert_eq!(classify_ax_error(-25_202), AxStatus::Gone);
        assert_eq!(classify_ax_error(-25_205), AxStatus::Absent);
        assert_eq!(classify_ax_error(-25_212), AxStatus::Absent);
        assert_eq!(classify_ax_error(-25_200), AxStatus::Absent);
    }

    #[test]
    fn batch_failures_fall_back_only_when_retrying_can_help() {
        assert_eq!(after_batch(AX_ERROR_SUCCESS), BatchNext::Decode);
        // Hung app: no per-attribute retry inside the source (the walk decides on a minimal one).
        assert_eq!(
            after_batch(AX_ERROR_CANNOT_COMPLETE),
            BatchNext::Stop(Outcome::Unresponsive)
        );
        assert_eq!(
            after_batch(AX_ERROR_INVALID_UI_ELEMENT),
            BatchNext::Stop(Outcome::Gone)
        );
        assert_eq!(
            after_batch(AX_ERROR_API_DISABLED),
            BatchNext::Stop(Outcome::ApiDisabled)
        );
        // kAXErrorIllegalArgument / kAXErrorNotImplemented / kAXErrorFailure.
        for code in [-25_201, -25_208, -25_200] {
            assert_eq!(after_batch(code), BatchNext::PerAttribute);
        }
    }

    // ----- decoding -----

    #[test]
    fn attribute_names_match_the_ax_constants() {
        let names: Vec<&str> = NODE_ATTRS.iter().map(|a| a.name()).collect();
        assert_eq!(
            names,
            [
                "AXRole",
                "AXSubrole",
                "AXTitle",
                "AXDescription",
                "AXPlaceholderValue",
                "AXValue",
                "AXPosition",
                "AXSize",
                "AXFocused",
                "AXEnabled",
                "AXExpanded",
                "AXURL",
                "AXChildren",
            ]
        );
        assert_eq!(Attr::Url.name(), "AXURL");
        assert_eq!(AttrSet::Probe.attrs(), PROBE_ATTRS);
        assert_eq!(AttrSet::Minimal.attrs(), [Attr::Role, Attr::Children]);
        let indices = [
            AttrSet::Node.index(),
            AttrSet::Probe.index(),
            AttrSet::Minimal.index(),
        ];
        assert_eq!(indices, [0, 1, 2]);
        assert!(indices.iter().all(|&i| i < ATTR_SETS));
    }

    #[test]
    fn window_and_flag_attribute_names_match_the_ax_constants() {
        assert_eq!(WindowAttr::Focused.name(), "AXFocusedWindow");
        assert_eq!(WindowAttr::Main.name(), "AXMainWindow");
        assert_eq!(WindowAttr::All.name(), "AXWindows");
        assert_eq!(
            ENHANCED_UI_ATTRS,
            ["AXEnhancedUserInterface", "AXManualAccessibility"]
        );
    }

    #[test]
    fn decode_maps_each_slot_to_its_attribute() {
        let slots = vec![
            Slot::Value(s("AXCheckBox")),
            Slot::Value(s("AXSwitch")),
            Slot::Value(s("Dark mode")),
            Slot::Value(s("desc")),
            Slot::Value(s("ph")),
            Slot::Value(Fake::Int(1)),
            Slot::Value(Fake::Point(10.0, 20.0)),
            Slot::Value(Fake::Size(30.0, 40.0)),
            Slot::Value(Fake::Bool(true)),
            Slot::Value(Fake::Bool(false)),
            Slot::Value(Fake::Bool(true)),
            Slot::Value(url("https://example.test/")),
            Slot::Value(Fake::Kids(vec![4, 5])),
        ];
        let expected = NodeAttrs {
            role: Some("AXCheckBox".to_owned()),
            subrole: Some("AXSwitch".to_owned()),
            title: Some("Dark mode".to_owned()),
            description: Some("desc".to_owned()),
            placeholder: Some("ph".to_owned()),
            value_text: None,
            value_number: Some(1),
            position: Some((10.0, 20.0)),
            size: Some((30.0, 40.0)),
            focused: Some(true),
            enabled: Some(false),
            expanded: Some(true),
            url: Some("https://example.test/".to_owned()),
            children: Some(vec![4, 5]),
        };
        assert_eq!(decode_slots(NODE_ATTRS, &slots), Ok(expected));
    }

    #[test]
    fn decode_treats_error_and_missing_slots_as_absent_not_values() {
        let attrs = [Attr::Role, Attr::Title, Attr::Focused, Attr::Children];
        let slots = vec![
            Slot::Value(s("AXButton")),
            // kAXErrorNoValue embedded as an AXValue of kAXValueAXErrorType.
            Slot::Error(AX_ERROR_NO_VALUE),
            Slot::Missing,
            Slot::Error(AX_ERROR_ATTRIBUTE_UNSUPPORTED),
        ];
        assert_eq!(
            decode_slots(&attrs, &slots),
            Ok(NodeAttrs {
                role: Some("AXButton".to_owned()),
                ..NodeAttrs::default()
            })
        );
    }

    #[test]
    fn decode_ignores_values_of_the_wrong_type() {
        let attrs = [Attr::Role, Attr::Focused, Attr::Position, Attr::Children];
        let slots = vec![
            Slot::Value(Fake::Int(3)),
            Slot::Value(s("yes")),
            Slot::Value(Fake::Size(1.0, 1.0)),
            Slot::Value(Fake::Bool(true)),
        ];
        assert_eq!(decode_slots(&attrs, &slots), Ok(NodeAttrs::default()));
    }

    #[test]
    fn decode_reads_string_and_boolean_ax_values() {
        let attrs = [Attr::Value];
        let text = decode_slots(&attrs, &[Slot::Value(s("hello"))]);
        assert_eq!(
            text.map(|a| (a.value_text, a.value_number)),
            Ok((Some("hello".to_owned()), None))
        );
        let switch = decode_slots(&attrs, &[Slot::Value(Fake::Bool(true))]);
        assert_eq!(
            switch.map(|a| (a.value_text, a.value_number)),
            Ok((None, Some(1)))
        );
    }

    #[test]
    fn decode_rejects_a_length_mismatch() {
        let slots: Vec<Slot<Fake>> = vec![Slot::Value(s("AXButton"))];
        assert_eq!(
            decode_slots(&[Attr::Role, Attr::Title], &slots),
            Err(LengthMismatch {
                expected: 2,
                actual: 1
            })
        );
    }

    // ----- node construction (behaviour preserved from the per-attribute reader) -----

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
    fn name_skips_empty_sources_in_order() {
        let attrs: NodeAttrs<usize> = NodeAttrs {
            title: Some(String::new()),
            description: Some(String::new()),
            placeholder: Some("Search".to_owned()),
            ..NodeAttrs::default()
        };
        assert_eq!(node_name(&attrs, Role::TextBox).as_deref(), Some("Search"));
        let text: NodeAttrs<usize> = NodeAttrs {
            role: Some("AXStaticText".to_owned()),
            value_text: Some("Hello".to_owned()),
            ..NodeAttrs::default()
        };
        assert_eq!(node_name(&text, Role::StaticText).as_deref(), Some("Hello"));
        let empty: NodeAttrs<usize> = NodeAttrs {
            value_text: Some(String::new()),
            ..NodeAttrs::default()
        };
        assert_eq!(node_name(&empty, Role::StaticText), None);
    }

    #[test]
    fn subrole_is_only_used_where_it_changes_the_role() {
        let with = |role: &str, subrole: &str| -> NodeAttrs<usize> {
            NodeAttrs {
                role: Some(role.to_owned()),
                subrole: Some(subrole.to_owned()),
                ..NodeAttrs::default()
            }
        };
        assert_eq!(node_role(&with("AXCheckBox", "AXSwitch")), Role::Switch);
        assert_eq!(node_role(&with("AXRadioButton", "AXTabButton")), Role::Tab);
        assert_eq!(
            node_role(&with("AXGroup", "AXApplicationDialog")),
            Role::Dialog
        );
        assert_eq!(node_role(&with("AXButton", "AXSwitch")), Role::Button);
        assert_eq!(node_role(&NodeAttrs::<usize>::default()), Role::Unknown);
    }

    #[test]
    fn bounds_need_both_position_and_size() {
        let b = bounds_of(Some((1.0, 2.0)), Some((3.0, 4.0)));
        assert!((b.x - 1.0).abs() < f64::EPSILON && (b.height - 4.0).abs() < f64::EPSILON);
        let none = bounds_of(Some((1.0, 2.0)), None);
        assert!(none.x.abs() < f64::EPSILON && none.width.abs() < f64::EPSILON);
        let none = bounds_of(None, Some((3.0, 4.0)));
        assert!(none.height.abs() < f64::EPSILON);
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

    #[test]
    fn expanded_state_respects_the_probe_policy() {
        assert_eq!(
            expanded_state(Role::ComboBox, Some(false), false),
            Some(false)
        );
        assert_eq!(expanded_state(Role::Button, Some(true), true), Some(true));
        // Chromium answers AXExpanded for any button; unadvertised means "not expandable".
        assert_eq!(expanded_state(Role::Button, Some(false), false), None);
        assert_eq!(expanded_state(Role::TextBox, Some(true), true), None);

        let with_value: NodeAttrs<usize> = NodeAttrs {
            expanded: Some(false),
            ..NodeAttrs::default()
        };
        assert!(needs_expanded_advert(Role::Button, &with_value));
        assert!(!needs_expanded_advert(Role::ComboBox, &with_value));
        assert!(!needs_expanded_advert(
            Role::Button,
            &NodeAttrs::<usize>::default()
        ));
    }

    #[test]
    fn make_node_fills_every_field() {
        let attrs: NodeAttrs<usize> = NodeAttrs {
            role: Some("AXCheckBox".to_owned()),
            title: Some("Agree".to_owned()),
            value_number: Some(1),
            position: Some((5.0, 6.0)),
            size: Some((7.0, 8.0)),
            focused: Some(true),
            enabled: Some(false),
            expanded: Some(true),
            ..NodeAttrs::default()
        };
        let role = node_role(&attrs);
        let node = make_node(&attrs, role, node_name(&attrs, role), 3, false);
        assert_eq!(node.id, "ax-3");
        assert_eq!(node.role, Role::CheckBox);
        assert_eq!(node.name.as_deref(), Some("Agree"));
        assert_eq!(node.value, None);
        assert_eq!(node.checked, Some(true));
        assert!(node.focused);
        assert!(node.disabled);
        assert_eq!(node.expanded, None);
        assert!((node.bounds.width - 7.0).abs() < f64::EPSILON);

        // AXEnabled is only reported for controls.
        let heading: NodeAttrs<usize> = NodeAttrs {
            role: Some("AXHeading".to_owned()),
            enabled: Some(false),
            ..NodeAttrs::default()
        };
        let node = make_node(&heading, Role::Heading, None, 0, false);
        assert!(!node.disabled);
        assert!(!node.focused);
    }

    // ----- budget -----

    #[test]
    fn budget_deadline_uses_the_injected_clock() {
        let clock = FakeClock::new();
        let budget = budget(&clock);
        assert_eq!(budget.check(), Ok(()));
        clock.advance(Duration::from_millis(9_999));
        assert_eq!(budget.check(), Ok(()));
        clock.advance(Duration::from_millis(1));
        assert_eq!(budget.check(), Err(Abort::Deadline));
    }

    #[test]
    fn budget_stops_after_three_unanswered_reads_in_a_row_only() {
        let clock = FakeClock::new();
        let mut budget = budget(&clock);
        assert_eq!(budget.settle::<u8>(Outcome::Unresponsive), Ok(None));
        assert_eq!(budget.settle::<u8>(Outcome::Unresponsive), Ok(None));
        // An answered read (even "gone") resets the streak.
        assert_eq!(budget.settle::<u8>(Outcome::Gone), Ok(None));
        assert_eq!(budget.settle::<u8>(Outcome::Unresponsive), Ok(None));
        assert_eq!(budget.settle(Outcome::Ok(1u8)), Ok(Some(1)));
        assert_eq!(budget.settle::<u8>(Outcome::Unresponsive), Ok(None));
        assert_eq!(budget.settle::<u8>(Outcome::Unresponsive), Ok(None));
        assert_eq!(
            budget.settle::<u8>(Outcome::Unresponsive),
            Err(Abort::Unresponsive)
        );
        assert_eq!(budget.reads(), 8);
        assert_eq!(
            budget.settle::<u8>(Outcome::ApiDisabled),
            Err(Abort::ApiDisabled)
        );
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock;
        let earlier = clock.now();
        assert!(clock.now() >= earlier);
        let budget = Budget::new(SystemClock, Duration::from_secs(3_600), 3);
        assert_eq!(budget.check(), Ok(()));
    }

    #[test]
    fn only_a_disabled_api_is_a_hard_error() {
        assert_eq!(stop_reason(Abort::Deadline), Ok(Limit::Deadline));
        assert_eq!(stop_reason(Abort::Unresponsive), Ok(Limit::Unresponsive));
        assert_eq!(stop_reason(Abort::ApiDisabled), Err(ApiDisabled));
        assert!(matches!(
            api_disabled_error(),
            WayboundError::BackendUnavailable { reason, .. } if reason.contains("kAXErrorAPIDisabled")
        ));
    }

    // ----- snapshot walk -----

    // 0: AXWebArea [1, 2, 5]
    //   1: AXHeading "Title"
    //   2: AXGroup [3, 4]
    //     3: AXStaticText value "Hello"
    //     4: AXButton "Go" (advertises AXExpanded)
    //   5: AXUnknown (no name, skipped but walked) [6]
    //     6: AXLink "More"
    fn page() -> Vec<FakeNode> {
        vec![
            FakeNode::new("AXWebArea").kids(&[1, 2, 5]),
            FakeNode::new("AXHeading").with(Attr::Title, s("Title")),
            FakeNode::new("AXGroup").kids(&[3, 4]),
            FakeNode::new("AXStaticText").with(Attr::Value, s("Hello")),
            FakeNode {
                advertises_expanded: true,
                ..FakeNode::new("AXButton")
                    .with(Attr::Title, s("Go"))
                    .with(Attr::Expanded, Fake::Bool(false))
            },
            FakeNode::new("AXUnknown").kids(&[6]),
            FakeNode::new("AXLink")
                .with(Attr::Title, s("More"))
                .with(Attr::Expanded, Fake::Bool(false)),
        ]
    }

    fn page_with(index: usize, edit: impl FnOnce(&mut FakeNode)) -> Vec<FakeNode> {
        let mut nodes = page();
        if let Some(node) = nodes.get_mut(index) {
            edit(node);
        }
        nodes
    }

    fn summary(result: &WalkResult) -> Vec<(String, Role, Option<String>)> {
        result
            .nodes
            .iter()
            .map(|n| (n.id.clone(), n.role, n.name.clone()))
            .collect()
    }

    fn walk(tree: &mut FakeTree, clock: &FakeClock, limits: &WalkLimits) -> WalkResult {
        let result = walk_tree(tree, 0, limits, &mut budget(clock));
        let Ok(result) = result else {
            unreachable!("walk failed: {result:?}");
        };
        result
    }

    #[test]
    fn walk_captures_semantic_nodes_in_document_order() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(page(), &clock);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(
            summary(&result),
            [
                ("ax-0".to_owned(), Role::Document, None),
                ("ax-1".to_owned(), Role::Heading, Some("Title".to_owned())),
                ("ax-2".to_owned(), Role::Group, None),
                (
                    "ax-3".to_owned(),
                    Role::StaticText,
                    Some("Hello".to_owned())
                ),
                ("ax-4".to_owned(), Role::Button, Some("Go".to_owned())),
                ("ax-5".to_owned(), Role::Link, Some("More".to_owned())),
            ]
        );
        assert_eq!(tree.reads, [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(tree.each_reads.len(), 0);
        assert_eq!(result.visited, 7);
        assert!(!result.truncation.is_truncated());
        // The advertised button keeps its expanded state, the unadvertised link loses it.
        assert_eq!(result.nodes.get(4).and_then(|n| n.expanded), Some(false));
        assert_eq!(result.nodes.get(5).and_then(|n| n.expanded), None);
        assert_eq!(tree.advert_calls, 2);
    }

    #[test]
    fn walk_reports_node_cap_truncation() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(page(), &clock);
        let limits = WalkLimits {
            nodes: 3,
            ..SNAPSHOT_LIMITS
        };
        let result = walk(&mut tree, &clock, &limits);
        assert_eq!(result.nodes.len(), 3);
        assert_eq!(
            result.truncation,
            Truncation {
                stopped_by: Some(Limit::Nodes),
                // 3 and 4 (children of the group) and 5 were discovered but never read.
                unvisited: 3,
                ..Truncation::default()
            }
        );
        assert!(result.truncation.is_truncated());
    }

    #[test]
    fn walk_reports_visit_cap_and_depth_truncation() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(page(), &clock);
        let limits = WalkLimits {
            visited: 2,
            ..SNAPSHOT_LIMITS
        };
        let result = walk(&mut tree, &clock, &limits);
        assert_eq!(result.visited, 2);
        assert_eq!(
            result.truncation,
            Truncation {
                stopped_by: Some(Limit::Visited),
                unvisited: 2,
                ..Truncation::default()
            }
        );

        let mut tree = FakeTree::new(page(), &clock);
        let limits = WalkLimits {
            depth: 1,
            ..SNAPSHOT_LIMITS
        };
        let result = walk(&mut tree, &clock, &limits);
        // Depth-1 nodes are read; the children of the group (2) and of node 5 are cut.
        assert_eq!(tree.reads, [0, 1, 2, 5]);
        assert_eq!(
            result.truncation,
            Truncation {
                depth_cut: 3,
                ..Truncation::default()
            }
        );
        assert!(result.truncation.is_truncated());
    }

    #[test]
    fn walk_skips_gone_elements_and_their_subtrees() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(page_with(2, |n| n.gone = true), &clock);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(result.nodes.len(), 3);
        assert_eq!(tree.reads, [0, 1, 2, 5, 6]);
        // A vanished element is not a truncation: it is no longer part of the page.
        assert!(!result.truncation.is_truncated());
    }

    #[test]
    fn a_slow_element_keeps_its_subtree_through_the_minimal_fallback() {
        let clock = FakeClock::new();
        // The group's batched read times out; reading role and children one by one works.
        let mut tree = FakeTree::new(page_with(2, |n| n.batch_unresponsive = true), &clock);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(tree.each_reads, [2]);
        // Same nodes and ids as the healthy walk: the subtree (3, 4) is kept.
        assert_eq!(
            summary(&result)
                .into_iter()
                .map(|(id, role, _)| (id, role))
                .collect::<Vec<_>>(),
            [
                ("ax-0".to_owned(), Role::Document),
                ("ax-1".to_owned(), Role::Heading),
                ("ax-2".to_owned(), Role::Group),
                ("ax-3".to_owned(), Role::StaticText),
                ("ax-4".to_owned(), Role::Button),
                ("ax-5".to_owned(), Role::Link),
            ]
        );
        assert_eq!(
            result.truncation,
            Truncation {
                partial: 1,
                ..Truncation::default()
            }
        );
    }

    #[test]
    fn an_unreadable_element_is_skipped_without_aborting_the_walk() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(page_with(1, |n| n.unresponsive = true), &clock);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(result.nodes.len(), 5);
        assert_eq!(
            result.truncation,
            Truncation {
                skipped: 1,
                ..Truncation::default()
            }
        );
    }

    #[test]
    fn an_unanswered_root_yields_an_empty_tree_not_an_error() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(page_with(0, |n| n.unresponsive = true), &clock);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.truncation.skipped, 1);
        assert!(result.truncation.is_truncated());
    }

    #[test]
    fn a_hung_app_stops_the_walk_early_and_returns_what_was_read() {
        let clock = FakeClock::new();
        // The app hangs after the root was read: every read then waits out the 3 s messaging
        // timeout. The walk stops after three unanswered messages in a row (about 9 s) instead
        // of one timeout per node, and keeps the root it already captured.
        let mut hung = page();
        for node in hung.iter_mut().skip(1) {
            node.unresponsive = true;
        }
        let mut tree = FakeTree::new(hung, &clock);
        tree.read_cost = Duration::from_secs(3);
        let start = clock.now();
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(summary(&result).len(), 1);
        assert_eq!(tree.reads, [0, 1, 2]);
        assert_eq!(tree.each_reads, [1]);
        assert_eq!(
            result.truncation,
            Truncation {
                stopped_by: Some(Limit::Unresponsive),
                // Element 2 (attempted) and 5 were never read.
                unvisited: 2,
                skipped: 1,
                ..Truncation::default()
            }
        );
        assert!(clock.now().saturating_duration_since(start) <= Duration::from_secs(12));
    }

    #[test]
    fn the_deadline_returns_the_partial_tree() {
        let clock = FakeClock::new();
        // A responsive but slow app: each read takes 1 s; the 10 s budget allows 10 reads.
        let wide: Vec<FakeNode> =
            std::iter::once(FakeNode::new("AXWebArea").kids(&(1..=40).collect::<Vec<_>>()))
                .chain((1..=40).map(|_| FakeNode::new("AXButton").with(Attr::Title, s("b"))))
                .collect();
        let mut tree = FakeTree::new(wide, &clock);
        tree.read_cost = Duration::from_secs(1);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        assert_eq!(result.nodes.len(), 10);
        assert_eq!(
            result.truncation,
            Truncation {
                stopped_by: Some(Limit::Deadline),
                unvisited: 31,
                ..Truncation::default()
            }
        );
    }

    #[test]
    fn a_disabled_api_is_still_a_hard_error() {
        let clock = FakeClock::new();
        assert_eq!(
            walk_tree(&mut Disabled, 0, &SNAPSHOT_LIMITS, &mut budget(&clock)),
            Err(ApiDisabled)
        );
        assert_eq!(
            find_web_area(&mut Disabled, &0, &WEB_AREA_SEARCH, &mut budget(&clock)),
            Err(ApiDisabled)
        );
    }

    #[test]
    fn truncation_warn_key_tracks_the_kind_not_the_counts() {
        let a = Truncation {
            stopped_by: Some(Limit::Nodes),
            unvisited: 10,
            ..Truncation::default()
        };
        let b = Truncation { unvisited: 99, ..a };
        let c = Truncation { skipped: 1, ..a };
        assert_eq!(a.warn_key(), b.warn_key());
        assert_ne!(a.warn_key(), c.warn_key());
        assert!(!Truncation::default().is_truncated());
    }

    // ----- upstream API: href, truncated flag, caller max_nodes -----

    #[test]
    fn href_is_the_trimmed_url_of_links_only() {
        assert_eq!(
            link_url(Role::Link, Some("  https://example.com/about \n")).as_deref(),
            Some("https://example.com/about")
        );
        assert_eq!(link_url(Role::Link, Some("   ")), None);
        assert_eq!(link_url(Role::Link, None), None);
        assert_eq!(link_url(Role::Button, Some("https://example.com/")), None);
        assert_eq!(link_url(Role::Document, Some("https://example.com/")), None);

        let clock = FakeClock::new();
        let nodes = vec![
            FakeNode::new("AXWebArea")
                .with(Attr::Url, url("https://page.test/"))
                .kids(&[1, 2]),
            FakeNode::new("AXLink")
                .with(Attr::Title, s("About"))
                .with(Attr::Url, url(" https://page.test/about ")),
            FakeNode::new("AXButton")
                .with(Attr::Title, s("Go"))
                .with(Attr::Url, url("https://page.test/go")),
        ];
        let mut tree = FakeTree::new(nodes, &clock);
        let result = walk(&mut tree, &clock, &SNAPSHOT_LIMITS);
        let hrefs: Vec<Option<String>> = result.nodes.iter().map(|n| n.url.clone()).collect();
        assert_eq!(
            hrefs,
            [None, Some("https://page.test/about".to_owned()), None]
        );
    }

    #[test]
    fn caller_max_nodes_is_clamped_like_the_protocol() {
        assert_eq!(WalkLimits::for_max_nodes(0).nodes, 1);
        assert_eq!(WalkLimits::for_max_nodes(2_000).nodes, 2_000);
        assert_eq!(WalkLimits::for_max_nodes(2_000).visited, 10_000);
        assert_eq!(WalkLimits::for_max_nodes(20_000).visited, 100_000);
        assert_eq!(WalkLimits::for_max_nodes(1_000_000).nodes, MAX_MAX_NODES);
        assert_eq!(WalkLimits::for_max_nodes(5).depth, SNAPSHOT_LIMITS.depth);
    }

    #[test]
    fn truncated_flag_for_each_stop_reason() {
        let clock = FakeClock::new();
        let flag = |nodes: Vec<FakeNode>, limits: &WalkLimits, cost: Duration| {
            let clock = FakeClock::new();
            let mut tree = FakeTree::new(nodes, &clock);
            tree.read_cost = cost;
            let r = walk(&mut tree, &clock, limits);
            (
                r.nodes.len(),
                r.truncation.stopped_by,
                r.truncation.truncated(),
            )
        };
        let ms = Duration::from_millis(1);
        // Complete walk.
        assert_eq!(flag(page(), &SNAPSHOT_LIMITS, ms), (6, None, false));
        // The driver's own node cap.
        let capped = WalkLimits {
            nodes: 2,
            ..SNAPSHOT_LIMITS
        };
        assert_eq!(flag(page(), &capped, ms), (2, Some(Limit::Nodes), true));
        // The caller's max_nodes, and a max_nodes larger than the page.
        assert_eq!(
            flag(page(), &WalkLimits::for_max_nodes(3), ms),
            (3, Some(Limit::Nodes), true)
        );
        assert_eq!(
            flag(page(), &WalkLimits::for_max_nodes(6), ms),
            (6, None, false)
        );
        assert_eq!(
            flag(page(), &WalkLimits::for_max_nodes(100), ms),
            (6, None, false)
        );
        // Depth.
        let shallow = WalkLimits {
            depth: 1,
            ..SNAPSHOT_LIMITS
        };
        assert_eq!(flag(page(), &shallow, ms), (3, None, true));
        // Deadline: each read takes 4 s, so only 3 reads fit in 10 s.
        assert_eq!(
            flag(page(), &SNAPSHOT_LIMITS, Duration::from_secs(4)),
            (3, Some(Limit::Deadline), true)
        );
        // Unanswered: the browser hangs after the root.
        let mut hung = page();
        for node in hung.iter_mut().skip(1) {
            node.unresponsive = true;
        }
        assert_eq!(
            flag(hung, &SNAPSHOT_LIMITS, ms),
            (1, Some(Limit::Unresponsive), true)
        );
        // One element unreadable: missing, so truncated, though the walk went on.
        assert_eq!(
            flag(
                page_with(1, |n| n.unresponsive = true),
                &SNAPSHOT_LIMITS,
                ms
            ),
            (5, None, true)
        );
        // One element only partially read: nothing missing, not truncated.
        assert_eq!(
            flag(
                page_with(2, |n| n.batch_unresponsive = true),
                &SNAPSHOT_LIMITS,
                ms
            ),
            (6, None, false)
        );
        drop(clock);
    }

    // ----- equivalence with the previous (main) macOS reader on healthy trees -----

    /// A transcription of main's recursive `walk_node` (before this branch), reading the fake
    /// tree directly: depth limit 40, node cap and visit budget as passed, `truncated` set
    /// exactly where main set it.
    struct Reference<'a> {
        nodes: &'a [FakeNode],
        max_nodes: usize,
        max_visited: usize,
        visited: usize,
        truncated: bool,
        out: Vec<AccessibilityNode>,
    }

    impl Reference<'_> {
        fn walk(&mut self, elem: usize, depth: usize) {
            if depth > 40 {
                return;
            }
            if self.out.len() >= self.max_nodes || self.visited >= self.max_visited {
                self.truncated = true;
                return;
            }
            self.visited += 1;
            let Some(node) = self.nodes.get(elem) else {
                return;
            };
            let Outcome::Ok(mut attrs) = FakeTree::decode(node, AttrSet::Node) else {
                return;
            };
            let children = attrs.children.take().unwrap_or_default();
            let role = node_role(&attrs);
            let name = node_name(&attrs, role);
            if is_captured(role, name.as_ref()) {
                let advertised = needs_expanded_advert(role, &attrs) && node.advertises_expanded;
                let index = self.out.len();
                self.out
                    .push(make_node(&attrs, role, name, index, advertised));
            }
            let budget = self.max_visited.saturating_sub(self.visited);
            let mut collected = Vec::new();
            for child in children {
                if collected.len() >= budget {
                    self.truncated = true;
                    break;
                }
                collected.push(child);
            }
            for child in collected {
                if self.out.len() >= self.max_nodes || self.visited >= self.max_visited {
                    self.truncated = true;
                    break;
                }
                self.walk(child, depth + 1);
            }
        }
    }

    fn reference(
        nodes: &[FakeNode],
        max_nodes: usize,
        max_visited: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut r = Reference {
            nodes,
            max_nodes,
            max_visited,
            visited: 0,
            truncated: false,
            out: Vec::new(),
        };
        r.walk(0, 0);
        (r.out, r.truncated)
    }

    /// A deterministic pseudo-random page (depth < 40) mixing every role the reader maps, links
    /// with and without URLs, duplicate names (for strict mode), unnamed containers, and
    /// expandable controls.
    fn generated_page(seed: u64, count: usize) -> Vec<FakeNode> {
        let mut state = seed;
        let mut next = move |bound: usize| -> usize {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap_or(0) % bound.max(1)
        };
        let roles = [
            "AXGroup",
            "AXLink",
            "AXButton",
            "AXStaticText",
            "AXCheckBox",
            "AXComboBox",
            "AXHeading",
            "AXUnknown",
            "AXTextField",
        ];
        let mut nodes: Vec<FakeNode> = (0..count)
            .map(|i| {
                let role = roles.get(next(roles.len())).copied().unwrap_or("AXGroup");
                let mut node = FakeNode::new(if i == 0 { "AXWebArea" } else { role })
                    .rect(0.0, 0.0, 10.0, 10.0);
                match next(4) {
                    0 => node = node.with(Attr::Title, s("Save")),
                    1 => node = node.with(Attr::Title, s(&format!("item {i}"))),
                    2 => node = node.with(Attr::Value, s(&format!("text {}", i % 3))),
                    _ => {}
                }
                if next(2) == 0 {
                    node = node.with(Attr::Url, url(&format!(" https://gen.test/{i} ")));
                }
                if next(3) == 0 {
                    node = node.with(Attr::Expanded, Fake::Bool(next(2) == 0));
                    node.advertises_expanded = next(2) == 0;
                }
                if next(3) == 0 {
                    node = node.with(Attr::Value, Fake::Int(i64::try_from(next(3)).unwrap_or(0)));
                }
                node
            })
            .collect();
        // Attach each node to an earlier parent, keeping depth well under 40.
        let mut parents: Vec<Vec<usize>> = vec![Vec::new(); count];
        let mut depth = vec![0usize; count];
        for child in 1..count {
            let mut parent = next(child);
            while depth.get(parent).copied().unwrap_or(0) >= 30 {
                parent = next(parent.max(1));
            }
            if let Some(kids) = parents.get_mut(parent) {
                kids.push(child);
            }
            let d = depth.get(parent).copied().unwrap_or(0) + 1;
            if let Some(slot) = depth.get_mut(child) {
                *slot = d;
            }
        }
        for (node, kids) in nodes.iter_mut().zip(parents) {
            if !kids.is_empty() {
                node.attrs.push((Attr::Children, Fake::Kids(kids)));
            }
        }
        nodes
    }

    fn strict_results(nodes: &[AccessibilityNode]) -> Vec<String> {
        let queries = [
            LocatorQuery::by_role(Role::Button, Some("Save".to_owned())),
            LocatorQuery::by_role(Role::Link, None),
            LocatorQuery::by_role(Role::Heading, Some("item 3".to_owned())),
            LocatorQuery::by_role(Role::Dialog, None),
        ];
        queries
            .into_iter()
            .flat_map(|mut q| {
                let loose = q.resolve_checked(nodes).map(|n| n.id.clone());
                q.strict = true;
                let strict = q.resolve_checked(nodes).map(|n| n.id.clone());
                [format!("{loose:?}"), format!("{strict:?}")]
            })
            .collect()
    }

    #[test]
    fn healthy_trees_match_the_previous_reader_exactly() {
        let mut pages = vec![page()];
        for seed in 1..=12 {
            pages.push(generated_page(
                seed,
                40 + usize::try_from(seed).unwrap_or(0) * 23,
            ));
        }
        for (i, nodes) in pages.iter().enumerate() {
            for max_nodes in [1, 2, 3, 7, 25, 2_000] {
                for max_visited in [1, 4, 30, 10_000] {
                    let limits = WalkLimits {
                        depth: SNAPSHOT_LIMITS.depth,
                        nodes: max_nodes,
                        visited: max_visited,
                    };
                    let clock = FakeClock::new();
                    let mut tree = FakeTree::new(nodes.clone(), &clock);
                    let ours = walk(&mut tree, &clock, &limits);
                    let (theirs, truncated) = reference(nodes, max_nodes, max_visited);
                    let context =
                        format!("page {i}, max_nodes {max_nodes}, max_visited {max_visited}");
                    assert_eq!(ours.nodes, theirs, "{context}");
                    assert_eq!(ours.truncation.truncated(), truncated, "{context}");
                    assert_eq!(
                        strict_results(&ours.nodes),
                        strict_results(&theirs),
                        "{context}"
                    );
                }
            }
            // The protocol path: `max_nodes` from the client with main's visit budget formula.
            for max_nodes in [1, 5, 2_000, 20_000] {
                let limits = WalkLimits::for_max_nodes(max_nodes);
                let clock = FakeClock::new();
                let mut tree = FakeTree::new(nodes.clone(), &clock);
                let ours = walk(&mut tree, &clock, &limits);
                let (theirs, truncated) =
                    reference(nodes, limits.nodes, 10_000.max(limits.nodes * 5));
                assert_eq!(
                    (ours.nodes, ours.truncation.truncated()),
                    (theirs, truncated),
                    "page {i}, max_nodes {max_nodes}"
                );
            }
        }
    }

    // ----- web-area selection -----

    fn candidate(url: Option<&str>, w: f64, h: f64, root: usize, order: usize) -> Candidate<usize> {
        Candidate {
            elem: order,
            url: url.map(str::to_owned),
            bounds: Bounds {
                x: 0.0,
                y: 0.0,
                width: w,
                height: h,
            },
            root,
            order,
        }
    }

    #[test]
    fn url_tiers_classify_browser_ui_and_devtools() {
        assert_eq!(url_tier(None), UrlTier::Page);
        assert_eq!(url_tier(Some("https://example.com/")), UrlTier::Page);
        assert_eq!(url_tier(Some("about:blank")), UrlTier::Page);
        assert_eq!(url_tier(Some("file:///tmp/x.html")), UrlTier::Page);
        assert_eq!(url_tier(Some("chrome://settings/")), UrlTier::BrowserUi);
        assert_eq!(
            url_tier(Some(
                "chrome-untrusted://read-anything-side-panel.top-chrome/"
            )),
            UrlTier::BrowserUi
        );
        assert_eq!(
            url_tier(Some("chrome-extension://abc/popup.html")),
            UrlTier::BrowserUi
        );
        assert_eq!(
            url_tier(Some("DEVTOOLS://devtools/bundled/devtools_app.html")),
            UrlTier::DevTools
        );
        assert_eq!(url_tier(Some("no scheme")), UrlTier::Page);
    }

    #[test]
    fn ranking_puts_the_focused_window_first() {
        let page = candidate(Some("https://a.test/"), 1200.0, 800.0, 0, 0);
        let navigating = candidate(Some("https://a.test/next"), 0.0, 0.0, 0, 1);
        let side_panel = candidate(Some("chrome://read-later/"), 300.0, 800.0, 0, 2);
        let devtools = candidate(Some("devtools://devtools/x"), 1200.0, 900.0, 0, 3);
        let other_window = candidate(Some("https://d.test/"), 2000.0, 2000.0, 1, 4);
        let newtab = candidate(Some("chrome://newtab/"), 1200.0, 800.0, 0, 5);

        // Within the focused window: page over side panel and DevTools.
        let all = [
            devtools.clone(),
            side_panel.clone(),
            page,
            other_window.clone(),
        ];
        assert_eq!(best_candidate(&all), Some(2));
        // A page that is 0x0 mid-navigation still beats DevTools in its window and a page in
        // another window.
        let mid_nav = [devtools.clone(), other_window.clone(), navigating];
        assert_eq!(best_candidate(&mid_nav), Some(2));
        // chrome://newtab in the focused window beats a regular page in another window.
        assert_eq!(best_candidate(&[other_window, newtab]), Some(1));
        // Without a regular page, WebUI beats DevTools.
        assert_eq!(best_candidate(&[devtools, side_panel]), Some(1));
        assert_eq!(best_candidate::<usize>(&[]), None);
    }

    // 0: app
    // 10: focused window [11 (tab strip), 12 (split)]
    //   11: AXTabGroup [20..=29 tabs]
    //   12: AXSplitGroup [13 (side panel), 14 (devtools), 15 (page)]
    //     13: AXWebArea chrome-untrusted://side-panel  300x800
    //     14: AXWebArea devtools://                    1200x300
    //     15: AXWebArea https://example.test/           1200x500 [16 iframe]
    //       16: AXWebArea (iframe, never visited)
    // 30: second window [31]
    //   31: AXWebArea https://other.test/ 1600x1000
    // 40: undocked DevTools window [41]
    //   41: AXWebArea devtools:// 800x600
    // 50: empty window (no web area)
    // 60: window showing chrome://newtab [61]
    //   61: AXWebArea chrome://newtab/ 1200x800
    fn browser() -> Vec<FakeNode> {
        let mut nodes = vec![FakeNode::default(); 70];
        let mut set = |i: usize, n: FakeNode| {
            if let Some(slot) = nodes.get_mut(i) {
                *slot = n;
            }
        };
        set(0, FakeNode::new("AXApplication").kids(&[10]));
        set(10, FakeNode::new("AXWindow").kids(&[11, 12]));
        set(
            11,
            FakeNode::new("AXTabGroup").kids(&(20..=29).collect::<Vec<_>>()),
        );
        set(12, FakeNode::new("AXSplitGroup").kids(&[13, 14, 15]));
        set(
            13,
            FakeNode::web("chrome-untrusted://side-panel/", 300.0, 800.0),
        );
        set(
            14,
            FakeNode::web("devtools://devtools/app.html", 1200.0, 300.0),
        );
        set(
            15,
            FakeNode::web("https://example.test/", 1200.0, 500.0).kids(&[16]),
        );
        set(16, FakeNode::new("AXWebArea"));
        for i in 20..=29 {
            set(i, FakeNode::new("AXRadioButton"));
        }
        set(30, FakeNode::new("AXWindow").kids(&[31]));
        set(31, FakeNode::web("https://other.test/", 1600.0, 1000.0));
        set(40, FakeNode::new("AXWindow").kids(&[41]));
        set(
            41,
            FakeNode::web("devtools://devtools/app.html", 800.0, 600.0),
        );
        set(50, FakeNode::new("AXWindow"));
        set(60, FakeNode::new("AXWindow").kids(&[61]));
        set(61, FakeNode::web("chrome://newtab/", 1200.0, 800.0));
        nodes
    }

    fn search(
        nodes: Vec<FakeNode>,
        focused: &[usize],
        others: &[usize],
    ) -> (WebAreaSearch<usize>, FakeTree) {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(nodes, &clock);
        tree.focused = focused.to_vec();
        tree.main = focused.to_vec();
        tree.all = others.to_vec();
        let found = find_web_area(&mut tree, &0, &WEB_AREA_SEARCH, &mut budget(&clock));
        let Ok(found) = found else {
            unreachable!("search failed: {found:?}");
        };
        (found, tree)
    }

    fn chosen(found: &WebAreaSearch<usize>) -> Option<usize> {
        found.web_area.as_ref().map(|c| c.elem)
    }

    #[test]
    fn web_area_search_picks_the_page_and_skips_the_tab_strip() {
        let (found, tree) = search(browser(), &[10], &[10, 30]);
        assert_eq!(chosen(&found), Some(15));
        assert_eq!(
            found.web_area.and_then(|c| c.url),
            Some("https://example.test/".to_owned())
        );
        assert_eq!(found.candidates, 3);
        assert_eq!(found.stats.roots, 1);
        assert_eq!(found.stats.stopped_by, None);
        assert!(!found.stats.truncated);
        // Never read: the iframe inside the page, any tab of the tab strip (a page was found
        // before the deferred tab strip), and the other window.
        assert!(
            !tree.reads.iter().any(|&r| r == 16 || r >= 20),
            "reads: {:?}",
            tree.reads
        );
        assert_eq!(tree.reads, [10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn deferred_areas_are_searched_when_nothing_else_has_a_page() {
        let mut nodes = browser();
        // The page sits inside the tab group; the rest of the window holds only DevTools.
        if let Some(n) = nodes.get_mut(10) {
            *n = FakeNode::new("AXWindow").kids(&[11, 14]);
        }
        if let Some(n) = nodes.get_mut(11) {
            *n = FakeNode::new("AXTabGroup").kids(&[20, 15]);
        }
        let (found, tree) = search(nodes, &[10], &[]);
        assert_eq!(chosen(&found), Some(15));
        assert!(tree.reads.contains(&20));
    }

    #[test]
    fn the_focused_window_wins_over_a_page_in_another_window() {
        // Focused window shows chrome://newtab: it is chosen, the other window is not read.
        let (found, tree) = search(browser(), &[60], &[60, 30]);
        assert_eq!(chosen(&found), Some(61));
        assert_eq!(found.stats.roots, 1);
        assert!(!tree.reads.contains(&31));

        // Focused window's page is 0x0 while navigating: still chosen.
        let mut nodes = browser();
        if let Some(n) = nodes.get_mut(61) {
            *n = FakeNode::web("https://navigating.test/", 0.0, 0.0);
        }
        let (found, _) = search(nodes, &[60], &[60, 30]);
        assert_eq!(chosen(&found), Some(61));

        // Undocked DevTools focused: its web area is chosen (documented limit: other windows are
        // only considered when the focused window has no web area at all).
        let (found, _) = search(browser(), &[40], &[40, 10]);
        assert_eq!(chosen(&found), Some(41));
    }

    #[test]
    fn other_windows_are_searched_only_without_any_web_area_in_the_focused_one() {
        let (found, _) = search(browser(), &[50], &[50, 30, 10]);
        assert_eq!(chosen(&found), Some(31));
        assert_eq!(found.stats.roots, 2);

        // No windows exposed at all: search the application element itself.
        let (found, _) = search(browser(), &[], &[]);
        assert_eq!(chosen(&found), Some(15));
    }

    #[test]
    fn web_area_search_reports_truncation_and_absence() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(browser(), &clock);
        tree.focused = vec![10];
        let limits = SearchLimits {
            depth: 1,
            visited: 100,
        };
        let found = find_web_area(&mut tree, &0, &limits, &mut budget(&clock));
        assert_eq!(
            found.map(|f| (f.web_area.is_none(), f.stats.truncated)),
            Ok((true, true))
        );

        let mut tree = FakeTree::new(browser(), &clock);
        tree.focused = vec![10];
        let limits = SearchLimits {
            depth: 24,
            visited: 2,
        };
        let found = find_web_area(&mut tree, &0, &limits, &mut budget(&clock));
        assert_eq!(
            found.map(|f| (f.web_area.is_none(), f.stats.truncated, f.stats.visited)),
            Ok((true, true, 2))
        );
    }

    #[test]
    fn a_stopped_search_returns_the_best_web_area_found_so_far() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(browser(), &clock);
        tree.focused = vec![10];
        tree.read_cost = Duration::from_secs(2);
        // Reads at 2 s each: 10, 11, 12, 13, 14 fit in 10 s; 15 (the page) does not.
        let found = find_web_area(&mut tree, &0, &WEB_AREA_SEARCH, &mut budget(&clock));
        assert_eq!(
            found.map(|f| (chosen(&f), f.stats.stopped_by)),
            Ok((Some(13), Some(Limit::Deadline)))
        );

        // Unanswered window reads: nothing found, no error.
        let mut nodes = browser();
        for node in &mut nodes {
            node.unresponsive = true;
        }
        let (found, _) = search(nodes, &[10], &[10]);
        assert_eq!(chosen(&found), None);
    }

    #[test]
    fn an_unanswered_focused_window_never_falls_through_to_another_window() {
        // The focused window's batched probe times out but role + children answer: the page in
        // the focused window is still found through the per-attribute fallback.
        let mut nodes = browser();
        if let Some(n) = nodes.get_mut(10) {
            n.batch_unresponsive = true;
        }
        let (found, tree) = search(nodes, &[10], &[10, 30]);
        assert_eq!(chosen(&found), Some(15));
        assert_eq!(tree.each_reads, [10]);
        assert!(!found.stats.unanswered);

        // The focused window does not answer at all: no web area this time, and the page in the
        // other window (31) is neither read nor chosen.
        let mut nodes = browser();
        if let Some(n) = nodes.get_mut(10) {
            n.unresponsive = true;
        }
        let (found, tree) = search(nodes, &[10], &[10, 30]);
        assert_eq!(chosen(&found), None);
        assert!(found.stats.unanswered);
        assert!(!tree.reads.contains(&30) && !tree.reads.contains(&31));
    }

    #[test]
    fn a_search_does_not_start_window_reads_past_the_deadline() {
        let clock = FakeClock::new();
        let mut tree = FakeTree::new(browser(), &clock);
        tree.focused = vec![10];
        let mut budget = budget(&clock);
        clock.advance(Duration::from_secs(10));
        let found = find_web_area(&mut tree, &0, &WEB_AREA_SEARCH, &mut budget);
        assert_eq!(
            found.map(|f| (chosen(&f), f.stats.stopped_by)),
            Ok((None, Some(Limit::Deadline)))
        );
        assert_eq!(tree.reads.len(), 0);
    }

    // ----- AXEnhancedUserInterface / AXManualAccessibility -----

    #[test]
    fn flag_values_decode_from_slots() {
        assert_eq!(flag_value::<Fake>(&Slot::Missing), FlagValue::Absent);
        assert_eq!(
            flag_value::<Fake>(&Slot::Error(AX_ERROR_NO_VALUE)),
            FlagValue::Absent
        );
        assert_eq!(
            flag_value::<Fake>(&Slot::Error(AX_ERROR_ATTRIBUTE_UNSUPPORTED)),
            FlagValue::Absent
        );
        assert_eq!(
            flag_value::<Fake>(&Slot::Error(AX_ERROR_CANNOT_COMPLETE)),
            FlagValue::Unreadable
        );
        assert_eq!(flag_value(&Slot::Value(Fake::Bool(true))), FlagValue::On);
        assert_eq!(flag_value(&Slot::Value(Fake::Bool(false))), FlagValue::Off);
        assert_eq!(flag_value(&Slot::Value(Fake::Int(1))), FlagValue::On);
        assert_eq!(flag_value(&Slot::Value(s("yes"))), FlagValue::Unreadable);
        assert_eq!(set_result(AX_ERROR_SUCCESS), SetResult::Set);
        assert_eq!(set_result(AX_ERROR_CANNOT_COMPLETE), SetResult::TimedOut);
        assert_eq!(
            set_result(AX_ERROR_ATTRIBUTE_UNSUPPORTED),
            SetResult::Failed
        );
    }

    #[test]
    fn a_flag_is_reasserted_whenever_it_is_found_off() {
        let t0 = Instant::now();
        let mut flag = FlagState::new();
        assert!(flag.plan(FlagValue::Off, t0));
        flag.record_set(SetResult::Set, t0);
        // On: nothing to do.
        assert!(!flag.plan(FlagValue::On, t0));
        // Another client turned it off later: set it again right away.
        assert!(flag.plan(FlagValue::Off, t0 + Duration::from_secs(60)));
        flag.record_set(SetResult::Set, t0 + Duration::from_secs(60));
        // The prior value is the one before the driver first turned it on.
        assert_eq!(flag.prior(), Some(FlagValue::Off));
        assert_eq!(flag.restore_value(), Some(false));
    }

    #[test]
    fn a_flag_that_was_already_on_or_unreadable_is_never_restored() {
        let t0 = Instant::now();
        let mut on = FlagState::new();
        assert!(!on.plan(FlagValue::On, t0));
        assert_eq!(on.restore_value(), None);

        // Unreadable: no write (it would only time out again) and nothing to restore.
        let mut unknown = FlagState::new();
        assert!(!unknown.plan(FlagValue::Unreadable, t0));
        assert_eq!(unknown.prior(), None);
        assert_eq!(unknown.restore_value(), None);

        // Absent before: turned on, but never written back to off (it might have been on).
        let mut absent = FlagState::new();
        assert!(absent.plan(FlagValue::Absent, t0));
        absent.record_set(SetResult::Set, t0);
        assert_eq!(absent.prior(), Some(FlagValue::Absent));
        assert_eq!(absent.restore_value(), None);
    }

    #[test]
    fn failed_writes_back_off_in_time_but_are_never_capped() {
        let t0 = Instant::now();
        let mut flag = FlagState::new();
        assert!(flag.plan(FlagValue::Off, t0));
        flag.record_set(SetResult::Failed, t0);
        assert!(!flag.plan(FlagValue::Off, t0 + Duration::from_millis(100)));
        assert!(flag.plan(FlagValue::Off, t0 + Duration::from_millis(250)));
        assert_eq!(flag.restore_value(), None);

        let mut now = t0;
        for _ in 0..50 {
            flag.record_set(SetResult::Failed, now);
            now += FLAG_RETRY_MAX;
            assert!(flag.plan(FlagValue::Off, now));
        }
        assert_eq!(flag_retry_delay(1), Duration::from_millis(250));
        assert_eq!(flag_retry_delay(2), Duration::from_millis(500));
        assert_eq!(flag_retry_delay(3), Duration::from_secs(1));
        assert_eq!(flag_retry_delay(40), FLAG_RETRY_MAX);
    }

    #[test]
    fn a_timed_out_write_counts_as_possibly_ours() {
        let t0 = Instant::now();
        let mut flag = FlagState::new();
        assert!(flag.plan(FlagValue::Off, t0));
        flag.record_set(SetResult::TimedOut, t0);
        assert_eq!(flag.restore_value(), Some(false));
        // It backs off before writing again.
        assert!(!flag.plan(FlagValue::Off, t0 + Duration::from_millis(10)));
    }

    // ----- warning rate limit -----

    #[test]
    fn warnings_are_rate_limited_per_key() {
        let t0 = Instant::now();
        let mut gate = WarnGate::new();
        assert!(gate.should_warn("a", t0));
        assert!(!gate.should_warn("a", t0 + Duration::from_millis(75)));
        assert!(gate.should_warn("b", t0 + Duration::from_millis(75)));
        assert!(!gate.should_warn("a", t0 + Duration::from_secs(29)));
        assert!(gate.should_warn("a", t0 + WARN_INTERVAL));
        // The key set is bounded.
        for i in 0..100 {
            assert!(gate.should_warn(&format!("k{i}"), t0));
        }
        assert!(gate.last.len() <= WARN_GATE_KEYS);
    }
}
