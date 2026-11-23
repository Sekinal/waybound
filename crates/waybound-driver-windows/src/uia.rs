//! Windows `UIAutomation` tree querying and snapshot normalization.
//!
//! Two backends produce the same [`UiaSnapshot`]:
//! - **native COM** (default): in-process `IUIAutomation` on a dedicated MTA worker thread,
//!   see `uia_com.rs`;
//! - **PowerShell**: the original `powershell.exe` + .NET `UIAutomationClient` walker below,
//!   selected with `WAYBOUND_WINDOWS_UIA=powershell`, and used automatically when COM
//!   initialization fails.
//!
//! Both feed [`finalize_snapshot`], so role mapping, state mapping, the node cap and id
//! assignment are shared.

use serde::Deserialize;
use waybound_core::{
    AccessibilityNode, Bounds, MAX_MAX_NODES, MIN_MAX_NODES, Result, Role, WayboundError,
};

#[cfg(target_os = "windows")]
pub use crate::uia_model::UiaBackend;
#[cfg(target_os = "windows")]
use crate::uia_model::{UIA_BACKEND_ENV, parse_uia_backend};

/// Prefix of the positional ids used when an element has no UIA runtime id.
pub const POSITIONAL_ID_PREFIX: &str = "uia-pos-";

/// Maximum number of accessibility nodes accepted from a single UIA tree snapshot.
pub const MAX_NODES: usize = 4_000;

/// Parsed snapshot of a Windows `UIAutomation` tree.
#[derive(Debug, Clone, PartialEq)]
pub struct UiaSnapshot {
    /// Flattened accessibility nodes up to the requested node limit.
    pub nodes: Vec<AccessibilityNode>,
    /// `true` when traversal stopped early because the node cap was reached.
    pub truncated: bool,
    /// Current URL extracted from the browser address bar, if available.
    pub current_url: Option<String>,
    /// Visible screen-space bounds of the active web viewport, if available.
    pub viewport_bounds: Option<Bounds>,
}

/// Maps a Windows `UIAutomation` `ControlType` programmatic name (with optional
/// `LocalizedControlType`) to a normalized [`Role`].
#[must_use]
pub fn map_uia_control_type(control_type: &str, localized: Option<&str>) -> Role {
    let trimmed = control_type.trim();
    let base = trimmed
        .strip_prefix("ControlType.")
        .or_else(|| trimmed.strip_prefix("controltype."))
        .unwrap_or(trimmed);

    let localized_norm = localized
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    if let Some(loc) = localized_norm.as_deref() {
        if loc == "switch" || loc == "toggle switch" || loc == "toggle" {
            return Role::Switch;
        }
        if (base.eq_ignore_ascii_case("window")
            || base.eq_ignore_ascii_case("pane")
            || base.eq_ignore_ascii_case("custom")
            || base.eq_ignore_ascii_case("group"))
            && (loc.contains("dialog") || loc == "alertdialog")
        {
            return Role::Dialog;
        }
        if (base.eq_ignore_ascii_case("text")
            || base.eq_ignore_ascii_case("group")
            || base.eq_ignore_ascii_case("custom"))
            && loc == "heading"
        {
            return Role::Heading;
        }
        if loc == "searchbox" || loc == "search" {
            return Role::SearchBox;
        }
        if loc == "region" || loc == "landmark" {
            return Role::Region;
        }
    }

    match base.to_ascii_lowercase().as_str() {
        "button" | "splitbutton" => Role::Button,
        "hyperlink" => Role::Link,
        "edit" => Role::TextBox,
        "checkbox" => Role::CheckBox,
        "radiobutton" => Role::Radio,
        "toggle" | "switch" => Role::Switch,
        "combobox" => Role::ComboBox,
        "list" => Role::ListBox,
        "listitem" => Role::Option,
        "tabitem" | "tab" => Role::Tab,
        "dialog" => Role::Dialog,
        "group" => Role::Group,
        "image" => Role::Img,
        "menuitem" => Role::MenuItem,
        "document" => Role::Document,
        "header" | "headeritem" => Role::Heading,
        "text" => Role::StaticText,
        _ => Role::Unknown,
    }
}

/// Un-normalized snapshot, as emitted by the PowerShell walker (JSON) or assembled by the
/// native COM backend. Both go through [`finalize_snapshot`], so the two backends share every
/// normalization rule.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawUiaSnapshot {
    #[serde(default)]
    pub(crate) nodes: Vec<RawUiaNode>,
    #[serde(default)]
    pub(crate) truncated: bool,
    #[serde(default)]
    pub(crate) current_url: Option<String>,
    #[serde(default)]
    pub(crate) viewport_bounds: Option<RawBounds>,
}

/// One un-normalized UIA element (see [`RawUiaSnapshot`]).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RawUiaNode {
    #[serde(default)]
    pub(crate) id: Option<String>,
    pub(crate) control_type: String,
    #[serde(default)]
    pub(crate) localized_control_type: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<String>,
    #[serde(default)]
    pub(crate) x: f64,
    #[serde(default)]
    pub(crate) y: f64,
    #[serde(default)]
    pub(crate) width: f64,
    #[serde(default)]
    pub(crate) height: f64,
    #[serde(default)]
    pub(crate) focused: bool,
    /// `TogglePattern.ToggleState` (`0` off, `1` on, `2` indeterminate), if supported.
    #[serde(default)]
    pub(crate) toggle_state: Option<i64>,
    /// `SelectionItemPattern.IsSelected` (radio buttons), if supported.
    #[serde(default)]
    pub(crate) selected: Option<bool>,
    /// `AutomationElement.IsEnabled`; a missing value means enabled.
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    /// `ExpandCollapsePattern.ExpandCollapseState`
    /// (`0` collapsed, `1` expanded, `2` partially expanded, `3` leaf), if supported.
    #[serde(default)]
    pub(crate) expand_state: Option<i64>,
    /// Resolved target URL (`href`) for hyperlink nodes (`ValuePattern.Current.Value`).
    #[serde(default)]
    pub(crate) url: Option<String>,
}

/// Derives the checked state from UIA patterns for checkable roles.
///
/// Checkboxes and switches use `TogglePattern` (indeterminate maps to `Some(false)`); radio
/// buttons use `SelectionItemPattern.IsSelected` and fall back to `TogglePattern`.
#[must_use]
pub fn uia_checked(role: Role, toggle_state: Option<i64>, selected: Option<bool>) -> Option<bool> {
    let from_toggle = toggle_state.and_then(|state| match state {
        1 => Some(true),
        0 | 2 => Some(false),
        _ => None,
    });
    match role {
        Role::CheckBox | Role::Switch | Role::MenuItem => from_toggle,
        Role::Radio => selected.or(from_toggle),
        _ => None,
    }
}

/// Maps `ExpandCollapseState` to the expanded state (`LeafNode` and unknown values are `None`).
#[must_use]
pub const fn uia_expanded(expand_state: Option<i64>) -> Option<bool> {
    match expand_state {
        Some(0) => Some(false),
        Some(1 | 2) => Some(true),
        _ => None,
    }
}

/// Un-validated viewport rectangle (see [`RawUiaSnapshot`]).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub(crate) struct RawBounds {
    pub(crate) x: f64,
    pub(crate) y: f64,
    pub(crate) width: f64,
    pub(crate) height: f64,
}

fn is_valid_bounds(b: &Bounds) -> bool {
    b.x.is_finite()
        && b.y.is_finite()
        && b.width.is_finite()
        && b.height.is_finite()
        && b.width >= 0.0
        && b.height >= 0.0
}

fn normalize_non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

/// Parses a JSON payload emitted by the Windows `UIAutomation` tree walker into a
/// validated [`UiaSnapshot`], enforcing [`MAX_NODES`] and finite bounds.
///
/// # Errors
///
/// Returns [`WayboundError::Io`] with [`std::io::ErrorKind::InvalidData`] if `raw` is not valid
/// UIA snapshot JSON.
pub fn parse_uia_snapshot_json(raw: &str) -> Result<UiaSnapshot> {
    parse_uia_snapshot_json_limited(raw, MAX_NODES)
}

/// Parses a JSON payload emitted by the Windows `UIAutomation` tree walker into a
/// validated [`UiaSnapshot`], enforcing `max_nodes` (clamped to `1..=20_000`) and finite bounds.
///
/// # Errors
///
/// Returns [`WayboundError::Io`] with [`std::io::ErrorKind::InvalidData`] if `raw` is not valid
/// UIA snapshot JSON.
pub fn parse_uia_snapshot_json_limited(raw: &str, max_nodes: usize) -> Result<UiaSnapshot> {
    let parsed: RawUiaSnapshot = serde_json::from_str(raw.trim()).map_err(|err| {
        WayboundError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid UIA snapshot JSON: {err}"),
        ))
    })?;
    Ok(finalize_snapshot(parsed, max_nodes))
}

/// Validates and normalizes a raw snapshot from either backend: drops nodes with non-finite or
/// negative bounds, enforces `max_nodes` (clamped to `1..=20_000`), maps roles and states,
/// assigns positional ids to nodes without a runtime id, and infers the viewport.
pub(crate) fn finalize_snapshot(parsed: RawUiaSnapshot, max_nodes: usize) -> UiaSnapshot {
    let limit = max_nodes.clamp(MIN_MAX_NODES, MAX_MAX_NODES);
    let mut nodes = Vec::with_capacity(parsed.nodes.len().min(limit));
    let mut inferred_viewport: Option<Bounds> = None;
    let mut truncated = parsed.truncated;

    for (idx, raw_node) in parsed.nodes.into_iter().enumerate() {
        let bounds = Bounds {
            x: raw_node.x,
            y: raw_node.y,
            width: raw_node.width,
            height: raw_node.height,
        };
        if !is_valid_bounds(&bounds) {
            continue;
        }
        if nodes.len() >= limit {
            truncated = true;
            break;
        }

        let role = map_uia_control_type(
            &raw_node.control_type,
            raw_node.localized_control_type.as_deref(),
        );

        if inferred_viewport.is_none()
            && role == Role::Document
            && bounds.width > 0.0
            && bounds.height > 0.0
        {
            inferred_viewport = Some(bounds);
        }

        let id = normalize_non_empty(raw_node.id)
            .unwrap_or_else(|| format!("{POSITIONAL_ID_PREFIX}{idx}"));

        nodes.push(AccessibilityNode {
            id,
            role,
            name: normalize_non_empty(raw_node.name),
            value: normalize_non_empty(raw_node.value),
            bounds,
            focused: raw_node.focused,
            checked: uia_checked(role, raw_node.toggle_state, raw_node.selected),
            disabled: raw_node.enabled == Some(false),
            expanded: uia_expanded(raw_node.expand_state),
            url: normalize_non_empty(raw_node.url),
        });
    }

    let explicit_viewport = parsed.viewport_bounds.and_then(|raw_b| {
        let b = Bounds {
            x: raw_b.x,
            y: raw_b.y,
            width: raw_b.width,
            height: raw_b.height,
        };
        if is_valid_bounds(&b) && b.width > 0.0 && b.height > 0.0 {
            Some(b)
        } else {
            None
        }
    });

    UiaSnapshot {
        nodes,
        truncated,
        current_url: normalize_non_empty(parsed.current_url),
        viewport_bounds: explicit_viewport.or(inferred_viewport),
    }
}

/// Caller-side deadline for one `UIAutomation` query, for either backend.
#[cfg(target_os = "windows")]
pub(crate) const UIA_QUERY_TIMEOUT_MS: u64 = 10_000;

#[cfg(target_os = "windows")]
const UIA_POWERSHELL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$targetPidRaw = $env:WAYBOUND_TARGET_PID
$maxNodes = 4000
if ($env:WAYBOUND_MAX_NODES -and $env:WAYBOUND_MAX_NODES -match '^\d+$') {
    $parsedMax = [int]$env:WAYBOUND_MAX_NODES
    if ($parsedMax -lt 1) { $parsedMax = 1 }
    if ($parsedMax -gt 20000) { $parsedMax = 20000 }
    $maxNodes = $parsedMax
}
$truncated = $false
$root = [System.Windows.Automation.AutomationElement]::RootElement
$targetWindow = $null

if ($targetPidRaw -and $targetPidRaw.Trim() -ne '') {
    $pidInt = [int]$targetPidRaw
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
        $pidInt
    )
    $targetWindow = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
} else {
    $procs = Get-Process -Name 'chrome','msedge','chromium' -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
            [int]$p.Id
        )
        $cand = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
        if ($null -ne $cand) {
            $targetWindow = $cand
            break
        }
    }
}

if ($null -eq $targetWindow) {
    @{ nodes = @(); current_url = $null; viewport_bounds = $null } | ConvertTo-Json -Depth 4 -Compress
    exit 0
}

$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
$currentUrl = $null
$viewportBounds = $null
$webRoot = $null

# Extract omnibox URL and active web document root so web locators don't match browser chrome.
try {
    $editCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Edit
    )
    $edits = $targetWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $editCond)
    foreach ($ed in $edits) {
        try {
            $edName = $ed.Current.Name
            $vp = $null
            if ($ed.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
                $edVal = $vp.Current.Value
                if ($edVal -and (($edName -and $edName -match 'Address|URL') -or $edVal -match '^https?://')) {
                    $currentUrl = $edVal
                    break
                }
            }
        } catch {}
    }
} catch {}

try {
    $docCond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Document
    )
    $docs = $targetWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $docCond)
    $bestArea = -1.0
    foreach ($doc in $docs) {
        try {
            $r = $doc.Current.BoundingRectangle
            if (-not [double]::IsInfinity($r.Width) -and -not [double]::IsNaN($r.Width) -and $r.Width -gt 0 -and $r.Height -gt 0) {
                $area = [double]$r.Width * [double]$r.Height
                if ($area -gt $bestArea) {
                    $bestArea = $area
                    $webRoot = $doc
                    $viewportBounds = @{ x = [double]$r.X; y = [double]$r.Y; width = [double]$r.Width; height = [double]$r.Height }
                }
            } elseif ($null -eq $webRoot) {
                $webRoot = $doc
            }
        } catch {}
    }
} catch {}

$queue = New-Object System.Collections.Generic.Queue[System.Windows.Automation.AutomationElement]
$queue.Enqueue($(if ($null -ne $webRoot) { $webRoot } else { $targetWindow }))

$nodes = New-Object System.Collections.Generic.List[object]

while ($queue.Count -gt 0 -and $nodes.Count -lt $maxNodes) {
    $el = $queue.Dequeue()
    try {
        $cur = $el.Current
        $rect = $cur.BoundingRectangle
        $x = if ([double]::IsInfinity($rect.X) -or [double]::IsNaN($rect.X)) { 0.0 } else { [double]$rect.X }
        $y = if ([double]::IsInfinity($rect.Y) -or [double]::IsNaN($rect.Y)) { 0.0 } else { [double]$rect.Y }
        $w = if ([double]::IsInfinity($rect.Width) -or [double]::IsNaN($rect.Width) -or $rect.Width -lt 0) { 0.0 } else { [double]$rect.Width }
        $h = if ([double]::IsInfinity($rect.Height) -or [double]::IsNaN($rect.Height) -or $rect.Height -lt 0) { 0.0 } else { [double]$rect.Height }

        $ct = $cur.ControlType.ProgrammaticName
        $loc = $cur.LocalizedControlType
        $name = $cur.Name
        $val = $null
        try {
            $vp = $null
            if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {
                $val = $vp.Current.Value
            }
        } catch {}

        # Probe state patterns only on control types that can carry them: each
        # TryGetCurrentPattern is a cross-process call.
        $toggleState = $null
        if ($ct -eq 'ControlType.CheckBox' -or $ct -eq 'ControlType.RadioButton' -or $ct -eq 'ControlType.Button' -or $ct -eq 'ControlType.MenuItem') {
            try {
                $tp = $null
                if ($el.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$tp)) {
                    $toggleState = [int]$tp.Current.ToggleState
                }
            } catch {}
        }
        $selected = $null
        if ($ct -eq 'ControlType.RadioButton') {
            try {
                $sp = $null
                if ($el.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$sp)) {
                    $selected = [bool]$sp.Current.IsSelected
                }
            } catch {}
        }
        $expandState = $null
        if ($ct -eq 'ControlType.ComboBox' -or $ct -eq 'ControlType.Button' -or $ct -eq 'ControlType.MenuItem' -or $ct -eq 'ControlType.TreeItem' -or $ct -eq 'ControlType.Hyperlink' -or $ct -eq 'ControlType.SplitButton') {
            try {
                $ep = $null
                if ($el.TryGetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern, [ref]$ep)) {
                    $expandState = [int]$ep.Current.ExpandCollapseState
                }
            } catch {}
        }

        $rid = $el.GetRuntimeId()
        $idStr = if ($null -ne $rid) { ($rid -join '-') } else { "uia-pos-$($nodes.Count)" }

        if ($null -eq $currentUrl -and $ct -eq 'ControlType.Edit' -and $val) {
            if (($name -and $name -match 'Address|URL') -or $val -match '^https?://') {
                $currentUrl = $val
            }
        }

        if ($null -eq $viewportBounds -and $ct -eq 'ControlType.Document' -and $w -gt 0 -and $h -gt 0) {
            $viewportBounds = @{ x = $x; y = $y; width = $w; height = $h }
        }

        $linkUrl = $null
        if ($ct -eq 'ControlType.Hyperlink' -and $val -and $val.Trim() -ne '') {
            $linkUrl = $val.Trim()
        }

        $nodes.Add(@{
            id = $idStr
            control_type = $ct
            localized_control_type = $loc
            name = $name
            value = $val
            x = $x
            y = $y
            width = $w
            height = $h
            focused = [bool]$cur.HasKeyboardFocus
            enabled = [bool]$cur.IsEnabled
            toggle_state = $toggleState
            selected = $selected
            expand_state = $expandState
            url = $linkUrl
        })

        $child = $walker.GetFirstChild($el)
        while ($null -ne $child) {
            if (($nodes.Count + $queue.Count) -ge $maxNodes) {
                $truncated = $true
                break
            }
            $queue.Enqueue($child)
            $child = $walker.GetNextSibling($child)
        }
    } catch {}
}

if ($queue.Count -gt 0) {
    $truncated = $true
}

@{
    nodes = $nodes
    truncated = $truncated
    current_url = $currentUrl
    viewport_bounds = $viewportBounds
} | ConvertTo-Json -Depth 4 -Compress
"#;

/// Queries the live Windows `UIAutomation` tree for the target browser `pid`
/// (or the first detected Chromium browser window when `pid` is `None`), capped at
/// [`MAX_NODES`].
///
/// Uses the backend selected by [`crate::uia_model::UIA_BACKEND_ENV`] (see
/// [`query_uia_tree_limited`]).
///
/// # Errors
///
/// Same as [`query_uia_tree_limited`].
#[cfg(target_os = "windows")]
pub fn query_uia_tree(pid: Option<i32>) -> Result<UiaSnapshot> {
    query_uia_tree_limited(pid, MAX_NODES)
}

/// Returns the configured backend, logging the choice once per process.
#[cfg(target_os = "windows")]
fn configured_backend() -> UiaBackend {
    static CHOICE: std::sync::OnceLock<UiaBackend> = std::sync::OnceLock::new();
    *CHOICE.get_or_init(|| {
        let raw = std::env::var(UIA_BACKEND_ENV).ok();
        let (backend, recognized) = parse_uia_backend(raw.as_deref());
        if recognized {
            tracing::info!(
                backend = backend.as_str(),
                env = UIA_BACKEND_ENV,
                "Windows UIAutomation backend selected"
            );
        } else {
            tracing::warn!(
                value = raw.as_deref().unwrap_or_default(),
                env = UIA_BACKEND_ENV,
                "unrecognized Windows UIAutomation backend; using native COM (set `powershell` for the fallback)"
            );
        }
        backend
    })
}

/// Queries the live Windows `UIAutomation` tree capped at `max_nodes` (clamped to
/// `1..=20_000`).
///
/// The backend is in-process COM `IUIAutomation` unless `WAYBOUND_WINDOWS_UIA=powershell`
/// selects the original PowerShell walker. If COM itself cannot be initialized, every query
/// falls back to PowerShell (logged once at `warn`).
///
/// # Errors
///
/// Returns [`WayboundError::Timeout`] if the query does not finish within 10 seconds or a
/// provider times out, [`WayboundError::Transient`] if the browser window went away mid-query
/// (native backend), [`WayboundError::BackendUnavailable`] for other `UIAutomation` failures
/// (the message carries the `HRESULT`) or a failed PowerShell run, or [`WayboundError::Io`] on
/// process spawning or JSON parsing failures (PowerShell backend).
#[cfg(target_os = "windows")]
pub fn query_uia_tree_limited(pid: Option<i32>, max_nodes: usize) -> Result<UiaSnapshot> {
    query_uia_tree_with_backend(pid, max_nodes, configured_backend())
}

/// Like [`query_uia_tree_limited`], with an explicit backend (for tests and diagnostics).
/// [`UiaBackend::NativeCom`] still falls back to PowerShell if COM cannot be initialized.
///
/// # Errors
///
/// Same as [`query_uia_tree_limited`].
#[cfg(target_os = "windows")]
pub fn query_uia_tree_with_backend(
    pid: Option<i32>,
    max_nodes: usize,
    backend: UiaBackend,
) -> Result<UiaSnapshot> {
    let limit = max_nodes.clamp(MIN_MAX_NODES, MAX_MAX_NODES);
    match backend {
        UiaBackend::PowerShell => query_uia_tree_powershell(pid, limit),
        UiaBackend::NativeCom => match crate::uia_com::query(pid, limit) {
            crate::uia_com::NativeOutcome::Done(raw) => {
                raw.map(|raw| finalize_snapshot(raw, limit))
            }
            crate::uia_com::NativeOutcome::Unavailable(reason) => {
                tracing::debug!(%reason, "native UIAutomation unavailable; using PowerShell");
                query_uia_tree_powershell(pid, limit)
            }
        },
    }
}

/// Runs the PowerShell walker (`powershell.exe` + .NET `UIAutomationClient`) with a
/// 10-second timeout.
#[cfg(target_os = "windows")]
fn query_uia_tree_powershell(pid: Option<i32>, limit: usize) -> Result<UiaSnapshot> {
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    tracing::debug!(
        ?pid,
        limit,
        backend = "powershell",
        "querying Windows UIAutomation tree"
    );

    let mut cmd = waybound_core::process::command("powershell.exe");
    let _ = cmd
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(UIA_POWERSHELL_SCRIPT)
        .env("WAYBOUND_MAX_NODES", limit.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(target_pid) = pid {
        let _ = cmd.env("WAYBOUND_TARGET_PID", target_pid.to_string());
    } else {
        let _ = cmd.env_remove("WAYBOUND_TARGET_PID");
    }

    let mut child = cmd.spawn()?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || -> std::io::Result<String> {
        let mut buf = String::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_string(&mut buf)?;
        }
        Ok(buf)
    });

    let stderr_handle = std::thread::spawn(move || -> std::io::Result<String> {
        let mut buf = String::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_string(&mut buf)?;
        }
        Ok(buf)
    });

    let deadline = Instant::now() + Duration::from_millis(UIA_QUERY_TIMEOUT_MS);
    let status = loop {
        if let Some(exit_status) = child.try_wait()? {
            break exit_status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WayboundError::Timeout {
                timeout_ms: UIA_QUERY_TIMEOUT_MS,
                context: "Windows UIAutomation PowerShell query".to_owned(),
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout_handle
        .join()
        .map_err(|_| WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: "stdout reader thread panicked".to_owned(),
        })??;

    let stderr = stderr_handle
        .join()
        .map_err(|_| WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: "stderr reader thread panicked".to_owned(),
        })??;

    if !status.success() {
        return Err(WayboundError::BackendUnavailable {
            backend: "windows".to_owned(),
            reason: format!(
                "UIAutomation PowerShell exited with {status}: {}",
                stderr.trim()
            ),
        });
    }

    parse_uia_snapshot_json_limited(&stdout, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_sixteen_uia_roles() {
        assert_eq!(map_uia_control_type("Button", None), Role::Button);
        assert_eq!(
            map_uia_control_type("ControlType.Hyperlink", None),
            Role::Link
        );
        assert_eq!(map_uia_control_type("Edit", None), Role::TextBox);
        assert_eq!(map_uia_control_type("CheckBox", None), Role::CheckBox);
        assert_eq!(map_uia_control_type("RadioButton", None), Role::Radio);
        assert_eq!(map_uia_control_type("Toggle", None), Role::Switch);
        assert_eq!(map_uia_control_type("Switch", None), Role::Switch);
        assert_eq!(
            map_uia_control_type("CheckBox", Some("toggle switch")),
            Role::Switch
        );
        assert_eq!(map_uia_control_type("ComboBox", None), Role::ComboBox);
        assert_eq!(map_uia_control_type("List", None), Role::ListBox);
        assert_eq!(map_uia_control_type("ListItem", None), Role::Option);
        assert_eq!(map_uia_control_type("TabItem", None), Role::Tab);
        assert_eq!(map_uia_control_type("Tab", None), Role::Tab);
        assert_eq!(map_uia_control_type("Window", Some("dialog")), Role::Dialog);
        assert_eq!(
            map_uia_control_type("Pane", Some("alertdialog")),
            Role::Dialog
        );
        assert_eq!(map_uia_control_type("MenuItem", None), Role::MenuItem);
        assert_eq!(map_uia_control_type("Document", None), Role::Document);
        assert_eq!(map_uia_control_type("Header", None), Role::Heading);
        assert_eq!(map_uia_control_type("Text", Some("heading")), Role::Heading);
        assert_eq!(map_uia_control_type("Text", None), Role::StaticText);
        assert_eq!(map_uia_control_type("Window", None), Role::Unknown);
        assert_eq!(map_uia_control_type("ScrollBar", None), Role::Unknown);
    }

    #[test]
    fn parses_valid_uia_snapshot_json() -> Result<()> {
        let json = r#"{
            "current_url": "https://example.com/search",
            "viewport_bounds": { "x": 0.0, "y": 80.0, "width": 1280.0, "height": 720.0 },
            "nodes": [
                {
                    "id": "42-100",
                    "control_type": "ControlType.Button",
                    "localized_control_type": "button",
                    "name": "Submit",
                    "value": "",
                    "x": 100.0,
                    "y": 200.0,
                    "width": 80.0,
                    "height": 32.0,
                    "focused": true
                },
                {
                    "control_type": "Edit",
                    "name": "Search",
                    "value": "rust",
                    "x": 10.0,
                    "y": 20.0,
                    "width": 200.0,
                    "height": 28.0,
                    "focused": false
                }
            ]
        }"#;

        let snapshot = parse_uia_snapshot_json(json)?;
        assert_eq!(
            snapshot.current_url.as_deref(),
            Some("https://example.com/search")
        );
        assert_eq!(
            snapshot.viewport_bounds,
            Some(Bounds {
                x: 0.0,
                y: 80.0,
                width: 1280.0,
                height: 720.0,
            })
        );
        assert_eq!(snapshot.nodes.len(), 2);

        let first = snapshot.nodes.first();
        assert_eq!(first.map(|n| n.id.as_str()), Some("42-100"));
        assert_eq!(first.map(|n| n.role), Some(Role::Button));
        assert_eq!(first.and_then(|n| n.name.as_deref()), Some("Submit"));
        assert_eq!(first.and_then(|n| n.value.as_deref()), None);
        assert_eq!(first.map(|n| n.focused), Some(true));

        let second = snapshot.nodes.get(1);
        assert_eq!(second.map(|n| n.id.as_str()), Some("uia-pos-1"));
        assert_eq!(second.map(|n| n.role), Some(Role::TextBox));
        assert_eq!(second.and_then(|n| n.value.as_deref()), Some("rust"));
        Ok(())
    }

    #[test]
    fn enforces_max_nodes_cap_and_filters_negative_bounds() -> Result<()> {
        let mut items = Vec::with_capacity(MAX_NODES + 25);
        for i in 0..(MAX_NODES + 25) {
            items.push(format!(
                r#"{{"id":"n-{i}","control_type":"Button","x":1.0,"y":2.0,"width":10.0,"height":10.0}}"#
            ));
        }
        let raw = format!(r#"{{"nodes":[{}]}}"#, items.join(","));
        let snapshot = parse_uia_snapshot_json(&raw)?;
        assert_eq!(snapshot.nodes.len(), MAX_NODES);

        let bad_bounds = r#"{"nodes":[
            {"id":"neg","control_type":"Button","x":0.0,"y":0.0,"width":-5.0,"height":10.0},
            {"id":"ok","control_type":"Document","x":0.0,"y":50.0,"width":800.0,"height":600.0}
        ]}"#;
        let filtered = parse_uia_snapshot_json(bad_bounds)?;
        assert_eq!(filtered.nodes.len(), 1);
        assert_eq!(
            filtered.viewport_bounds,
            Some(Bounds {
                x: 0.0,
                y: 50.0,
                width: 800.0,
                height: 600.0,
            })
        );
        Ok(())
    }

    #[test]
    fn parses_toggle_enabled_and_expand_states() -> Result<()> {
        let json = r#"{"nodes":[
            {"id":"cb","control_type":"ControlType.CheckBox","name":"Agree","x":0,"y":0,"width":10,"height":10,
             "enabled":true,"toggle_state":1,"selected":null,"expand_state":null},
            {"id":"mixed","control_type":"ControlType.CheckBox","name":"All","x":0,"y":0,"width":10,"height":10,
             "enabled":false,"toggle_state":2},
            {"id":"radio","control_type":"ControlType.RadioButton","name":"Economy","x":0,"y":0,"width":10,"height":10,
             "enabled":true,"selected":true},
            {"id":"combo","control_type":"ControlType.ComboBox","name":"Cabin","x":0,"y":0,"width":10,"height":10,
             "enabled":true,"expand_state":0},
            {"id":"pressed","control_type":"ControlType.Button","name":"Bold","x":0,"y":0,"width":10,"height":10,
             "enabled":true,"toggle_state":1,"expand_state":3},
            {"id":"legacy","control_type":"ControlType.Button","name":"Old","x":0,"y":0,"width":10,"height":10}
        ]}"#;
        let snapshot = parse_uia_snapshot_json(json)?;
        let states: Vec<(&str, Option<bool>, bool, Option<bool>)> = snapshot
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n.checked, n.disabled, n.expanded))
            .collect();
        assert_eq!(
            states,
            vec![
                ("cb", Some(true), false, None),
                ("mixed", Some(false), true, None),
                ("radio", Some(true), false, None),
                ("combo", None, false, Some(false)),
                ("pressed", None, false, None),
                ("legacy", None, false, None),
            ]
        );
        Ok(())
    }

    #[test]
    fn uia_state_helpers_map_pattern_values() {
        assert_eq!(uia_checked(Role::CheckBox, Some(0), None), Some(false));
        assert_eq!(uia_checked(Role::Switch, Some(1), None), Some(true));
        assert_eq!(uia_checked(Role::CheckBox, None, None), None);
        assert_eq!(uia_checked(Role::Radio, Some(0), Some(true)), Some(true));
        assert_eq!(uia_checked(Role::Radio, Some(1), None), Some(true));
        assert_eq!(uia_checked(Role::Button, Some(1), Some(true)), None);
        assert_eq!(uia_expanded(Some(1)), Some(true));
        assert_eq!(uia_expanded(Some(2)), Some(true));
        assert_eq!(uia_expanded(Some(3)), None);
        assert_eq!(uia_expanded(None), None);
    }

    #[test]
    fn parses_link_url_field_and_omits_empty() -> Result<()> {
        let json = r#"{"nodes":[
            {"id":"l1","control_type":"ControlType.Hyperlink","name":"About","url":"  https://example.com/about  ","x":0,"y":0,"width":50,"height":20},
            {"id":"l2","control_type":"ControlType.Hyperlink","name":"Blank","url":"   ","x":0,"y":20,"width":50,"height":20},
            {"id":"b1","control_type":"ControlType.Button","name":"Go","x":0,"y":40,"width":50,"height":20}
        ]}"#;
        let snapshot = parse_uia_snapshot_json(json)?;
        assert_eq!(snapshot.nodes.len(), 3);
        assert_eq!(
            snapshot.nodes[0].url.as_deref(),
            Some("https://example.com/about")
        );
        assert_eq!(snapshot.nodes[1].url, None);
        assert_eq!(snapshot.nodes[2].url, None);
        Ok(())
    }

    #[test]
    fn rejects_malformed_uia_json() {
        let err = parse_uia_snapshot_json("{not valid json");
        assert!(err.is_err());
    }
}
