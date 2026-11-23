//! Pure-Rust AT-SPI2 D-Bus accessibility client via `zbus`.
//!
//! Replaces per-snapshot `python3` (`gi.repository.Atspi`) subprocess spawns with a
//! persistent D-Bus connection to the AT-SPI2 accessibility bus, cutting snapshot
//! latency from ~150–250 ms to a few milliseconds with `#![forbid(unsafe_code)]`.
//!
//! # Tree walk strategies
//!
//! AT-SPI2 has no bulk "give me the subtree" call that Chromium answers: its ATK bridge
//! does not implement `org.a11y.atspi.Cache.GetItems` (the method call fails with
//! `UnknownMethod`), and even where `GetItems` exists it carries neither extents, link URIs
//! nor text. Each node therefore needs 4–6 calls (`GetRoleName`, `Name`, `GetExtents`,
//! `GetChildren`, plus `GetState`, `GetURI` or text depending on the role).
//!
//! * [`WalkStrategy::Pipelined`] (default) keeps a bounded window of nodes in flight on the
//!   one connection: every call for a node is sent without waiting for the previous reply,
//!   and replies are consumed in breadth-first order, so the result is identical to the
//!   sequential walk while paying the D-Bus round trip once per window instead of once
//!   per call. Calls for at most `window` nodes are outstanding at any time.
//! * [`WalkStrategy::Sequential`] is the original one-call-at-a-time walk, kept as the
//!   reference and as the fallback when the pipelined walk hits a transport-level error
//!   (I/O failure, bus limits).
//!
//! Set `WAYBOUND_ATSPI_WALK=sequential` to force the sequential walk (for debugging).
//! Which walk ran is logged at `debug` level.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::StreamExt as _;
use futures_util::future::{join, join3, join4};
use futures_util::stream::FuturesOrdered;
use tracing::debug;
use waybound_core::{AccessibilityNode, Bounds, Result, Role, WayboundError};
use zbus::Message;
use zbus::blocking::{Connection, connection::Builder};
use zbus::zvariant::{DynamicType, OwnedObjectPath, OwnedValue};

use crate::atspi::{
    AtspiSnapshot, AtspiStates, MAX_NODES, decode_atspi_node_states, is_atspi_showing,
    is_checkable_atspi_role, map_atspi_role,
};
use crate::process::BACKEND_NAME;

const REGISTRY_BUS: &str = "org.a11y.atspi.Registry";
const REGISTRY_ROOT: &str = "/org/a11y/atspi/accessible/root";
const IFACE_ACCESSIBLE: &str = "org.a11y.atspi.Accessible";
const IFACE_COMPONENT: &str = "org.a11y.atspi.Component";
const IFACE_DOCUMENT: &str = "org.a11y.atspi.Document";
const IFACE_HYPERLINK: &str = "org.a11y.atspi.Hyperlink";
const IFACE_TEXT: &str = "org.a11y.atspi.Text";
const IFACE_PROPERTIES: &str = "org.freedesktop.DBus.Properties";

/// `ATSPI_COORD_TYPE_SCREEN = 0`.
const COORD_TYPE_SCREEN: u32 = 0;
const CHROME_TOKENS: [&str; 4] = ["chrome", "chromium", "google-chrome", "brave"];

type AccessibleRef = (String, OwnedObjectPath);
type ResolvedRoot = (Option<AccessibleRef>, Option<String>, Option<Bounds>);

/// Environment variable selecting the tree walk: `sequential` forces
/// [`WalkStrategy::Sequential`]; anything else (or unset) uses the pipelined default.
pub const WALK_STRATEGY_ENV: &str = "WAYBOUND_ATSPI_WALK";

/// Default number of nodes whose AT-SPI2 calls may be in flight at once in the
/// pipelined walk (each node has at most 4 concurrent calls outstanding).
pub const DEFAULT_PIPELINE_WINDOW: usize = 64;

/// Upper bound on the pipelined walk's in-flight node window.
pub const MAX_PIPELINE_WINDOW: usize = 512;

/// How [`AtspiClient`] walks the AT-SPI2 tree. Both produce identical snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkStrategy {
    /// One blocking D-Bus call at a time (the reference implementation).
    Sequential,
    /// Calls for up to `window` nodes (clamped to 1 ..= [`MAX_PIPELINE_WINDOW`]) in flight
    /// at once, consumed in breadth-first order.
    Pipelined {
        /// Maximum number of nodes being fetched concurrently.
        window: usize,
    },
}

impl Default for WalkStrategy {
    fn default() -> Self {
        Self::Pipelined {
            window: DEFAULT_PIPELINE_WINDOW,
        }
    }
}

impl WalkStrategy {
    /// Reads [`WALK_STRATEGY_ENV`] (`WAYBOUND_ATSPI_WALK`): `sequential` selects
    /// [`WalkStrategy::Sequential`], anything else the pipelined default.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(std::env::var(WALK_STRATEGY_ENV).ok().as_deref())
    }

    fn parse(raw: Option<&str>) -> Self {
        match raw.map(|value| value.trim().to_ascii_lowercase()) {
            Some(value) if value == "sequential" => Self::Sequential,
            _ => Self::default(),
        }
    }
}

/// Persistent pure-Rust D-Bus client connected to the AT-SPI2 accessibility bus.
pub struct AtspiClient {
    conn: Connection,
}

impl std::fmt::Debug for AtspiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtspiClient").finish_non_exhaustive()
    }
}

impl AtspiClient {
    /// Connects to the AT-SPI2 accessibility D-Bus (via `AT_SPI_BUS_ADDRESS` or
    /// `org.a11y.Bus.GetAddress` on the session bus).
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the accessibility bus cannot
    /// be discovered or connected.
    pub fn connect() -> Result<Self> {
        let addr = discover_a11y_bus_address()?;
        let conn = Builder::address(addr.as_str())
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("invalid AT-SPI2 bus address {addr:?}: {err}"),
            })?
            .build()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to connect to AT-SPI2 bus: {err}"),
            })?;
        debug!(addr = %addr, "connected native pure-Rust AtspiClient");
        Ok(Self { conn })
    }

    /// Lists the applications registered on the AT-SPI2 registry root.
    fn registry_apps(&self) -> Result<Vec<AccessibleRef>> {
        self.get_children(REGISTRY_BUS, REGISTRY_ROOT)
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("AT-SPI2 Registry GetChildren failed: {err}"),
            })
    }

    /// Resolves the currently attached `document web` node from the live application tree.
    ///
    /// We intentionally avoid caching the document object path across calls: Chrome keeps
    /// navigated-away documents alive in its `BFcache` answering D-Bus queries (`GetRoleName`,
    /// `GetState`, `GetExtents`, `GetChildren`) with frozen state even after detaching them
    /// from the active window hierarchy.
    fn resolve_web_root(&self, target_pid: Option<i32>) -> Result<ResolvedRoot> {
        let apps = self.registry_apps()?;
        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok((None, None, None));
        };
        Ok(self.locate_web_document(&target_app))
    }

    /// [`Self::resolve_web_root`] using `strategy`, falling back to the sequential scan when
    /// the pipelined one hits a transport-level error.
    fn resolve_web_root_with(
        &self,
        target_pid: Option<i32>,
        strategy: WalkStrategy,
    ) -> Result<ResolvedRoot> {
        let WalkStrategy::Pipelined { window } = strategy else {
            debug!("resolving AT-SPI2 web root with the sequential scan");
            return self.resolve_web_root(target_pid);
        };
        let apps = self.registry_apps()?;
        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok((None, None, None));
        };
        let walker = PipelinedWalker::new(self.conn.inner(), window);
        let resolved = futures_lite::future::block_on(walker.locate_web_document(&target_app));
        if walker.failed.load(Ordering::Relaxed) {
            debug!("pipelined AT-SPI2 root scan failed; falling back to the sequential scan");
            return Ok(self.locate_web_document(&target_app));
        }
        debug!(window, "resolved AT-SPI2 web root with the pipelined scan");
        Ok(resolved)
    }

    /// Fast-path URL lookup on the active web document without walking DOM children.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn current_url(&mut self, target_pid: Option<i32>) -> Result<Option<String>> {
        let (_, url, _) = self.resolve_web_root_with(target_pid, WalkStrategy::from_env())?;
        Ok(url.filter(|u| !u.trim().is_empty()))
    }

    /// Fast-path viewport bounds lookup on the active web document without walking DOM children.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn viewport_bounds(&mut self, target_pid: Option<i32>) -> Result<Option<Bounds>> {
        let (_, _, bounds) = self.resolve_web_root_with(target_pid, WalkStrategy::from_env())?;
        Ok(bounds)
    }

    /// Captures a bounded accessibility snapshot of the active browser web document.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn snapshot(&mut self, target_pid: Option<i32>) -> Result<AtspiSnapshot> {
        self.snapshot_limited(target_pid, MAX_NODES)
    }

    /// Captures an accessibility snapshot of the active browser web document capped at
    /// `max_nodes`, reporting whether traversal was truncated.
    ///
    /// Uses [`WalkStrategy::from_env`] (pipelined unless `WAYBOUND_ATSPI_WALK=sequential`).
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn snapshot_limited(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
    ) -> Result<AtspiSnapshot> {
        self.snapshot_with_strategy(target_pid, max_nodes, WalkStrategy::from_env())
    }

    /// Captures an accessibility snapshot capped at `max_nodes` with an explicit tree walk
    /// `strategy`. The pipelined walk falls back to the sequential one when it hits a
    /// transport-level error; both return identical snapshots for an unchanging page.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn snapshot_with_strategy(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
        strategy: WalkStrategy,
    ) -> Result<AtspiSnapshot> {
        let limit = max_nodes.clamp(waybound_core::MIN_MAX_NODES, waybound_core::MAX_MAX_NODES);
        if let WalkStrategy::Pipelined { window } = strategy {
            if let Some(snapshot) = self.snapshot_pipelined(target_pid, limit, window)? {
                debug!(
                    window,
                    nodes = snapshot.nodes.len(),
                    truncated = snapshot.truncated,
                    "AT-SPI2 snapshot via the pipelined walk"
                );
                return Ok(snapshot);
            }
            debug!("pipelined AT-SPI2 walk failed; falling back to the sequential walk");
        }
        let snapshot = self.snapshot_sequential(target_pid, limit)?;
        debug!(
            nodes = snapshot.nodes.len(),
            truncated = snapshot.truncated,
            "AT-SPI2 snapshot via the sequential walk"
        );
        Ok(snapshot)
    }

    /// The reference walk: one blocking D-Bus call at a time.
    fn snapshot_sequential(&self, target_pid: Option<i32>, limit: usize) -> Result<AtspiSnapshot> {
        let (web_root, current_url, viewport_bounds) = self.resolve_web_root(target_pid)?;
        let Some(root) = web_root else {
            return Ok(AtspiSnapshot {
                nodes: Vec::new(),
                truncated: false,
                current_url,
                viewport_bounds,
            });
        };
        let (nodes, truncated) = self.walk_web_document(&root, limit);
        Ok(finish_snapshot(
            nodes,
            truncated,
            current_url,
            viewport_bounds,
        ))
    }

    /// The pipelined walk. `Ok(None)` means it hit a transport-level error and the caller
    /// should fall back to [`Self::snapshot_sequential`].
    fn snapshot_pipelined(
        &self,
        target_pid: Option<i32>,
        limit: usize,
        window: usize,
    ) -> Result<Option<AtspiSnapshot>> {
        let apps = self.registry_apps()?;
        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok(Some(AtspiSnapshot {
                nodes: Vec::new(),
                truncated: false,
                current_url: None,
                viewport_bounds: None,
            }));
        };
        let walker = PipelinedWalker::new(self.conn.inner(), window);
        let ((web_root, current_url, viewport_bounds), tree) =
            futures_lite::future::block_on(async {
                let resolved = walker.locate_web_document(&target_app).await;
                let tree = match &resolved.0 {
                    Some(root) => Some(walker.walk_web_document(root, limit).await),
                    None => None,
                };
                (resolved, tree)
            });
        if walker.failed.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let snapshot = match (web_root, tree) {
            (Some(_), Some((nodes, truncated))) => {
                finish_snapshot(nodes, truncated, current_url, viewport_bounds)
            }
            _ => AtspiSnapshot {
                nodes: Vec::new(),
                truncated: false,
                current_url,
                viewport_bounds,
            },
        };
        Ok(Some(snapshot))
    }

    fn find_target_app(
        &self,
        apps: &[AccessibleRef],
        target_pid: Option<i32>,
    ) -> Option<AccessibleRef> {
        for (bus, path) in apps {
            if bus.is_empty() {
                continue;
            }
            if let Some(pid) = target_pid {
                if self
                    .bus_pid(bus)
                    .is_some_and(|p| i32::try_from(p).ok() == Some(pid))
                {
                    return Some((bus.clone(), path.clone()));
                }
            } else {
                let name = self
                    .get_name(bus, path.as_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if CHROME_TOKENS.iter().any(|tok| name.contains(tok)) {
                    return Some((bus.clone(), path.clone()));
                }
            }
        }
        None
    }

    fn locate_web_document(
        &self,
        app: &AccessibleRef,
    ) -> (Option<AccessibleRef>, Option<String>, Option<Bounds>) {
        let mut current_url: Option<String> = None;
        let mut viewport_bounds: Option<Bounds> = None;
        let mut web_root: Option<AccessibleRef> = None;
        let mut best_showing = false;
        let mut best_area: f64 = -1.0;

        let mut queue: VecDeque<AccessibleRef> = VecDeque::new();
        queue.push_back(app.clone());
        let mut scanned: usize = 0;

        while let Some((bus, path)) = queue.pop_front() {
            if scanned >= MAX_NODES {
                break;
            }
            scanned += 1;
            let role_raw = self
                .get_role_name(&bus, path.as_str())
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();

            if role_raw == "entry"
                && current_url.is_none()
                && self.get_name(&bus, path.as_str()).as_deref() == Some("Address and search bar")
                && let Some(val) = self.read_text(&bus, path.as_str())
                && !val.trim().is_empty()
            {
                current_url = Some(val.trim().to_owned());
            }

            if role_raw == "document web" || role_raw == "document frame" {
                let showing = self
                    .get_state(&bus, path.as_str())
                    .is_some_and(|words| is_atspi_showing(&words));
                if let Some(bounds) = self.get_extents(&bus, path.as_str()) {
                    let area = bounds.width.max(0.0) * bounds.height.max(0.0);
                    let is_better =
                        (showing && !best_showing) || (showing == best_showing && area > best_area);
                    if is_better {
                        best_showing = showing;
                        best_area = area;
                        web_root = Some((bus.clone(), path.clone()));
                        if bounds.width > 0.0 && bounds.height > 0.0 {
                            viewport_bounds = Some(bounds);
                        }
                        if let Some(doc_url) = self.get_document_url(&bus, path.as_str()) {
                            current_url = Some(doc_url);
                        }
                    }
                } else if web_root.is_none() {
                    web_root = Some((bus.clone(), path.clone()));
                    if let Some(doc_url) = self.get_document_url(&bus, path.as_str()) {
                        current_url = Some(doc_url);
                    }
                }
                continue;
            }

            if let Ok(children) = self.get_children(&bus, path.as_str()) {
                for child in children {
                    if !child.0.is_empty() {
                        queue.push_back(child);
                    }
                }
            }
        }

        (web_root, current_url, viewport_bounds)
    }

    fn walk_web_document(
        &self,
        root: &AccessibleRef,
        max_nodes: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut nodes = Vec::new();
        let mut truncated = false;
        let mut queue: VecDeque<AccessibleRef> = VecDeque::new();
        queue.push_back(root.clone());

        while let Some((bus, path)) = queue.pop_front() {
            if nodes.len() >= max_nodes {
                truncated = true;
                break;
            }

            let role_raw = self.get_role_name(&bus, path.as_str()).unwrap_or_default();
            let role = map_atspi_role(&role_raw);
            let mut name = self.get_name(&bus, path.as_str());
            let value = if matches!(role, Role::TextBox | Role::SearchBox | Role::ComboBox) {
                self.read_text(&bus, path.as_str())
            } else {
                None
            };
            if name.is_none() && role == Role::StaticText {
                name = self.read_text(&bus, path.as_str());
            }
            let bounds = self.get_extents(&bus, path.as_str()).unwrap_or(Bounds {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            });
            // One `GetState` round trip per node yields focused, checked, disabled, and
            // expanded together; text, unknown, and document nodes skip it entirely.
            let states = if matches!(role, Role::StaticText | Role::Unknown | Role::Document) {
                AtspiStates::default()
            } else {
                self.get_state(&bus, path.as_str())
                    .map_or_else(AtspiStates::default, |words| {
                        decode_atspi_node_states(&words, role, is_checkable_atspi_role(&role_raw))
                    })
            };

            let url = if role == Role::Link {
                self.get_hyperlink_uri(&bus, path.as_str())
            } else {
                None
            };

            if bounds.width >= 0.0 && bounds.height >= 0.0 {
                nodes.push(AccessibilityNode {
                    id: format!("atspi-{}", nodes.len()),
                    role,
                    name,
                    value,
                    bounds,
                    focused: states.focused,
                    checked: states.checked,
                    disabled: states.disabled,
                    expanded: states.expanded,
                    url,
                });
            }

            if let Ok(children) = self.get_children(&bus, path.as_str()) {
                let free_slots = queue_room(max_nodes, nodes.len(), queue.len());
                truncated |= enqueue_children(&mut queue, children, free_slots);
            }
        }

        (nodes, truncated)
    }

    fn bus_pid(&self, bus: &str) -> Option<u32> {
        let msg = self
            .conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetConnectionUnixProcessID",
                &(bus,),
            )
            .ok()?;
        msg.body().deserialize::<u32>().ok()
    }

    fn get_children(
        &self,
        bus: &str,
        path: &str,
    ) -> std::result::Result<Vec<AccessibleRef>, zbus::Error> {
        let msg =
            self.conn
                .call_method(Some(bus), path, Some(IFACE_ACCESSIBLE), "GetChildren", &())?;
        decode_children(&msg)
    }

    fn get_role_name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_ACCESSIBLE), "GetRoleName", &())
            .ok()?;
        decode_role_name(&msg)
    }

    fn get_name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(
                Some(bus),
                path,
                Some(IFACE_PROPERTIES),
                "Get",
                &(IFACE_ACCESSIBLE, "Name"),
            )
            .ok()?;
        decode_name(&msg)
    }

    fn get_extents(&self, bus: &str, path: &str) -> Option<Bounds> {
        let msg = self
            .conn
            .call_method(
                Some(bus),
                path,
                Some(IFACE_COMPONENT),
                "GetExtents",
                &(COORD_TYPE_SCREEN,),
            )
            .ok()?;
        decode_extents(&msg)
    }

    fn get_state(&self, bus: &str, path: &str) -> Option<Vec<u32>> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_ACCESSIBLE), "GetState", &())
            .ok()?;
        decode_state(&msg)
    }

    fn get_document_url(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_DOCUMENT), "GetAttributes", &())
            .ok()?;
        decode_document_url(&msg)
    }

    fn get_hyperlink_uri(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_HYPERLINK), "GetURI", &(0i32,))
            .ok()?;
        decode_trimmed_string(&msg)
    }

    fn read_text(&self, bus: &str, path: &str) -> Option<String> {
        let count_msg = self
            .conn
            .call_method(
                Some(bus),
                path,
                Some(IFACE_PROPERTIES),
                "Get",
                &(IFACE_TEXT, "CharacterCount"),
            )
            .ok()?;
        let count = decode_character_count(&count_msg)?;
        let text_msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_TEXT), "GetText", &(0i32, count))
            .ok()?;
        decode_trimmed_string(&text_msg)
    }
}

/// Builds the final snapshot, dropping a blank document URL.
fn finish_snapshot(
    nodes: Vec<AccessibilityNode>,
    truncated: bool,
    mut current_url: Option<String>,
    viewport_bounds: Option<Bounds>,
) -> AtspiSnapshot {
    if current_url.as_deref().is_some_and(|u| u.trim().is_empty()) {
        current_url = None;
    }
    AtspiSnapshot {
        nodes,
        truncated,
        current_url,
        viewport_bounds,
    }
}

/// How many more accessibles the walk queue may hold. Visited plus queued nodes are capped
/// at `4 * max_nodes + 1024` so a node reporting a huge child list cannot grow the queue
/// without bound; the cap is far above what a walk limited to `max_nodes` ever consumes.
const fn queue_room(max_nodes: usize, visited: usize, queued: usize) -> usize {
    max_nodes
        .saturating_mul(4)
        .saturating_add(1_024)
        .saturating_sub(visited.saturating_add(queued))
}

/// Appends the children with a bus name to `queue`, at most `room` of them. Returns `true`
/// when some were dropped for lack of room (the walk is then reported as truncated).
fn enqueue_children(
    queue: &mut VecDeque<AccessibleRef>,
    children: Vec<AccessibleRef>,
    room: usize,
) -> bool {
    let mut room = room;
    for child in children {
        if child.0.is_empty() {
            continue;
        }
        if room == 0 {
            return true;
        }
        queue.push_back(child);
        room -= 1;
    }
    false
}

fn decode_children(msg: &Message) -> std::result::Result<Vec<AccessibleRef>, zbus::Error> {
    msg.body().deserialize::<Vec<AccessibleRef>>()
}

fn decode_role_name(msg: &Message) -> Option<String> {
    msg.body().deserialize::<String>().ok()
}

fn decode_name(msg: &Message) -> Option<String> {
    let val = msg.body().deserialize::<OwnedValue>().ok()?;
    let s: String = val.try_into().ok()?;
    let trimmed = s.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn decode_extents(msg: &Message) -> Option<Bounds> {
    let (x, y, w, h) = msg.body().deserialize::<(i32, i32, i32, i32)>().ok()?;
    Some(Bounds {
        x: f64::from(x),
        y: f64::from(y),
        width: f64::from(w),
        height: f64::from(h),
    })
}

fn decode_state(msg: &Message) -> Option<Vec<u32>> {
    msg.body().deserialize::<Vec<u32>>().ok()
}

fn decode_document_url(msg: &Message) -> Option<String> {
    let attrs = msg.body().deserialize::<HashMap<String, String>>().ok()?;
    attrs
        .get("DocURL")
        .or_else(|| attrs.get("URI"))
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// `Text.CharacterCount`, when it is in `1..=4096`.
fn decode_character_count(msg: &Message) -> Option<i32> {
    let count_val = msg.body().deserialize::<OwnedValue>().ok()?;
    let count: i32 = count_val.try_into().ok()?;
    (1..=4_096).contains(&count).then_some(count)
}

fn decode_trimmed_string(msg: &Message) -> Option<String> {
    let text = msg.body().deserialize::<String>().ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// `true` for errors that mean the connection or the bus is in trouble rather than that
/// one accessible could not answer (a dead node, a missing interface). The sequential walk
/// treats every error as "no value", so a pipelined walk that sees one of these is
/// abandoned and redone sequentially instead.
fn is_transport_failure(err: &zbus::Error) -> bool {
    const BUS_LIMIT_ERRORS: [&str; 3] = [
        "org.freedesktop.DBus.Error.LimitsExceeded",
        "org.freedesktop.DBus.Error.NoMemory",
        "org.freedesktop.DBus.Error.Disconnected",
    ];
    match err {
        zbus::Error::InputOutput(_) | zbus::Error::Connection(..) => true,
        zbus::Error::MethodError(name, _, _) => BUS_LIMIT_ERRORS.contains(&name.as_str()),
        zbus::Error::FDO(fdo) => matches!(
            **fdo,
            zbus::fdo::Error::LimitsExceeded(_)
                | zbus::fdo::Error::NoMemory(_)
                | zbus::fdo::Error::Disconnected(_)
        ),
        _ => false,
    }
}

/// Everything the walk needs from one accessible, fetched with pipelined calls.
struct FetchedNode {
    role_raw: String,
    name: Option<String>,
    text: Option<String>,
    extents: Option<Bounds>,
    state: Option<Vec<u32>>,
    url: Option<String>,
    children: Option<Vec<AccessibleRef>>,
}

/// What the web-root scan needs from one accessible of the browser UI tree.
struct ScannedNode {
    role_raw: String,
    /// Text of an `entry` named "Address and search bar".
    address_bar_text: Option<String>,
    /// `(showing, extents, DocURL)` of a `document web` / `document frame`.
    document: Option<(bool, Option<Bounds>, Option<String>)>,
    children: Option<Vec<AccessibleRef>>,
}

/// Issues AT-SPI2 calls concurrently on the async half of the client's connection.
///
/// Every call a node needs is sent before its replies are awaited, and up to `window`
/// nodes are in flight at once; results are consumed in queue order, so the walk visits
/// exactly the nodes, in exactly the order, of the sequential walk.
struct PipelinedWalker<'a> {
    conn: &'a zbus::Connection,
    window: usize,
    /// Set when a call failed for a transport-level reason (see [`is_transport_failure`]).
    failed: AtomicBool,
}

impl<'a> PipelinedWalker<'a> {
    fn new(conn: &'a zbus::Connection, window: usize) -> Self {
        Self {
            conn,
            window: window.clamp(1, MAX_PIPELINE_WINDOW),
            failed: AtomicBool::new(false),
        }
    }

    async fn call<B>(
        &self,
        bus: &str,
        path: &str,
        iface: &str,
        method: &str,
        body: &B,
    ) -> Option<Message>
    where
        B: serde::Serialize + DynamicType + Sync,
    {
        match self
            .conn
            .call_method(Some(bus), path, Some(iface), method, body)
            .await
        {
            Ok(msg) => Some(msg),
            Err(err) => {
                if is_transport_failure(&err) && !self.failed.swap(true, Ordering::Relaxed) {
                    debug!(%err, method, "AT-SPI2 transport failure in the pipelined walk");
                }
                None
            }
        }
    }

    async fn children(&self, bus: &str, path: &str) -> Option<Vec<AccessibleRef>> {
        let msg = self
            .call(bus, path, IFACE_ACCESSIBLE, "GetChildren", &())
            .await?;
        decode_children(&msg).ok()
    }

    async fn role_name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .call(bus, path, IFACE_ACCESSIBLE, "GetRoleName", &())
            .await?;
        decode_role_name(&msg)
    }

    async fn name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .call(
                bus,
                path,
                IFACE_PROPERTIES,
                "Get",
                &(IFACE_ACCESSIBLE, "Name"),
            )
            .await?;
        decode_name(&msg)
    }

    async fn extents(&self, bus: &str, path: &str) -> Option<Bounds> {
        let msg = self
            .call(
                bus,
                path,
                IFACE_COMPONENT,
                "GetExtents",
                &(COORD_TYPE_SCREEN,),
            )
            .await?;
        decode_extents(&msg)
    }

    async fn state(&self, bus: &str, path: &str) -> Option<Vec<u32>> {
        let msg = self
            .call(bus, path, IFACE_ACCESSIBLE, "GetState", &())
            .await?;
        decode_state(&msg)
    }

    async fn document_url(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .call(bus, path, IFACE_DOCUMENT, "GetAttributes", &())
            .await?;
        decode_document_url(&msg)
    }

    async fn hyperlink_uri(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .call(bus, path, IFACE_HYPERLINK, "GetURI", &(0i32,))
            .await?;
        decode_trimmed_string(&msg)
    }

    async fn read_text(&self, bus: &str, path: &str) -> Option<String> {
        let count_msg = self
            .call(
                bus,
                path,
                IFACE_PROPERTIES,
                "Get",
                &(IFACE_TEXT, "CharacterCount"),
            )
            .await?;
        let count = decode_character_count(&count_msg)?;
        let text_msg = self
            .call(bus, path, IFACE_TEXT, "GetText", &(0i32, count))
            .await?;
        decode_trimmed_string(&text_msg)
    }

    /// Fetches one web node: role, name, extents and children in parallel, then the
    /// role-dependent text, state and link URI in parallel.
    async fn fetch_node(&self, node: AccessibleRef) -> FetchedNode {
        let (bus, path) = (node.0.as_str(), node.1.as_str());
        let (role_raw, name, extents, children) = join4(
            self.role_name(bus, path),
            self.name(bus, path),
            self.extents(bus, path),
            self.children(bus, path),
        )
        .await;
        let role_raw = role_raw.unwrap_or_default();
        let role = map_atspi_role(&role_raw);
        let wants_text = matches!(role, Role::TextBox | Role::SearchBox | Role::ComboBox)
            || (name.is_none() && role == Role::StaticText);
        let wants_state = !matches!(role, Role::StaticText | Role::Unknown | Role::Document);
        let wants_url = role == Role::Link;
        let (text, state, url) = join3(
            async {
                if wants_text {
                    self.read_text(bus, path).await
                } else {
                    None
                }
            },
            async {
                if wants_state {
                    self.state(bus, path).await
                } else {
                    None
                }
            },
            async {
                if wants_url {
                    self.hyperlink_uri(bus, path).await
                } else {
                    None
                }
            },
        )
        .await;
        FetchedNode {
            role_raw,
            name,
            text,
            extents,
            state,
            url,
            children,
        }
    }

    /// Pipelined equivalent of [`AtspiClient::walk_web_document`].
    async fn walk_web_document(
        &self,
        root: &AccessibleRef,
        max_nodes: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut nodes = Vec::new();
        let mut truncated = false;
        let mut queue: VecDeque<AccessibleRef> = VecDeque::new();
        queue.push_back(root.clone());
        let mut in_flight = FuturesOrdered::new();

        loop {
            // Only start nodes the sequential walk would also reach: it stops once
            // `max_nodes` nodes are kept, and every in-flight node may still be kept.
            while in_flight.len() < self.window && nodes.len() + in_flight.len() < max_nodes {
                let Some(next) = queue.pop_front() else {
                    break;
                };
                in_flight.push_back(self.fetch_node(next));
            }
            let Some(fetched) = in_flight.next().await else {
                break;
            };
            let FetchedNode {
                role_raw,
                mut name,
                text,
                extents,
                state,
                url,
                children,
            } = fetched;

            let role = map_atspi_role(&role_raw);
            let value = if matches!(role, Role::TextBox | Role::SearchBox | Role::ComboBox) {
                text
            } else {
                if name.is_none() && role == Role::StaticText {
                    name = text;
                }
                None
            };
            let bounds = extents.unwrap_or(Bounds {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
            });
            let states = if matches!(role, Role::StaticText | Role::Unknown | Role::Document) {
                AtspiStates::default()
            } else {
                state.map_or_else(AtspiStates::default, |words| {
                    decode_atspi_node_states(&words, role, is_checkable_atspi_role(&role_raw))
                })
            };
            let url = if role == Role::Link { url } else { None };

            if bounds.width >= 0.0 && bounds.height >= 0.0 {
                nodes.push(AccessibilityNode {
                    id: format!("atspi-{}", nodes.len()),
                    role,
                    name,
                    value,
                    bounds,
                    focused: states.focused,
                    checked: states.checked,
                    disabled: states.disabled,
                    expanded: states.expanded,
                    url,
                });
            }

            if let Some(children) = children {
                // Nodes still in flight were popped from the queue but not yet visited,
                // exactly like the queue entries of the sequential walk.
                let free_slots = queue_room(max_nodes, nodes.len(), queue.len() + in_flight.len());
                truncated |= enqueue_children(&mut queue, children, free_slots);
            }
        }

        // The loop only ends with an empty window: either the queue is drained, or
        // `max_nodes` nodes were kept with accessibles left unvisited.
        truncated |= !queue.is_empty();
        (nodes, truncated)
    }

    /// Fetches what the web-root scan needs from one browser UI node. Document metadata
    /// and the address bar text are fetched speculatively for every document / entry; the
    /// scan then applies the sequential walk's rules in order.
    async fn scan_node(&self, node: AccessibleRef) -> ScannedNode {
        let (bus, path) = (node.0.as_str(), node.1.as_str());
        let (role_raw, children) = join(self.role_name(bus, path), self.children(bus, path)).await;
        let role_raw = role_raw.unwrap_or_default().trim().to_ascii_lowercase();
        let mut address_bar_text = None;
        let mut document = None;
        if role_raw == "entry" {
            if self.name(bus, path).await.as_deref() == Some("Address and search bar") {
                address_bar_text = self.read_text(bus, path).await;
            }
        } else if role_raw == "document web" || role_raw == "document frame" {
            let (state, extents, url) = join3(
                self.state(bus, path),
                self.extents(bus, path),
                self.document_url(bus, path),
            )
            .await;
            let showing = state.is_some_and(|words| is_atspi_showing(&words));
            document = Some((showing, extents, url));
        }
        ScannedNode {
            role_raw,
            address_bar_text,
            document,
            children,
        }
    }

    /// Pipelined equivalent of [`AtspiClient::locate_web_document`].
    async fn locate_web_document(&self, app: &AccessibleRef) -> ResolvedRoot {
        let mut current_url: Option<String> = None;
        let mut viewport_bounds: Option<Bounds> = None;
        let mut web_root: Option<AccessibleRef> = None;
        let mut best_showing = false;
        let mut best_area: f64 = -1.0;

        let mut queue: VecDeque<AccessibleRef> = VecDeque::new();
        queue.push_back(app.clone());
        let mut in_flight = FuturesOrdered::new();
        let mut scanned: usize = 0;

        loop {
            while in_flight.len() < self.window && scanned + in_flight.len() < MAX_NODES {
                let Some(next) = queue.pop_front() else {
                    break;
                };
                in_flight.push_back(async move {
                    let scanned_node = self.scan_node(next.clone()).await;
                    (next, scanned_node)
                });
            }
            let Some((node, item)) = in_flight.next().await else {
                break;
            };
            scanned += 1;

            if item.role_raw == "entry"
                && current_url.is_none()
                && let Some(val) = item.address_bar_text
                && !val.trim().is_empty()
            {
                current_url = Some(val.trim().to_owned());
            }

            if let Some((showing, extents, doc_url)) = item.document {
                if let Some(bounds) = extents {
                    let area = bounds.width.max(0.0) * bounds.height.max(0.0);
                    let is_better =
                        (showing && !best_showing) || (showing == best_showing && area > best_area);
                    if is_better {
                        best_showing = showing;
                        best_area = area;
                        web_root = Some(node);
                        if bounds.width > 0.0 && bounds.height > 0.0 {
                            viewport_bounds = Some(bounds);
                        }
                        if let Some(doc_url) = doc_url {
                            current_url = Some(doc_url);
                        }
                    }
                } else if web_root.is_none() {
                    web_root = Some(node);
                    if let Some(doc_url) = doc_url {
                        current_url = Some(doc_url);
                    }
                }
                continue;
            }

            if let Some(children) = item.children {
                for child in children {
                    if !child.0.is_empty() {
                        queue.push_back(child);
                    }
                }
            }
        }

        (web_root, current_url, viewport_bounds)
    }
}

fn discover_a11y_bus_address() -> Result<String> {
    if let Ok(addr) = std::env::var("AT_SPI_BUS_ADDRESS")
        && !addr.trim().is_empty()
    {
        return Ok(addr);
    }

    let session = Connection::session().map_err(|err| WayboundError::BackendUnavailable {
        backend: BACKEND_NAME.to_owned(),
        reason: format!("failed to connect to D-Bus session bus: {err}"),
    })?;
    let msg = session
        .call_method(
            Some("org.a11y.Bus"),
            "/org/a11y/bus",
            Some("org.a11y.Bus"),
            "GetAddress",
            &(),
        )
        .map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("org.a11y.Bus.GetAddress failed: {err}"),
        })?;
    let addr =
        msg.body()
            .deserialize::<String>()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to decode AT-SPI2 bus address: {err}"),
            })?;
    if addr.trim().is_empty() {
        return Err(WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: "org.a11y.Bus.GetAddress returned empty address".to_owned(),
        });
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(bus: &str, idx: usize) -> std::result::Result<AccessibleRef, zbus::Error> {
        let path = OwnedObjectPath::try_from(format!("/org/a11y/atspi/accessible/{idx}"))?;
        Ok((bus.to_owned(), path))
    }

    #[test]
    fn walk_strategy_env_values() {
        assert_eq!(WalkStrategy::parse(None), WalkStrategy::default());
        assert_eq!(
            WalkStrategy::parse(Some(" Sequential ")),
            WalkStrategy::Sequential
        );
        assert_eq!(
            WalkStrategy::parse(Some("pipelined")),
            WalkStrategy::default()
        );
        assert_eq!(WalkStrategy::parse(Some("")), WalkStrategy::default());
        assert_eq!(
            WalkStrategy::default(),
            WalkStrategy::Pipelined {
                window: DEFAULT_PIPELINE_WINDOW
            }
        );
    }

    #[test]
    fn queue_room_caps_visited_plus_queued() {
        assert_eq!(queue_room(10, 0, 0), 1_064);
        assert_eq!(queue_room(10, 60, 1_000), 4);
        assert_eq!(queue_room(10, 64, 1_000), 0);
        assert_eq!(queue_room(10, 2_000, 2_000), 0);
        assert_eq!(queue_room(usize::MAX, 1, 1), usize::MAX - 2);
    }

    #[test]
    fn enqueue_children_skips_busless_and_reports_overflow() -> std::result::Result<(), zbus::Error>
    {
        let mut queue = VecDeque::new();
        let children = vec![acc(":1.2", 1)?, acc("", 2)?, acc(":1.2", 3)?];
        assert!(!enqueue_children(&mut queue, children.clone(), 2));
        assert_eq!(queue.len(), 2);
        assert_eq!(
            queue.back().map(|c| c.1.as_str()),
            Some("/org/a11y/atspi/accessible/3")
        );

        let mut short = VecDeque::new();
        assert!(enqueue_children(&mut short, children, 1));
        assert_eq!(short.len(), 1);

        // Dropping only bus-less children is not an overflow.
        let mut exact = VecDeque::new();
        assert!(!enqueue_children(
            &mut exact,
            vec![acc(":1.2", 1)?, acc("", 2)?],
            1
        ));
        Ok(())
    }

    #[test]
    fn only_bus_level_errors_abandon_the_pipelined_walk() {
        let io = zbus::Error::InputOutput(std::sync::Arc::new(std::io::Error::other("gone")));
        assert!(is_transport_failure(&io));
        let limits = zbus::Error::FDO(Box::new(zbus::fdo::Error::LimitsExceeded(String::new())));
        assert!(is_transport_failure(&limits));
        let unknown = zbus::Error::FDO(Box::new(zbus::fdo::Error::UnknownObject(String::new())));
        assert!(!is_transport_failure(&unknown));
        assert!(!is_transport_failure(&zbus::Error::InvalidReply));
    }
}
