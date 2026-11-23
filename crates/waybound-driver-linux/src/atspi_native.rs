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
//!   reference and as the fallback when the bus refuses the pipelined walk's outstanding
//!   calls (`LimitsExceeded` / `NoMemory`).
//!
//! Set `WAYBOUND_ATSPI_WALK=sequential` to force the sequential walk (for debugging).
//! Which walk ran is logged at `debug` level.
//!
//! # Time limits
//!
//! Every call has a [`CALL_TIMEOUT`] and every operation (snapshot, URL, viewport) a
//! [`OPERATION_DEADLINE`]. A browser that stops answering (hung or `SIGSTOP`ped) makes the
//! operation fail at once with [`WayboundError::Timeout`] instead of blocking for the bus's
//! own reply timeout (minutes); a stall shorter than [`CALL_TIMEOUT`] only slows it down.
//! The connection stays usable afterwards. A dead connection (I/O error) fails the
//! operation and marks the client broken ([`AtspiClient::is_broken`]) so its owner
//! reconnects.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use futures_util::future::{join, join3, join4};
use futures_util::stream::FuturesOrdered;
use tracing::{debug, warn};
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

/// Optional AT-SPI2 top-level `frame` scope for multi-window browsers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowScope<'a> {
    /// Expected window title (for example from `xdg_toplevel::set_title`).
    pub title: Option<&'a str>,
    /// 0-based fallback index among direct `frame` children of the browser application.
    pub index: Option<usize>,
}

impl WindowScope<'_> {
    const fn is_unscoped(self) -> bool {
        self.title.is_none() && self.index.is_none()
    }
}

/// Selects the index of the matching `frame` child for `scope`.
///
/// Matching priority:
/// 1. Exact `Name == title` (when `title` is non-empty).
/// 2. Case-insensitive prefix match on `title` (when `title` is non-empty).
/// 3. Case-insensitive substring match (either `name` contains `title` or `title` contains
///    non-empty `name`).
/// 4. Fallback to `scope.index` when in bounds.
///
/// Within each title tier, `scope.index` is checked first so multiple windows sharing the
/// exact same title (for example two `"New Tab - Google Chrome"` frames) still resolve to
/// their respective frame instead of always collapsing onto index `0`.
#[must_use]
pub fn select_frame_index(frame_names: &[Option<String>], scope: WindowScope<'_>) -> Option<usize> {
    fn pick_tier<F>(
        frame_names: &[Option<String>],
        index: Option<usize>,
        predicate: F,
    ) -> Option<usize>
    where
        F: Fn(&Option<String>) -> bool,
    {
        if let Some(idx) = index
            && frame_names.get(idx).is_some_and(&predicate)
        {
            return Some(idx);
        }
        frame_names.iter().position(predicate)
    }

    if frame_names.is_empty() {
        return None;
    }
    if let Some(title) = scope.title.map(str::trim).filter(|t| !t.is_empty()) {
        if let Some(pos) = pick_tier(frame_names, scope.index, |name| {
            name.as_deref() == Some(title)
        }) {
            return Some(pos);
        }
        let needle = title.to_ascii_lowercase();
        if let Some(pos) = pick_tier(frame_names, scope.index, |name| {
            name.as_deref()
                .is_some_and(|n| n.to_ascii_lowercase().starts_with(&needle))
        }) {
            return Some(pos);
        }
        if let Some(pos) = pick_tier(frame_names, scope.index, |name| {
            name.as_deref().is_some_and(|n| {
                let hay = n.trim().to_ascii_lowercase();
                !hay.is_empty() && (hay.contains(&needle) || needle.contains(&hay))
            })
        }) {
            return Some(pos);
        }
    }
    scope.index.filter(|&idx| idx < frame_names.len())
}

/// Environment variable selecting the tree walk: `sequential` forces
/// [`WalkStrategy::Sequential`]; anything else (or unset) uses the pipelined default.
pub const WALK_STRATEGY_ENV: &str = "WAYBOUND_ATSPI_WALK";

/// Default number of nodes whose AT-SPI2 calls may be in flight at once in the
/// pipelined walk (each node has at most 4 concurrent calls outstanding).
pub const DEFAULT_PIPELINE_WINDOW: usize = 64;

/// Upper bound on the pipelined walk's in-flight node window.
pub const MAX_PIPELINE_WINDOW: usize = 512;

/// Longest wait for any single AT-SPI2 reply. A browser that answers nothing for this
/// long is treated as hung and the operation fails with [`WayboundError::Timeout`].
pub const CALL_TIMEOUT: Duration = Duration::from_secs(6);

/// Wall-clock budget for one operation (snapshot, URL or viewport lookup).
///
/// No new call is started after it, so an operation returns within about
/// `OPERATION_DEADLINE + CALL_TIMEOUT`, below the SDKs' 30 s request timeout. A 5,000-node
/// page takes ~0.3 s pipelined and ~3.5 s sequentially.
pub const OPERATION_DEADLINE: Duration = Duration::from_secs(15);

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

/// Why an operation stopped issuing calls.
///
/// Ordered by severity so a bus-limit refusal never masks a timeout or lost connection when
/// in-flight pipelined calls drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Abort {
    /// The bus refused a call for resource limits; pipelined walks retry sequentially, and a
    /// sequential failure drops and reconnects the bus connection.
    BusLimits,
    /// The operation ran past [`OPERATION_DEADLINE`].
    Deadline,
    /// A call got no reply within [`CALL_TIMEOUT`] (or the bus reported `NoReply`).
    TimedOut,
    /// The connection to the bus is gone.
    ConnectionLost,
}

impl Abort {
    const fn code(self) -> u8 {
        match self {
            Self::BusLimits => 1,
            Self::Deadline => 2,
            Self::TimedOut => 3,
            Self::ConnectionLost => 4,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::BusLimits),
            2 => Some(Self::Deadline),
            3 => Some(Self::TimedOut),
            4 => Some(Self::ConnectionLost),
            _ => None,
        }
    }
}

/// Classifies a failed call. `None` means only this accessible could not answer (a dead
/// node, a missing interface): the walk records "no value" and carries on, as it always
/// has.
fn classify_failure(err: &zbus::Error) -> Option<Abort> {
    const TIMEOUT_ERRORS: [&str; 3] = [
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.DBus.Error.Timeout",
        "org.freedesktop.DBus.Error.TimedOut",
    ];
    const LIMIT_ERRORS: [&str; 2] = [
        "org.freedesktop.DBus.Error.LimitsExceeded",
        "org.freedesktop.DBus.Error.NoMemory",
    ];
    match err {
        zbus::Error::InputOutput(io) if io.kind() == std::io::ErrorKind::TimedOut => {
            Some(Abort::TimedOut)
        }
        zbus::Error::InputOutput(_) | zbus::Error::Connection(..) => Some(Abort::ConnectionLost),
        zbus::Error::MethodError(name, _, _) => {
            let name = name.as_str();
            if TIMEOUT_ERRORS.contains(&name) {
                Some(Abort::TimedOut)
            } else if LIMIT_ERRORS.contains(&name) {
                Some(Abort::BusLimits)
            } else if name == "org.freedesktop.DBus.Error.Disconnected" {
                Some(Abort::ConnectionLost)
            } else {
                None
            }
        }
        zbus::Error::FDO(fdo) => match **fdo {
            zbus::fdo::Error::NoReply(_)
            | zbus::fdo::Error::Timeout(_)
            | zbus::fdo::Error::TimedOut(_) => Some(Abort::TimedOut),
            zbus::fdo::Error::LimitsExceeded(_) | zbus::fdo::Error::NoMemory(_) => {
                Some(Abort::BusLimits)
            }
            zbus::fdo::Error::Disconnected(_) => Some(Abort::ConnectionLost),
            _ => None,
        },
        _ => None,
    }
}

/// Per-operation call budget shared by the sequential and pipelined walks: the deadline
/// and the highest-severity fatal failure observed. Once set, no further call is sent.
#[derive(Debug)]
struct CallBudget {
    deadline: Instant,
    abort: AtomicU8,
}

impl CallBudget {
    const fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            abort: AtomicU8::new(0),
        }
    }

    fn abort(&self) -> Option<Abort> {
        Abort::from_code(self.abort.load(Ordering::Relaxed))
    }

    fn set_abort(&self, abort: Abort) {
        let code = abort.code();
        let prev = self.abort.fetch_max(code, Ordering::Relaxed);
        if prev < code {
            debug!(?abort, "AT-SPI2 operation aborted");
        }
    }

    fn record(&self, err: &zbus::Error) {
        if let Some(abort) = classify_failure(err) {
            self.set_abort(abort);
        }
    }

    /// `false` once the operation was aborted or ran out of time.
    fn may_call(&self) -> bool {
        if self.abort().is_some() {
            return false;
        }
        if Instant::now() >= self.deadline {
            self.set_abort(Abort::Deadline);
            return false;
        }
        true
    }
}

/// Persistent pure-Rust D-Bus client connected to the AT-SPI2 accessibility bus.
pub struct AtspiClient {
    conn: Connection,
    budget: CallBudget,
    broken: bool,
}

impl std::fmt::Debug for AtspiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtspiClient")
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

/// Converts `millis` of a [`Duration`] to `u64` for error payloads.
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
            .method_timeout(CALL_TIMEOUT)
            .build()
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("failed to connect to AT-SPI2 bus: {err}"),
            })?;
        debug!(addr = %addr, "connected native pure-Rust AtspiClient");
        Ok(Self {
            conn,
            budget: CallBudget::new(Instant::now()),
            broken: false,
        })
    }

    /// `true` once the connection to the accessibility bus was found dead; the owner
    /// should drop this client and [`Self::connect`] again.
    #[must_use]
    pub const fn is_broken(&self) -> bool {
        self.broken
    }

    /// Runs one operation under a fresh [`CallBudget`]: the pipelined variant first (when
    /// `strategy` asks for it), redone sequentially only if the bus refused its
    /// outstanding calls. A timeout or a lost connection fails the operation at once.
    fn run<T>(
        &mut self,
        strategy: WalkStrategy,
        what: &'static str,
        pipelined: impl FnOnce(&Self, usize) -> Result<T>,
        sequential: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        self.budget = CallBudget::new(Instant::now() + OPERATION_DEADLINE);
        if let WalkStrategy::Pipelined { window } = strategy {
            let result = pipelined(self, window);
            match self.budget.abort() {
                None => {
                    debug!(what, window, "AT-SPI2 {what} via the pipelined walk");
                    return result;
                }
                Some(Abort::BusLimits) => {
                    warn!(
                        what,
                        "AT-SPI2 bus refused the pipelined walk's calls; redoing it sequentially"
                    );
                    let deadline = self.budget.deadline;
                    self.budget = CallBudget::new(deadline);
                }
                Some(abort) => return Err(self.abort_error(abort, what)),
            }
        }
        let result = sequential(self);
        if let Some(abort) = self.budget.abort() {
            return Err(self.abort_error(abort, what));
        }
        debug!(what, "AT-SPI2 {what} via the sequential walk");
        result
    }

    fn abort_error(&mut self, abort: Abort, what: &str) -> WayboundError {
        match abort {
            Abort::TimedOut => WayboundError::Timeout {
                timeout_ms: duration_ms(CALL_TIMEOUT),
                context: format!(
                    "AT-SPI2 {what}: the browser did not answer an accessibility call within \
                     {} s (hung or stopped?)",
                    CALL_TIMEOUT.as_secs()
                ),
            },
            Abort::Deadline => WayboundError::Timeout {
                timeout_ms: duration_ms(OPERATION_DEADLINE),
                context: format!(
                    "AT-SPI2 {what} did not finish within {} s",
                    OPERATION_DEADLINE.as_secs()
                ),
            },
            Abort::ConnectionLost | Abort::BusLimits => {
                // Reconnect on both a dropped bus and sequential `BusLimits` so a fresh D-Bus
                // connection clears any orphaned per-connection pending-reply slots.
                self.broken = true;
                warn!(?abort, what, "AT-SPI2 bus connection failed");
                WayboundError::BackendUnavailable {
                    backend: BACKEND_NAME.to_owned(),
                    reason: format!("AT-SPI2 {what}: accessibility bus connection failed"),
                }
            }
        }
    }

    /// Lists the applications registered on the AT-SPI2 registry root.
    fn registry_apps(&self) -> Result<Vec<AccessibleRef>> {
        self.call_sync_result(
            REGISTRY_BUS,
            REGISTRY_ROOT,
            IFACE_ACCESSIBLE,
            "GetChildren",
            &(),
        )
        .and_then(|msg| decode_children(&msg))
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
    fn resolve_web_root(
        &self,
        target_pid: Option<i32>,
        scope: WindowScope<'_>,
    ) -> Result<ResolvedRoot> {
        let apps = self.registry_apps()?;
        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok((None, None, None));
        };
        let scan_root = if scope.is_unscoped() {
            target_app
        } else {
            let Some(frame) = self.resolve_window_frame(&target_app, scope) else {
                return Ok((None, None, None));
            };
            frame
        };
        Ok(self.locate_web_document(&scan_root))
    }

    /// Pipelined [`Self::resolve_web_root`].
    fn resolve_web_root_pipelined(
        &self,
        target_pid: Option<i32>,
        scope: WindowScope<'_>,
        window: usize,
    ) -> Result<ResolvedRoot> {
        let apps = self.registry_apps()?;
        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok((None, None, None));
        };
        let walker = PipelinedWalker::new(self.conn.inner(), &self.budget, window);
        Ok(futures_lite::future::block_on(async {
            let scan_root = if scope.is_unscoped() {
                target_app
            } else {
                let Some(frame) = walker.resolve_window_frame(&target_app, scope).await else {
                    return (None, None, None);
                };
                frame
            };
            walker.locate_web_document(&scan_root).await
        }))
    }

    fn resolve_web_root_with(
        &mut self,
        target_pid: Option<i32>,
        scope: WindowScope<'_>,
        strategy: WalkStrategy,
        what: &'static str,
    ) -> Result<ResolvedRoot> {
        self.run(
            strategy,
            what,
            |client, window| client.resolve_web_root_pipelined(target_pid, scope, window),
            |client| client.resolve_web_root(target_pid, scope),
        )
    }

    /// Fast-path URL lookup on the active web document without walking DOM children.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be
    /// queried or the connection is lost, or [`WayboundError::Timeout`] if the browser
    /// stops answering (see [`CALL_TIMEOUT`] and [`OPERATION_DEADLINE`]).
    pub fn current_url(&mut self, target_pid: Option<i32>) -> Result<Option<String>> {
        self.current_url_for_window(target_pid, None, None)
    }

    /// Fast-path URL lookup scoped to a specific browser window `frame` (matched by
    /// `window_title` and/or fallback `window_index`).
    ///
    /// # Errors
    ///
    /// Same as [`Self::current_url`].
    pub fn current_url_for_window(
        &mut self,
        target_pid: Option<i32>,
        window_title: Option<&str>,
        window_index: Option<usize>,
    ) -> Result<Option<String>> {
        let scope = WindowScope {
            title: window_title,
            index: window_index,
        };
        let (_, url, _) =
            self.resolve_web_root_with(target_pid, scope, WalkStrategy::from_env(), "URL lookup")?;
        Ok(url.filter(|u| !u.trim().is_empty()))
    }

    /// Fast-path viewport bounds lookup on the active web document without walking DOM children.
    ///
    /// # Errors
    ///
    /// Same as [`Self::current_url`].
    pub fn viewport_bounds(&mut self, target_pid: Option<i32>) -> Result<Option<Bounds>> {
        let (_, _, bounds) = self.resolve_web_root_with(
            target_pid,
            WindowScope::default(),
            WalkStrategy::from_env(),
            "viewport lookup",
        )?;
        Ok(bounds)
    }

    /// Captures a bounded accessibility snapshot of the active browser web document.
    ///
    /// # Errors
    ///
    /// Same as [`Self::current_url`].
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
    /// Same as [`Self::current_url`].
    pub fn snapshot_limited(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
    ) -> Result<AtspiSnapshot> {
        self.snapshot_with_strategy(target_pid, max_nodes, WalkStrategy::from_env())
    }

    /// Captures an accessibility snapshot scoped to a specific browser window `frame`
    /// (matched by `window_title` and/or fallback `window_index`), capped at `max_nodes`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::current_url`].
    pub fn snapshot_limited_for_window(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
        window_title: Option<&str>,
        window_index: Option<usize>,
    ) -> Result<AtspiSnapshot> {
        let scope = WindowScope {
            title: window_title,
            index: window_index,
        };
        self.snapshot_with_strategy_scoped(target_pid, max_nodes, scope, WalkStrategy::from_env())
    }

    /// Captures an accessibility snapshot capped at `max_nodes` with an explicit tree walk
    /// `strategy`. Both strategies return identical snapshots for an unchanging page.
    ///
    /// # Errors
    ///
    /// Same as [`Self::current_url`].
    pub fn snapshot_with_strategy(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
        strategy: WalkStrategy,
    ) -> Result<AtspiSnapshot> {
        self.snapshot_with_strategy_scoped(target_pid, max_nodes, WindowScope::default(), strategy)
    }

    fn snapshot_with_strategy_scoped(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
        scope: WindowScope<'_>,
        strategy: WalkStrategy,
    ) -> Result<AtspiSnapshot> {
        let limit = max_nodes.clamp(waybound_core::MIN_MAX_NODES, waybound_core::MAX_MAX_NODES);
        let snapshot = self.run(
            strategy,
            "snapshot",
            |client, window| client.snapshot_pipelined(target_pid, scope, limit, window),
            |client| client.snapshot_sequential(target_pid, scope, limit),
        )?;
        debug!(
            nodes = snapshot.nodes.len(),
            truncated = snapshot.truncated,
            "AT-SPI2 snapshot captured"
        );
        Ok(snapshot)
    }

    /// The reference walk: one blocking D-Bus call at a time.
    fn snapshot_sequential(
        &self,
        target_pid: Option<i32>,
        scope: WindowScope<'_>,
        limit: usize,
    ) -> Result<AtspiSnapshot> {
        let (web_root, current_url, viewport_bounds) = self.resolve_web_root(target_pid, scope)?;
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

    /// The pipelined walk.
    fn snapshot_pipelined(
        &self,
        target_pid: Option<i32>,
        scope: WindowScope<'_>,
        limit: usize,
        window: usize,
    ) -> Result<AtspiSnapshot> {
        let apps = self.registry_apps()?;
        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok(AtspiSnapshot {
                nodes: Vec::new(),
                truncated: false,
                current_url: None,
                viewport_bounds: None,
            });
        };
        let walker = PipelinedWalker::new(self.conn.inner(), &self.budget, window);
        let ((web_root, current_url, viewport_bounds), tree) =
            futures_lite::future::block_on(async {
                let scan_root = if scope.is_unscoped() {
                    target_app
                } else {
                    let Some(frame) = walker.resolve_window_frame(&target_app, scope).await else {
                        return ((None, None, None), None);
                    };
                    frame
                };
                let resolved = walker.locate_web_document(&scan_root).await;
                let tree = match &resolved.0 {
                    Some(root) => Some(walker.walk_web_document(root, limit).await),
                    None => None,
                };
                (resolved, tree)
            });
        Ok(match (web_root, tree) {
            (Some(_), Some((nodes, truncated))) => {
                finish_snapshot(nodes, truncated, current_url, viewport_bounds)
            }
            _ => AtspiSnapshot {
                nodes: Vec::new(),
                truncated: false,
                current_url,
                viewport_bounds,
            },
        })
    }

    fn resolve_window_frame(
        &self,
        app: &AccessibleRef,
        scope: WindowScope<'_>,
    ) -> Option<AccessibleRef> {
        let children = self.get_children(&app.0, app.1.as_str())?;
        let mut frames: Vec<AccessibleRef> = Vec::new();
        let mut names: Vec<Option<String>> = Vec::new();
        for child in children {
            if child.0.is_empty() || self.budget.abort().is_some() {
                continue;
            }
            let role = self
                .get_role_name(&child.0, child.1.as_str())
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if role == "frame" {
                let name = self.get_name(&child.0, child.1.as_str());
                frames.push(child);
                names.push(name);
            }
        }
        let idx = select_frame_index(&names, scope)?;
        frames.into_iter().nth(idx)
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
            if scanned >= MAX_NODES || self.budget.abort().is_some() {
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

            if let Some(children) = self.get_children(&bus, path.as_str()) {
                for child in children {
                    if !child.0.is_empty() {
                        queue.push_back(child);
                    }
                }
            }
        }

        (web_root, current_url, viewport_bounds)
    }

    /// Fetches one web node with blocking calls, one at a time.
    fn fetch_node_sync(&self, (bus, path): &AccessibleRef) -> FetchedNode {
        let path = path.as_str();
        let role_raw = self.get_role_name(bus, path).unwrap_or_default();
        let role = map_atspi_role(&role_raw);
        let name = self.get_name(bus, path);
        let text = wants_text(role, name.as_ref())
            .then(|| self.read_text(bus, path))
            .flatten();
        let extents = self.get_extents(bus, path);
        // One `GetState` round trip per node yields focused, checked, disabled, and
        // expanded together; text, unknown, and document nodes skip it entirely.
        let state = wants_state(role)
            .then(|| self.get_state(bus, path))
            .flatten();
        let url = (role == Role::Link)
            .then(|| self.get_hyperlink_uri(bus, path))
            .flatten();
        let children = self.get_children(bus, path);
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

    fn walk_web_document(
        &self,
        root: &AccessibleRef,
        max_nodes: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut walk = WalkState::new(root.clone(), max_nodes);
        while self.budget.abort().is_none()
            && let Some(next) = walk.start_next(0)
        {
            walk.consume(self.fetch_node_sync(&next));
        }
        walk.finish()
    }

    /// One blocking call under the operation's [`CallBudget`].
    fn call_sync_result<B>(
        &self,
        dest: &str,
        path: &str,
        iface: &str,
        method: &str,
        body: &B,
    ) -> zbus::Result<Message>
    where
        B: serde::Serialize + DynamicType,
    {
        if !self.budget.may_call() {
            return Err(zbus::Error::Failure(
                "AT-SPI2 operation aborted (timeout or lost connection)".to_owned(),
            ));
        }
        self.conn
            .call_method(Some(dest), path, Some(iface), method, body)
            .inspect_err(|err| self.budget.record(err))
    }

    fn call_sync<B>(
        &self,
        dest: &str,
        path: &str,
        iface: &str,
        method: &str,
        body: &B,
    ) -> Option<Message>
    where
        B: serde::Serialize + DynamicType,
    {
        self.call_sync_result(dest, path, iface, method, body).ok()
    }

    fn bus_pid(&self, bus: &str) -> Option<u32> {
        let msg = self.call_sync(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionUnixProcessID",
            &(bus,),
        )?;
        msg.body().deserialize::<u32>().ok()
    }

    fn get_children(&self, bus: &str, path: &str) -> Option<Vec<AccessibleRef>> {
        let msg = self.call_sync(bus, path, IFACE_ACCESSIBLE, "GetChildren", &())?;
        decode_children(&msg).ok()
    }

    fn get_role_name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self.call_sync(bus, path, IFACE_ACCESSIBLE, "GetRoleName", &())?;
        decode_role_name(&msg)
    }

    fn get_name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self.call_sync(
            bus,
            path,
            IFACE_PROPERTIES,
            "Get",
            &(IFACE_ACCESSIBLE, "Name"),
        )?;
        decode_name(&msg)
    }

    fn get_extents(&self, bus: &str, path: &str) -> Option<Bounds> {
        let msg = self.call_sync(
            bus,
            path,
            IFACE_COMPONENT,
            "GetExtents",
            &(COORD_TYPE_SCREEN,),
        )?;
        decode_extents(&msg)
    }

    fn get_state(&self, bus: &str, path: &str) -> Option<Vec<u32>> {
        let msg = self.call_sync(bus, path, IFACE_ACCESSIBLE, "GetState", &())?;
        decode_state(&msg)
    }

    fn get_document_url(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self.call_sync(bus, path, IFACE_DOCUMENT, "GetAttributes", &())?;
        decode_document_url(&msg)
    }

    fn get_hyperlink_uri(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self.call_sync(bus, path, IFACE_HYPERLINK, "GetURI", &(0i32,))?;
        decode_trimmed_string(&msg)
    }

    fn read_text(&self, bus: &str, path: &str) -> Option<String> {
        let count_msg = self.call_sync(
            bus,
            path,
            IFACE_PROPERTIES,
            "Get",
            &(IFACE_TEXT, "CharacterCount"),
        )?;
        let count = decode_character_count(&count_msg)?;
        let text_msg = self.call_sync(bus, path, IFACE_TEXT, "GetText", &(0i32, count))?;
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

/// How many more accessibles the walk queue may hold. Visited (started, whether kept or
/// filtered out) plus queued accessibles are capped at `4 * max_nodes + 1024`, so neither a
/// node reporting a huge child list nor a cycle of filtered-out nodes can grow the queue or
/// the walk without bound; a walk that keeps `max_nodes` nodes of a real page never gets
/// near it.
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

/// Role-dependent fetches shared by both walks.
const fn wants_text(role: Role, name: Option<&String>) -> bool {
    matches!(role, Role::TextBox | Role::SearchBox | Role::ComboBox)
        || (name.is_none() && matches!(role, Role::StaticText))
}

const fn wants_state(role: Role) -> bool {
    !matches!(role, Role::StaticText | Role::Unknown | Role::Document)
}

/// Everything the walk needs from one accessible.
#[derive(Debug, Clone)]
struct FetchedNode {
    role_raw: String,
    name: Option<String>,
    /// Text contents: the value of a text field, or the name of an unnamed static text.
    text: Option<String>,
    extents: Option<Bounds>,
    state: Option<Vec<u32>>,
    url: Option<String>,
    children: Option<Vec<AccessibleRef>>,
}

impl FetchedNode {
    /// The snapshot node for this accessible, or `None` when its extents are negative.
    fn into_node(self, index: usize) -> (Option<AccessibilityNode>, Option<Vec<AccessibleRef>>) {
        let Self {
            role_raw,
            mut name,
            text,
            extents,
            state,
            url,
            children,
        } = self;
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
        let states = if wants_state(role) {
            state.map_or_else(AtspiStates::default, |words| {
                decode_atspi_node_states(&words, role, is_checkable_atspi_role(&role_raw))
            })
        } else {
            AtspiStates::default()
        };
        let url = if role == Role::Link { url } else { None };
        let node = (bounds.width >= 0.0 && bounds.height >= 0.0).then(|| AccessibilityNode {
            id: format!("atspi-{index}"),
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
        (node, children)
    }
}

/// Breadth-first walk bookkeeping shared by the sequential and the pipelined walk, so both
/// visit the same accessibles in the same order and agree on `truncated`.
///
/// The sequential walk calls [`Self::start_next`] with nothing in flight and consumes each
/// node before starting the next. The pipelined walk starts several nodes ahead; it only
/// starts a node the sequential walk would also reach (every in-flight node might still be
/// kept) and consumes results in start order.
#[derive(Debug)]
struct WalkState {
    max_nodes: usize,
    nodes: Vec<AccessibilityNode>,
    queue: VecDeque<AccessibleRef>,
    /// Accessibles started so far, kept or filtered out.
    visited: usize,
    truncated: bool,
}

impl WalkState {
    fn new(root: AccessibleRef, max_nodes: usize) -> Self {
        let mut queue = VecDeque::new();
        queue.push_back(root);
        Self {
            max_nodes,
            nodes: Vec::new(),
            queue,
            visited: 0,
            truncated: false,
        }
    }

    /// The next accessible to fetch, given `in_flight` started but not yet consumed.
    fn start_next(&mut self, in_flight: usize) -> Option<AccessibleRef> {
        if self.nodes.len() + in_flight >= self.max_nodes {
            return None;
        }
        let next = self.queue.pop_front()?;
        self.visited += 1;
        Some(next)
    }

    /// Consumes the oldest started node.
    fn consume(&mut self, fetched: FetchedNode) {
        let (node, children) = fetched.into_node(self.nodes.len());
        if let Some(node) = node {
            self.nodes.push(node);
        }
        if let Some(children) = children {
            let free_slots = queue_room(self.max_nodes, self.visited, self.queue.len());
            self.truncated |= enqueue_children(&mut self.queue, children, free_slots);
        }
    }

    /// Ends the walk. Accessibles left in the queue (the cap was reached) mean truncation.
    fn finish(mut self) -> (Vec<AccessibilityNode>, bool) {
        self.truncated |= !self.queue.is_empty();
        (self.nodes, self.truncated)
    }
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
    budget: &'a CallBudget,
    window: usize,
}

impl<'a> PipelinedWalker<'a> {
    fn new(conn: &'a zbus::Connection, budget: &'a CallBudget, window: usize) -> Self {
        Self {
            conn,
            budget,
            window: window.clamp(1, MAX_PIPELINE_WINDOW),
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
        // Once the operation is aborted, in-flight nodes finish without sending more.
        if !self.budget.may_call() {
            return None;
        }
        self.conn
            .call_method(Some(bus), path, Some(iface), method, body)
            .await
            .inspect_err(|err| self.budget.record(err))
            .ok()
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
        let fetch_text = wants_text(role, name.as_ref());
        let fetch_state = wants_state(role);
        let fetch_url = role == Role::Link;
        let (text, state, url) = join3(
            async {
                if fetch_text {
                    self.read_text(bus, path).await
                } else {
                    None
                }
            },
            async {
                if fetch_state {
                    self.state(bus, path).await
                } else {
                    None
                }
            },
            async {
                if fetch_url {
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
        let mut walk = WalkState::new(root.clone(), max_nodes);
        let mut in_flight = FuturesOrdered::new();
        loop {
            while in_flight.len() < self.window && self.budget.abort().is_none() {
                let Some(next) = walk.start_next(in_flight.len()) else {
                    break;
                };
                in_flight.push_back(self.fetch_node(next));
            }
            let Some(fetched) = in_flight.next().await else {
                break;
            };
            walk.consume(fetched);
        }
        walk.finish()
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

    /// Pipelined equivalent of [`AtspiClient::resolve_window_frame`].
    async fn resolve_window_frame(
        &self,
        app: &AccessibleRef,
        scope: WindowScope<'_>,
    ) -> Option<AccessibleRef> {
        let children = self.children(&app.0, app.1.as_str()).await?;
        let mut in_flight = FuturesOrdered::new();
        for child in children {
            if child.0.is_empty() {
                continue;
            }
            in_flight.push_back(async move {
                let (role_raw, name) = join(
                    self.role_name(&child.0, child.1.as_str()),
                    self.name(&child.0, child.1.as_str()),
                )
                .await;
                let role = role_raw.unwrap_or_default().trim().to_ascii_lowercase();
                (child, role, name)
            });
        }
        let mut frames: Vec<AccessibleRef> = Vec::new();
        let mut names: Vec<Option<String>> = Vec::new();
        while let Some((child, role, name)) = in_flight.next().await {
            if role == "frame" {
                frames.push(child);
                names.push(name);
            }
        }
        let idx = select_frame_index(&names, scope)?;
        frames.into_iter().nth(idx)
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
            while in_flight.len() < self.window
                && scanned + in_flight.len() < MAX_NODES
                && self.budget.abort().is_none()
            {
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

    let session = Builder::session()
        .map_err(|err| WayboundError::BackendUnavailable {
            backend: BACKEND_NAME.to_owned(),
            reason: format!("failed to locate D-Bus session bus: {err}"),
        })?
        .method_timeout(CALL_TIMEOUT)
        .build()
        .map_err(|err| WayboundError::BackendUnavailable {
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

    type TestResult = std::result::Result<(), zbus::Error>;

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
    fn enqueue_children_skips_busless_and_reports_overflow() -> TestResult {
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
    fn classifies_failures_that_end_an_operation() {
        let io = |kind| zbus::Error::InputOutput(std::sync::Arc::new(std::io::Error::from(kind)));
        let fdo = |err| zbus::Error::FDO(Box::new(err));
        assert_eq!(
            classify_failure(&io(std::io::ErrorKind::TimedOut)),
            Some(Abort::TimedOut)
        );
        assert_eq!(
            classify_failure(&io(std::io::ErrorKind::BrokenPipe)),
            Some(Abort::ConnectionLost)
        );
        assert_eq!(
            classify_failure(&fdo(zbus::fdo::Error::NoReply(String::new()))),
            Some(Abort::TimedOut)
        );
        assert_eq!(
            classify_failure(&fdo(zbus::fdo::Error::LimitsExceeded(String::new()))),
            Some(Abort::BusLimits)
        );
        assert_eq!(
            classify_failure(&fdo(zbus::fdo::Error::Disconnected(String::new()))),
            Some(Abort::ConnectionLost)
        );
        // One dead accessible is not a reason to stop.
        assert_eq!(
            classify_failure(&fdo(zbus::fdo::Error::UnknownObject(String::new()))),
            None
        );
        assert_eq!(classify_failure(&zbus::Error::InvalidReply), None);
    }

    #[test]
    fn call_budget_deadline_and_bus_limit_policy() {
        let limits = zbus::Error::FDO(Box::new(zbus::fdo::Error::LimitsExceeded(String::new())));
        let timeout = zbus::Error::FDO(Box::new(zbus::fdo::Error::NoReply(String::new())));

        let budget = CallBudget::new(Instant::now() + Duration::from_secs(60));
        budget.record(&limits);
        assert_eq!(budget.abort(), Some(Abort::BusLimits));
        assert!(!budget.may_call());
        // Higher-severity aborts supersede `BusLimits` while draining in-flight calls.
        budget.record(&timeout);
        assert_eq!(budget.abort(), Some(Abort::TimedOut));
        budget.set_abort(Abort::ConnectionLost);
        assert_eq!(budget.abort(), Some(Abort::ConnectionLost));
        // Lower-severity aborts never downgrade a higher-severity one.
        budget.set_abort(Abort::Deadline);
        assert_eq!(budget.abort(), Some(Abort::ConnectionLost));

        let expired = CallBudget::new(Instant::now());
        assert!(!expired.may_call());
        assert_eq!(expired.abort(), Some(Abort::Deadline));
        expired.set_abort(Abort::BusLimits);
        assert_eq!(expired.abort(), Some(Abort::Deadline));
    }

    /// A synthetic accessible tree: index -> fetched data.
    struct Tree(HashMap<String, FetchedNode>);

    impl Tree {
        fn fetch(&self, node: &AccessibleRef) -> FetchedNode {
            self.0
                .get(node.1.as_str())
                .cloned()
                .unwrap_or_else(|| leaf(-1, None))
        }
    }

    fn leaf(width: i32, children: Option<Vec<AccessibleRef>>) -> FetchedNode {
        FetchedNode {
            role_raw: "push button".to_owned(),
            name: Some(format!("w{width}")),
            text: None,
            extents: Some(Bounds {
                x: 0.0,
                y: 0.0,
                width: f64::from(width),
                height: 10.0,
            }),
            state: Some(vec![1 << 8]),
            url: None,
            children,
        }
    }

    /// `count` accessibles in a pseudo-random tree; about a third have negative extents
    /// (filtered out of the snapshot) and some fail `GetChildren`.
    fn synthetic_tree(count: usize) -> std::result::Result<Tree, zbus::Error> {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(seed >> 33).unwrap_or(0)
        };
        let mut children: Vec<Vec<AccessibleRef>> = vec![Vec::new(); count];
        for idx in 1..count {
            let parent = next() % idx;
            children[parent].push(acc(":1.9", idx)?);
        }
        let mut map = HashMap::new();
        for (idx, kids) in children.into_iter().enumerate() {
            let width = if next() % 3 == 0 { -1 } else { 20 };
            let kids = (next() % 11 != 0).then_some(kids);
            let _ = map.insert(acc(":1.9", idx)?.1.as_str().to_owned(), leaf(width, kids));
        }
        Ok(Tree(map))
    }

    /// The walk exactly as it was written before the pipelined one existed.
    fn reference_walk(
        tree: &Tree,
        root: &AccessibleRef,
        max_nodes: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut nodes = Vec::new();
        let mut truncated = false;
        let mut queue = VecDeque::from([root.clone()]);
        while let Some(next) = queue.pop_front() {
            if nodes.len() >= max_nodes {
                truncated = true;
                break;
            }
            let (node, children) = tree.fetch(&next).into_node(nodes.len());
            nodes.extend(node);
            for child in children.unwrap_or_default() {
                if !child.0.is_empty() {
                    queue.push_back(child);
                }
            }
        }
        (nodes, truncated)
    }

    fn sequential_walk(
        tree: &Tree,
        root: &AccessibleRef,
        max_nodes: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut walk = WalkState::new(root.clone(), max_nodes);
        while let Some(next) = walk.start_next(0) {
            walk.consume(tree.fetch(&next));
        }
        walk.finish()
    }

    /// Drives [`WalkState`] like [`PipelinedWalker::walk_web_document`]: up to `window`
    /// nodes started ahead, consumed in start order.
    fn pipelined_walk(
        tree: &Tree,
        root: &AccessibleRef,
        max_nodes: usize,
        window: usize,
    ) -> (Vec<AccessibilityNode>, bool) {
        let mut walk = WalkState::new(root.clone(), max_nodes);
        let mut in_flight = VecDeque::new();
        loop {
            while in_flight.len() < window {
                let Some(next) = walk.start_next(in_flight.len()) else {
                    break;
                };
                in_flight.push_back(next);
            }
            let Some(next) = in_flight.pop_front() else {
                break;
            };
            walk.consume(tree.fetch(&next));
        }
        walk.finish()
    }

    #[test]
    fn walks_agree_with_filtered_nodes_at_every_cap() -> TestResult {
        let tree = synthetic_tree(400)?;
        let root = acc(":1.9", 0)?;
        let (all, _) = reference_walk(&tree, &root, usize::MAX);
        assert!(all.len() > 150 && all.len() < 400, "{} kept", all.len());
        for max_nodes in [1, 2, 3, 5, 10, 17, 64, 100, all.len() - 1, all.len(), 5_000] {
            let expected = reference_walk(&tree, &root, max_nodes);
            assert_eq!(sequential_walk(&tree, &root, max_nodes), expected);
            for window in [1, 2, 7, 64, 512] {
                assert_eq!(
                    pipelined_walk(&tree, &root, max_nodes, window),
                    expected,
                    "max_nodes {max_nodes}, window {window}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn queue_cap_bounds_cycles_and_huge_child_lists() -> TestResult {
        // A filtered-out node listing itself twice: without the cap the walk never ends.
        let root = acc(":1.9", 0)?;
        let cycle = Tree(HashMap::from([(
            root.1.as_str().to_owned(),
            leaf(-1, Some(vec![root.clone(), root.clone()])),
        )]));
        for window in [1, 64] {
            let (nodes, truncated) = pipelined_walk(&cycle, &root, 10, window);
            assert!(nodes.is_empty() && truncated);
        }
        assert_eq!(sequential_walk(&cycle, &root, 10), (Vec::new(), true));

        // A root with 5,000 kept children: the queue is capped, the walk stays exact.
        let kids = (1..=5_000)
            .map(|idx| acc(":1.9", idx))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut map = HashMap::from([(root.1.as_str().to_owned(), leaf(20, Some(kids.clone())))]);
        for kid in &kids {
            let _ = map.insert(kid.1.as_str().to_owned(), leaf(20, Some(Vec::new())));
        }
        let wide = Tree(map);
        let expected = reference_walk(&wide, &root, 10);
        assert_eq!(expected.0.len(), 10);
        assert_eq!(sequential_walk(&wide, &root, 10), expected);
        assert_eq!(pipelined_walk(&wide, &root, 10, 64), expected);
        Ok(())
    }

    #[test]
    fn select_frame_index_prefers_exact_then_prefix_then_substring_then_index() {
        let frames = vec![
            Some("Waybound Window 1 - Google Chrome".to_owned()),
            Some("Waybound Window 2 - Google Chrome".to_owned()),
            Some("Dashboard - Waybound Window 2".to_owned()),
            None,
        ];

        // Exact match wins over prefix/substring.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("Waybound Window 2 - Google Chrome"),
                    index: Some(0),
                }
            ),
            Some(1)
        );

        // Case-insensitive prefix match wins over substring match.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("waybound window 2"),
                    index: Some(0),
                }
            ),
            Some(1)
        );

        // Case-insensitive substring match when no exact or prefix match exists.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("dashboard"),
                    index: Some(0),
                }
            ),
            Some(2)
        );

        // Fallback to index when title is absent or unmatched.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("Nonexistent Title"),
                    index: Some(3),
                }
            ),
            Some(3)
        );
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: None,
                    index: Some(1),
                }
            ),
            Some(1)
        );

        // Out-of-bounds index returns None.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("Nonexistent"),
                    index: Some(10),
                }
            ),
            None
        );

        // Empty frame list returns None.
        assert_eq!(
            select_frame_index(
                &[],
                WindowScope {
                    title: Some("Waybound"),
                    index: Some(0),
                }
            ),
            None
        );
    }

    #[test]
    fn select_frame_index_disambiguates_identical_titles_using_scope_index() {
        let frames = vec![
            Some("New Tab - Google Chrome".to_owned()),
            Some("New Tab - Google Chrome".to_owned()),
        ];

        // Exact-title tie prefers scope.index (1 instead of 0).
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("New Tab - Google Chrome"),
                    index: Some(1),
                }
            ),
            Some(1)
        );
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("New Tab - Google Chrome"),
                    index: Some(0),
                }
            ),
            Some(0)
        );

        // Case-insensitive prefix tie prefers scope.index.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("new tab"),
                    index: Some(1),
                }
            ),
            Some(1)
        );

        // Case-insensitive substring tie prefers scope.index.
        assert_eq!(
            select_frame_index(
                &frames,
                WindowScope {
                    title: Some("google chrome"),
                    index: Some(1),
                }
            ),
            Some(1)
        );

        // Higher-priority tier still beats a lower-priority match at scope.index.
        let mixed = vec![
            Some("New Tab - Google Chrome".to_owned()),
            Some("New Tab".to_owned()),
        ];
        assert_eq!(
            select_frame_index(
                &mixed,
                WindowScope {
                    title: Some("New Tab"),
                    index: Some(0),
                }
            ),
            Some(1)
        );
    }
}
