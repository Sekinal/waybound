//! Pure-Rust AT-SPI2 D-Bus accessibility client via `zbus`.
//!
//! Replaces per-snapshot `python3` (`gi.repository.Atspi`) subprocess spawns with a
//! persistent D-Bus connection to the AT-SPI2 accessibility bus, cutting snapshot
//! latency from ~150–250 ms to a few milliseconds with `#![forbid(unsafe_code)]`.

use std::collections::{HashMap, VecDeque};

use tracing::debug;
use waybound_core::{AccessibilityNode, Bounds, Result, Role, WayboundError};
use zbus::blocking::{Connection, connection::Builder};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

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

    /// Resolves the currently attached `document web` node from the live application tree.
    ///
    /// We intentionally avoid caching the document object path across calls: Chrome keeps
    /// navigated-away documents alive in its `BFcache` answering D-Bus queries (`GetRoleName`,
    /// `GetState`, `GetExtents`, `GetChildren`) with frozen state even after detaching them
    /// from the active window hierarchy.
    fn resolve_web_root(
        &self,
        target_pid: Option<i32>,
    ) -> Result<(Option<AccessibleRef>, Option<String>, Option<Bounds>)> {
        let apps = self
            .get_children(REGISTRY_BUS, REGISTRY_ROOT)
            .map_err(|err| WayboundError::BackendUnavailable {
                backend: BACKEND_NAME.to_owned(),
                reason: format!("AT-SPI2 Registry GetChildren failed: {err}"),
            })?;

        let Some(target_app) = self.find_target_app(&apps, target_pid) else {
            return Ok((None, None, None));
        };

        Ok(self.locate_web_document(&target_app))
    }

    /// Fast-path URL lookup on the active web document without walking DOM children.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn current_url(&mut self, target_pid: Option<i32>) -> Result<Option<String>> {
        let (_, url, _) = self.resolve_web_root(target_pid)?;
        Ok(url.filter(|u| !u.trim().is_empty()))
    }

    /// Fast-path viewport bounds lookup on the active web document without walking DOM children.
    ///
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn viewport_bounds(&mut self, target_pid: Option<i32>) -> Result<Option<Bounds>> {
        let (_, _, bounds) = self.resolve_web_root(target_pid)?;
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
    /// # Errors
    ///
    /// Returns [`WayboundError::BackendUnavailable`] if the AT-SPI2 registry cannot be queried.
    pub fn snapshot_limited(
        &mut self,
        target_pid: Option<i32>,
        max_nodes: usize,
    ) -> Result<AtspiSnapshot> {
        let limit = max_nodes.clamp(waybound_core::MIN_MAX_NODES, waybound_core::MAX_MAX_NODES);
        let (web_root, mut current_url, viewport_bounds) = self.resolve_web_root(target_pid)?;
        let Some(root) = web_root else {
            return Ok(AtspiSnapshot {
                nodes: Vec::new(),
                truncated: false,
                current_url,
                viewport_bounds,
            });
        };

        let (nodes, truncated) = self.walk_web_document(&root, limit);
        if current_url.as_deref().is_some_and(|u| u.trim().is_empty()) {
            current_url = None;
        }

        Ok(AtspiSnapshot {
            nodes,
            truncated,
            current_url,
            viewport_bounds,
        })
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
                for child in children {
                    if !child.0.is_empty() {
                        queue.push_back(child);
                    }
                }
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
        msg.body().deserialize::<Vec<AccessibleRef>>()
    }

    fn get_role_name(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_ACCESSIBLE), "GetRoleName", &())
            .ok()?;
        msg.body().deserialize::<String>().ok()
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
        let val = msg.body().deserialize::<OwnedValue>().ok()?;
        let s: String = val.try_into().ok()?;
        let trimmed = s.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
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
        let (x, y, w, h) = msg.body().deserialize::<(i32, i32, i32, i32)>().ok()?;
        Some(Bounds {
            x: f64::from(x),
            y: f64::from(y),
            width: f64::from(w),
            height: f64::from(h),
        })
    }

    fn get_state(&self, bus: &str, path: &str) -> Option<Vec<u32>> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_ACCESSIBLE), "GetState", &())
            .ok()?;
        msg.body().deserialize::<Vec<u32>>().ok()
    }

    fn get_document_url(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_DOCUMENT), "GetAttributes", &())
            .ok()?;
        let attrs = msg.body().deserialize::<HashMap<String, String>>().ok()?;
        attrs
            .get("DocURL")
            .or_else(|| attrs.get("URI"))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    fn get_hyperlink_uri(&self, bus: &str, path: &str) -> Option<String> {
        let msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_HYPERLINK), "GetURI", &(0i32,))
            .ok()?;
        let uri = msg.body().deserialize::<String>().ok()?;
        let trimmed = uri.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
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
        let count_val = count_msg.body().deserialize::<OwnedValue>().ok()?;
        let count: i32 = count_val.try_into().ok()?;
        if count <= 0 || count > 4_096 {
            return None;
        }
        let text_msg = self
            .conn
            .call_method(Some(bus), path, Some(IFACE_TEXT), "GetText", &(0i32, count))
            .ok()?;
        let text = text_msg.body().deserialize::<String>().ok()?;
        let trimmed = text.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
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
