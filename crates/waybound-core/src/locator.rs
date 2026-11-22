//! Semantic accessibility node and locator definitions.

use serde::{Deserialize, Serialize};

/// Semantic accessibility role mapped across OS accessibility APIs
/// (`AXUIElement` on macOS, `UIAutomation` on Windows, AT-SPI2 on Linux,
/// and Android `AccessibilityNodeInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Interactive push button.
    Button,
    /// Hyperlink.
    Link,
    /// Single-line or multi-line text input.
    TextBox,
    /// Search input field (`<input type="search">` / `role="searchbox"`).
    SearchBox,
    /// Checkbox toggle.
    CheckBox,
    /// Radio button option.
    Radio,
    /// On/off toggle switch.
    Switch,
    /// Combobox / autocomplete input.
    ComboBox,
    /// Selectable list container.
    ListBox,
    /// Individual option inside a listbox or select menu.
    Option,
    /// Generic list container (`<ul>` / `<ol>` / `role="list"`).
    List,
    /// Individual item inside a list (`<li>` / `role="listitem"`).
    ListItem,
    /// Tab selector inside a tablist.
    Tab,
    /// Modal or dialog container.
    Dialog,
    /// Named landmark region (`role="region"` / `<section aria-label="...">`).
    Region,
    /// Generic grouping container (`role="group"` / `<fieldset>`).
    Group,
    /// Image element (`<img>` / `role="img"`).
    Img,
    /// Menu item entry.
    MenuItem,
    /// Document root or web area.
    Document,
    /// Heading element.
    Heading,
    /// Static text node.
    StaticText,
    /// Fallback for unmapped roles.
    Unknown,
}

/// Screen-space bounding rectangle in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    /// Left edge X coordinate.
    pub x: f64,
    /// Top edge Y coordinate.
    pub y: f64,
    /// Rectangle width.
    pub width: f64,
    /// Rectangle height.
    pub height: f64,
}

impl Bounds {
    /// Returns the center point `(x, y)` of the bounding rectangle.
    #[must_use]
    pub fn center(&self) -> (f64, f64) {
        (self.x + self.width / 2.0, self.y + self.height / 2.0)
    }

    /// Returns `true` when `other`'s center lies within this bounding rectangle (with 1px tolerance).
    #[must_use]
    pub fn contains_center(&self, other: &Self) -> bool {
        if !self.x.is_finite()
            || !self.y.is_finite()
            || !self.width.is_finite()
            || !self.height.is_finite()
            || self.width <= 0.0
            || self.height <= 0.0
        {
            return false;
        }
        let (cx, cy) = other.center();
        if !cx.is_finite() || !cy.is_finite() {
            return false;
        }
        let tol = 1.0;
        cx >= self.x - tol
            && cx <= self.x + self.width + tol
            && cy >= self.y - tol
            && cy <= self.y + self.height + tol
    }
}

/// Maximum nesting depth for chained `within` parent scopes.
const MAX_SCOPE_DEPTH: usize = 8;

/// A single node in the live OS accessibility tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessibilityNode {
    /// Backend-assigned node identifier.
    pub id: String,
    /// Normalized semantic role.
    pub role: Role,
    /// Accessible name (label or visible text).
    pub name: Option<String>,
    /// Current editable value, if applicable.
    pub value: Option<String>,
    /// Logical screen-space bounding box.
    pub bounds: Bounds,
    /// Whether the node is currently focused.
    pub focused: bool,
    /// Checked state of a checkbox, radio button, switch, or checkable menu item.
    ///
    /// `None` when the concept does not apply to the node (buttons, links, text, ...).
    /// A mixed / indeterminate tri-state checkbox is reported as `Some(false)`: it is not
    /// fully checked, so `is_checked()` is `false` and `check()` clicks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    /// Whether the node is disabled (not enabled / not sensitive) and ignores input.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    /// Expanded state of an expandable node (combobox, disclosure, tree item, menu button).
    ///
    /// `None` when the node cannot be expanded or collapsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded: Option<bool>,
}

// `skip_serializing_if` passes the field by reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl AccessibilityNode {
    /// Creates a node with no checked/expanded state, enabled, and not focused.
    #[must_use]
    pub const fn new(
        id: String,
        role: Role,
        name: Option<String>,
        value: Option<String>,
        bounds: Bounds,
    ) -> Self {
        Self {
            id,
            role,
            name,
            value,
            bounds,
            focused: false,
            checked: None,
            disabled: false,
            expanded: None,
        }
    }
}

/// Query used to resolve a semantic element in the accessibility tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatorQuery {
    /// Optional semantic role constraint.
    pub role: Option<Role>,
    /// Optional accessible name substring or exact match.
    pub name: Option<String>,
    /// Whether `name` must match exactly.
    pub exact: bool,
    /// Zero-based match index when multiple nodes satisfy the query.
    #[serde(default)]
    pub nth: usize,
    /// Optional parent container query; matches are spatially scoped inside the resolved parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within: Option<Box<Self>>,
}

impl LocatorQuery {
    /// Creates a query matching by semantic role and optional accessible name.
    #[must_use]
    pub const fn by_role(role: Role, name: Option<String>) -> Self {
        Self {
            role: Some(role),
            name,
            exact: false,
            nth: 0,
            within: None,
        }
    }

    /// Evaluates whether a candidate [`AccessibilityNode`] satisfies this query's own filters
    /// (ignoring `within` parent scoping and `nth`).
    #[must_use]
    pub fn matches(&self, node: &AccessibilityNode) -> bool {
        if let Some(expected_role) = self.role
            && node.role != expected_role
        {
            return false;
        }

        if let Some(expected_name) = &self.name {
            let Some(actual_name) = &node.name else {
                return false;
            };
            if self.exact {
                if actual_name != expected_name {
                    return false;
                }
            } else if !actual_name
                .to_lowercase()
                .contains(&expected_name.to_lowercase())
            {
                return false;
            }
        }

        true
    }

    /// Resolves all nodes matching this query (honoring any chained `within` parent scopes,
    /// ignoring `self.nth`).
    #[must_use]
    pub fn resolve_all<'a>(&self, nodes: &'a [AccessibilityNode]) -> Vec<&'a AccessibilityNode> {
        self.resolve_all_with_depth(nodes, 0)
    }

    /// Resolves the `self.nth`-th node matching this query (honoring any chained `within` scopes).
    #[must_use]
    pub fn resolve_one<'a>(&self, nodes: &'a [AccessibilityNode]) -> Option<&'a AccessibilityNode> {
        self.resolve_all_with_depth(nodes, 0)
            .into_iter()
            .nth(self.nth)
    }

    fn resolve_all_with_depth<'a>(
        &self,
        nodes: &'a [AccessibilityNode],
        depth: usize,
    ) -> Vec<&'a AccessibilityNode> {
        if depth > MAX_SCOPE_DEPTH {
            return Vec::new();
        }

        let parent = match &self.within {
            None => None,
            Some(parent_query) => {
                let Some(resolved) = parent_query
                    .resolve_all_with_depth(nodes, depth + 1)
                    .into_iter()
                    .nth(parent_query.nth)
                else {
                    return Vec::new();
                };
                Some(resolved)
            }
        };

        nodes
            .iter()
            .filter(|node| {
                if let Some(container) = parent
                    && (node.id == container.id || !container.bounds.contains_center(&node.bounds))
                {
                    return false;
                }
                self.matches(node)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_center_computes_midpoint() {
        let bounds = Bounds {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 40.0,
        };
        assert_eq!(bounds.center(), (60.0, 40.0));
    }

    #[test]
    fn locator_matches_role_and_case_insensitive_name() {
        let node = AccessibilityNode {
            id: "node-1".to_owned(),
            role: Role::Button,
            name: Some("Search Flights".to_owned()),
            value: None,
            bounds: Bounds {
                x: 0.0,
                y: 0.0,
                width: 80.0,
                height: 30.0,
            },
            focused: false,
            checked: None,
            disabled: false,
            expanded: None,
        };

        let query = LocatorQuery::by_role(Role::Button, Some("search".to_owned()));
        assert!(query.matches(&node));

        let wrong_role = LocatorQuery::by_role(Role::Link, Some("search".to_owned()));
        assert!(!wrong_role.matches(&node));
    }

    #[test]
    fn scoped_locator_resolves_only_inside_parent_bounds() {
        let nodes = vec![
            AccessibilityNode {
                id: "outer-save".to_owned(),
                role: Role::Button,
                name: Some("Save".to_owned()),
                value: None,
                bounds: Bounds {
                    x: 10.0,
                    y: 10.0,
                    width: 60.0,
                    height: 30.0,
                },
                focused: false,
                checked: None,
                disabled: false,
                expanded: None,
            },
            AccessibilityNode {
                id: "settings-dialog".to_owned(),
                role: Role::Dialog,
                name: Some("Settings".to_owned()),
                value: None,
                bounds: Bounds {
                    x: 200.0,
                    y: 200.0,
                    width: 400.0,
                    height: 300.0,
                },
                focused: false,
                checked: None,
                disabled: false,
                expanded: None,
            },
            AccessibilityNode {
                id: "dialog-save".to_owned(),
                role: Role::Button,
                name: Some("Save".to_owned()),
                value: None,
                bounds: Bounds {
                    x: 500.0,
                    y: 440.0,
                    width: 70.0,
                    height: 30.0,
                },
                focused: false,
                checked: None,
                disabled: false,
                expanded: None,
            },
        ];

        let query = LocatorQuery {
            role: Some(Role::Button),
            name: Some("Save".to_owned()),
            exact: true,
            nth: 0,
            within: Some(Box::new(LocatorQuery::by_role(
                Role::Dialog,
                Some("Settings".to_owned()),
            ))),
        };

        let resolved = query.resolve_one(&nodes);
        assert_eq!(resolved.map(|n| n.id.as_str()), Some("dialog-save"));

        let missing_parent = LocatorQuery {
            within: Some(Box::new(LocatorQuery::by_role(
                Role::Dialog,
                Some("Nonexistent".to_owned()),
            ))),
            ..query
        };
        assert_eq!(missing_parent.resolve_all(&nodes).len(), 0);
    }

    #[test]
    fn node_without_state_fields_deserialises_with_defaults() {
        let legacy = r#"{"id":"n","role":"button","name":"Go","value":null,
            "bounds":{"x":0.0,"y":0.0,"width":1.0,"height":1.0},"focused":true}"#;
        let parsed: Result<AccessibilityNode, _> = serde_json::from_str(legacy);
        assert!(parsed.is_ok());
        if let Ok(node) = parsed {
            assert_eq!(node.checked, None);
            assert!(!node.disabled);
            assert_eq!(node.expanded, None);
            assert!(node.focused);
        }
    }

    #[test]
    fn default_state_fields_are_not_serialised() {
        let node = AccessibilityNode::new(
            "n".to_owned(),
            Role::Button,
            None,
            None,
            Bounds {
                x: 0.0,
                y: 0.0,
                width: 1.0,
                height: 1.0,
            },
        );
        let json = serde_json::to_string(&node).unwrap_or_default();
        assert!(!json.contains("checked"));
        assert!(!json.contains("disabled"));
        assert!(!json.contains("expanded"));
    }

    #[test]
    fn state_fields_round_trip() {
        let node = AccessibilityNode {
            checked: Some(true),
            disabled: true,
            expanded: Some(false),
            ..AccessibilityNode::new(
                "cb".to_owned(),
                Role::CheckBox,
                Some("Agree".to_owned()),
                None,
                Bounds {
                    x: 0.0,
                    y: 0.0,
                    width: 1.0,
                    height: 1.0,
                },
            )
        };
        let json = serde_json::to_string(&node).unwrap_or_default();
        assert!(json.contains(r#""checked":true"#));
        assert!(json.contains(r#""disabled":true"#));
        assert!(json.contains(r#""expanded":false"#));
        let back: Result<AccessibilityNode, _> = serde_json::from_str(&json);
        assert!(matches!(back, Ok(ref parsed) if *parsed == node));
    }
}
