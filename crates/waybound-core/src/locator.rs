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
    /// Tab selector inside a tablist.
    Tab,
    /// Modal or dialog container.
    Dialog,
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
}

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
        }
    }

    /// Evaluates whether a candidate [`AccessibilityNode`] satisfies this query.
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
        };

        let query = LocatorQuery::by_role(Role::Button, Some("search".to_owned()));
        assert!(query.matches(&node));

        let wrong_role = LocatorQuery::by_role(Role::Link, Some("search".to_owned()));
        assert!(!wrong_role.matches(&node));
    }
}
