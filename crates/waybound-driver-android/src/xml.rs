//! Pure-Rust, zero-panic parser for Android `uiautomator dump` XML hierarchies.

use waybound_core::{AccessibilityNode, Bounds, Role};

/// Upper bound on accessibility nodes extracted from a single `uiautomator` dump.
pub const MAX_NODES: usize = 2_000;

/// Parses an Android `uiautomator dump` XML payload into normalized
/// [`AccessibilityNode`] entries.
///
/// Tolerates leading/trailing non-XML status lines (such as Android's
/// `UI hierchary dumped to: /dev/tty`) and truncates output at [`MAX_NODES`].
#[must_use]
pub fn parse_uiautomator_xml(xml: &str) -> Vec<AccessibilityNode> {
    let mut nodes = Vec::new();
    let bytes = xml.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() && nodes.len() < MAX_NODES {
        let Some(rel_lt) = xml.get(pos..).and_then(|s| s.find('<')) else {
            break;
        };
        let tag_start = pos + rel_lt;

        // Skip XML comments (`<!-- ... -->`) so `<node` inside comments is ignored.
        if xml.get(tag_start..).is_some_and(|s| s.starts_with("<!--")) {
            if let Some(end_rel) = xml.get(tag_start + 4..).and_then(|s| s.find("-->")) {
                pos = tag_start + 4 + end_rel + 3;
                continue;
            }
            break;
        }

        let Some(tag_end) = find_tag_end(xml, tag_start + 1) else {
            break;
        };

        if let Some(inner) = xml.get(tag_start + 1..tag_end)
            && let Some(attr_region) = strip_node_tag_prefix(inner)
            && let Some(node) = parse_node_attributes(attr_region, nodes.len())
        {
            nodes.push(node);
        }

        pos = tag_end + 1;
    }

    nodes
}

/// Finds the byte index of the closing `>` for an XML tag starting after `<`,
/// ignoring `>` characters inside single- or double-quoted attribute values.
fn find_tag_end(xml: &str, start: usize) -> Option<usize> {
    let bytes = xml.as_bytes();
    let mut i = start;
    let mut quote: Option<u8> = None;

    while let Some(&b) = bytes.get(i) {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Some(i),
                _ => {}
            },
        }
        i += 1;
    }

    None
}

/// Returns the attribute slice if `tag_inner` is a `<node ...>` or `<node .../>` tag.
fn strip_node_tag_prefix(tag_inner: &str) -> Option<&str> {
    let rest = tag_inner.strip_prefix("node")?;
    let first = rest.as_bytes().first().copied()?;
    if !first.is_ascii_whitespace() {
        return None;
    }
    let trimmed = rest.trim();
    Some(trimmed.strip_suffix('/').unwrap_or(trimmed))
}

/// Raw attributes extracted from a single `<node ...>` element.
// Mirrors the independent boolean attributes of a `uiautomator` node one to one.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct RawNodeAttrs<'a> {
    class_name: &'a str,
    text: &'a str,
    content_desc: &'a str,
    resource_id: &'a str,
    bounds: &'a str,
    clickable: bool,
    focused: bool,
    checkable: bool,
    checked: bool,
    /// `enabled="false"` seen; a missing attribute means enabled.
    disabled: bool,
}

fn parse_node_attributes(attrs: &str, index: usize) -> Option<AccessibilityNode> {
    let raw = scan_attributes(attrs);
    let bounds = parse_bounds(raw.bounds)?;

    let resource_id = (!raw.resource_id.is_empty()).then_some(raw.resource_id);
    let role = map_class_to_role(raw.class_name, raw.clickable, resource_id);

    let text = unescape_xml(raw.text);
    let content_desc = unescape_xml(raw.content_desc);

    let text_opt = (!text.is_empty()).then_some(text);
    let desc_opt = (!content_desc.is_empty()).then_some(content_desc);

    let (name, value) = if role == Role::TextBox {
        let name = desc_opt.or_else(|| text_opt.clone());
        (name, text_opt)
    } else {
        let name = text_opt.or(desc_opt);
        (name, None)
    };

    if role == Role::Unknown && name.is_none() && value.is_none() {
        return None;
    }

    Some(AccessibilityNode {
        id: format!("android-node-{index}"),
        role,
        name,
        value,
        bounds,
        focused: raw.focused,
        // `uiautomator` has no tri-state: `checked` is only meaningful when `checkable`.
        checked: raw.checkable.then_some(raw.checked),
        disabled: raw.disabled,
        // `uiautomator dump` does not expose an expanded/collapsed state.
        expanded: None,
    })
}

/// Extracts the active URL text from Chrome's `:id/url_bar` node in `uiautomator` XML, if present.
#[must_use]
pub fn extract_chrome_url(xml: &str) -> Option<String> {
    let bytes = xml.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        let rel_open = xml.get(pos..)?.find('<')?;
        let tag_start = pos + rel_open;
        if xml.get(tag_start..)?.starts_with("<!--") {
            let rel_end = xml.get(tag_start + 4..)?.find("-->")?;
            pos = tag_start + 4 + rel_end + 3;
            continue;
        }
        let tag_end = find_tag_end(xml, tag_start)?;
        if let Some(rest) = xml
            .get(tag_start..tag_end)
            .and_then(|s| s.strip_prefix("<node"))
            && rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace)
        {
            let raw = scan_attributes(rest.trim_end_matches('/'));
            if raw.resource_id.ends_with(":id/url_bar") {
                let text = unescape_xml(raw.text);
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
        pos = tag_end + 1;
    }

    None
}

fn scan_attributes(attrs: &str) -> RawNodeAttrs<'_> {
    let mut raw = RawNodeAttrs::default();
    let bytes = attrs.as_bytes();
    let mut pos = 0;

    while pos < bytes.len() {
        while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        let name_start = pos;
        while bytes
            .get(pos)
            .is_some_and(|&b| !b.is_ascii_whitespace() && b != b'=')
        {
            pos += 1;
        }
        let Some(attr_name) = attrs.get(name_start..pos) else {
            break;
        };

        while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos += 1;
        }
        if bytes.get(pos) != Some(&b'=') {
            while bytes.get(pos).is_some_and(|&b| !b.is_ascii_whitespace()) {
                pos += 1;
            }
            continue;
        }
        pos += 1;

        while bytes.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos += 1;
        }
        let Some(&quote) = bytes.get(pos) else {
            break;
        };
        if quote != b'"' && quote != b'\'' {
            while bytes.get(pos).is_some_and(|&b| !b.is_ascii_whitespace()) {
                pos += 1;
            }
            continue;
        }
        pos += 1;

        let val_start = pos;
        while bytes.get(pos).is_some_and(|&b| b != quote) {
            pos += 1;
        }
        let Some(attr_val) = attrs.get(val_start..pos) else {
            break;
        };
        if bytes.get(pos) == Some(&quote) {
            pos += 1;
        }

        match attr_name {
            "class" => raw.class_name = attr_val,
            "text" => raw.text = attr_val,
            "content-desc" => raw.content_desc = attr_val,
            "resource-id" => raw.resource_id = attr_val,
            "bounds" => raw.bounds = attr_val,
            "clickable" => raw.clickable = attr_val == "true",
            "focused" => raw.focused = attr_val == "true",
            "checkable" => raw.checkable = attr_val == "true",
            "checked" => raw.checked = attr_val == "true",
            "enabled" => raw.disabled = attr_val == "false",
            _ => {}
        }
    }

    raw
}

/// Maps an Android widget `class` name (plus `clickable` state and optional
/// `resource-id`) to a normalized [`Role`].
#[must_use]
pub fn map_class_to_role(class_name: &str, clickable: bool, resource_id: Option<&str>) -> Role {
    let simple = class_name.rsplit('.').next().unwrap_or(class_name);

    match simple {
        "EditText" | "AutoCompleteTextView" | "MultiAutoCompleteTextView" => Role::TextBox,
        "Spinner" => Role::ComboBox,
        "CheckBox" | "CheckedTextView" => Role::CheckBox,
        "RadioButton" => Role::Radio,
        "Switch" | "ToggleButton" => Role::Switch,
        "Button" | "ImageButton" => Role::Button,
        "ImageView" => Role::Img,
        "ListView" | "RecyclerView" => Role::ListBox,
        "TabWidget" => Role::Tab,
        "WebView" => Role::Document,
        "TextView" => {
            if clickable {
                Role::Link
            } else {
                Role::StaticText
            }
        }
        "View" => {
            if !clickable {
                return Role::Unknown;
            }
            let looks_like_button = resource_id.is_some_and(|id| {
                let lower = id.to_ascii_lowercase();
                lower.contains("button") || lower.contains("btn")
            });
            if looks_like_button {
                Role::Button
            } else {
                Role::Link
            }
        }
        _ => {
            if clickable {
                Role::Button
            } else {
                Role::Unknown
            }
        }
    }
}

/// Parses an Android `uiautomator` bounds string of the form `"[x1,y1][x2,y2]"`.
#[must_use]
pub fn parse_bounds(raw: &str) -> Option<Bounds> {
    let trimmed = raw.trim();
    let rest = trimmed.strip_prefix('[')?;
    let (first, second) = rest.split_once("][")?;
    let second = second.strip_suffix(']')?;

    let (x1_str, y1_str) = first.split_once(',')?;
    let (x2_str, y2_str) = second.split_once(',')?;

    let x1 = x1_str.trim().parse::<i32>().ok()?;
    let y1 = y1_str.trim().parse::<i32>().ok()?;
    let x2 = x2_str.trim().parse::<i32>().ok()?;
    let y2 = y2_str.trim().parse::<i32>().ok()?;

    let x = f64::from(x1);
    let y = f64::from(y1);
    let width = (f64::from(x2) - x).max(0.0);
    let height = (f64::from(y2) - y).max(0.0);

    Some(Bounds {
        x,
        y,
        width,
        height,
    })
}

/// Unescapes standard XML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`)
/// and numeric character references (`&#...;` / `&#x...;`).
#[must_use]
pub fn unescape_xml(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }

    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;

    while let Some(amp_idx) = rest.find('&') {
        if let Some(prefix) = rest.get(..amp_idx) {
            out.push_str(prefix);
        }
        let after_amp = rest.get(amp_idx + 1..).unwrap_or("");
        if let Some(semi_idx) = after_amp.find(';') {
            let entity = after_amp.get(..semi_idx).unwrap_or("");
            if let Some(decoded) = decode_xml_entity(entity) {
                out.push(decoded);
                rest = after_amp.get(semi_idx + 1..).unwrap_or("");
                continue;
            }
        }
        out.push('&');
        rest = after_amp;
    }

    out.push_str(rest);
    out
}

fn decode_xml_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let num = entity.strip_prefix('#')?;
            let code = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                num.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_FIXTURE: &str = r#"UI hierchary dumped to: /dev/tty
<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.android.chrome" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,0][1080,2400]">
    <node index="0" text="https://example.com/search?a=1&amp;b=2" resource-id="com.android.chrome:id/url_bar" class="android.widget.EditText" package="com.android.chrome" content-desc="Search or type URL" clickable="true" focused="true" bounds="[144,100][880,210]" />
    <node index="1" text="" resource-id="com.android.chrome:id/tab_switcher_button" class="android.widget.ImageButton" package="com.android.chrome" content-desc="Switch or close tabs" clickable="true" focused="false" bounds="[890,100][980,210]" />
    <node index="2" text="" resource-id="" class="android.webkit.WebView" package="com.android.chrome" content-desc="Example Domain" clickable="false" focused="false" bounds="[0,220][1080,2280]">
      <node index="0" text="Example &amp; &quot;Demo&quot; &lt;Site&gt;" resource-id="" class="android.widget.TextView" package="com.android.chrome" content-desc="" clickable="false" focused="false" bounds="[48,280][1032,360]" />
      <node index="1" text="More information..." resource-id="" class="android.view.View" package="com.android.chrome" content-desc="More information..." clickable="true" focused="false" bounds="[48,400][420,470]" />
      <node index="2" text="Accept &apos;Terms&apos;" resource-id="" class="android.widget.CheckBox" package="com.android.chrome" content-desc="" clickable="true" focused="false" bounds="[48,500][500,560]" />
      <node index="3" text="Continue &gt; Next" resource-id="" class="android.widget.Button" package="com.android.chrome" content-desc="" clickable="true" focused="false" bounds="[48,600][400,700]" />
    </node>
  </node>
</hierarchy>
"#;

    #[test]
    fn parses_realistic_android_chrome_hierarchy() {
        let nodes = parse_uiautomator_xml(CHROME_FIXTURE);
        assert_eq!(nodes.len(), 7);
        assert_eq!(
            extract_chrome_url(CHROME_FIXTURE).as_deref(),
            Some("https://example.com/search?a=1&b=2")
        );

        // URL bar (EditText)
        let url_bar = nodes.first();
        assert!(url_bar.is_some());
        if let Some(node) = url_bar {
            assert_eq!(node.role, Role::TextBox);
            assert_eq!(node.name.as_deref(), Some("Search or type URL"));
            assert_eq!(
                node.value.as_deref(),
                Some("https://example.com/search?a=1&b=2")
            );
            assert!(node.focused);
            assert_eq!(
                node.bounds,
                Bounds {
                    x: 144.0,
                    y: 100.0,
                    width: 736.0,
                    height: 110.0,
                }
            );
        }

        // Tab switcher (ImageButton)
        if let Some(node) = nodes.get(1) {
            assert_eq!(node.role, Role::Button);
            assert_eq!(node.name.as_deref(), Some("Switch or close tabs"));
            assert!(!node.focused);
        }

        // WebView document
        if let Some(node) = nodes.get(2) {
            assert_eq!(node.role, Role::Document);
            assert_eq!(node.name.as_deref(), Some("Example Domain"));
        }

        // Static text with XML entities
        if let Some(node) = nodes.get(3) {
            assert_eq!(node.role, Role::StaticText);
            assert_eq!(node.name.as_deref(), Some("Example & \"Demo\" <Site>"));
        }

        // Clickable View -> Link
        if let Some(node) = nodes.get(4) {
            assert_eq!(node.role, Role::Link);
            assert_eq!(node.name.as_deref(), Some("More information..."));
        }

        // CheckBox with &apos;
        if let Some(node) = nodes.get(5) {
            assert_eq!(node.role, Role::CheckBox);
            assert_eq!(node.name.as_deref(), Some("Accept 'Terms'"));
        }

        // Button with &gt;
        if let Some(node) = nodes.get(6) {
            assert_eq!(node.role, Role::Button);
            assert_eq!(node.name.as_deref(), Some("Continue > Next"));
        }
    }

    #[test]
    fn parses_checkable_checked_and_enabled_states() {
        let xml = r#"<hierarchy>
  <node text="Nonstop" class="android.widget.CheckBox" checkable="true" checked="true" enabled="true" clickable="true" bounds="[0,0][10,10]" />
  <node text="Insurance" class="android.widget.CheckBox" checkable="true" checked="false" enabled="false" clickable="true" bounds="[0,20][10,30]" />
  <node text="Go" class="android.widget.Button" checkable="false" checked="false" enabled="true" clickable="true" bounds="[0,40][10,50]" />
  <node text="Legacy" class="android.widget.Button" clickable="true" bounds="[0,60][10,70]" />
</hierarchy>"#;
        let nodes = parse_uiautomator_xml(xml);
        assert_eq!(nodes.len(), 4);
        let states: Vec<(Option<bool>, bool, Option<bool>)> = nodes
            .iter()
            .map(|n| (n.checked, n.disabled, n.expanded))
            .collect();
        assert_eq!(
            states,
            vec![
                (Some(true), false, None),
                (Some(false), true, None),
                (None, false, None),
                (None, false, None),
            ]
        );
    }

    #[test]
    fn parse_bounds_handles_valid_and_invalid_inputs() {
        assert_eq!(
            parse_bounds("[10,20][110,220]"),
            Some(Bounds {
                x: 10.0,
                y: 20.0,
                width: 100.0,
                height: 200.0,
            })
        );
        assert_eq!(
            parse_bounds("[-10,-5][30,15]"),
            Some(Bounds {
                x: -10.0,
                y: -5.0,
                width: 40.0,
                height: 20.0,
            })
        );
        // Inverted bounds clamp width/height to 0.0 instead of negative.
        assert_eq!(
            parse_bounds("[100,100][50,40]"),
            Some(Bounds {
                x: 100.0,
                y: 100.0,
                width: 0.0,
                height: 0.0,
            })
        );
        assert_eq!(parse_bounds(""), None);
        assert_eq!(parse_bounds("[10,20]"), None);
        assert_eq!(parse_bounds("[a,20][30,40]"), None);
    }

    #[test]
    fn role_mapping_covers_widgets_and_clickable_heuristics() {
        assert_eq!(
            map_class_to_role("android.widget.Button", true, None),
            Role::Button
        );
        assert_eq!(
            map_class_to_role("android.widget.EditText", true, None),
            Role::TextBox
        );
        assert_eq!(
            map_class_to_role("android.widget.CheckBox", true, None),
            Role::CheckBox
        );
        assert_eq!(
            map_class_to_role("android.webkit.WebView", false, None),
            Role::Document
        );
        assert_eq!(
            map_class_to_role("android.widget.TextView", false, None),
            Role::StaticText
        );
        assert_eq!(
            map_class_to_role("android.widget.TextView", true, None),
            Role::Link
        );
        assert_eq!(
            map_class_to_role("android.view.View", true, None),
            Role::Link
        );
        assert_eq!(
            map_class_to_role("android.view.View", true, Some("app:id/submit_btn")),
            Role::Button
        );
        assert_eq!(
            map_class_to_role("android.view.View", false, None),
            Role::Unknown
        );
        assert_eq!(
            map_class_to_role("android.widget.LinearLayout", true, None),
            Role::Button
        );
    }

    #[test]
    fn unescape_xml_handles_named_numeric_and_unknown_entities() {
        assert_eq!(
            unescape_xml("A &amp; B &lt; C &gt; &quot;D&quot; &apos;E&apos;"),
            "A & B < C > \"D\" 'E'"
        );
        assert_eq!(unescape_xml("Line1&#10;Line2&#x21;"), "Line1\nLine2!");
        assert_eq!(unescape_xml("unknown &foo; & bare"), "unknown &foo; & bare");
    }

    #[test]
    fn handles_gt_inside_attribute_and_comments() {
        let xml = r#"<hierarchy>
            <!-- <node class="android.widget.Button" text="Ignored" bounds="[0,0][10,10]" /> -->
            <node class="android.widget.Button" text="A > B" bounds="[1,2][11,22]" clickable="true" />
        </hierarchy>"#;
        let nodes = parse_uiautomator_xml(xml);
        assert_eq!(nodes.len(), 1);
        if let Some(node) = nodes.first() {
            assert_eq!(node.name.as_deref(), Some("A > B"));
            assert_eq!(node.role, Role::Button);
        }
    }

    #[test]
    fn enforces_max_nodes_bound() {
        use std::fmt::Write as _;

        let mut xml = String::from("<hierarchy>");
        for i in 0..(MAX_NODES + 50) {
            let _ = write!(
                xml,
                "<node class=\"android.widget.TextView\" text=\"item-{i}\" bounds=\"[0,0][10,10]\" />"
            );
        }
        xml.push_str("</hierarchy>");

        let nodes = parse_uiautomator_xml(&xml);
        assert_eq!(nodes.len(), MAX_NODES);
    }
}
