"""Typed protocol and value objects for the waybound Python SDK."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class BackendKind(StrEnum):
    """Supported execution backends."""

    MACOS_NATIVE = "mac_os_native"
    WINDOWS_NATIVE = "windows_native"
    LINUX_WAYLAND = "linux_wayland"
    ANDROID_WAYDROID = "android_waydroid"


class Role(StrEnum):
    """Normalized semantic accessibility roles."""

    BUTTON = "button"
    LINK = "link"
    TEXTBOX = "text_box"
    CHECKBOX = "check_box"
    RADIO = "radio"
    SWITCH = "switch"
    COMBOBOX = "combo_box"
    LISTBOX = "list_box"
    OPTION = "option"
    TAB = "tab"
    DIALOG = "dialog"
    MENUITEM = "menu_item"
    DOCUMENT = "document"
    HEADING = "heading"
    STATIC_TEXT = "static_text"
    UNKNOWN = "unknown"


class KeyModifier(StrEnum):
    """Modifier keys held during a key press."""

    META = "meta"
    CONTROL = "control"
    ALT = "alt"
    SHIFT = "shift"


@dataclass(frozen=True, slots=True)
class Bounds:
    """Logical screen-space bounding rectangle."""

    x: float
    y: float
    width: float
    height: float

    @property
    def center(self) -> tuple[float, float]:
        """Return the midpoint (x, y) of this rectangle."""
        return (self.x + self.width / 2.0, self.y + self.height / 2.0)


@dataclass(frozen=True, slots=True)
class AccessibilityNode:
    """Single node captured from the OS accessibility tree."""

    id: str
    role: Role
    name: str | None
    value: str | None
    bounds: Bounds
    focused: bool


@dataclass(frozen=True, slots=True)
class CapturedResponse:
    """Passively decrypted HTTP/1.1, HTTP/2, or HTTP/3 response."""

    url: str
    status: int
    content_type: str | None
    body: str | None

    def json(self) -> object:
        """Parse and return the captured response body as JSON."""
        if self.body is None:
            msg = f"captured response for {self.url!r} has no body"
            raise ValueError(msg)
        return json.loads(self.body)


@dataclass(frozen=True, slots=True)
class LocatorQuery:
    """Semantic query resolved by the Rust control daemon."""

    role: Role | None = None
    name: str | None = None
    exact: bool = False
    nth: int = 0
    within: LocatorQuery | None = None


class Transport(Protocol):
    """IPC transport abstraction between the Python SDK and waybound-daemon."""

    def snapshot_tree(self) -> list[AccessibilityNode]:
        """Return the live OS accessibility tree."""
        ...

    def locate_all(self, query: LocatorQuery) -> list[AccessibilityNode]:
        """Return all nodes matching `query`."""
        ...

    def current_url(self) -> str | None:
        """Return the active tab URL, if available."""
        ...

    def wait_for(self, query: LocatorQuery, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Poll until an element matching `query` appears or `timeout_ms` elapses."""
        ...

    def hover(self, query: LocatorQuery) -> None:
        """Locate the target element and move the pointer over it without clicking."""
        ...

    def click(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native click."""
        ...

    def fill(self, query: LocatorQuery, text: str) -> None:
        """Focus the target element and type text via native keyboard events."""
        ...

    def navigate(self, url: str) -> None:
        """Navigate the active browser tab to `url`."""
        ...

    def reload(self) -> None:
        """Reload the active browser tab."""
        ...

    def go_back(self) -> None:
        """Navigate back in browser history."""
        ...

    def go_forward(self) -> None:
        """Navigate forward in browser history."""
        ...

    def new_tab(self, url: str | None = None) -> None:
        """Open a new browser tab, optionally navigating to `url`."""
        ...

    def close_tab(self) -> None:
        """Close the active browser tab."""
        ...

    def next_tab(self) -> None:
        """Switch to the next browser tab."""
        ...

    def prev_tab(self) -> None:
        """Switch to the previous browser tab."""
        ...

    def scroll(self, delta_x: float, delta_y: float) -> None:
        """Emit a native scroll event."""
        ...

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a key press (`enter`, `tab`, `escape`, `backspace`, or single char)."""
        ...

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        """Return passively captured HTTP responses, optionally filtered by URL substring."""
        ...

    def wait_for_response(self, url_contains: str, *, timeout_ms: int = 10_000) -> CapturedResponse:
        """Wait until a passively captured HTTP response matches `url_contains`."""
        ...

    def screenshot(self, path: str) -> None:
        """Capture a native OS PNG screenshot of the browser window to `path`."""
        ...
