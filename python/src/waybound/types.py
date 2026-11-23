"""Typed protocol and value objects for the waybound Python SDK."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable


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
    SEARCHBOX = "search_box"
    CHECKBOX = "check_box"
    RADIO = "radio"
    SWITCH = "switch"
    COMBOBOX = "combo_box"
    LISTBOX = "list_box"
    OPTION = "option"
    LIST = "list"
    LISTITEM = "list_item"
    TAB = "tab"
    DIALOG = "dialog"
    REGION = "region"
    GROUP = "group"
    IMG = "img"
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
    """Single node captured from the OS accessibility tree.

    `checked` and `expanded` are `None` when the state does not apply to the node. A mixed /
    indeterminate checkbox is reported as `checked=False` (not fully checked).
    """

    id: str
    role: Role
    name: str | None
    value: str | None
    bounds: Bounds
    focused: bool
    checked: bool | None = None
    disabled: bool = False
    expanded: bool | None = None


@dataclass(frozen=True, slots=True)
class HttpHeader:
    """Single HTTP header field as seen on the wire (repeated names are kept separately)."""

    name: str
    # Values can be credentials (cookie, authorization); keep them out of reprs and logs.
    value: str = field(repr=False)


def _header_values(headers: tuple[HttpHeader, ...], name: str) -> list[str]:
    wanted = name.lower()
    return [h.value for h in headers if h.name.lower() == wanted]


@dataclass(frozen=True, slots=True)
class CapturedResponse:
    """Passively decrypted HTTP/1.1, HTTP/2, or HTTP/3 response.

    `headers`, `request_method`, `request_headers`, and `request_body` are empty when the
    daemon did not observe them (for example with the legacy `tshark` capture path or an
    older daemon).
    """

    url: str
    status: int
    content_type: str | None
    # Bodies and header values may hold credentials or personal data: kept out of reprs.
    body: str | None = field(repr=False)
    headers: tuple[HttpHeader, ...] = field(default=(), repr=False)
    request_method: str | None = None
    request_headers: tuple[HttpHeader, ...] = field(default=(), repr=False)
    request_body: str | None = field(default=None, repr=False)

    def json(self) -> object:
        """Parse and return the captured response body as JSON."""
        if self.body is None:
            msg = f"captured response for {self.url!r} has no body"
            raise ValueError(msg)
        return json.loads(self.body)

    def header(self, name: str) -> str | None:
        """Return the first response header named `name` (case-insensitive), if present."""
        values = _header_values(self.headers, name)
        return values[0] if values else None

    def header_values(self, name: str) -> list[str]:
        """Return every response header value named `name` (e.g. all `set-cookie` lines)."""
        return _header_values(self.headers, name)

    def request_header(self, name: str) -> str | None:
        """Return the first request header named `name` (case-insensitive), if present."""
        values = _header_values(self.request_headers, name)
        return values[0] if values else None

    def request_header_values(self, name: str) -> list[str]:
        """Return every request header value named `name`."""
        return _header_values(self.request_headers, name)

    def request_json(self) -> object:
        """Parse and return the captured request body (e.g. a POST payload) as JSON."""
        if self.request_body is None:
            msg = f"captured request for {self.url!r} has no body"
            raise ValueError(msg)
        return json.loads(self.request_body)


class WebSocketDirection(StrEnum):
    """Direction of a captured WebSocket message."""

    SENT = "sent"
    RECEIVED = "received"


class WebSocketOpcode(StrEnum):
    """Opcode of a captured WebSocket message (RFC 6455)."""

    TEXT = "text"
    BINARY = "binary"
    CLOSE = "close"
    PING = "ping"
    PONG = "pong"


@dataclass(frozen=True, slots=True)
class CapturedWebSocketFrame:
    """Passively decrypted WebSocket message (fragments reassembled) or control frame."""

    url: str
    direction: WebSocketDirection
    opcode: WebSocketOpcode
    payload: str | None = field(default=None, repr=False)
    payload_len: int = 0
    compressed: bool = False
    truncated: bool = False
    close_code: int | None = None

    def json(self) -> object:
        """Parse and return the message payload as JSON."""
        if self.payload is None:
            msg = f"captured WebSocket message for {self.url!r} has no decoded payload"
            raise ValueError(msg)
        return json.loads(self.payload)


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

    def dblclick(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native double-click."""
        ...

    def select_option(
        self,
        query: LocatorQuery,
        *,
        label: str | None = None,
        index: int | None = None,
    ) -> None:
        """Select an option from a `<select>` or combobox by label or 0-based index."""
        ...

    def fill(self, query: LocatorQuery, text: str) -> None:
        """Focus the target element and type text via native keyboard events."""
        ...

    def set_checked(self, query: LocatorQuery, *, checked: bool) -> AccessibilityNode:
        """Idempotently drive a checkbox/radio/switch to `checked`; return the re-read node."""
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

    def wait_for_network_idle(self, *, idle_ms: int = 500, timeout_ms: int = 15_000) -> None:
        """Wait until zero HTTP/1.1 or HTTP/2 requests remain inflight for `idle_ms`."""
        ...

    def screenshot(self, path: str) -> None:
        """Capture a native OS PNG screenshot to `path` (browser window on macOS, else screen)."""
        ...

    def drag_to(
        self, source: LocatorQuery, target: LocatorQuery, *, timeout_ms: int = 5_000
    ) -> None:
        """Press on `source`, drag along a native pointer path to `target`, and release."""
        ...


@runtime_checkable
class SupportsWebSocketFrames(Protocol):
    """Optional transport capability: listing passively captured WebSocket messages.

    Kept separate from `Transport` so custom transports written before WebSocket
    capture existed remain valid `Transport` implementations.
    """

    def captured_websocket_frames(
        self, *, url_contains: str | None = None, limit: int | None = None
    ) -> list[CapturedWebSocketFrame]:
        """Return captured WebSocket messages (oldest first), at most the newest `limit`."""
        ...
