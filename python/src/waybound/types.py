"""Typed protocol and value objects for the waybound Python SDK."""

from __future__ import annotations

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
class LocatorQuery:
    """Semantic query resolved by the Rust control daemon."""

    role: Role | None = None
    name: str | None = None
    exact: bool = False


class Transport(Protocol):
    """IPC transport abstraction between the Python SDK and waybound-daemon."""

    def snapshot_tree(self) -> list[AccessibilityNode]:
        """Return the live OS accessibility tree."""
        ...

    def wait_for(self, query: LocatorQuery, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Poll until an element matching `query` appears or `timeout_ms` elapses."""
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

    def scroll(self, delta_x: float, delta_y: float) -> None:
        """Emit a native scroll event."""
        ...

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a key press (`enter`, `tab`, `escape`, `backspace`, or single char)."""
        ...
