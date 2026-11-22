"""waybound: Ergonomic, out-of-band OS-level browser automation."""

from waybound.client import Locator, Page
from waybound.session import LaunchOptions, Session, launch
from waybound.transport import UnixSocketTransport, WayboundDaemonError
from waybound.types import (
    AccessibilityNode,
    BackendKind,
    Bounds,
    KeyModifier,
    LocatorQuery,
    Role,
    Transport,
)

__all__ = [
    "AccessibilityNode",
    "BackendKind",
    "Bounds",
    "KeyModifier",
    "LaunchOptions",
    "Locator",
    "LocatorQuery",
    "Page",
    "Role",
    "Session",
    "Transport",
    "UnixSocketTransport",
    "WayboundDaemonError",
    "launch",
]
