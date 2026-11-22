"""Ergonomic Playwright-style client facade for waybound."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from waybound.types import AccessibilityNode, KeyModifier, LocatorQuery, Role

if TYPE_CHECKING:
    from waybound.types import Transport


@dataclass(frozen=True, slots=True)
class Locator:
    """Lazy handle to a semantic UI element."""

    _transport: Transport
    query: LocatorQuery

    def wait_for(self, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Wait until this element appears in the accessibility tree."""
        return self._transport.wait_for(self.query, timeout_ms=timeout_ms)

    def click(self) -> None:
        """Click the resolved element using native OS input."""
        self._transport.click(self.query)

    def fill(self, text: str) -> None:
        """Fill the resolved input element using native keyboard events."""
        self._transport.fill(self.query, text)


class Page:
    """High-level semantic interface to a controlled browser session."""

    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def goto(self, url: str) -> None:
        """Navigate the active browser tab to `url` via native OS shortcut."""
        self._transport.navigate(url)

    def scroll(self, *, delta_x: float = 0.0, delta_y: float = -300.0) -> None:
        """Scroll the viewport by `(delta_x, delta_y)` pixels."""
        self._transport.scroll(delta_x, delta_y)

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a native key press (`enter`, `tab`, `escape`, `backspace`, or single char)."""
        self._transport.press(key, modifiers=modifiers)

    def snapshot_tree(self) -> list[AccessibilityNode]:
        """Return a snapshot of the live OS accessibility tree."""
        return self._transport.snapshot_tree()

    def get_by_role(self, role: Role, *, name: str | None = None, exact: bool = False) -> Locator:
        """Return a locator targeting an element by its semantic accessibility role."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=role, name=name, exact=exact),
        )

    def get_by_text(self, text: str, *, exact: bool = False) -> Locator:
        """Return a locator matching an element by its accessible text."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=None, name=text, exact=exact),
        )
