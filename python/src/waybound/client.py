"""Ergonomic Playwright-style client facade for waybound."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from waybound.types import AccessibilityNode, CapturedResponse, KeyModifier, LocatorQuery, Role

if TYPE_CHECKING:
    from waybound.types import Transport


@dataclass(frozen=True, slots=True)
class Locator:
    """Lazy handle to a semantic UI element."""

    _transport: Transport
    query: LocatorQuery

    def nth(self, index: int) -> Locator:
        """Return a locator narrowed to the zero-based `index`-th matching element."""
        if index < 0:
            msg = f"nth index must be non-negative, got {index}"
            raise ValueError(msg)
        return Locator(_transport=self._transport, query=replace(self.query, nth=index))

    def all(self) -> list[AccessibilityNode]:
        """Return all accessibility nodes matching this locator."""
        return self._transport.locate_all(self.query)

    def wait_for(self, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Wait until this element appears in the accessibility tree."""
        return self._transport.wait_for(self.query, timeout_ms=timeout_ms)

    def text_content(self, *, timeout_ms: int = 5_000) -> str | None:
        """Return the accessible name or value text of the resolved element."""
        node = self.wait_for(timeout_ms=timeout_ms)
        return node.name if node.name is not None else node.value

    def input_value(self, *, timeout_ms: int = 5_000) -> str:
        """Return the current editable value of a textbox/input element."""
        node = self.wait_for(timeout_ms=timeout_ms)
        return node.value or ""

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

    def url(self) -> str | None:
        """Return the active tab URL from the browser's web area, if available."""
        return self._transport.current_url()

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
        """Return a snapshot of the live web-content accessibility tree."""
        return self._transport.snapshot_tree()

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        """Return passively captured HTTP responses, optionally filtered by URL substring."""
        return self._transport.captured_responses(url_contains=url_contains)

    def wait_for_response(self, url_contains: str, *, timeout_ms: int = 10_000) -> CapturedResponse:
        """Wait until a passively decrypted HTTP response matches `url_contains`."""
        return self._transport.wait_for_response(url_contains, timeout_ms=timeout_ms)

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
