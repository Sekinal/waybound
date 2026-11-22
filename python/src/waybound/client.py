"""Ergonomic Playwright-style client facade for waybound."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from waybound.transport import WayboundDaemonError
from waybound.types import AccessibilityNode, CapturedResponse, KeyModifier, LocatorQuery, Role

if TYPE_CHECKING:
    from waybound.types import Transport


@dataclass(frozen=True, slots=True)
class Locator:
    """Lazy handle to a semantic UI element."""

    _transport: Transport
    query: LocatorQuery

    @property
    def first(self) -> Locator:
        """Return a locator narrowed to the first matching element (`nth(0)`)."""
        return self.nth(0)

    def nth(self, index: int) -> Locator:
        """Return a locator narrowed to the zero-based `index`-th matching element."""
        if index < 0:
            msg = f"nth index must be non-negative, got {index}"
            raise ValueError(msg)
        return Locator(_transport=self._transport, query=replace(self.query, nth=index))

    def get_by_role(self, role: Role, *, name: str | None = None, exact: bool = False) -> Locator:
        """Return a child locator scoped spatially inside this container element."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=role, name=name, exact=exact, within=self.query),
        )

    def get_by_text(self, text: str, *, exact: bool = False) -> Locator:
        """Return a child locator matching accessible text inside this container element."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=None, name=text, exact=exact, within=self.query),
        )

    def all(self) -> list[AccessibilityNode]:
        """Return all accessibility nodes matching this locator."""
        return self._transport.locate_all(self.query)

    def count(self) -> int:
        """Return the number of accessibility nodes matching this locator."""
        return len(self.all())

    def is_visible(self) -> bool:
        """Return `True` if the matched element exists with positive on-screen bounds."""
        matches = self.all()
        if self.query.nth >= len(matches):
            return False
        b = matches[self.query.nth].bounds
        return b.width > 0.0 and b.height > 0.0

    def hover(self) -> None:
        """Move the pointer over the resolved element using native OS input without clicking."""
        self._transport.hover(self.query)

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

    def wait_for_url(self, url_contains: str, *, timeout_ms: int = 10_000) -> str:
        """Poll until the active tab URL contains `url_contains` or `timeout_ms` elapses."""
        needle = url_contains.lower()
        deadline = time.monotonic() + max(0, timeout_ms) / 1000.0
        while True:
            current = self._transport.current_url()
            if current is not None and needle in current.lower():
                return current
            if time.monotonic() >= deadline:
                msg = f"timed out after {timeout_ms}ms waiting for URL containing {url_contains!r}"
                raise WayboundDaemonError("timeout", msg)
            time.sleep(0.075)

    def goto(self, url: str) -> None:
        """Navigate the active browser tab to `url` via native OS shortcut."""
        self._transport.navigate(url)

    def reload(self) -> None:
        """Reload the active browser tab via native OS shortcut."""
        self._transport.reload()

    def go_back(self) -> None:
        """Navigate back in browser history via native OS shortcut."""
        self._transport.go_back()

    def go_forward(self) -> None:
        """Navigate forward in browser history via native OS shortcut."""
        self._transport.go_forward()

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

    def screenshot(self, path: Path | str | None = None) -> bytes:
        """Capture a native OS PNG screenshot of the browser window and return PNG bytes."""
        if path is not None:
            out_path = Path(path).resolve()
            self._transport.screenshot(str(out_path))
            return out_path.read_bytes()

        with tempfile.TemporaryDirectory(prefix="wb-shot-") as tmp_dir:
            out_path = Path(tmp_dir) / "shot.png"
            self._transport.screenshot(str(out_path))
            return out_path.read_bytes()

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
