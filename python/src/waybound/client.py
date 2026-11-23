"""Ergonomic Playwright-style client facade for waybound."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from waybound.transport import WayboundDaemonError
from waybound.types import (
    AccessibilityNode,
    CapturedResponse,
    CapturedWebSocketFrame,
    KeyModifier,
    LocatorQuery,
    Role,
    SessionFingerprint,
    SupportsTreeSnapshot,
    SupportsWebSocketFrames,
    TreeSnapshot,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from waybound.handoff import HandoffHttpClient
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

    def get_by_role(
        self,
        role: Role,
        *,
        name: str | None = None,
        exact: bool = False,
        strict: bool = False,
    ) -> Locator:
        """Return a child locator scoped spatially inside this container element."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(
                role=role,
                name=name,
                exact=exact,
                within=self.query,
                strict=strict,
            ),
        )

    def get_by_text(self, text: str, *, exact: bool = False, strict: bool = False) -> Locator:
        """Return a child locator matching accessible text inside this container element."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(
                role=None,
                name=text,
                exact=exact,
                within=self.query,
                strict=strict,
            ),
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

    def dblclick(self) -> None:
        """Double-click the resolved element using native OS input."""
        self._transport.dblclick(self.query)

    def select_option(self, *, label: str | None = None, index: int | None = None) -> None:
        """Select an option from a `<select>` or combobox by label or 0-based index."""
        self._transport.select_option(self.query, label=label, index=index)

    def fill(self, text: str) -> None:
        """Fill the resolved input element using native keyboard events."""
        self._transport.fill(self.query, text)

    def drag_to(self, target: Locator, *, timeout_ms: int = 5_000) -> None:
        """Drag this element onto `target` with a native press, pointer path, and release.

        Waits up to `timeout_ms` for each of the two elements to appear. The mouse button
        is always released, even when the drag fails part-way.
        """
        self._transport.drag_to(self.query, target.query, timeout_ms=timeout_ms)

    def check(self) -> None:
        """Ensure the checkbox/radio/switch is checked, clicking only if it is not.

        Waits for the element to appear and, if a click is needed, to become enabled. Raises
        `WayboundDaemonError` with code `element_disabled` if it stays disabled, or
        `invalid_element_state` if the element has no checked state or the click did not
        check it.
        """
        self._transport.set_checked(self.query, checked=True)

    def uncheck(self) -> None:
        """Ensure the checkbox/switch is unchecked, clicking only if it is checked.

        A mixed (indeterminate) checkbox counts as unchecked, so it is left mixed without a
        click. Radio buttons cannot be unchecked (`invalid_element_state`); check another
        option instead. Errors are otherwise the same as for `check()`.
        """
        self._transport.set_checked(self.query, checked=False)

    def is_checked(self, *, timeout_ms: int = 5_000) -> bool:
        """Return whether the element is checked (a mixed checkbox is not checked).

        Raises `WayboundDaemonError` with code `invalid_element_state` if the element has
        no checked state.
        """
        node = self.wait_for(timeout_ms=timeout_ms)
        if node.checked is None:
            msg = f"element {node.name!r} (role {node.role.value}) has no checked state"
            raise WayboundDaemonError("invalid_element_state", msg)
        return node.checked

    def is_enabled(self, *, timeout_ms: int = 5_000) -> bool:
        """Return `True` unless the element is disabled."""
        return not self.wait_for(timeout_ms=timeout_ms).disabled


class Page:
    """High-level semantic interface to a controlled browser session."""

    def __init__(self, transport: Transport) -> None:
        self._transport = transport
        self._last_tree_truncated = False

    @property
    def last_tree_truncated(self) -> bool:
        """Whether the most recent `snapshot_tree()` call was truncated at the node cap."""
        return self._last_tree_truncated

    def url(self) -> str | None:
        """Return the active tab URL from the browser's web area, if available."""
        return self._transport.current_url()

    def wait_for_url(self, url_contains: str, *, timeout_ms: int = 10_000) -> str:
        """Poll until the active tab URL contains `url_contains` or `timeout_ms` elapses.

        Transient backend failures (daemon error code ``transient``, for example an
        Android UI dump taken mid-animation) count as "not there yet"; any other error
        is raised at once. On timeout the message includes the last transient error.
        """
        needle = url_contains.lower()
        deadline = time.monotonic() + max(0, timeout_ms) / 1000.0
        last_transient: WayboundDaemonError | None = None
        while True:
            try:
                current = self._transport.current_url()
            except WayboundDaemonError as exc:
                if exc.code != "transient":
                    raise
                last_transient = exc
                current = None
            if current is not None and needle in current.lower():
                return current
            if time.monotonic() >= deadline:
                msg = f"timed out after {timeout_ms}ms waiting for URL containing {url_contains!r}"
                if last_transient is not None:
                    msg += f"; last backend error: {last_transient}"
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

    def new_tab(self, url: str | None = None) -> None:
        """Open a new browser tab via native OS shortcut, optionally navigating to `url`."""
        self._transport.new_tab(url)

    def close_tab(self) -> None:
        """Close the active browser tab via native OS shortcut."""
        self._transport.close_tab()

    def next_tab(self) -> None:
        """Switch to the next browser tab (Ctrl+Tab)."""
        self._transport.next_tab()

    def prev_tab(self) -> None:
        """Switch to the previous browser tab (Ctrl+Shift+Tab)."""
        self._transport.prev_tab()

    def wait_for_text(
        self, text: str, *, exact: bool = False, timeout_ms: int = 10_000
    ) -> AccessibilityNode:
        """Wait until any element with accessible text matching `text` appears."""
        return self.get_by_text(text, exact=exact).wait_for(timeout_ms=timeout_ms)

    def scroll(self, *, delta_x: float = 0.0, delta_y: float = -300.0) -> None:
        """Scroll the viewport by `(delta_x, delta_y)` pixels."""
        self._transport.scroll(delta_x, delta_y)

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a native key press (`enter`, `tab`, `escape`, `backspace`, or single char)."""
        self._transport.press(key, modifiers=modifiers)

    def snapshot_tree(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        """Return a snapshot of the live web-content accessibility tree."""
        return self.snapshot_tree_with_meta(max_nodes=max_nodes).nodes

    def snapshot_tree_with_meta(self, *, max_nodes: int | None = None) -> TreeSnapshot:
        """Return a `TreeSnapshot` with `nodes` and `truncated` metadata."""
        if max_nodes is not None and max_nodes < 1:
            msg = f"max_nodes must be a positive integer, got {max_nodes}"
            raise ValueError(msg)
        transport = self._transport
        if isinstance(transport, SupportsTreeSnapshot):
            snap = transport.snapshot_tree_with_meta(max_nodes=max_nodes)
        else:
            nodes = transport.snapshot_tree()
            truncated = max_nodes is not None and len(nodes) > max_nodes
            if truncated and max_nodes is not None:
                nodes = nodes[:max_nodes]
            snap = TreeSnapshot(nodes=nodes, truncated=truncated)
        self._last_tree_truncated = snap.truncated
        return snap

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        """Return passively captured HTTP responses, optionally filtered by URL substring."""
        return self._transport.captured_responses(url_contains=url_contains)

    def wait_for_response(self, url_contains: str, *, timeout_ms: int = 10_000) -> CapturedResponse:
        """Wait until a passively decrypted HTTP response matches `url_contains`."""
        return self._transport.wait_for_response(url_contains, timeout_ms=timeout_ms)

    def captured_websocket_frames(
        self, *, url_contains: str | None = None, limit: int | None = None
    ) -> list[CapturedWebSocketFrame]:
        """Return passively decrypted WebSocket messages (oldest first).

        Covers HTTP/1.1 `101 Switching Protocols` upgrades; fragmented messages are
        reassembled and `permessage-deflate` payloads are inflated. `limit` keeps only
        the newest messages.

        Raises:
            NotImplementedError: if the page's transport does not support WebSocket capture.
        """
        transport = self._transport
        if not isinstance(transport, SupportsWebSocketFrames):
            msg = f"{type(transport).__name__} does not support captured_websocket_frames"
            raise NotImplementedError(msg)
        return transport.captured_websocket_frames(url_contains=url_contains, limit=limit)

    def wait_for_network_idle(self, *, idle_ms: int = 500, timeout_ms: int = 15_000) -> None:
        """Wait until zero HTTP/1.1 or HTTP/2 requests remain inflight for `idle_ms`."""
        self._transport.wait_for_network_idle(idle_ms=idle_ms, timeout_ms=timeout_ms)

    def export_fingerprint(self) -> SessionFingerprint:
        """Export the live TLS, HTTP/2, header, and cookie fingerprint captured from the session."""
        return self._transport.export_fingerprint()

    def handoff_http_client(  # noqa: PLR0913
        self,
        *,
        proxy: str | None = None,
        timeout_ms: int = 30_000,
        follow_redirects: bool = True,
        daemon_binary: Path | str | None = None,
        on_refresh: Callable[[], SessionFingerprint] | None = None,
        refresh_statuses: tuple[int, ...] = (403,),
    ) -> HandoffHttpClient:
        """Export the live browser fingerprint and create a standalone BoringSSL/H2 HTTP client.

        The returned [`HandoffHttpClient`] continues working after the browser session closes.
        """
        from waybound.handoff import HandoffHttpClient  # noqa: PLC0415

        fp = self.export_fingerprint()
        return HandoffHttpClient(
            fp,
            proxy=proxy,
            timeout_ms=timeout_ms,
            follow_redirects=follow_redirects,
            daemon_binary=daemon_binary,
            on_refresh=on_refresh,
            refresh_statuses=refresh_statuses,
        )

    def screenshot(self, path: Path | str | None = None) -> bytes:
        """Capture a native OS PNG screenshot and return PNG bytes.

        macOS captures the browser window; the other backends capture the whole screen.
        """
        if path is not None:
            out_path = Path(path).resolve()
            self._transport.screenshot(str(out_path))
            return out_path.read_bytes()

        with tempfile.TemporaryDirectory(prefix="wb-shot-") as tmp_dir:
            out_path = Path(tmp_dir) / "shot.png"
            self._transport.screenshot(str(out_path))
            return out_path.read_bytes()

    def get_by_role(
        self,
        role: Role,
        *,
        name: str | None = None,
        exact: bool = False,
        strict: bool = False,
    ) -> Locator:
        """Return a locator targeting an element by its semantic accessibility role."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=role, name=name, exact=exact, strict=strict),
        )

    def get_by_text(self, text: str, *, exact: bool = False, strict: bool = False) -> Locator:
        """Return a locator matching an element by its accessible text."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=None, name=text, exact=exact, strict=strict),
        )
