"""Ergonomic Playwright-style client facade for waybound."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from waybound.transport import WayboundDaemonError, _validate_window_id
from waybound.types import (
    AccessibilityNode,
    CapturedResponse,
    CapturedWebSocketFrame,
    KeyModifier,
    LocatorQuery,
    NetworkStats,
    Role,
    SessionFingerprint,
    SupportsTreeSnapshot,
    SupportsWebSocketFrames,
    SupportsWindows,
    TreeSnapshot,
    WindowSummary,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from waybound.handoff import HandoffHttpClient
    from waybound.types import Transport

    class _ScopedTransport(Protocol):
        def snapshot_tree(
            self, *, max_nodes: int | None = None, window_id: int | None = None
        ) -> list[AccessibilityNode]: ...
        def snapshot_tree_with_meta(
            self, *, max_nodes: int | None = None, window_id: int | None = None
        ) -> TreeSnapshot: ...
        def locate_all(
            self, query: LocatorQuery, *, window_id: int | None = None
        ) -> list[AccessibilityNode]: ...
        def current_url(self, *, window_id: int | None = None) -> str | None: ...
        def wait_for(
            self,
            query: LocatorQuery,
            *,
            timeout_ms: int = 10_000,
            window_id: int | None = None,
        ) -> AccessibilityNode: ...
        def hover(self, query: LocatorQuery, *, window_id: int | None = None) -> None: ...
        def click(self, query: LocatorQuery, *, window_id: int | None = None) -> None: ...
        def dblclick(self, query: LocatorQuery, *, window_id: int | None = None) -> None: ...
        def select_option(
            self,
            query: LocatorQuery,
            *,
            label: str | None = None,
            index: int | None = None,
            window_id: int | None = None,
        ) -> None: ...
        def fill(self, query: LocatorQuery, text: str, *, window_id: int | None = None) -> None: ...
        def set_checked(
            self, query: LocatorQuery, *, checked: bool, window_id: int | None = None
        ) -> AccessibilityNode: ...
        def navigate(self, url: str, *, window_id: int | None = None) -> None: ...
        def reload(self, *, window_id: int | None = None) -> None: ...
        def go_back(self, *, window_id: int | None = None) -> None: ...
        def go_forward(self, *, window_id: int | None = None) -> None: ...
        def new_tab(self, url: str | None = None, *, window_id: int | None = None) -> None: ...
        def close_tab(self, *, window_id: int | None = None) -> None: ...
        def next_tab(self, *, window_id: int | None = None) -> None: ...
        def prev_tab(self, *, window_id: int | None = None) -> None: ...
        def scroll(
            self, delta_x: float, delta_y: float, *, window_id: int | None = None
        ) -> None: ...
        def press(
            self,
            key: str,
            *,
            modifiers: tuple[KeyModifier, ...] = (),
            window_id: int | None = None,
        ) -> None: ...
        def screenshot(self, path: str, *, window_id: int | None = None) -> None: ...
        def drag_to(
            self,
            source: LocatorQuery,
            target: LocatorQuery,
            *,
            timeout_ms: int = 5_000,
            window_id: int | None = None,
        ) -> None: ...


def _as_scoped(transport: Transport) -> _ScopedTransport:
    return cast("_ScopedTransport", transport)


@dataclass(frozen=True, slots=True)
class Locator:
    """Lazy handle to a semantic UI element."""

    _transport: Transport
    query: LocatorQuery
    _window_id: int | None = None

    @property
    def first(self) -> Locator:
        """Return a locator narrowed to the first matching element (`nth(0)`)."""
        return self.nth(0)

    def nth(self, index: int) -> Locator:
        """Return a locator narrowed to the zero-based `index`-th matching element."""
        if index < 0:
            msg = f"nth index must be non-negative, got {index}"
            raise ValueError(msg)
        return Locator(
            _transport=self._transport,
            query=replace(self.query, nth=index, strict=False),
            _window_id=self._window_id,
        )

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
            _window_id=self._window_id,
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
            _window_id=self._window_id,
        )

    def all(self) -> list[AccessibilityNode]:
        """Return all accessibility nodes matching this locator."""
        if self._window_id is None:
            return self._transport.locate_all(self.query)
        return _as_scoped(self._transport).locate_all(self.query, window_id=self._window_id)

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
        if self._window_id is None:
            self._transport.hover(self.query)
            return
        _as_scoped(self._transport).hover(self.query, window_id=self._window_id)

    def wait_for(self, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Wait until this element appears in the accessibility tree."""
        if self._window_id is None:
            return self._transport.wait_for(self.query, timeout_ms=timeout_ms)
        return _as_scoped(self._transport).wait_for(
            self.query, timeout_ms=timeout_ms, window_id=self._window_id
        )

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
        if self._window_id is None:
            self._transport.click(self.query)
            return
        _as_scoped(self._transport).click(self.query, window_id=self._window_id)

    def dblclick(self) -> None:
        """Double-click the resolved element using native OS input."""
        if self._window_id is None:
            self._transport.dblclick(self.query)
            return
        _as_scoped(self._transport).dblclick(self.query, window_id=self._window_id)

    def select_option(self, *, label: str | None = None, index: int | None = None) -> None:
        """Select an option from a `<select>` or combobox by label or 0-based index."""
        if self._window_id is None:
            self._transport.select_option(self.query, label=label, index=index)
            return
        _as_scoped(self._transport).select_option(
            self.query, label=label, index=index, window_id=self._window_id
        )

    def fill(self, text: str) -> None:
        """Fill the resolved input element using native keyboard events."""
        if self._window_id is None:
            self._transport.fill(self.query, text)
            return
        _as_scoped(self._transport).fill(self.query, text, window_id=self._window_id)

    def drag_to(self, target: Locator, *, timeout_ms: int = 5_000) -> None:
        """Drag this element onto `target` with a native press, pointer path, and release.

        Waits up to `timeout_ms` for each of the two elements to appear. The mouse button
        is always released, even when the drag fails part-way.
        """
        if self._window_id is None:
            self._transport.drag_to(self.query, target.query, timeout_ms=timeout_ms)
            return
        _as_scoped(self._transport).drag_to(
            self.query, target.query, timeout_ms=timeout_ms, window_id=self._window_id
        )

    def check(self) -> None:
        """Ensure the checkbox/radio/switch is checked, clicking only if it is not.

        Waits for the element to appear and, if a click is needed, to become enabled. Raises
        `WayboundDaemonError` with code `element_disabled` if it stays disabled, or
        `invalid_element_state` if the element has no checked state or the click did not
        check it.
        """
        if self._window_id is None:
            self._transport.set_checked(self.query, checked=True)
            return
        _as_scoped(self._transport).set_checked(self.query, checked=True, window_id=self._window_id)

    def uncheck(self) -> None:
        """Ensure the checkbox/switch is unchecked, clicking only if it is checked.

        A mixed (indeterminate) checkbox counts as unchecked, so it is left mixed without a
        click. Radio buttons cannot be unchecked (`invalid_element_state`); check another
        option instead. Errors are otherwise the same as for `check()`.
        """
        if self._window_id is None:
            self._transport.set_checked(self.query, checked=False)
            return
        _as_scoped(self._transport).set_checked(
            self.query, checked=False, window_id=self._window_id
        )

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

    def __init__(self, transport: Transport, *, window_id: int | None = None) -> None:
        if window_id is not None:
            _validate_window_id(window_id)
        self._transport = transport
        self._window_id = window_id
        self._last_tree_truncated = False

    @property
    def window_id(self) -> int | None:
        """Backend window identifier this page is scoped to, or `None` for the default window."""
        return self._window_id

    @property
    def last_tree_truncated(self) -> bool:
        """Whether the most recent `snapshot_tree()` call was truncated at the node cap."""
        return self._last_tree_truncated

    def list_windows(self) -> list[WindowSummary]:
        """Return open browser windows tracked by the active backend."""
        transport = self._transport
        if not isinstance(transport, SupportsWindows):
            msg = f"{type(transport).__name__} does not support list_windows"
            raise NotImplementedError(msg)
        return transport.list_windows()

    def new_page(self, url: str | None = None, *, incognito: bool = False) -> Page:
        """Open a new browser window on this transport and return a `Page` scoped to it."""
        transport = self._transport
        if not isinstance(transport, SupportsWindows):
            msg = f"{type(transport).__name__} does not support new_window"
            raise NotImplementedError(msg)
        win = transport.new_window(url, incognito=incognito)
        return Page(self._transport, window_id=win.id)

    def close_window(self) -> None:
        """Close the browser window this page is scoped to.

        Raises `ValueError` when this page is unscoped (`window_id is None`).
        """
        if self._window_id is None:
            msg = "cannot close_window() on an unscoped Page (window_id is None)"
            raise ValueError(msg)
        transport = self._transport
        if not isinstance(transport, SupportsWindows):
            msg = f"{type(transport).__name__} does not support close_window"
            raise NotImplementedError(msg)
        transport.close_window(self._window_id)

    def url(self) -> str | None:
        """Return the active tab URL from the browser's web area, if available."""
        if self._window_id is None:
            return self._transport.current_url()
        return _as_scoped(self._transport).current_url(window_id=self._window_id)

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
                current = self.url()
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
        if self._window_id is None:
            self._transport.navigate(url)
            return
        _as_scoped(self._transport).navigate(url, window_id=self._window_id)

    def reload(self) -> None:
        """Reload the active browser tab via native OS shortcut."""
        if self._window_id is None:
            self._transport.reload()
            return
        _as_scoped(self._transport).reload(window_id=self._window_id)

    def go_back(self) -> None:
        """Navigate back in browser history via native OS shortcut."""
        if self._window_id is None:
            self._transport.go_back()
            return
        _as_scoped(self._transport).go_back(window_id=self._window_id)

    def go_forward(self) -> None:
        """Navigate forward in browser history via native OS shortcut."""
        if self._window_id is None:
            self._transport.go_forward()
            return
        _as_scoped(self._transport).go_forward(window_id=self._window_id)

    def new_tab(self, url: str | None = None) -> None:
        """Open a new browser tab via native OS shortcut, optionally navigating to `url`."""
        if self._window_id is None:
            self._transport.new_tab(url)
            return
        _as_scoped(self._transport).new_tab(url, window_id=self._window_id)

    def close_tab(self) -> None:
        """Close the active browser tab via native OS shortcut."""
        if self._window_id is None:
            self._transport.close_tab()
            return
        _as_scoped(self._transport).close_tab(window_id=self._window_id)

    def next_tab(self) -> None:
        """Switch to the next browser tab (Ctrl+Tab)."""
        if self._window_id is None:
            self._transport.next_tab()
            return
        _as_scoped(self._transport).next_tab(window_id=self._window_id)

    def prev_tab(self) -> None:
        """Switch to the previous browser tab (Ctrl+Shift+Tab)."""
        if self._window_id is None:
            self._transport.prev_tab()
            return
        _as_scoped(self._transport).prev_tab(window_id=self._window_id)

    def wait_for_text(
        self, text: str, *, exact: bool = False, timeout_ms: int = 10_000
    ) -> AccessibilityNode:
        """Wait until any element with accessible text matching `text` appears."""
        return self.get_by_text(text, exact=exact).wait_for(timeout_ms=timeout_ms)

    def scroll(self, *, delta_x: float = 0.0, delta_y: float = -300.0) -> None:
        """Scroll the viewport by `(delta_x, delta_y)` pixels."""
        if self._window_id is None:
            self._transport.scroll(delta_x, delta_y)
            return
        _as_scoped(self._transport).scroll(delta_x, delta_y, window_id=self._window_id)

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a native key press (`enter`, `tab`, `escape`, `backspace`, or single char)."""
        if self._window_id is None:
            self._transport.press(key, modifiers=modifiers)
            return
        _as_scoped(self._transport).press(key, modifiers=modifiers, window_id=self._window_id)

    def snapshot_tree(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        """Return a snapshot of the live web-content accessibility tree."""
        return self.snapshot_tree_with_meta(max_nodes=max_nodes).nodes

    def links(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        """Return all link nodes on the current page that expose a non-empty target URL."""
        return [
            node
            for node in self.snapshot_tree(max_nodes=max_nodes)
            if node.role is Role.LINK and node.url is not None and node.url != ""
        ]

    def snapshot_tree_with_meta(self, *, max_nodes: int | None = None) -> TreeSnapshot:
        """Return a `TreeSnapshot` with `nodes` and `truncated` metadata."""
        if max_nodes is not None and max_nodes < 1:
            msg = f"max_nodes must be a positive integer, got {max_nodes}"
            raise ValueError(msg)
        transport = self._transport
        if isinstance(transport, SupportsTreeSnapshot):
            if self._window_id is None:
                snap = transport.snapshot_tree_with_meta(max_nodes=max_nodes)
            else:
                snap = _as_scoped(transport).snapshot_tree_with_meta(
                    max_nodes=max_nodes, window_id=self._window_id
                )
        else:
            nodes = (
                transport.snapshot_tree()
                if self._window_id is None
                else _as_scoped(transport).snapshot_tree(window_id=self._window_id)
            )
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

    def network_stats(self) -> NetworkStats:
        """Return per-session bandwidth and connection counters from the daemon proxy."""
        return self._transport.network_stats()

    def handoff_http_client(  # noqa: PLR0913
        self,
        *,
        proxy: str | None = None,
        timeout_ms: int = 30_000,
        follow_redirects: bool = True,
        http3: bool = False,
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
            http3=http3,
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
            if self._window_id is None:
                self._transport.screenshot(str(out_path))
            else:
                _as_scoped(self._transport).screenshot(str(out_path), window_id=self._window_id)
            return out_path.read_bytes()

        with tempfile.TemporaryDirectory(prefix="wb-shot-") as tmp_dir:
            out_path = Path(tmp_dir) / "shot.png"
            if self._window_id is None:
                self._transport.screenshot(str(out_path))
            else:
                _as_scoped(self._transport).screenshot(str(out_path), window_id=self._window_id)
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
            _window_id=self._window_id,
        )

    def get_by_text(self, text: str, *, exact: bool = False, strict: bool = False) -> Locator:
        """Return a locator matching an element by its accessible text."""
        return Locator(
            _transport=self._transport,
            query=LocatorQuery(role=None, name=text, exact=exact, strict=strict),
            _window_id=self._window_id,
        )
