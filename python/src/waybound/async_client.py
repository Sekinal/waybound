"""First-class asyncio facade (`async with waybound.launch_async(...) as page:`)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from waybound.session import BackendName, LaunchOptions, Session

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from types import TracebackType

    from waybound.client import Locator, Page
    from waybound.handoff import AsyncHandoffHttpClient
    from waybound.types import (
        AccessibilityNode,
        CapturedResponse,
        CapturedWebSocketFrame,
        KeyModifier,
        NetworkStats,
        Role,
        SessionFingerprint,
        TreeSnapshot,
    )


@dataclass(frozen=True, slots=True)
class AsyncLocator:
    """Async handle to a semantic UI element."""

    _inner: Locator

    @property
    def first(self) -> AsyncLocator:
        """Return a locator narrowed to the first matching element (`nth(0)`)."""
        return AsyncLocator(self._inner.first)

    def nth(self, index: int) -> AsyncLocator:
        """Return a locator narrowed to the zero-based `index`-th matching element."""
        return AsyncLocator(self._inner.nth(index))

    def get_by_role(
        self,
        role: Role,
        *,
        name: str | None = None,
        exact: bool = False,
        strict: bool = False,
    ) -> AsyncLocator:
        """Return a child async locator scoped spatially inside this container element."""
        return AsyncLocator(self._inner.get_by_role(role, name=name, exact=exact, strict=strict))

    def get_by_text(self, text: str, *, exact: bool = False, strict: bool = False) -> AsyncLocator:
        """Return a child async locator matching accessible text inside this container element."""
        return AsyncLocator(self._inner.get_by_text(text, exact=exact, strict=strict))

    async def all(self) -> list[AccessibilityNode]:
        """Return all accessibility nodes matching this locator."""
        return await asyncio.to_thread(self._inner.all)

    async def count(self) -> int:
        """Return the number of accessibility nodes matching this locator."""
        return await asyncio.to_thread(self._inner.count)

    async def is_visible(self) -> bool:
        """Return `True` if the matched element exists with positive on-screen bounds."""
        return await asyncio.to_thread(self._inner.is_visible)

    async def hover(self) -> None:
        """Move the pointer over the resolved element without clicking."""
        await asyncio.to_thread(self._inner.hover)

    async def wait_for(self, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Wait until this element appears in the accessibility tree."""
        return await asyncio.to_thread(self._inner.wait_for, timeout_ms=timeout_ms)

    async def text_content(self, *, timeout_ms: int = 5_000) -> str | None:
        """Return the accessible name or value text of the resolved element."""
        return await asyncio.to_thread(self._inner.text_content, timeout_ms=timeout_ms)

    async def input_value(self, *, timeout_ms: int = 5_000) -> str:
        """Return the current editable value of a textbox/input element."""
        return await asyncio.to_thread(self._inner.input_value, timeout_ms=timeout_ms)

    async def click(self) -> None:
        """Click the resolved element using native OS input."""
        await asyncio.to_thread(self._inner.click)

    async def dblclick(self) -> None:
        """Double-click the resolved element using native OS input."""
        await asyncio.to_thread(self._inner.dblclick)

    async def select_option(self, *, label: str | None = None, index: int | None = None) -> None:
        """Select an option from a `<select>` or combobox by label or 0-based index."""
        await asyncio.to_thread(self._inner.select_option, label=label, index=index)

    async def fill(self, text: str) -> None:
        """Fill the resolved input element using native keyboard events."""
        await asyncio.to_thread(self._inner.fill, text)

    async def drag_to(self, target: AsyncLocator, *, timeout_ms: int = 5_000) -> None:
        """Drag this element onto `target` with a native press, pointer path, and release."""
        await asyncio.to_thread(self._inner.drag_to, target._inner, timeout_ms=timeout_ms)

    async def check(self) -> None:
        """Ensure the checkbox/radio/switch is checked, clicking only if it is not."""
        await asyncio.to_thread(self._inner.check)

    async def uncheck(self) -> None:
        """Ensure the checkbox/switch is unchecked, clicking only if it is checked.

        A mixed (indeterminate) checkbox counts as unchecked and is left as is; radio buttons
        cannot be unchecked.
        """
        await asyncio.to_thread(self._inner.uncheck)

    async def is_checked(self, *, timeout_ms: int = 5_000) -> bool:
        """Return whether the element is checked (a mixed checkbox is not checked)."""
        return await asyncio.to_thread(self._inner.is_checked, timeout_ms=timeout_ms)

    async def is_enabled(self, *, timeout_ms: int = 5_000) -> bool:
        """Return `True` unless the element is disabled."""
        return await asyncio.to_thread(self._inner.is_enabled, timeout_ms=timeout_ms)


class AsyncPage:
    """Async Playwright-style interface to a controlled browser session."""

    def __init__(self, inner: Page) -> None:
        self._inner = inner

    async def url(self) -> str | None:
        """Return the active tab URL from the browser's web area, if available."""
        return await asyncio.to_thread(self._inner.url)

    async def wait_for_url(self, url_contains: str, *, timeout_ms: int = 10_000) -> str:
        """Poll until the active tab URL contains `url_contains` or `timeout_ms` elapses."""
        return await asyncio.to_thread(
            self._inner.wait_for_url, url_contains, timeout_ms=timeout_ms
        )

    async def goto(self, url: str) -> None:
        """Navigate the active browser tab to `url` via native OS shortcut."""
        await asyncio.to_thread(self._inner.goto, url)

    async def reload(self) -> None:
        """Reload the active browser tab via native OS shortcut."""
        await asyncio.to_thread(self._inner.reload)

    async def go_back(self) -> None:
        """Navigate back in browser history via native OS shortcut."""
        await asyncio.to_thread(self._inner.go_back)

    async def go_forward(self) -> None:
        """Navigate forward in browser history via native OS shortcut."""
        await asyncio.to_thread(self._inner.go_forward)

    async def new_tab(self, url: str | None = None) -> None:
        """Open a new browser tab via native OS shortcut, optionally navigating to `url`."""
        await asyncio.to_thread(self._inner.new_tab, url)

    async def close_tab(self) -> None:
        """Close the active browser tab via native OS shortcut."""
        await asyncio.to_thread(self._inner.close_tab)

    async def next_tab(self) -> None:
        """Switch to the next browser tab (Ctrl+Tab)."""
        await asyncio.to_thread(self._inner.next_tab)

    async def prev_tab(self) -> None:
        """Switch to the previous browser tab (Ctrl+Shift+Tab)."""
        await asyncio.to_thread(self._inner.prev_tab)

    async def wait_for_text(
        self, text: str, *, exact: bool = False, timeout_ms: int = 10_000
    ) -> AccessibilityNode:
        """Wait until any element with accessible text matching `text` appears."""
        return await asyncio.to_thread(
            self._inner.wait_for_text, text, exact=exact, timeout_ms=timeout_ms
        )

    async def scroll(self, *, delta_x: float = 0.0, delta_y: float = -300.0) -> None:
        """Scroll the viewport by `(delta_x, delta_y)` pixels."""
        await asyncio.to_thread(self._inner.scroll, delta_x=delta_x, delta_y=delta_y)

    async def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a native key press."""
        await asyncio.to_thread(self._inner.press, key, modifiers=modifiers)

    @property
    def last_tree_truncated(self) -> bool:
        """Whether the most recent `snapshot_tree()` call was truncated at the node cap."""
        return self._inner.last_tree_truncated

    async def snapshot_tree(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        """Return a snapshot of the live web-content accessibility tree."""
        return await asyncio.to_thread(self._inner.snapshot_tree, max_nodes=max_nodes)

    async def links(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        """Return all link nodes on the current page that expose a non-empty target URL."""
        return await asyncio.to_thread(self._inner.links, max_nodes=max_nodes)

    async def snapshot_tree_with_meta(self, *, max_nodes: int | None = None) -> TreeSnapshot:
        """Return a `TreeSnapshot` with `nodes` and `truncated` metadata."""
        return await asyncio.to_thread(self._inner.snapshot_tree_with_meta, max_nodes=max_nodes)

    async def captured_responses(
        self, *, url_contains: str | None = None
    ) -> list[CapturedResponse]:
        """Return passively captured HTTP responses, optionally filtered by URL substring."""
        return await asyncio.to_thread(self._inner.captured_responses, url_contains=url_contains)

    async def wait_for_response(
        self, url_contains: str, *, timeout_ms: int = 10_000
    ) -> CapturedResponse:
        """Wait until a passively decrypted HTTP response matches `url_contains`."""
        return await asyncio.to_thread(
            self._inner.wait_for_response, url_contains, timeout_ms=timeout_ms
        )

    async def captured_websocket_frames(
        self, *, url_contains: str | None = None, limit: int | None = None
    ) -> list[CapturedWebSocketFrame]:
        """Return passively decrypted WebSocket messages (oldest first, newest `limit`)."""
        return await asyncio.to_thread(
            self._inner.captured_websocket_frames, url_contains=url_contains, limit=limit
        )

    async def wait_for_network_idle(self, *, idle_ms: int = 500, timeout_ms: int = 15_000) -> None:
        """Wait until zero HTTP/1.1 or HTTP/2 requests remain inflight for `idle_ms`."""
        await asyncio.to_thread(
            self._inner.wait_for_network_idle, idle_ms=idle_ms, timeout_ms=timeout_ms
        )

    async def export_fingerprint(self) -> SessionFingerprint:
        """Export the live TLS, HTTP/2, header, and cookie fingerprint captured from the session."""
        return await asyncio.to_thread(self._inner.export_fingerprint)

    async def network_stats(self) -> NetworkStats:
        """Return per-session bandwidth and connection counters from the daemon proxy."""
        return await asyncio.to_thread(self._inner.network_stats)

    async def handoff_http_client(  # noqa: PLR0913
        self,
        *,
        proxy: str | None = None,
        timeout_ms: int = 30_000,
        follow_redirects: bool = True,
        daemon_binary: Path | str | None = None,
        on_refresh: Callable[[], Awaitable[SessionFingerprint]] | None = None,
        refresh_statuses: tuple[int, ...] = (403,),
    ) -> AsyncHandoffHttpClient:
        """Export the live browser fingerprint and return an async BoringSSL/H2 HTTP client.

        The returned [`AsyncHandoffHttpClient`] continues working after the browser closes.
        """
        from waybound.handoff import AsyncHandoffHttpClient  # noqa: PLC0415

        fp = await self.export_fingerprint()
        return await asyncio.to_thread(
            AsyncHandoffHttpClient,
            fp,
            proxy=proxy,
            timeout_ms=timeout_ms,
            follow_redirects=follow_redirects,
            daemon_binary=daemon_binary,
            on_refresh=on_refresh,
            refresh_statuses=refresh_statuses,
        )

    async def screenshot(self, path: Path | str | None = None) -> bytes:
        """Capture a native OS PNG screenshot and return PNG bytes.

        macOS captures the browser window; the other backends capture the whole screen.
        """
        return await asyncio.to_thread(self._inner.screenshot, path)

    def get_by_role(
        self,
        role: Role,
        *,
        name: str | None = None,
        exact: bool = False,
        strict: bool = False,
    ) -> AsyncLocator:
        """Return an async locator targeting an element by its semantic role."""
        return AsyncLocator(self._inner.get_by_role(role, name=name, exact=exact, strict=strict))

    def get_by_text(self, text: str, *, exact: bool = False, strict: bool = False) -> AsyncLocator:
        """Return an async locator matching an element by its accessible text."""
        return AsyncLocator(self._inner.get_by_text(text, exact=exact, strict=strict))


class AsyncSession:
    """Async context manager wrapping [`Session`] without blocking the event loop."""

    def __init__(self, options: LaunchOptions | None = None) -> None:
        self._session = Session(options)

    async def __aenter__(self) -> AsyncPage:
        try:
            page = await asyncio.to_thread(self._session.__enter__)
        except BaseException:
            await asyncio.to_thread(self._session.close)
            raise
        return AsyncPage(page)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await asyncio.to_thread(self._session.__exit__, exc_type, exc_val, exc_tb)


def launch_async(
    options: LaunchOptions | None = None,
    *,
    backend: BackendName = "mock",
    launch_chrome: bool = False,
    headless_wayland: bool = False,
    url: str | None = None,
) -> AsyncSession:
    """Create an `AsyncSession` context manager for `async with` browser automation."""
    resolved = (
        options
        if options is not None
        else LaunchOptions(
            backend=backend,
            launch_chrome=launch_chrome,
            headless_wayland=headless_wayland,
            url=url,
        )
    )
    return AsyncSession(resolved)
