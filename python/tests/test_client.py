"""Unit tests for the waybound Python SDK."""

from __future__ import annotations

import pytest

from waybound import (
    AccessibilityNode,
    Bounds,
    CapturedResponse,
    KeyModifier,
    LocatorQuery,
    Page,
    Role,
)
from waybound.transport import WayboundDaemonError


class FakeTransport:
    """In-memory transport recording semantic commands."""

    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []

    def snapshot_tree(self) -> list[AccessibilityNode]:
        return []

    def locate_all(self, query: LocatorQuery) -> list[AccessibilityNode]:
        self.events.append(("locate_all", query))
        return []

    def current_url(self) -> str | None:
        return "https://example.com"

    def wait_for(self, query: LocatorQuery, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        self.events.append(("wait_for", (query, timeout_ms)))
        return AccessibilityNode(
            id="n1",
            role=query.role or Role.UNKNOWN,
            name=query.name,
            value=None,
            bounds=Bounds(10.0, 20.0, 100.0, 30.0),
            focused=False,
        )

    def hover(self, query: LocatorQuery) -> None:
        self.events.append(("hover", query))

    def click(self, query: LocatorQuery) -> None:
        self.events.append(("click", query))

    def fill(self, query: LocatorQuery, text: str) -> None:
        self.events.append(("fill", (query, text)))

    def dblclick(self, query: LocatorQuery) -> None:
        self.events.append(("dblclick", query))

    def select_option(
        self,
        query: LocatorQuery,
        *,
        label: str | None = None,
        index: int | None = None,
    ) -> None:
        self.events.append(("select_option", (query, label, index)))

    def navigate(self, url: str) -> None:
        self.events.append(("navigate", url))

    def reload(self) -> None:
        self.events.append(("reload", None))

    def go_back(self) -> None:
        self.events.append(("go_back", None))

    def go_forward(self) -> None:
        self.events.append(("go_forward", None))

    def new_tab(self, url: str | None = None) -> None:
        self.events.append(("new_tab", url))

    def close_tab(self) -> None:
        self.events.append(("close_tab", None))

    def next_tab(self) -> None:
        self.events.append(("next_tab", None))

    def prev_tab(self) -> None:
        self.events.append(("prev_tab", None))

    def scroll(self, delta_x: float, delta_y: float) -> None:
        self.events.append(("scroll", (delta_x, delta_y)))

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        self.events.append(("press", (key, modifiers)))

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        self.events.append(("captured_responses", url_contains))
        return []

    def wait_for_response(self, url_contains: str, *, timeout_ms: int = 10_000) -> CapturedResponse:
        self.events.append(("wait_for_response", (url_contains, timeout_ms)))
        return CapturedResponse(
            url=f"https://example.com/{url_contains}",
            status=200,
            content_type="application/json",
            body="{}",
        )

    def wait_for_network_idle(self, *, idle_ms: int = 500, timeout_ms: int = 15_000) -> None:
        self.events.append(("wait_for_network_idle", (idle_ms, timeout_ms)))

    def screenshot(self, path: str) -> None:
        self.events.append(("screenshot", path))


def test_bounds_center() -> None:
    bounds = Bounds(x=10.0, y=20.0, width=100.0, height=40.0)
    assert bounds.center == (60.0, 40.0)


def test_page_semantic_locators() -> None:
    transport = FakeTransport()
    page = Page(transport)

    page.goto("https://example.com")
    page.get_by_role(Role.TEXTBOX, name="Origin").fill("SFO")
    page.get_by_role(Role.BUTTON, name="Search", exact=True).click()
    page.scroll(delta_y=-250.0)
    page.press("enter")

    assert transport.events == [
        ("navigate", "https://example.com"),
        ("fill", (LocatorQuery(role=Role.TEXTBOX, name="Origin", exact=False), "SFO")),
        ("click", LocatorQuery(role=Role.BUTTON, name="Search", exact=True)),
        ("scroll", (0.0, -250.0)),
        ("press", ("enter", ())),
    ]


class FlakyUrlTransport(FakeTransport):
    """Transport whose `current_url` fails with daemon errors before answering."""

    def __init__(self, failures: list[WayboundDaemonError], url: str | None) -> None:
        super().__init__()
        self.failures = failures
        self.url = url
        self.calls = 0

    def current_url(self) -> str | None:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return self.url


def _transient(n: int) -> WayboundDaemonError:
    return WayboundDaemonError(
        "transient",
        f"transient backend failure: android_waydroid (ERROR: could not get idle state. #{n})",
    )


def test_wait_for_url_retries_transient_failures() -> None:
    transport = FlakyUrlTransport([_transient(1), _transient(2), _transient(3)], "https://ok.test/")
    assert Page(transport).wait_for_url("ok.test", timeout_ms=5_000) == "https://ok.test/"
    assert transport.calls == 4


def test_wait_for_url_timeout_carries_last_transient_error() -> None:
    transport = FlakyUrlTransport([_transient(n) for n in range(1_000)], None)
    with pytest.raises(WayboundDaemonError) as info:
        Page(transport).wait_for_url("ok.test", timeout_ms=200)
    assert info.value.code == "timeout"
    assert "could not get idle state" in str(info.value)


def test_wait_for_url_raises_fatal_errors_immediately() -> None:
    fatal = WayboundDaemonError("backend_unavailable", "error: device offline")
    transport = FlakyUrlTransport([fatal], "https://ok.test/")
    with pytest.raises(WayboundDaemonError) as info:
        Page(transport).wait_for_url("ok.test", timeout_ms=5_000)
    assert info.value is fatal
    assert transport.calls == 1
