"""Unit tests for the waybound Python SDK."""

from __future__ import annotations

from waybound import (
    AccessibilityNode,
    Bounds,
    CapturedResponse,
    KeyModifier,
    LocatorQuery,
    Page,
    Role,
)


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

    def navigate(self, url: str) -> None:
        self.events.append(("navigate", url))

    def reload(self) -> None:
        self.events.append(("reload", None))

    def go_back(self) -> None:
        self.events.append(("go_back", None))

    def go_forward(self) -> None:
        self.events.append(("go_forward", None))

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
