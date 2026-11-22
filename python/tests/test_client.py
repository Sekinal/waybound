"""Unit tests for the waybound Python SDK."""

from __future__ import annotations

from waybound import Bounds, LocatorQuery, Page, Role


class FakeTransport:
    """In-memory transport recording semantic commands."""

    def __init__(self) -> None:
        self.events: list[tuple[str, LocatorQuery, str | None]] = []

    def click(self, query: LocatorQuery) -> None:
        self.events.append(("click", query, None))

    def fill(self, query: LocatorQuery, text: str) -> None:
        self.events.append(("fill", query, text))


def test_bounds_center() -> None:
    bounds = Bounds(x=10.0, y=20.0, width=100.0, height=40.0)
    assert bounds.center == (60.0, 40.0)


def test_page_semantic_locators() -> None:
    transport = FakeTransport()
    page = Page(transport)

    page.get_by_role(Role.TEXTBOX, name="Origin").fill("SFO")
    page.get_by_role(Role.BUTTON, name="Search", exact=True).click()

    assert transport.events == [
        ("fill", LocatorQuery(role=Role.TEXTBOX, name="Origin", exact=False), "SFO"),
        ("click", LocatorQuery(role=Role.BUTTON, name="Search", exact=True), None),
    ]
