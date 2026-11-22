"""Ergonomic Playwright-style client facade for waybound."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from waybound.types import LocatorQuery, Role

if TYPE_CHECKING:
    from waybound.types import Transport


@dataclass(frozen=True, slots=True)
class Locator:
    """Lazy handle to a semantic UI element."""

    _transport: Transport
    query: LocatorQuery

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
