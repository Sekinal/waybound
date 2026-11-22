"""Unit tests for chained/scoped locators and recursive query encoding."""

from __future__ import annotations

from waybound.transport import _encode_query
from waybound.types import LocatorQuery, Role


def test_encode_query_serializes_nested_within_scopes() -> None:
    dialog = LocatorQuery(role=Role.DIALOG, name="Settings", exact=False, nth=0)
    save_btn = LocatorQuery(role=Role.BUTTON, name="Save", exact=True, nth=1, within=dialog)

    encoded = _encode_query(save_btn)
    assert encoded == {
        "role": "button",
        "name": "Save",
        "exact": True,
        "nth": 1,
        "within": {
            "role": "dialog",
            "name": "Settings",
            "exact": False,
            "nth": 0,
        },
    }


def test_encode_query_omits_within_when_none() -> None:
    encoded = _encode_query(LocatorQuery(role=Role.LINK, name="Docs"))
    assert "within" not in encoded
