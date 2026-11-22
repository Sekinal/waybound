"""End-to-end tests for loopback TCP daemon transport (used on Windows and optionally Unix)."""

from __future__ import annotations

import pytest

from waybound import LaunchOptions, Role, launch
from waybound.transport import UnixSocketTransport


def test_transport_rejects_ambiguous_endpoint() -> None:
    with pytest.raises(ValueError, match="provide exactly one"):
        UnixSocketTransport()


def test_session_over_loopback_tcp_round_trips_requests() -> None:
    try:
        opts = LaunchOptions(backend="mock", use_tcp=True)
        with launch(opts) as page:
            tree = page.snapshot_tree()
            assert len(tree) > 0
            btn = page.get_by_role(Role.BUTTON)
            btn.click()
    except FileNotFoundError:
        pytest.skip("waybound-daemon binary not built in this environment")
