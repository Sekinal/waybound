"""End-to-end IPC tests between the Python SDK and Rust waybound-daemon."""

from __future__ import annotations

from pathlib import Path

import pytest

from waybound import KeyModifier, LaunchOptions, Role, WayboundDaemonError, launch

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_BIN = REPO_ROOT / "target" / "debug" / "waybound-daemon"


def test_ergonomic_launch_full_workflow() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        nodes = page.snapshot_tree()
        assert len(nodes) == 2
        assert nodes[0].role is Role.TEXTBOX
        assert nodes[0].name == "Origin"

        found = page.get_by_role(Role.BUTTON, name="Search").wait_for(timeout_ms=1_000)
        assert found.id == "btn-search"

        page.goto("https://example.com")
        page.get_by_role(Role.TEXTBOX, name="Origin").fill("NRT")
        page.get_by_role(Role.BUTTON, name="Search").click()
        page.scroll(delta_y=-200.0)
        page.press("enter")
        page.press("l", modifiers=(KeyModifier.META,))

        with pytest.raises(WayboundDaemonError) as exc_info:
            page.get_by_role(Role.BUTTON, name="Nonexistent").wait_for(timeout_ms=120)
        assert exc_info.value.code == "timeout"

        with pytest.raises(WayboundDaemonError) as bad_url:
            page.goto("javascript:alert(1)")
        assert bad_url.value.code == "io_error"
