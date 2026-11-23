"""End-to-end IPC tests between the Python SDK and Rust waybound-daemon."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from waybound import (
    KeyModifier,
    LaunchOptions,
    NetworkStats,
    Role,
    WayboundDaemonError,
    launch,
    launch_async,
)
from waybound.transport import UnixSocketTransport

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_BIN = REPO_ROOT / "target" / "debug" / "waybound-daemon"


def test_ergonomic_launch_full_workflow() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        nodes = page.snapshot_tree()
        assert len(nodes) == 5
        assert nodes[0].role is Role.TEXTBOX
        assert nodes[0].name == "Origin"
        assert page.url() == "https://mock.waybound.local/"

        buttons = page.get_by_role(Role.BUTTON).all()
        assert len(buttons) == 1
        assert page.get_by_role(Role.BUTTON).nth(0).text_content() == "Search Flights"

        found = page.get_by_role(Role.BUTTON, name="Search").wait_for(timeout_ms=1_000)
        assert found.id == "btn-search"

        page.goto("https://example.com")
        page.get_by_role(Role.TEXTBOX, name="Origin").fill("NRT")
        page.get_by_role(Role.BUTTON, name="Search").click()
        page.get_by_role(Role.BUTTON, name="Search").dblclick()
        page.scroll(delta_y=-200.0)
        page.press("enter")
        page.press("l", modifiers=(KeyModifier.META,))

        # The mock backend has no network tap: both capture lists are empty but well-formed.
        assert page.captured_responses() == []
        assert page.captured_websocket_frames(url_contains="wss://") == []
        assert page.captured_websocket_frames(limit=5) == []
        assert page.network_stats() == NetworkStats(
            bytes_sent=0,
            bytes_received=0,
            connections_total=0,
            connections_blocked=0,
        )

        png_bytes = page.screenshot()
        assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")

        with pytest.raises(WayboundDaemonError) as exc_info:
            page.get_by_role(Role.BUTTON, name="Nonexistent").wait_for(timeout_ms=120)
        assert exc_info.value.code == "timeout"

        with pytest.raises(WayboundDaemonError) as bad_url:
            page.goto("javascript:alert(1)")
        assert bad_url.value.code == "io_error"


async def test_async_launch_workflow() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    async with launch_async(
        LaunchOptions(
            backend="mock",
            block_presets=("analytics", "ads"),
            daemon_binary=DAEMON_BIN,
        )
    ) as page:
        assert await page.url() == "https://mock.waybound.local/"
        assert await page.network_stats() == NetworkStats(
            bytes_sent=0,
            bytes_received=0,
            connections_total=0,
            connections_blocked=0,
        )
        assert await page.get_by_role(Role.BUTTON).nth(0).text_content() == "Search Flights"
        await page.get_by_role(Role.TEXTBOX, name="Origin").fill("HND")
        await page.get_by_role(Role.BUTTON, name="Search").click()


def test_drag_to_against_mock_daemon() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        origin = page.get_by_role(Role.TEXTBOX, name="Origin")
        search = page.get_by_role(Role.BUTTON, name="Search")
        origin.drag_to(search)
        search.drag_to(origin, timeout_ms=200)

        with pytest.raises(WayboundDaemonError) as missing:
            origin.drag_to(page.get_by_role(Role.BUTTON, name="Nonexistent"), timeout_ms=100)
        assert missing.value.code == "element_not_found"

        # The connection stays usable after a failed drag.
        assert page.url() == "https://mock.waybound.local/"


async def test_async_drag_to_against_mock_daemon() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    async with launch_async(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        origin = page.get_by_role(Role.TEXTBOX, name="Origin")
        await origin.drag_to(page.get_by_role(Role.BUTTON, name="Search"), timeout_ms=200)


def test_check_uncheck_round_trip_against_mock() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        nonstop = page.get_by_role(Role.CHECKBOX, name="Nonstop")
        assert nonstop.is_checked() is False
        assert nonstop.is_enabled() is True

        nonstop.check()
        assert nonstop.is_checked() is True
        nonstop.check()  # idempotent: already checked, no click
        assert nonstop.is_checked() is True

        nonstop.uncheck()
        assert nonstop.is_checked() is False
        nonstop.uncheck()
        assert nonstop.is_checked() is False

        insurance = page.get_by_role(Role.CHECKBOX, name="Travel insurance")
        assert insurance.is_enabled() is False
        assert insurance.is_checked() is True
        insurance.check()  # already in the requested state: allowed even though disabled
        # Refusing `uncheck()` waits out the 5 s enable auto-wait; the daemon unit tests cover
        # it with a short injected wait instead.

        with pytest.raises(WayboundDaemonError) as not_checkable:
            page.get_by_role(Role.BUTTON, name="Search").check()
        assert not_checkable.value.code == "invalid_element_state"
        with pytest.raises(WayboundDaemonError):
            page.get_by_role(Role.BUTTON, name="Search").is_checked()

        cabin = page.get_by_role(Role.COMBOBOX, name="Cabin").wait_for(timeout_ms=1_000)
        assert cabin.expanded is False
        assert cabin.checked is None


async def test_async_check_uncheck_against_mock() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    async with launch_async(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        nonstop = page.get_by_role(Role.CHECKBOX, name="Nonstop")
        await nonstop.check()
        assert await nonstop.is_checked() is True
        await nonstop.uncheck()
        assert await nonstop.is_checked() is False
        assert await nonstop.is_enabled() is True


def _wait_for_socket(path: Path, proc: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5.0
    while not path.exists():
        assert proc.poll() is None, "daemon exited before binding its socket"
        assert time.monotonic() < deadline, "daemon did not bind its socket in time"
        time.sleep(0.02)


def test_sigterm_shuts_down_gracefully_and_removes_socket() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with tempfile.TemporaryDirectory(prefix="wb-", dir="/tmp") as tmp:
        sock = Path(tmp) / "w.sock"
        proc = subprocess.Popen(  # noqa: S603
            [str(DAEMON_BIN), "--backend", "mock", "--socket", str(sock)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_socket(sock, proc)
            proc.send_signal(signal.SIGTERM)
            assert proc.wait(timeout=5.0) == 0
            assert not sock.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def test_idle_connection_survives_read_timeout_wakeups() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        assert page.url() == "https://mock.waybound.local/"
        # Longer than the daemon's idle poll interval, so the connection has been through
        # at least two read-timeout wakeups before the next request.
        time.sleep(2.5)
        assert page.url() == "https://mock.waybound.local/"


def test_partial_frame_is_reassembled_across_idle_wakeups() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with tempfile.TemporaryDirectory(prefix="wb-", dir="/tmp") as tmp:
        sock = Path(tmp) / "w.sock"
        proc = subprocess.Popen(  # noqa: S603
            [str(DAEMON_BIN), "--backend", "mock", "--socket", str(sock)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_socket(sock, proc)
            with UnixSocketTransport(sock) as transport:
                raw = transport._sock
                assert raw is not None
                raw.sendall(b'{"method":')
                time.sleep(1.5)
                raw.sendall(b'"ping"}\n')
                assert b'"pong"' in raw.recv(4096)
                transport.shutdown()
            assert proc.wait(timeout=5.0) == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def test_snapshot_tree_truncation_and_strict_locator_mode() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        full = page.snapshot_tree_with_meta(max_nodes=20)
        assert len(full.nodes) == 5
        assert full.truncated is False
        full_truncated = page.last_tree_truncated
        assert full_truncated is False

        capped = page.snapshot_tree_with_meta(max_nodes=2)
        assert len(capped.nodes) == 2
        assert capped.truncated is True
        capped_truncated = page.last_tree_truncated
        assert capped_truncated is True

        # `snapshot_tree(max_nodes=...)` stays backwards-compatible and sets `last_tree_truncated`.
        nodes = page.snapshot_tree(max_nodes=3)
        assert len(nodes) == 3
        after_truncated = page.last_tree_truncated
        assert after_truncated is True

        # Single match succeeds in strict mode.
        btn = page.get_by_role(Role.BUTTON, strict=True).wait_for(timeout_ms=1_000)
        assert btn.id == "btn-search"

        # Multiple matches (2 checkboxes in mock page) fail immediately with strict_mode_violation.
        with pytest.raises(WayboundDaemonError) as strict_err:
            page.get_by_role(Role.CHECKBOX, strict=True).click()
        assert strict_err.value.code == "strict_mode_violation"
        assert "2 elements" in strict_err.value.message

        # `.first` and `.nth(i)` disambiguate a strict locator without raising.
        assert (
            page.get_by_role(Role.CHECKBOX, strict=True).first.wait_for(timeout_ms=1_000).id
            == "chk-nonstop"
        )
        assert (
            page.get_by_role(Role.CHECKBOX, strict=True).nth(1).wait_for(timeout_ms=1_000).id
            == "chk-insurance"
        )

        # Non-strict mode still resolves the first match cleanly.
        assert page.get_by_role(Role.CHECKBOX).wait_for(timeout_ms=1_000).id == "chk-nonstop"


async def test_async_snapshot_tree_truncation_and_strict_mode() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    async with launch_async(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        capped = await page.snapshot_tree_with_meta(max_nodes=2)
        assert len(capped.nodes) == 2
        assert capped.truncated is True
        assert page.last_tree_truncated is True

        with pytest.raises(WayboundDaemonError) as strict_err:
            await page.get_by_role(Role.CHECKBOX, strict=True).wait_for(timeout_ms=1_000)
        assert strict_err.value.code == "strict_mode_violation"


def test_multi_window_lifecycle_and_isolation_against_mock_daemon() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as root:
        assert root.window_id is None
        initial = root.list_windows()
        assert len(initial) == 1
        assert initial[0].id == 1
        assert initial[0].has_buffer is True

        win2 = root.new_page("https://window-two.example/page")
        win3 = root.new_page("https://window-three.example/page", incognito=True)
        assert win2.window_id is not None
        assert win3.window_id is not None
        assert win2.window_id != win3.window_id

        listed = root.list_windows()
        assert {w.id for w in listed} == {1, win2.window_id, win3.window_id}
        incognito_summary = next(w for w in listed if w.id == win3.window_id)
        assert "Incognito" in incognito_summary.title

        # Each scoped Page reads its own window's isolated URL and drives its own commands.
        assert root.url() == "https://mock.waybound.local/"
        assert win2.url() == "https://window-two.example/page"
        assert win3.url() == "https://window-three.example/page"

        assert len(win2.snapshot_tree()) == 5
        win2.get_by_role(Role.BUTTON, name="Search").click()
        assert len(win3.snapshot_tree()) == 5
        win3.get_by_role(Role.TEXTBOX, name="Origin").fill("SFO")

        # Closing win2 removes only win2; win3 stays open and responsive.
        win2.close_window()
        assert {w.id for w in root.list_windows()} == {1, win3.window_id}
        with pytest.raises(WayboundDaemonError) as closed_err:
            win2.url()
        assert closed_err.value.code == "element_not_found"
        assert win3.url() == "https://window-three.example/page"

        win3.close_window()
        assert [w.id for w in root.list_windows()] == [1]


async def test_async_multi_window_lifecycle_against_mock_daemon() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    async with launch_async(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as root:
        assert root.window_id is None
        win2 = await root.new_page("https://async-win2.example/")
        assert win2.window_id == 2
        assert await win2.url() == "https://async-win2.example/"
        assert len(await win2.snapshot_tree()) == 5
        await win2.get_by_role(Role.BUTTON, name="Search").click()
        assert len(await root.list_windows()) == 2

        await win2.close_window()
        assert [w.id for w in await root.list_windows()] == [1]
