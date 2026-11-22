"""End-to-end IPC tests between the Python SDK and Rust waybound-daemon."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from waybound import KeyModifier, LaunchOptions, Role, WayboundDaemonError, launch, launch_async
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

    async with launch_async(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        assert await page.url() == "https://mock.waybound.local/"
        assert await page.get_by_role(Role.BUTTON).nth(0).text_content() == "Search Flights"
        await page.get_by_role(Role.TEXTBOX, name="Origin").fill("HND")
        await page.get_by_role(Role.BUTTON, name="Search").click()


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
        with pytest.raises(WayboundDaemonError) as disabled:
            insurance.uncheck()
        assert disabled.value.code == "element_disabled"
        assert insurance.is_checked() is True

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
