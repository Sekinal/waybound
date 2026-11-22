"""End-to-end IPC tests between the Python SDK and Rust waybound-daemon."""

from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from waybound import Page, Role, UnixSocketTransport, WayboundDaemonError, launch

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_BIN = REPO_ROOT / "target" / "debug" / "waybound-daemon"


def _wait_for_socket(socket_path: Path, timeout_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        time.sleep(0.02)
    msg = f"daemon socket did not appear at {socket_path}"
    raise TimeoutError(msg)


def test_python_sdk_round_trip_with_rust_daemon() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    # Keep socket path short to stay within macOS's 104-byte AF_UNIX sun_path limit.
    with tempfile.TemporaryDirectory(prefix="wb-", dir="/tmp") as tmp_dir:
        socket_path = Path(tmp_dir) / "w.sock"
        proc = subprocess.Popen(  # noqa: S603
            [str(DAEMON_BIN), "--socket", str(socket_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_socket(socket_path)
            with UnixSocketTransport(socket_path) as transport:
                assert transport.ping() == "0.1.0"

                tree = transport.snapshot_tree()
                assert len(tree) == 2

                page = Page(transport)
                page.get_by_role(Role.TEXTBOX, name="Origin").fill("SFO")
                page.get_by_role(Role.BUTTON, name="Search").click()

                with pytest.raises(WayboundDaemonError) as exc_info:
                    page.get_by_role(Role.BUTTON, name="Nonexistent").click()
                assert exc_info.value.code == "element_not_found"
        finally:
            proc.terminate()
            proc.wait(timeout=3.0)


def test_ergonomic_launch_context_manager() -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    with launch(backend="mock", daemon_binary=DAEMON_BIN) as page:
        page.get_by_role(Role.TEXTBOX, name="Origin").fill("NRT")
        page.get_by_role(Role.BUTTON, name="Search").click()
