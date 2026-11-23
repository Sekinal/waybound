"""Session process lifetime: process group, parent watchdog, fork safety, health (mock daemon)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from waybound import LaunchOptions, Session
from waybound import session as session_mod

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_BIN = REPO_ROOT / "target" / "debug" / "waybound-daemon"
MOCK = LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)
MOCK_URL = "https://mock.waybound.local/"


def _running_daemon_pids() -> set[int]:
    """Return pids of live (non-zombie) processes running this worktree's daemon binary."""
    out = subprocess.run(
        ["/bin/ps", "-axo", "pid=,stat=,args="], capture_output=True, text=True, check=True
    ).stdout
    pids: set[int] = set()
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and not parts[1].startswith("Z") and str(DAEMON_BIN) in parts[2]:
            pids.add(int(parts[0]))
    return pids


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_gone(pid: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while _pid_alive(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def _wait_daemon_gone(pid: int, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while pid in _running_daemon_pids():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


@pytest.fixture
def daemon() -> Iterator[None]:
    if sys.platform == "win32":
        pytest.skip("process-group behaviour is POSIX-only")
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")
    before = _running_daemon_pids()
    yield
    leaked = _running_daemon_pids() - before
    assert not leaked, f"leaked waybound-daemon processes: {sorted(leaked)}"


@pytest.mark.usefixtures("daemon")
def test_session_reaps_its_process_group(tmp_path: Path) -> None:
    child_file = tmp_path / "child.pid"
    wrapper = tmp_path / "daemon-with-child.sh"
    # Stands in for the daemon's browser/Xvfb: a child left in the daemon's process group.
    wrapper.write_text(
        f'#!/bin/sh\nsleep 300 &\necho $! > "{child_file}"\nexec "{DAEMON_BIN}" "$@"\n'
    )
    wrapper.chmod(0o755)
    opts = replace(MOCK, daemon_binary=wrapper)

    session = Session(opts)
    with session as page:
        assert page.url() == MOCK_URL
        tmp_dir = session._tmp_dir
        daemon_pid = session.daemon_pid
        assert daemon_pid is not None
        assert os.getpgid(daemon_pid) == daemon_pid != os.getpgrp()
    child = int(child_file.read_text())
    assert _wait_gone(child), "graceful close left the daemon's group running"
    assert tmp_dir is not None
    assert not tmp_dir.exists()

    # A SIGKILLed daemon cannot clean up; closing the session kills what it left behind.
    child_file.unlink()
    session = Session(opts)
    session.__enter__()
    killed = session.daemon_pid
    assert killed is not None
    os.kill(killed, signal.SIGKILL)
    child = int(child_file.read_text())
    assert _pid_alive(child)
    session.close()
    session.close()
    assert _wait_gone(child), "orphan of a SIGKILLed daemon survived close()"


@pytest.mark.usefixtures("daemon")
def test_is_healthy_reports_dead_daemon_closed_transport_and_dead_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Session(MOCK)
    with session:
        transport = session._transport
        assert transport is not None
        assert transport.browser_alive(timeout_s=2.0) is None  # mock launched no browser
        assert session.ping(timeout_s=2.0)
        assert session.is_healthy()
        monkeypatch.setattr(transport, "browser_alive", lambda **_kw: False)
        assert not session.is_healthy()
        monkeypatch.undo()
        transport.close()
        assert transport.closed
        assert not session.is_healthy()

    session = Session(MOCK)
    with session:
        pid = session.daemon_pid
        assert pid is not None
        os.kill(pid, signal.SIGKILL)
        assert _wait_daemon_gone(pid)
        assert not session.is_healthy()


_SIGNAL_CHILD = """
import sys, time
from pathlib import Path
from waybound import LaunchOptions, launch
opts = LaunchOptions(backend="mock", daemon_binary=Path(sys.argv[1]))
if sys.argv[2] == "unreferenced":
    page = launch(opts).__enter__()
else:
    session = launch(opts)
    page = session.__enter__()
print("ready", flush=True)
time.sleep(60)
"""


def _daemon_children(parent: int) -> set[int]:
    out = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid="], capture_output=True, text=True, check=True
    ).stdout
    pairs = (line.split() for line in out.splitlines())
    return {int(pid) for pid, ppid in pairs if int(ppid) == parent} & _running_daemon_pids()


@pytest.mark.usefixtures("daemon")
@pytest.mark.parametrize(
    ("sig", "mode"),
    [
        (signal.SIGINT, "unreferenced"),
        (signal.SIGINT, "referenced"),
        (signal.SIGTERM, "referenced"),
        (signal.SIGHUP, "referenced"),
        (signal.SIGKILL, "referenced"),
    ],
    ids=["sigint-unreferenced", "sigint", "sigterm", "sighup", "sigkill"],
)
def test_daemon_exits_when_its_python_process_group_is_signalled(sig: int, mode: str) -> None:
    child = subprocess.Popen(  # noqa: S603 - the child leads its own group, like a CI step
        [sys.executable, "-c", _SIGNAL_CHILD, str(DAEMON_BIN), mode],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    assert child.stdout is not None
    try:
        assert child.stdout.readline().strip() == "ready"
        daemons = _daemon_children(child.pid)
        assert len(daemons) == 1
        os.killpg(child.pid, sig)
        child.wait(timeout=20)
        for pid in daemons:
            assert _wait_daemon_gone(pid), f"daemon {pid} outlived its Python process"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()


_FORK_CHILD = """
import os, sys
from pathlib import Path
from waybound import LaunchOptions, launch
session = launch(LaunchOptions(backend="mock", daemon_binary=Path(sys.argv[1])))
page = session.__enter__()
pid = os.fork()
if pid == 0:
    session.close()  # explicit close in the child must not touch the parent's daemon
    sys.exit(0)      # ... and neither may the inherited atexit hook
os.waitpid(pid, 0)
print(page.url(), session.daemon_pid is not None and session._daemon_running(), flush=True)
session.close()
"""


@pytest.mark.usefixtures("daemon")
def test_forked_child_does_not_shut_down_the_parents_daemon() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-W", "ignore::DeprecationWarning", "-c", _FORK_CHILD, str(DAEMON_BIN)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [MOCK_URL, "True"]


@pytest.mark.skipif(not hasattr(os, "waitid"), reason="needs os.waitid (not on macOS)")
def test_has_exited_does_not_reap() -> None:
    proc = subprocess.Popen(["/bin/sleep", "0.05"])
    deadline = time.monotonic() + 5
    while not session_mod._has_exited(proc):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert proc.returncode is None  # still a zombie: its pid (and group id) stays reserved
    assert proc.wait(timeout=5) == 0
