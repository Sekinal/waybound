"""Session process lifetime: process group, parent watchdog, fork safety, health (mock daemon)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
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


@pytest.mark.usefixtures("daemon")
def test_concurrent_close_runs_one_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session(MOCK)
    session.__enter__()
    transport = session._transport
    assert transport is not None
    calls: list[int] = []
    original = transport.shutdown

    def counting_shutdown() -> None:
        calls.append(1)
        time.sleep(0.2)  # widen the window for a second, concurrent close()
        original()

    monkeypatch.setattr(transport, "shutdown", counting_shutdown)
    threads = [threading.Thread(target=session.close) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert calls == [1]
    assert session.daemon_pid is None


def test_lifetime_variables_cannot_come_from_extra_env_or_be_our_group() -> None:
    for name in ("WAYBOUND_REAP_PGID", "WAYBOUND_EXIT_WITH_PARENT"):
        with pytest.raises(ValueError, match="SDK manages"):
            Session(MOCK, extra_env={name: "12345"})
    for bad in (0, 1, os.getpgrp(), os.getpid()):
        with pytest.raises(ValueError, match="refusing to reap"):
            Session(MOCK, _reap_pgid=bad)


def _helper_group() -> subprocess.Popen[bytes]:
    # Stands in for a pool slot's Xvfb/D-Bus stack: its own process group.
    helper = subprocess.Popen(["/bin/sh", "-c", "sleep 60 & sleep 60"], process_group=0)
    time.sleep(0.2)
    return helper


def _group_alive(pgid: int) -> bool:
    """Whether the group has a live (non-zombie) member; `killpg(pgid, 0)` cannot tell, as
    macOS answers EPERM for a group whose members are zombies awaiting their reaper."""
    out = subprocess.run(
        ["/bin/ps", "-axo", "pgid=,stat="], capture_output=True, text=True, check=True
    ).stdout
    return any(
        parts[0] == str(pgid) and not parts[1].startswith("Z")
        for parts in (line.split() for line in out.splitlines())
        if len(parts) == 2
    )


def _stop_group(helper: subprocess.Popen[bytes]) -> None:
    if _group_alive(helper.pid):
        os.killpg(helper.pid, signal.SIGKILL)
    helper.wait()


@pytest.mark.usefixtures("daemon")
def test_inherited_lifetime_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    helper = _helper_group()
    try:
        # A stale value in the user's environment must not reach the daemon.
        monkeypatch.setenv("WAYBOUND_REAP_PGID", str(helper.pid))
        monkeypatch.setenv("WAYBOUND_EXIT_WITH_PARENT", "1")
        with Session(MOCK) as page:
            assert page.url() == MOCK_URL
        time.sleep(0.5)
        assert _group_alive(helper.pid), "an inherited WAYBOUND_REAP_PGID was honoured"
    finally:
        _stop_group(helper)


@pytest.mark.usefixtures("daemon")
def test_daemon_behind_a_wrapper_that_does_not_exec_keeps_running(tmp_path: Path) -> None:
    seen = tmp_path / "env.txt"
    wrapper = tmp_path / "daemon-noexec.sh"
    wrapper.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$WAYBOUND_EXIT_WITH_PARENT" > "{seen}"\n'
        f'"{DAEMON_BIN}" "$@"\n'  # no exec: the daemon's parent is the shell, not us
    )
    wrapper.chmod(0o755)
    with Session(replace(MOCK, daemon_binary=wrapper)) as page:
        time.sleep(1.0)  # several watchdog polls
        assert page.url() == MOCK_URL
    assert seen.read_text().split() == [str(os.getpid())]


@pytest.mark.usefixtures("daemon")
def test_helper_group_is_left_to_us_while_we_live_and_close_is_fast() -> None:
    helper = _helper_group()
    try:
        session = Session(MOCK, _reap_pgid=helper.pid)
        session.__enter__()
        started = time.monotonic()
        session.close()
        assert time.monotonic() - started < 1.5  # no 2 s reap grace on the normal path
        assert _group_alive(helper.pid), "daemon reaped helpers although we are alive"
    finally:
        _stop_group(helper)


_REAP_CHILD = """
import os, subprocess, sys, time
from pathlib import Path
from waybound import LaunchOptions, Session
helper = subprocess.Popen(["/bin/sh", "-c", "sleep 60 & sleep 60"], process_group=0)
time.sleep(0.2)
session = Session(LaunchOptions(backend="mock", daemon_binary=Path(sys.argv[1])),
                  _reap_pgid=helper.pid)
session.__enter__()
print(helper.pid, session.daemon_pid, flush=True)
time.sleep(60)
"""


@pytest.mark.usefixtures("daemon")
@pytest.mark.parametrize("sig", [signal.SIGKILL, signal.SIGTERM], ids=["sigkill", "sigterm"])
def test_helper_group_is_stopped_when_python_alone_dies(sig: int) -> None:
    child = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _REAP_CHILD, str(DAEMON_BIN)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    assert child.stdout is not None
    helper_pgid = daemon_pid = 0
    try:
        helper_pgid, daemon_pid = (int(v) for v in child.stdout.readline().split())
        os.kill(child.pid, sig)  # the Python process alone, not its group
        child.wait(timeout=20)
        deadline = time.monotonic() + 10
        while _group_alive(helper_pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _group_alive(helper_pgid), "helper group outlived the dead Python process"
        assert _wait_daemon_gone(daemon_pid)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()
        if helper_pgid and _group_alive(helper_pgid):
            os.killpg(helper_pgid, signal.SIGKILL)


@pytest.mark.usefixtures("daemon")
def test_daemon_stopped_by_a_signal_terminates_helpers_even_while_we_live() -> None:
    helper = _helper_group()
    try:
        session = Session(MOCK, _reap_pgid=helper.pid)
        session.__enter__()
        daemon_pid = session.daemon_pid
        assert daemon_pid is not None
        os.kill(daemon_pid, signal.SIGTERM)  # a third party stops the slot's daemon
        deadline = time.monotonic() + 5
        while _group_alive(helper.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _group_alive(helper.pid), "helpers of a signalled daemon kept running"
        assert not session.is_healthy()
        session.close()  # tolerates helpers and daemon already gone
    finally:
        _stop_group(helper)


@pytest.mark.usefixtures("daemon")
def test_close_removes_temp_dirs_a_killed_daemon_left_behind() -> None:
    session = Session(MOCK)
    session.__enter__()
    pid = session.daemon_pid
    assert pid is not None
    base = Path(tempfile.gettempdir())
    # What a daemon creates and would remove on a graceful shutdown.
    left = [base / f"waybound-wl-daemon-{pid}-0", base / f"waybound-profile-{pid}-1-2"]
    unrelated = base / f"waybound-profile-{pid + 1}-1-2"
    for path in [*left, unrelated]:
        path.mkdir()
    try:
        os.kill(pid, signal.SIGKILL)
        session.close()
        assert not any(path.exists() for path in left)
        assert unrelated.exists()
    finally:
        for path in [*left, unrelated]:
            if path.exists():
                path.rmdir()


RUST_UNIX_TEMP_DEFAULT = Path("/tmp")  # noqa: S108 - what Rust's temp_dir() falls back to


def test_daemon_temp_base_follows_rust_temp_dir() -> None:
    assert session_mod._daemon_temp_base({}) == RUST_UNIX_TEMP_DEFAULT
    assert session_mod._daemon_temp_base({"TMPDIR": "/x/y"}) == Path("/x/y")
    assert session_mod._daemon_temp_base({"TMPDIR": ""}) is None
    # TEMP/TMP are not consulted by Rust on Unix.
    assert session_mod._daemon_temp_base({"TEMP": "/elsewhere"}) == RUST_UNIX_TEMP_DEFAULT


@pytest.mark.usefixtures("daemon")
def test_temp_dirs_are_found_in_the_daemons_tmpdir_and_only_those_recorded(
    tmp_path: Path,
) -> None:
    session = Session(MOCK, extra_env={"TMPDIR": str(tmp_path)})
    session.__enter__()
    pid = session.daemon_pid
    assert pid is not None
    ours = tmp_path / f"waybound-profile-{pid}-1-2"
    ours.mkdir()
    os.kill(pid, signal.SIGKILL)
    session.close()
    assert not ours.exists()
    # A directory appearing after the session closed is never touched by it.
    later = tmp_path / f"waybound-profile-{pid}-3-4"
    later.mkdir()
    session.close()
    assert later.exists()


@pytest.mark.usefixtures("daemon")
def test_temp_dirs_are_kept_if_the_daemon_may_still_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    session = Session(MOCK, extra_env={"TMPDIR": str(tmp_path)})
    session.__enter__()
    pid = session.daemon_pid
    assert pid is not None
    ours = tmp_path / f"waybound-wl-daemon-{pid}-0"
    ours.mkdir()
    proc = session._proc
    assert proc is not None
    proc.kill()
    proc.wait()
    for name in ("_GRACEFUL_SHUTDOWN_S", "_TERMINATE_GRACE_S", "_KILL_GRACE_S"):
        monkeypatch.setattr(session_mod, name, 0.05)
    monkeypatch.setattr(session_mod, "_has_exited", lambda _proc: False)
    # Re-snapshot needs an unreaped pid; simulate one recorded at start-up instead.
    session._daemon_temp_dirs = {ours}
    session.close()
    assert ours.exists()
    assert "did not exit after SIGKILL" in caplog.text
