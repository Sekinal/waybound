"""Unit and live daemon integration tests for `waybound.BrowserPool`."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from waybound import BrowserPool, LaunchOptions, PoolStats, Role, Session
from waybound import pool as pool_mod
from waybound.pool import (
    build_dbus_command,
    build_slot_env,
    build_xvfb_command,
    find_free_display_num,
    parse_remote_worker,
)
from waybound.session import _resolve_daemon_binary
from waybound.transport import UnixSocketTransport

if TYPE_CHECKING:
    from pathlib import Path

    from waybound.pool import DisplayBackend

# ---------------------------------------------------------------------------
# Pure unit tests (run on every OS)
# ---------------------------------------------------------------------------


def test_parse_remote_worker_valid_and_invalid() -> None:
    assert parse_remote_worker("127.0.0.1:49222") == ("127.0.0.1", 49222)
    assert parse_remote_worker("worker-1.internal:9000") == ("worker-1.internal", 9000)
    assert parse_remote_worker("[::1]:49222") == ("::1", 49222)

    for bad in ("", "   ", "localhost", ":8080", "host:0", "host:70000", "host:abc", "[::1]8080"):
        with pytest.raises(ValueError, match=r"remote worker|port"):
            parse_remote_worker(bad)


def test_linux_display_and_env_builders() -> None:
    assert build_xvfb_command(100) == [
        "Xvfb",
        ":100",
        "-screen",
        "0",
        "1280x800x24",
        "-nolisten",
        "tcp",
        "-ac",
    ]
    assert build_xvfb_command(105, width=1920, height=1080, color_depth=24) == [
        "Xvfb",
        ":105",
        "-screen",
        "0",
        "1920x1080x24",
        "-nolisten",
        "tcp",
        "-ac",
    ]
    with pytest.raises(ValueError, match="non-negative"):
        build_xvfb_command(-1)

    assert build_dbus_command() == ["dbus-daemon", "--session", "--print-address=1", "--nofork"]

    env = build_slot_env(display=":100", dbus_address="unix:path=/tmp/dbus-slot-100")
    assert env == {
        "DISPLAY": ":100",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/dbus-slot-100",
        "ACCESSIBILITY_ENABLED": "1",
        "GTK_MODULES": "gail:atk-bridge",
        "QT_ACCESSIBILITY": "1",
    }

    env_with_atspi = build_slot_env(
        display=":101",
        dbus_address="unix:path=/tmp/dbus-101",
        atspi_address="unix:path=/tmp/atspi-101",
    )
    assert env_with_atspi["AT_SPI_BUS_ADDRESS"] == "unix:path=/tmp/atspi-101"


def test_find_free_display_num_skips_reserved_and_existing_locks(tmp_path: Path) -> None:
    # A lock counts as taken while its owner pid is alive (here: this test process).
    (tmp_path / ".X100-lock").write_text(f"{os.getpid():>10}\n", encoding="utf-8")
    x11_dir = tmp_path / ".X11-unix"
    x11_dir.mkdir()
    (x11_dir / "X101").write_text("", encoding="utf-8")

    # 100 has lock file, 101 has X11 socket, 102 is in reserved -> picks 103
    chosen = find_free_display_num(100, reserved={102}, lock_dir=tmp_path)
    assert chosen == 103

    with pytest.raises(ValueError, match="non-negative"):
        find_free_display_num(-5, lock_dir=tmp_path)


def test_pool_config_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="size must be >= 1"):
        BrowserPool(size=0)
    with pytest.raises(ValueError, match="cannot exceed number of remote_workers"):
        BrowserPool(size=2, remote_workers=["127.0.0.1:49222"])
    with pytest.raises(ValueError, match="max_uses_per_slot must be >= 1"):
        BrowserPool(size=1, max_uses_per_slot=0)
    with pytest.raises(ValueError, match="acquire_timeout_s must be > 0"):
        BrowserPool(size=1, acquire_timeout_s=0)
    with pytest.raises(ValueError, match="display_base must be >= 0"):
        BrowserPool(size=1, display_base=-1)
    with pytest.raises(ValueError, match="duplicate remote worker"):
        BrowserPool(remote_workers=["127.0.0.1:49222", " 127.0.0.1:49222 "])
    with pytest.raises(ValueError, match="profile_dir"):
        BrowserPool(
            size=2,
            launch_options=LaunchOptions(backend="mock", profile_dir=tmp_path / "shared"),
        )
    with pytest.raises(ValueError, match="display_backend"):
        BrowserPool(size=1, display_backend="invalid")  # type: ignore[arg-type]


async def test_pool_wayland_backend_skips_xvfb_and_passes_headless_wayland(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_opts: list[LaunchOptions] = []
    captured_cmds: list[list[str]] = []
    xvfb_called = False
    wayland_dbus_called = False

    def _fail_xvfb(*_args: object, **_kwargs: object) -> object:
        nonlocal xvfb_called
        xvfb_called = True
        msg = "Xvfb stack must not be started in wayland mode"
        raise AssertionError(msg)

    def _fake_wayland_dbus() -> None:
        nonlocal wayland_dbus_called
        wayland_dbus_called = True

    real_session_cls = Session

    class _FakeSession:
        def __init__(
            self,
            options: LaunchOptions,
            *,
            extra_env: dict[str, str] | None = None,
            _reap_pgid: int | None = None,
        ) -> None:
            _ = extra_env, _reap_pgid
            captured_opts.append(options)
            real = real_session_cls(options)
            captured_cmds.append(
                real._build_daemon_cmd(socket_path=None, tcp_addr=("127.0.0.1", 1))
            )

        def __enter__(self) -> object:
            return object()

        def ping(self) -> str:
            return "0.5.0"

        def is_healthy(self, *, timeout_s: float = 2.0) -> bool:
            _ = timeout_s
            return True

        def close(self) -> None:
            pass

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(pool_mod, "find_free_display_num", _fail_xvfb)
    monkeypatch.setattr(pool_mod._IsolatedDisplayStack, "start", classmethod(_fail_xvfb))
    monkeypatch.setattr(
        pool_mod._IsolatedDisplayStack,
        "start_wayland_dbus",
        classmethod(lambda _cls: _fake_wayland_dbus()),
    )
    monkeypatch.setattr(pool_mod, "Session", _FakeSession)

    async with (
        BrowserPool(
            size=1,
            isolated_displays=True,
            display_backend="wayland",
            launch_options=LaunchOptions(
                backend="linux",
                headless_xvfb=True,
                daemon_binary="/nonexistent/waybound-daemon",
            ),
        ) as pool,
        pool.acquire(),
    ):
        pass

    assert not xvfb_called
    assert wayland_dbus_called
    assert len(captured_opts) == 1
    assert captured_opts[0].headless_wayland is True
    assert captured_opts[0].headless_xvfb is False
    assert captured_opts[0].display is None
    assert "--headless-wayland" in captured_cmds[0]
    assert "--headless-xvfb" not in captured_cmds[0]


# ---------------------------------------------------------------------------
# Live `waybound-daemon --backend mock` integration tests
# ---------------------------------------------------------------------------


def _require_daemon_binary() -> Path:
    try:
        return _resolve_daemon_binary(None)
    except FileNotFoundError:
        pytest.skip("waybound-daemon binary not built in this environment")


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        addr: tuple[str, int] = probe.getsockname()
        return addr[1]


async def test_pool_concurrent_checkouts_and_queueing() -> None:
    _require_daemon_binary()
    current_active = 0
    max_observed_active = 0
    both_running = asyncio.Event()

    async with BrowserPool(size=3, launch_options=LaunchOptions(backend="mock")) as pool:

        async def worker(idx: int) -> int:
            nonlocal current_active, max_observed_active
            async with pool.acquire() as page:
                current_active += 1
                max_observed_active = max(max_observed_active, current_active)
                if current_active == 3:
                    both_running.set()
                tree = await page.snapshot_tree()
                assert len(tree) > 0
                await asyncio.sleep(0.08)
                current_active -= 1
                return idx

        results = await asyncio.gather(*(worker(i) for i in range(5)))
        assert sorted(results) == [0, 1, 2, 3, 4]
        assert max_observed_active == 3
        assert both_running.is_set()

        stats = pool.stats()
        assert stats == PoolStats(
            size=3,
            active=0,
            idle=3,
            launched=3,
            recycled=0,
            failed=0,
        )


async def test_pool_recycles_slot_on_exception() -> None:
    _require_daemon_binary()

    async with BrowserPool(size=1, launch_options=LaunchOptions(backend="mock")) as pool:

        async def _crashing_checkout() -> None:
            async with pool.acquire() as page:
                assert len(await page.snapshot_tree()) > 0
                msg = "simulated crash"
                raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="simulated crash"):
            await _crashing_checkout()

        after_crash = pool.stats()
        assert after_crash.launched == 1
        assert after_crash.recycled == 1
        assert after_crash.idle == 0
        assert after_crash.active == 0

        # Next checkout launches a fresh, healthy slot.
        async with pool.acquire() as fresh_page:
            btn = fresh_page.get_by_role(Role.BUTTON)
            assert await btn.count() >= 1

        after_recovery = pool.stats()
        assert after_recovery.launched == 2
        assert after_recovery.recycled == 1
        assert after_recovery.idle == 1


async def test_pool_proactive_recycling_max_uses_per_slot() -> None:
    _require_daemon_binary()

    async with BrowserPool(
        size=1,
        launch_options=LaunchOptions(backend="mock"),
        max_uses_per_slot=2,
    ) as pool:
        # Use 1 -> returned to idle
        async with pool.acquire() as page:
            assert len(await page.snapshot_tree()) > 0
        assert pool.stats() == PoolStats(size=1, active=0, idle=1, launched=1, recycled=0, failed=0)

        # Use 2 -> hits max_uses_per_slot -> recycled
        async with pool.acquire() as page:
            assert len(await page.snapshot_tree()) > 0
        assert pool.stats() == PoolStats(size=1, active=0, idle=0, launched=1, recycled=1, failed=0)

        # Use 3 -> launches fresh slot
        async with pool.acquire() as page:
            assert len(await page.snapshot_tree()) > 0
        assert pool.stats() == PoolStats(size=1, active=0, idle=1, launched=2, recycled=1, failed=0)


async def test_pool_acquire_timeout_when_exhausted() -> None:
    _require_daemon_binary()

    async with (
        BrowserPool(
            size=1,
            launch_options=LaunchOptions(backend="mock"),
            acquire_timeout_s=0.15,
        ) as pool,
        pool.acquire() as page,
    ):
        assert len(await page.snapshot_tree()) > 0
        with pytest.raises(TimeoutError):
            async with pool.acquire():
                pass


async def test_pool_remote_tcp_worker_checkout() -> None:
    daemon_bin = _require_daemon_binary()
    port = _reserve_port()
    addr = f"127.0.0.1:{port}"

    proc = subprocess.Popen(  # noqa: S603
        [str(daemon_bin), "--tcp", addr, "--backend", "mock"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Wait for remote daemon to listen.
        deadline = time.monotonic() + 5.0
        ready = False
        while time.monotonic() < deadline:
            try:
                with UnixSocketTransport(tcp_addr=("127.0.0.1", port), timeout_s=1.0) as probe:
                    probe.ping()
                    ready = True
                    break
            except OSError:
                await asyncio.sleep(0.03)
        assert ready, f"remote mock daemon failed to start on {addr}"

        async with BrowserPool(remote_workers=[addr]) as pool:
            async with pool.acquire() as page:
                tree = await page.snapshot_tree()
                assert len(tree) > 0
                node = await page.wait_for_text("Search")
                assert node.name is not None

            stats = pool.stats()
            assert stats == PoolStats(size=1, active=0, idle=1, launched=1, recycled=0, failed=0)

        # Closing the pool must NOT shut down the remote daemon.
        with UnixSocketTransport(tcp_addr=("127.0.0.1", port), timeout_s=2.0) as verify:
            assert verify.ping()
    finally:
        with (
            contextlib.suppress(OSError),
            UnixSocketTransport(tcp_addr=("127.0.0.1", port), timeout_s=1.0) as closer,
        ):
            closer.shutdown()
        if proc.poll() is None:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2.0)
        if proc.poll() is None:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=1.0)


async def test_pool_close_rejects_further_acquire() -> None:
    _require_daemon_binary()
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"))
    await pool.start()
    await pool.close()
    await pool.close()  # idempotent
    with pytest.raises(RuntimeError, match="closed"):
        async with pool.acquire():
            pass


async def test_pool_close_unblocks_queued_waiters_immediately() -> None:
    _require_daemon_binary()
    pool = BrowserPool(
        size=1,
        launch_options=LaunchOptions(backend="mock"),
        acquire_timeout_s=30.0,
    )
    entered = asyncio.Event()

    async def waiter_task() -> None:
        async with pool.acquire():
            pass

    async with pool.acquire() as page:
        assert len(await page.snapshot_tree()) > 0
        entered.set()
        queued = asyncio.create_task(waiter_task())
        await asyncio.sleep(0.05)

        started_close = time.monotonic()
        await pool.close()
        elapsed = time.monotonic() - started_close
        assert elapsed < 5.0

        with pytest.raises(RuntimeError, match="closed"):
            await queued

    stats = pool.stats()
    assert stats.active == 0
    assert stats.idle == 0


async def test_pool_close_during_inflight_acquire_cleans_up_without_leaking() -> None:
    _require_daemon_binary()
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"))

    async def slow_acquire() -> None:
        async with pool.acquire() as page:
            await page.snapshot_tree()

    task = asyncio.create_task(slow_acquire())
    await asyncio.sleep(0.01)
    await pool.close()
    with contextlib.suppress(RuntimeError):
        await task

    stats = pool.stats()
    assert stats.active == 0
    assert stats.idle == 0


async def test_pool_proxy_override_recycles_and_does_not_leak() -> None:
    _require_daemon_binary()

    async with BrowserPool(size=1, launch_options=LaunchOptions(backend="mock")) as pool:
        async with pool.acquire(proxy="http://127.0.0.1:18080") as page:
            assert len(await page.snapshot_tree()) > 0

        # Override proxy slot must be recycled rather than left in idle for default callers.
        assert pool.stats() == PoolStats(size=1, active=0, idle=0, launched=1, recycled=1, failed=0)

        # Next default acquire launches a fresh slot with the pool's default proxy (None).
        async with pool.acquire() as page:
            assert len(await page.snapshot_tree()) > 0

        assert pool.stats() == PoolStats(size=1, active=0, idle=1, launched=2, recycled=1, failed=0)


# ---------------------------------------------------------------------------
# Hardening: cancellation, health, policy, display ownership, process cleanup
# ---------------------------------------------------------------------------


def _daemon_bin_for_tests() -> Path:
    return _require_daemon_binary()


def _live_daemon_pids(daemon_bin: Path) -> set[int]:
    out = subprocess.run(
        ["/bin/ps", "-axo", "pid=,stat=,args="], capture_output=True, text=True, check=True
    ).stdout
    pids: set[int] = set()
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and not parts[1].startswith("Z") and str(daemon_bin) in parts[2]:
            pids.add(int(parts[0]))
    return pids


async def _assert_no_new_daemons(daemon_bin: Path, before: set[int]) -> None:
    deadline = time.monotonic() + 10.0
    while _live_daemon_pids(daemon_bin) - before and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    assert not _live_daemon_pids(daemon_bin) - before, "pool leaked a waybound-daemon"


def _slow_daemon(tmp_path: Path, daemon_bin: Path, delay_s: float) -> Path:
    script = tmp_path / "slow-daemon.sh"
    script.write_text(f'#!/bin/sh\nsleep {delay_s}\nexec "{daemon_bin}" "$@"\n')
    script.chmod(0o755)
    return script


async def test_pool_cancel_during_launch_does_not_leak_the_daemon(tmp_path: Path) -> None:
    daemon_bin = _daemon_bin_for_tests()
    before = _live_daemon_pids(daemon_bin)
    slow = _slow_daemon(tmp_path, daemon_bin, 0.8)
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock", daemon_binary=slow))
    await pool.start()

    async def borrow() -> None:
        async with pool.acquire() as page:
            await page.url()

    task = asyncio.create_task(borrow())
    await asyncio.sleep(0.3)  # the daemon is starting in a worker thread
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await asyncio.sleep(1.5)  # the launch finishes and is torn down in the background
    assert pool._available_permits == 1
    await pool.close()
    await _assert_no_new_daemons(daemon_bin, before)


async def test_pool_cancel_during_idle_health_check_keeps_the_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_bin = _daemon_bin_for_tests()
    before = _live_daemon_pids(daemon_bin)
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"))
    await pool.start()
    async with pool.acquire():
        pass
    original = pool_mod._PoolSlot.ping

    def slow_ping(self: pool_mod._PoolSlot) -> None:
        time.sleep(0.4)
        original(self)

    monkeypatch.setattr(pool_mod._PoolSlot, "ping", slow_ping)

    async def borrow() -> None:
        async with pool.acquire():
            pass

    task = asyncio.create_task(borrow())
    await asyncio.sleep(0.1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await asyncio.sleep(0.6)
    monkeypatch.undo()
    assert pool.stats().idle == 1  # the healthy slot went back to the pool
    async with pool.acquire() as page:
        assert len(await page.snapshot_tree()) > 0
    assert pool.stats().launched == 1
    await pool.close()
    await _assert_no_new_daemons(daemon_bin, before)


async def test_pool_recycles_a_slot_whose_browser_died(monkeypatch: pytest.MonkeyPatch) -> None:
    _require_daemon_binary()
    async with BrowserPool(size=1, launch_options=LaunchOptions(backend="mock")) as pool:
        async with pool.acquire():
            pass
        session = pool._idle[0]._session
        assert session is not None
        transport = session._transport
        assert transport is not None
        # What a daemon reports after the Chrome it launched exited.
        monkeypatch.setattr(transport, "browser_alive", lambda **_kw: False)
        async with pool.acquire() as page:
            assert len(await page.snapshot_tree()) > 0
        stats = pool.stats()
        assert (stats.launched, stats.recycled, stats.failed) == (2, 1, 1)


async def test_pool_health_check_is_bounded_for_a_hung_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_daemon_binary()
    monkeypatch.setattr(pool_mod, "_HEALTH_CHECK_TIMEOUT_S", 0.5)
    async with BrowserPool(size=1, launch_options=LaunchOptions(backend="mock")) as pool:
        async with pool.acquire():
            pass
        session = pool._idle[0]._session
        assert session is not None
        pid = session.daemon_pid
        assert pid is not None
        os.kill(pid, signal.SIGSTOP)
        try:
            started = time.monotonic()
            async with pool.acquire(timeout_s=30) as page:
                assert len(await page.snapshot_tree()) > 0
            assert time.monotonic() - started < 5.0
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGCONT)
        assert pool.stats().launched == 2


@pytest.mark.parametrize(
    "options",
    [
        LaunchOptions(backend="macos", launch_chrome=True),
        LaunchOptions(backend="windows", launch_chrome=True),
        LaunchOptions(backend="linux", launch_chrome=True),
        LaunchOptions(backend="linux", launch_chrome=True, headless_xvfb=True),
        LaunchOptions(backend="android", serial="emulator-5554"),
    ],
    ids=["macos", "windows", "linux-shared-display", "linux-daemon-xvfb", "android"],
)
def test_pool_refuses_parallel_slots_that_share_input(options: LaunchOptions) -> None:
    with pytest.raises(ValueError, match="size > 1"):
        BrowserPool(size=2, launch_options=options)
    BrowserPool(size=1, launch_options=options)
    BrowserPool(size=2, launch_options=options, remote_workers=["h1:1", "h2:1"])
    BrowserPool(
        size=2,
        launch_options=LaunchOptions(backend="linux", launch_chrome=True),
        isolated_displays=True,
    )


def test_find_free_display_num_reuses_stale_locks(tmp_path: Path) -> None:
    dead = subprocess.Popen(["/bin/sleep", "0"])
    dead.wait()
    (tmp_path / ".X100-lock").write_text(f"{dead.pid:>10}\n", encoding="utf-8")
    (tmp_path / ".X11-unix").mkdir()
    (tmp_path / ".X11-unix" / "X100").write_text("", encoding="utf-8")
    (tmp_path / ".X101-lock").write_text("garbage\n", encoding="utf-8")
    assert find_free_display_num(100, lock_dir=tmp_path) == 100  # owner gone: stale
    (tmp_path / ".X100-lock").write_text(f"{os.getpid():>10}\n", encoding="utf-8")
    assert find_free_display_num(100, lock_dir=tmp_path) == 102  # 101: unreadable owner


def test_xvfb_readiness_requires_our_own_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pool_mod, "_X11_LOCK_DIR", tmp_path)
    monkeypatch.setattr(pool_mod, "_XVFB_READY_TIMEOUT_S", 0.3)
    (tmp_path / ".X11-unix").mkdir()
    (tmp_path / ".X11-unix" / "X100").write_text("", encoding="utf-8")
    (tmp_path / ".X100-lock").write_text(f"{os.getpid():>10}\n", encoding="utf-8")
    impostor = subprocess.Popen(["/bin/sleep", "5"])  # stands in for "our" Xvfb
    try:
        with pytest.raises(RuntimeError, match="owned by another process"):
            pool_mod._IsolatedDisplayStack._wait_for_xvfb(impostor, 100)
        (tmp_path / ".X100-lock").write_text(f"{impostor.pid:>10}\n", encoding="utf-8")
        pool_mod._IsolatedDisplayStack._wait_for_xvfb(impostor, 100)
    finally:
        impostor.kill()
        impostor.wait()


async def test_two_pools_in_one_process_never_reserve_the_same_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pool_mod, "_X11_LOCK_DIR", tmp_path)
    a = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"), isolated_displays=True)
    b = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"), isolated_displays=True)
    first = a._reserve_display()
    second = b._reserve_display()
    try:
        assert first != second
    finally:
        a._unreserve_display(first)
        b._unreserve_display(second)
    assert first not in pool_mod._PROCESS_RESERVED_DISPLAYS


def test_display_stacks_are_closed_at_interpreter_exit() -> None:
    proc = subprocess.Popen(["/bin/sleep", "30"])
    stack = pool_mod._IsolatedDisplayStack(display_num=999, env={}, processes=[proc])
    assert stack in pool_mod._LIVE_STACKS
    pool_mod._close_live_stacks()  # what the atexit hook runs
    assert proc.poll() is not None
    assert stack not in pool_mod._LIVE_STACKS


async def test_close_does_not_spin_on_finished_teardowns() -> None:
    # Python 3.12's gather() completes synchronously when every child is already done, so a
    # close() that looped while the set was merely non-empty never yielded to the loop and
    # the done-callbacks that would have emptied it could never run.
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"))
    finished: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    finished.set_result(None)
    pool._background.add(finished)
    await asyncio.wait_for(pool.close(), timeout=2.0)
    assert not pool._background


async def test_close_and_a_borrower_tear_a_slot_down_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_daemon_binary()
    closes: list[int] = []
    original = pool_mod._PoolSlot._close_once

    def counting(self: pool_mod._PoolSlot) -> None:
        closes.append(id(self))
        original(self)

    monkeypatch.setattr(pool_mod._PoolSlot, "_close_once", counting)
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"))
    await pool.start()

    async def borrower() -> None:
        async with pool.acquire() as page:
            await page.url()
            await asyncio.sleep(0.3)

    task = asyncio.create_task(borrower())
    await asyncio.sleep(0.15)
    await asyncio.gather(pool.close(), task, return_exceptions=True)
    assert len(closes) == 1


async def test_cancelled_health_check_never_oversubscribes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_bin = _daemon_bin_for_tests()
    before = _live_daemon_pids(daemon_bin)
    pool = BrowserPool(size=1, launch_options=LaunchOptions(backend="mock"))
    await pool.start()
    async with pool.acquire():
        pass
    original = pool_mod._PoolSlot.ping

    def slow_ping(self: pool_mod._PoolSlot) -> None:
        time.sleep(0.4)
        original(self)

    monkeypatch.setattr(pool_mod._PoolSlot, "ping", slow_ping)

    async def use() -> None:
        async with pool.acquire():
            await asyncio.sleep(0.05)

    for _ in range(3):
        first = asyncio.create_task(use())
        await asyncio.sleep(0.1)  # inside the slow health check of the idle slot
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        second = asyncio.create_task(use())
        await asyncio.gather(second, return_exceptions=True)
        await asyncio.sleep(0.6)
        assert len(pool._idle) + len(pool._active_slots) <= 1
        assert len(_live_daemon_pids(daemon_bin) - before) <= 1
    monkeypatch.undo()
    await pool.close()
    await _assert_no_new_daemons(daemon_bin, before)


def test_stacks_hook_closes_sessions_before_stacks(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(pool_mod, "_close_live_sessions", lambda: order.append("sessions"))

    def terminate(proc: subprocess.Popen[bytes]) -> None:
        order.append("stack")
        proc.kill()
        proc.wait()

    monkeypatch.setattr(pool_mod, "_terminate_process", terminate)
    proc = subprocess.Popen(["/bin/sleep", "30"])
    pool_mod._IsolatedDisplayStack(display_num=998, env={}, processes=[proc])
    pool_mod._close_live_stacks()
    assert order == ["sessions", "stack"]


def test_parallel_refusal_points_crawlee_users_at_the_fix() -> None:
    with pytest.raises(ValueError, match="pool_size=1"):
        BrowserPool(size=2, launch_options=LaunchOptions(backend="macos", launch_chrome=True))


def test_wayland_slots_have_their_own_input_and_xvfb_needs_isolation() -> None:
    linux = LaunchOptions(backend="linux", launch_chrome=True)
    # One in-process compositor per daemon: no shared input even without isolated_displays.
    BrowserPool(size=2, launch_options=linux, display_backend="wayland")
    BrowserPool(size=2, launch_options=replace(linux, headless_wayland=True))
    with pytest.raises(ValueError, match="display_backend='wayland'"):
        BrowserPool(size=2, launch_options=linux, display_backend="xvfb")


def test_wayland_helper_stack_runs_in_one_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "fake-at-spi-bus-launcher"
    launcher.write_text("#!/bin/sh\nexec sleep 30\n")
    launcher.chmod(0o755)
    monkeypatch.setattr(shutil, "which", lambda _name: "/bin/sh")
    monkeypatch.setattr(
        pool_mod,
        "build_dbus_command",
        lambda: ["/bin/sh", "-c", "echo unix:path=/tmp/fake-bus; exec sleep 30"],
    )
    monkeypatch.setattr(pool_mod, "find_atspi_launcher", lambda: launcher)
    monkeypatch.setattr(pool_mod, "_ATSPI_SETTLE_DELAY_S", 0.0)
    stack = pool_mod._IsolatedDisplayStack.start_wayland_dbus()
    assert stack is not None
    try:
        pids = [proc.pid for proc in stack._processes]
        assert len(pids) == 2
        assert stack.pgid == pids[0]
        assert {os.getpgid(pid) for pid in pids} == {pids[0]}  # the daemon's WAYBOUND_REAP_PGID
        assert stack.pgid != os.getpgrp()
    finally:
        stack.close()


@pytest.mark.parametrize("display_backend", ["wayland", "xvfb"])
def test_linux_pool_without_launch_chrome_is_refused(display_backend: DisplayBackend) -> None:
    for opts in (
        LaunchOptions(backend="linux"),
        LaunchOptions(backend="linux", pid=4242),
    ):
        with pytest.raises(ValueError, match="launch_chrome=True"):
            BrowserPool(
                size=2,
                launch_options=opts,
                display_backend=display_backend,
                isolated_displays=True,
            )
    BrowserPool(size=1, launch_options=LaunchOptions(backend="linux"), display_backend="wayland")
