"""Async multi-display Linux & remote-worker browser pool (`BrowserPool`).

Designed for Crawlee's `AutoscaledPool` and standalone concurrent crawlers:
- Manages up to `size` concurrent browser slots with lazy launch, health checks,
  automatic crash recycling, and optional proactive recycling (`max_uses_per_slot`).
- On Linux, `isolated_displays=True` allocates a free virtual X11 display (`:N`),
  spawns `Xvfb`, `openbox`, an isolated `dbus-daemon --session`, and
  `at-spi-bus-launcher` per slot, tearing down all child processes on recycle/close.
- Also supports scheduling across remote TCP `waybound-daemon --tcp` workers
  (`remote_workers=["host:port", ...]`).
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import dataclasses
import os
import select
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self

from waybound.async_client import AsyncPage
from waybound.client import Page
from waybound.session import LaunchOptions, Session, _close_live_sessions
from waybound.transport import UnixSocketTransport, WayboundDaemonError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Sequence
    from collections.abc import Set as AbstractSet
    from types import TracebackType

DisplayBackend = Literal["xvfb", "wayland"]
_DISPLAY_BACKENDS: frozenset[str] = frozenset({"xvfb", "wayland"})

_DEFAULT_DISPLAY_WIDTH = 1280
_DEFAULT_DISPLAY_HEIGHT = 800
_DEFAULT_DISPLAY_DEPTH = 24
_MAX_PORT = 65_535
_MAX_DISPLAY_SCAN = 10_000
_XVFB_READY_TIMEOUT_S = 3.0
_DBUS_READY_TIMEOUT_S = 3.0
_XVFB_POLL_INTERVAL_S = 0.05
_INITIAL_WINDOW_POLL_INTERVAL_S = 0.05
_ATSPI_SETTLE_DELAY_S = 0.2
_CHILD_STOP_TIMEOUT_S = 2.0
_CHILD_KILL_TIMEOUT_S = 1.0
# Bounds every slot health check, so a hung daemon is recycled instead of blocking `acquire`
# for the transport's 30 s default (the TypeScript pool uses a similar bounded ping).
_HEALTH_CHECK_TIMEOUT_S = 5.0
_ATSPI_LAUNCHER_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/libexec/at-spi-bus-launcher"),
    Path("/usr/lib/at-spi2-core/at-spi-bus-launcher"),
)
# X11 display lock files (`.X<N>-lock`) and sockets (`.X11-unix/X<N>`) are fixed by X11 spec.
_X11_LOCK_DIR = Path("/tmp")  # noqa: S108

# Display numbers reserved by any pool in this process, so two pools never pick the same one
# in the moment before its Xvfb has written a lock file.
_PROCESS_DISPLAYS_LOCK = threading.Lock()
_PROCESS_RESERVED_DISPLAYS: set[int] = set()


@dataclass(frozen=True, slots=True)
class PoolStats:
    """Point-in-time observability snapshot of a [`BrowserPool`]."""

    size: int
    active: int
    idle: int
    launched: int
    recycled: int
    failed: int


@dataclass(frozen=True, slots=True)
class PoolSlotConfig:
    """Resolved launch configuration for a single pool worker slot."""

    slot_index: int
    launch_options: LaunchOptions
    remote_endpoint: tuple[str, int] | None = None
    display_num: int | None = None


def parse_remote_worker(endpoint: str) -> tuple[str, int]:
    """Parse a `host:port` or `[ipv6]:port` TCP worker endpoint string."""
    raw = endpoint.strip()
    if not raw:
        msg = "remote worker endpoint must not be empty"
        raise ValueError(msg)

    if raw.startswith("["):
        closing = raw.find("]")
        if closing == -1 or closing + 1 >= len(raw) or raw[closing + 1] != ":":
            msg = f"invalid IPv6 remote worker endpoint: {endpoint!r}"
            raise ValueError(msg)
        host = raw[1:closing]
        port_str = raw[closing + 2 :]
    else:
        host, sep, port_str = raw.rpartition(":")
        if not sep or not host:
            msg = f"remote worker endpoint must be 'host:port', got {endpoint!r}"
            raise ValueError(msg)

    try:
        port = int(port_str)
    except ValueError as err:
        msg = f"invalid port in remote worker endpoint {endpoint!r}"
        raise ValueError(msg) from err

    if port < 1 or port > _MAX_PORT:
        msg = f"port out of range (1..{_MAX_PORT}) in remote worker endpoint {endpoint!r}"
        raise ValueError(msg)

    return (host, port)


def build_xvfb_command(
    display_num: int,
    *,
    width: int = _DEFAULT_DISPLAY_WIDTH,
    height: int = _DEFAULT_DISPLAY_HEIGHT,
    color_depth: int = _DEFAULT_DISPLAY_DEPTH,
) -> list[str]:
    """Build the `Xvfb` command vector for a virtual display slot."""
    if display_num < 0:
        msg = f"display_num must be non-negative, got {display_num}"
        raise ValueError(msg)
    return [
        "Xvfb",
        f":{display_num}",
        "-screen",
        "0",
        f"{width}x{height}x{color_depth}",
        "-nolisten",
        "tcp",
        "-ac",
    ]


def build_dbus_command() -> list[str]:
    """Build the isolated `dbus-daemon` session command vector."""
    return ["dbus-daemon", "--session", "--print-address=1", "--nofork"]


def build_slot_env(
    *,
    display: str | None = None,
    dbus_address: str,
    atspi_address: str | None = None,
) -> dict[str, str]:
    """Build the isolated Linux display + D-Bus/AT-SPI2 environment variables for a slot."""
    env: dict[str, str] = {
        "DBUS_SESSION_BUS_ADDRESS": dbus_address,
        "ACCESSIBILITY_ENABLED": "1",
        "GTK_MODULES": "gail:atk-bridge",
        "QT_ACCESSIBILITY": "1",
    }
    if display is not None:
        env["DISPLAY"] = display
    if atspi_address is not None:
        env["AT_SPI_BUS_ADDRESS"] = atspi_address
    return env


def _read_lock_owner(lock_file: Path) -> int | None:
    """Return the pid recorded in an X11 lock file, or `None` if absent or unparsable."""
    try:
        raw = lock_file.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() else None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # e.g. PermissionError: the process exists but belongs to someone else
        return True
    return True


def _display_taken(candidate: int, lock_dir: Path) -> bool:
    """A display is taken if it has a live lock, or a socket without a readable stale lock.

    A lock whose owner pid is dead is stale (an Xvfb that was killed leaves it behind) and
    does not count; `_IsolatedDisplayStack` then verifies that its own Xvfb took the lock.
    """
    lock_file = lock_dir / f".X{candidate}-lock"
    x11_sock = lock_dir / ".X11-unix" / f"X{candidate}"
    if lock_file.exists():
        owner = _read_lock_owner(lock_file)
        return owner is None or _pid_alive(owner)
    return x11_sock.exists()


def find_free_display_num(
    start: int = 100,
    *,
    reserved: AbstractSet[int] = frozenset(),
    lock_dir: Path = _X11_LOCK_DIR,
) -> int:
    """Find the lowest X11 display number `>= start` not in `reserved` or in use on disk.

    A lock file whose owner process no longer exists is treated as free.
    """
    if start < 0:
        msg = f"display_base must be non-negative, got {start}"
        raise ValueError(msg)
    for candidate in range(start, start + _MAX_DISPLAY_SCAN):
        if candidate in reserved:
            continue
        if not _display_taken(candidate, lock_dir):
            return candidate
    msg = f"no free X11 display numbers available starting from :{start}"
    raise RuntimeError(msg)


def find_atspi_launcher() -> Path | None:
    """Locate the system `at-spi-bus-launcher` binary, if installed."""
    for candidate in _ATSPI_LAUNCHER_CANDIDATES:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    on_path = shutil.which("at-spi-bus-launcher")
    return Path(on_path) if on_path is not None else None


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    with contextlib.suppress(OSError):
        proc.terminate()
    try:
        proc.wait(timeout=_CHILD_STOP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.wait(timeout=_CHILD_KILL_TIMEOUT_S)


# Display stacks not yet closed, so an interpreter exit without `BrowserPool.close()` (an
# unhandled exception or Ctrl-C) does not leave their Xvfb/D-Bus/openbox/AT-SPI behind.
_LIVE_STACKS: set[_IsolatedDisplayStack] = set()
_LIVE_STACKS_LOCK = threading.Lock()


def _close_live_stacks() -> None:
    # Shut daemons (and so their browsers) down first, gracefully, while their Xvfb and D-Bus
    # are still running. Registered after the session module's own hook, this runs before it
    # (atexit is LIFO), so it closes the sessions itself rather than relying on that order.
    _close_live_sessions()
    with _LIVE_STACKS_LOCK:
        stacks = list(_LIVE_STACKS)
    for stack in stacks:
        with contextlib.suppress(Exception):
            stack.close()


def _forget_stacks_after_fork() -> None:
    """A forked child must not tear down its parent's display stacks at exit."""
    global _LIVE_STACKS_LOCK, _PROCESS_DISPLAYS_LOCK  # noqa: PLW0603 - locks held at fork
    _LIVE_STACKS_LOCK = threading.Lock()
    _LIVE_STACKS.clear()
    _PROCESS_DISPLAYS_LOCK = threading.Lock()


atexit.register(_close_live_stacks)
if sys.platform != "win32":
    os.register_at_fork(after_in_child=_forget_stacks_after_fork)


class _IsolatedDisplayStack:
    """Owns per-slot `Xvfb`, `dbus-daemon`, `openbox`, and `at-spi-bus-launcher` processes."""

    def __init__(
        self,
        *,
        display_num: int | None,
        env: dict[str, str],
        processes: list[subprocess.Popen[bytes]],
    ) -> None:
        self.display_num = display_num
        self.display = f":{display_num}" if display_num is not None else None
        self.env = env
        self._processes = processes
        # All of the stack's processes share one process group led by Xvfb. The slot's daemon
        # is told about it (`WAYBOUND_REAP_PGID`) and stops it only if this Python process is
        # gone when the daemon shuts down; normally `close()` stops the stack itself.
        self.pgid: int | None = processes[0].pid if processes else None
        self._owner_pid = os.getpid()
        with _LIVE_STACKS_LOCK:
            _LIVE_STACKS.add(self)

    @classmethod
    def start(cls, display_num: int) -> _IsolatedDisplayStack:
        processes: list[subprocess.Popen[bytes]] = []
        display = f":{display_num}"
        try:
            xvfb = subprocess.Popen(  # noqa: S603
                build_xvfb_command(display_num),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                process_group=0,  # new group led by Xvfb; the others join it below
            )
            processes.append(xvfb)
            cls._wait_for_xvfb(xvfb, display_num)

            dbus = subprocess.Popen(  # noqa: S603
                build_dbus_command(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                process_group=xvfb.pid,
            )
            processes.append(dbus)
            dbus_address = cls._read_dbus_address(dbus)

            slot_env = build_slot_env(display=display, dbus_address=dbus_address)
            child_env = {**os.environ, **slot_env}

            openbox_bin = shutil.which("openbox")
            if openbox_bin is not None:
                openbox = subprocess.Popen(  # noqa: S603
                    [openbox_bin],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=child_env,
                    process_group=xvfb.pid,
                )
                processes.append(openbox)

            atspi_bin = find_atspi_launcher()
            if atspi_bin is not None:
                atspi = subprocess.Popen(  # noqa: S603
                    [str(atspi_bin), "--launch-immediately"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=child_env,
                    process_group=xvfb.pid,
                )
                processes.append(atspi)
                time.sleep(_ATSPI_SETTLE_DELAY_S)

            return cls(display_num=display_num, env=slot_env, processes=processes)
        except BaseException:
            for proc in reversed(processes):
                _terminate_process(proc)
            raise

    @classmethod
    def start_wayland_dbus(cls) -> _IsolatedDisplayStack | None:
        """Spawn isolated `dbus-daemon` + `at-spi-bus-launcher` without `Xvfb`/`openbox`."""
        if shutil.which("dbus-daemon") is None:
            return None
        processes: list[subprocess.Popen[bytes]] = []
        try:
            dbus = subprocess.Popen(  # noqa: S603
                build_dbus_command(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                process_group=0,  # new group led by dbus-daemon; AT-SPI joins it below
            )
            processes.append(dbus)
            dbus_address = cls._read_dbus_address(dbus)

            slot_env = build_slot_env(dbus_address=dbus_address)
            child_env = {**os.environ, **slot_env}

            atspi_bin = find_atspi_launcher()
            if atspi_bin is not None:
                atspi = subprocess.Popen(  # noqa: S603
                    [str(atspi_bin), "--launch-immediately"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=child_env,
                    process_group=dbus.pid,
                )
                processes.append(atspi)
                time.sleep(_ATSPI_SETTLE_DELAY_S)

            return cls(display_num=None, env=slot_env, processes=processes)
        except BaseException:
            for proc in reversed(processes):
                _terminate_process(proc)
            raise

    @staticmethod
    def _wait_for_xvfb(proc: subprocess.Popen[bytes], display_num: int) -> None:
        # Ready only when *our* Xvfb owns the display: if another process already runs a
        # server on this number, its socket exists too and ours is about to exit, and using
        # the display would silently drive someone else's server.
        sock_path = _X11_LOCK_DIR / ".X11-unix" / f"X{display_num}"
        lock_path = _X11_LOCK_DIR / f".X{display_num}-lock"
        deadline = time.monotonic() + _XVFB_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                msg = f"Xvfb :{display_num} exited prematurely (code {proc.returncode})"
                owner = _read_lock_owner(lock_path)
                if owner is not None:
                    msg += f"; display :{display_num} is owned by pid {owner}"
                raise RuntimeError(msg)
            if sock_path.exists() and _read_lock_owner(lock_path) == proc.pid:
                return
            time.sleep(_XVFB_POLL_INTERVAL_S)
        if proc.poll() is not None:
            msg = f"Xvfb :{display_num} exited prematurely (code {proc.returncode})"
            raise RuntimeError(msg)
        owner = _read_lock_owner(lock_path)
        if owner is not None and owner != proc.pid:
            msg = f"Xvfb :{display_num} is owned by another process (pid {owner})"
            raise RuntimeError(msg)

    @staticmethod
    def _read_dbus_address(
        proc: subprocess.Popen[bytes],
        *,
        timeout_s: float = _DBUS_READY_TIMEOUT_S,
    ) -> str:
        stdout = proc.stdout
        if stdout is None:
            msg = "dbus-daemon stdout pipe unavailable"
            raise RuntimeError(msg)
        fd = stdout.fileno()
        chunks = bytearray()
        deadline = time.monotonic() + timeout_s
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    msg = f"timed out after {timeout_s:.1f}s waiting for dbus-daemon bus address"
                    raise TimeoutError(msg)
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    msg = f"timed out after {timeout_s:.1f}s waiting for dbus-daemon bus address"
                    raise TimeoutError(msg)
                data = os.read(fd, 4096)
                if not data:
                    break
                chunks.extend(data)
                if b"\n" in chunks:
                    break
        finally:
            with contextlib.suppress(OSError):
                stdout.close()

        first_line = bytes(chunks).split(b"\n", 1)[0]
        address = first_line.decode("utf-8", errors="replace").strip()
        if not address:
            msg = f"dbus-daemon failed to emit session bus address (code {proc.poll()})"
            raise RuntimeError(msg)
        return address

    def close(self) -> None:
        """Terminate all spawned display/D-Bus/WM child processes in reverse order."""
        processes = self._processes
        self._processes = []
        try:
            if self._owner_pid == os.getpid():  # never from a forked child
                for proc in reversed(processes):
                    _terminate_process(proc)
        finally:
            with _LIVE_STACKS_LOCK:
                _LIVE_STACKS.discard(self)


async def _run_detached[T](
    fn: Callable[[], T], on_abandoned: Callable[[asyncio.Future[T]], None]
) -> T:
    """Run blocking `fn` in a thread without letting cancellation lose its result.

    Cancelling the awaiting task cannot stop a running thread. Instead of dropping whatever
    `fn` produces (a launched slot, a health verdict), `on_abandoned` receives its future once
    it completes, so the caller can clean up or put the slot back.
    """
    future = asyncio.get_running_loop().run_in_executor(None, fn)
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        future.add_done_callback(on_abandoned)
        raise


_PARALLEL_HINT = (
    " (With `WayboundCrawler`, the same applies to `pool_size`: pass `pool_size=1`, "
    "`remote_workers=[...]`, or on Linux `isolated_displays=True`.)"
)


def _check_parallel_input(
    options: LaunchOptions, *, isolated_displays: bool, display_backend: DisplayBackend
) -> None:
    """Refuse local pools whose slots would share one pointer/keyboard (or one device)."""
    try:
        _check_parallel_input_inner(
            options, isolated_displays=isolated_displays, display_backend=display_backend
        )
    except ValueError as err:
        raise ValueError(f"{err}{_PARALLEL_HINT}") from None


def _check_parallel_input_inner(
    options: LaunchOptions, *, isolated_displays: bool, display_backend: DisplayBackend
) -> None:
    backend = options.backend
    # Every Wayland slot's daemon runs its own in-process compositor, with its own seat (pointer
    # and keyboard), so Wayland slots never share input even without `isolated_displays`.
    own_input = isolated_displays or display_backend == "wayland" or options.headless_wayland
    if backend in ("macos", "windows"):
        msg = (
            f"size > 1 is not supported for backend={backend!r}: every slot would drive the "
            "one real desktop pointer, keyboard and window focus, so parallel slots would steal "
            "each other's clicks and keystrokes. Use size=1, remote_workers, or Linux with "
            "display_backend='wayland' or isolated_displays=True."
        )
        raise ValueError(msg)
    if backend == "linux" and not options.launch_chrome:
        msg = (
            "size > 1 with backend='linux' requires launch_chrome=True: every slot uses the same "
            "launch options, so without it the slots would all attach to one browser (the same "
            "pid) or, with no pid, to whichever Chrome answers first on the shared accessibility "
            "bus."
        )
        raise ValueError(msg)
    if backend == "linux" and not own_input:
        msg = (
            "size > 1 with backend='linux' requires display_backend='wayland' (one headless "
            "compositor per slot) or isolated_displays=True (one Xvfb per slot): otherwise every "
            "slot shares one X display (or the daemon's single headless_xvfb display :99) and its "
            "input."
        )
        raise ValueError(msg)
    if backend == "android":
        msg = (
            "size > 1 with backend='android' is not supported locally: every slot would drive the "
            "same adb device. Use remote_workers with one device per worker."
        )
        raise ValueError(msg)


def _consume_future_exception(future: asyncio.Future[None]) -> None:
    """Prevent asyncio from logging 'Future exception was never retrieved' on abandoned futures."""
    if not future.cancelled():
        future.exception()


def _validate_windows_per_browser(
    windows_per_browser: object,
    *,
    options: LaunchOptions,
    display_backend: DisplayBackend,
    has_remotes: bool,
) -> None:
    if (
        not isinstance(windows_per_browser, int)
        or isinstance(windows_per_browser, bool)
        or windows_per_browser < 1
    ):
        msg = f"windows_per_browser must be >= 1 (integer), got {windows_per_browser!r}"
        raise ValueError(msg)
    if windows_per_browser == 1:
        return
    if has_remotes:
        msg = "windows_per_browser > 1 is not supported with remote_workers"
        raise ValueError(msg)
    if options.backend != "mock" and (display_backend != "wayland" or options.backend != "linux"):
        msg = (
            "windows_per_browser > 1 requires display_backend='wayland' on Linux "
            "(or launch_options.backend='mock')"
        )
        raise ValueError(msg)
    if options.backend == "linux" and not options.launch_chrome:
        msg = "windows_per_browser > 1 with backend='linux' requires launch_chrome=True"
        raise ValueError(msg)


def _validate_pool_config(  # noqa: PLR0913
    *,
    resolved_size: int,
    windows_per_browser: int,
    options: LaunchOptions,
    proxies: Sequence[str] | None,
    display_backend: DisplayBackend,
    isolated_displays: bool,
    parsed_remotes: Sequence[tuple[str, tuple[str, int]]],
    max_uses_per_slot: int | None,
    acquire_timeout_s: float,
    display_base: int,
) -> None:
    if resolved_size < 1:
        msg = f"size must be >= 1, got {resolved_size}"
        raise ValueError(msg)
    if parsed_remotes and resolved_size > len(parsed_remotes):
        msg = (
            f"size ({resolved_size}) cannot exceed number of remote_workers ({len(parsed_remotes)})"
        )
        raise ValueError(msg)
    _validate_windows_per_browser(
        windows_per_browser,
        options=options,
        display_backend=display_backend,
        has_remotes=bool(parsed_remotes),
    )
    max_hosts = (resolved_size + windows_per_browser - 1) // windows_per_browser
    if not parsed_remotes and options.profile_dir is not None:
        if max_hosts > 1:
            msg = (
                "launch_options.profile_dir cannot be set when size > windows_per_browser "
                "(multiple Chrome slots cannot share one --user-data-dir)"
            )
            raise ValueError(msg)
        if proxies is not None and len(set(proxies)) > 1:
            msg = (
                "launch_options.profile_dir cannot be combined with multiple distinct proxies "
                "(multiple Chrome hosts cannot share one --user-data-dir)"
            )
            raise ValueError(msg)
    if not parsed_remotes and resolved_size > 1:
        _check_parallel_input(
            options,
            isolated_displays=isolated_displays,
            display_backend=display_backend,
        )
    if max_uses_per_slot is not None and max_uses_per_slot < 1:
        msg = f"max_uses_per_slot must be >= 1, got {max_uses_per_slot}"
        raise ValueError(msg)
    if acquire_timeout_s <= 0:
        msg = f"acquire_timeout_s must be > 0, got {acquire_timeout_s}"
        raise ValueError(msg)
    if display_base < 0:
        msg = f"display_base must be >= 0, got {display_base}"
        raise ValueError(msg)


class _BrowserHost:
    """Shared local browser process (daemon + Chrome) hosting up to `max_windows` stacked pages."""

    def __init__(
        self,
        *,
        proxy: str | None,
        override_proxy: bool,
        max_windows: int,
        ready_future: asyncio.Future[None],
    ) -> None:
        self.proxy = proxy
        self.override_proxy = override_proxy
        self.max_windows = max_windows
        self.ready_future = ready_future
        self.ready_future.add_done_callback(_consume_future_exception)
        self.launch_task: asyncio.Task[None] | None = None
        self.session: Session | None = None
        self.root_page: Page | None = None
        self.display_stack: _IsolatedDisplayStack | None = None
        self.initial_window_id: int | None = None
        self.initial_window_claimed = False
        self.pending_opens = 0
        self.closing_windows = 0
        self.active_slots: set[_PoolSlot] = set()
        self.idle_slots: deque[_PoolSlot] = deque()
        self.retired = False
        self.teardown: asyncio.Future[None] | None = None
        self._close_lock = threading.Lock()
        self._closed = False

    @property
    def open_window_count(self) -> int:
        return len(self.active_slots) + len(self.idle_slots)

    @property
    def live_window_count(self) -> int:
        return self.open_window_count + self.pending_opens

    @property
    def capacity_used(self) -> int:
        return self.live_window_count + self.closing_windows

    @property
    def in_use_count(self) -> int:
        return len(self.active_slots) + self.pending_opens + self.closing_windows

    def is_retired(self) -> bool:
        return self.retired

    def has_root_page(self) -> bool:
        return self.root_page is not None

    def ping(self) -> None:
        """Verify that this host's daemon and browser are healthy."""
        if self.session is None:
            msg = "browser host is not started or already closed"
            raise RuntimeError(msg)
        if not self.session.is_healthy(timeout_s=_HEALTH_CHECK_TIMEOUT_S):
            msg = "browser host is unhealthy (daemon or browser gone, or ping timed out)"
            raise RuntimeError(msg)

    def close(self) -> None:
        """Tear down this host's daemon and any isolated display stack (idempotent, thread-safe)."""
        with self._close_lock:
            if self._closed:
                return
            if not self.ready_future.done():
                self.retired = True
                return
            self._closed = True
            self._close_once()

    def _close_once(self) -> None:
        try:
            if self.session is not None:
                with contextlib.suppress(OSError, WayboundDaemonError, RuntimeError):
                    self.session.close()
                self.session = None
            self.root_page = None
        finally:
            if self.display_stack is not None:
                with contextlib.suppress(OSError, RuntimeError):
                    self.display_stack.close()
                self.display_stack = None


class _PoolSlot:
    """Internal runtime state for a single local or remote browser worker slot."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        page: AsyncPage,
        proxy: str | None,
        override_proxy: bool = False,
        session: Session | None = None,
        remote_transport: UnixSocketTransport | None = None,
        remote_worker: str | None = None,
        display_stack: _IsolatedDisplayStack | None = None,
        display_num: int | None = None,
        host: _BrowserHost | None = None,
        window_id: int | None = None,
    ) -> None:
        self.page = page
        self.proxy = proxy
        self.override_proxy = override_proxy
        self.uses = 0
        self.remote_worker = remote_worker
        self.display_num = display_num
        self.host = host
        self.window_id = window_id
        self._session = session
        self._remote_transport = remote_transport
        self._display_stack = display_stack
        # The one teardown of this slot, shared by everyone who asks for it (the pool's close()
        # and a borrower's exit can both reach an in-use slot).
        self.teardown: asyncio.Future[None] | None = None
        self._close_lock = threading.Lock()
        self._closed = False

    def ping(self) -> None:
        """Verify that the slot is healthy; raise `RuntimeError` or `WayboundDaemonError` if not.

        Healthy means the daemon (local or remote) answers a ping within
        `_HEALTH_CHECK_TIMEOUT_S` and, when it launched the browser, reports the browser still
        running (`browser_alive`); a local daemon must also still be running.
        """
        if self.host is not None:
            self.host.ping()
            return
        if self._session is not None:
            if not self._session.is_healthy(timeout_s=_HEALTH_CHECK_TIMEOUT_S):
                msg = "slot is unhealthy (daemon or browser gone, or ping timed out)"
                raise RuntimeError(msg)
            return
        if self._remote_transport is not None:
            if self._remote_transport.browser_alive(timeout_s=_HEALTH_CHECK_TIMEOUT_S) is False:
                msg = "remote worker reports its browser is no longer running"
                raise RuntimeError(msg)
            return
        msg = "slot has neither local session nor remote transport"
        raise RuntimeError(msg)

    def close(self) -> None:
        """Tear down this slot's daemon/connection and any isolated display stack.

        Idempotent and thread-safe: a second caller waits for the first teardown and returns.
        """
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._close_once()

    def _close_once(self) -> None:
        try:
            if self._session is not None:
                with contextlib.suppress(OSError, WayboundDaemonError, RuntimeError):
                    self._session.close()
                self._session = None
            if self._remote_transport is not None:
                # Never send `shutdown` to remote workers; close only our client socket.
                with contextlib.suppress(OSError):
                    self._remote_transport.close()
                self._remote_transport = None
        finally:
            if self._display_stack is not None:
                with contextlib.suppress(OSError, RuntimeError):
                    self._display_stack.close()
                self._display_stack = None


def _parse_remote_workers(
    remote_workers: Sequence[str] | None,
) -> list[tuple[str, tuple[str, int]]]:
    parsed_remotes: list[tuple[str, tuple[str, int]]] = []
    seen_remotes: set[tuple[str, int]] = set()
    if remote_workers is not None:
        for raw in remote_workers:
            parsed = parse_remote_worker(raw)
            if parsed in seen_remotes:
                msg = f"duplicate remote worker endpoint: {raw!r}"
                raise ValueError(msg)
            seen_remotes.add(parsed)
            parsed_remotes.append((raw, parsed))
    return parsed_remotes


class _Permit:
    """One acquire's permit; released exactly once, possibly by a detached health check."""

    __slots__ = ("released", "transferred")

    def __init__(self) -> None:
        self.released = False
        # Set when a cancelled acquire hands its permit to a still-running health check, which
        # releases it once it has decided the slot's fate (so a replacement cannot be launched
        # while the old slot may still be returned to the pool).
        self.transferred = False


class BrowserPool:
    """Async pool of isolated local or remote `waybound` browser sessions."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        size: int | None = None,
        launch_options: LaunchOptions | None = None,
        proxies: Sequence[str] | None = None,
        isolated_displays: bool = False,
        display_backend: DisplayBackend = "xvfb",
        display_base: int = 100,
        remote_workers: Sequence[str] | None = None,
        max_uses_per_slot: int | None = None,
        acquire_timeout_s: float = 60.0,
        windows_per_browser: int = 1,
    ) -> None:
        if display_backend not in _DISPLAY_BACKENDS:
            msg = f"display_backend must be 'xvfb' or 'wayland', got {display_backend!r}"
            raise ValueError(msg)
        parsed_remotes = _parse_remote_workers(remote_workers)

        resolved_size = size if size is not None else (len(parsed_remotes) or 1)
        resolved_options = launch_options if launch_options is not None else LaunchOptions()
        _validate_pool_config(
            resolved_size=resolved_size,
            windows_per_browser=windows_per_browser,
            options=resolved_options,
            proxies=proxies,
            display_backend=display_backend,
            isolated_displays=isolated_displays,
            parsed_remotes=parsed_remotes,
            max_uses_per_slot=max_uses_per_slot,
            acquire_timeout_s=acquire_timeout_s,
            display_base=display_base,
        )

        self._size = resolved_size
        self._windows_per_browser = windows_per_browser
        self._launch_options = resolved_options
        self._proxies: tuple[str, ...] = tuple(proxies) if proxies is not None else ()
        self._isolated_displays = isolated_displays
        self._display_backend: DisplayBackend = display_backend
        self._display_base = display_base
        self._remote_endpoints: dict[str, tuple[str, int]] = dict(parsed_remotes)
        self._available_remotes: deque[str] = deque(raw for raw, _ in parsed_remotes)
        self._max_uses_per_slot = max_uses_per_slot
        self._acquire_timeout_s = acquire_timeout_s

        self._available_permits = resolved_size
        self._waiters: deque[asyncio.Future[None]] = deque()
        self._idle: deque[_PoolSlot] = deque()
        self._active_slots: set[_PoolSlot] = set()
        self._hosts: list[_BrowserHost] = []
        self._retiring_hosts: set[_BrowserHost] = set()
        self._reserved_displays: set[int] = set()
        # Guards display reservations and the remote-worker queue, which slot teardowns update
        # from worker threads.
        self._resources_lock = threading.Lock()
        # Slot/host teardowns and launches still running in background; `close()` waits for them
        # so nothing outlives the pool.
        self._background: set[asyncio.Future[None]] = set()
        self._proxy_cursor = 0
        self._slot_counter = 0
        self._started = False
        self._closed = False

        self._launched = 0
        self._recycled = 0
        self._failed = 0

    async def start(self) -> None:
        """Mark the pool as started (slots are lazily launched on `acquire()`)."""
        if self._closed:
            msg = "BrowserPool is already closed"
            raise RuntimeError(msg)
        self._started = True

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    def _is_closed(self) -> bool:
        return self._closed

    def stats(self) -> PoolStats:
        """Return a snapshot of current pool utilization and lifecycle counters."""
        return PoolStats(
            size=self._size,
            active=len(self._active_slots),
            idle=len(self._idle),
            launched=self._launched,
            recycled=self._recycled,
            failed=self._failed,
        )

    async def _acquire_permit(self, timeout_s: float) -> None:
        if self._available_permits > 0:
            self._available_permits -= 1
            return
        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[None] = loop.create_future()
        self._waiters.append(waiter)
        try:
            await asyncio.wait_for(waiter, timeout=timeout_s)
        except BaseException:
            with contextlib.suppress(ValueError):
                self._waiters.remove(waiter)
            # If a permit was handed to `waiter` concurrently with timeout/cancellation, return it.
            if waiter.done() and not waiter.cancelled() and waiter.exception() is None:
                self._release_permit()
            raise

    def _give_back(self, permit: _Permit) -> None:
        if not permit.released:
            permit.released = True
            self._release_permit()

    def _release_permit(self) -> None:
        while self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_result(None)
                return
        self._available_permits += 1

    def _is_override_proxy(self, proxy: str | None) -> bool:
        if proxy is None:
            return False
        if self._proxies:
            return proxy not in self._proxies
        return proxy != self._launch_options.proxy

    def _next_proxy(self, override: str | None) -> tuple[str | None, bool]:
        if override is not None:
            return (override, self._is_override_proxy(override))
        if self._proxies:
            proxy = self._proxies[self._proxy_cursor % len(self._proxies)]
            self._proxy_cursor += 1
            return (proxy, False)
        return (self._launch_options.proxy, False)

    def _reserve_display(self) -> int:
        with self._resources_lock, _PROCESS_DISPLAYS_LOCK:
            display_num = find_free_display_num(
                self._display_base,
                reserved=self._reserved_displays | _PROCESS_RESERVED_DISPLAYS,
            )
            _PROCESS_RESERVED_DISPLAYS.add(display_num)
            self._reserved_displays.add(display_num)
        return display_num

    def _unreserve_display(self, display_num: int) -> None:
        with self._resources_lock, _PROCESS_DISPLAYS_LOCK:
            self._reserved_displays.discard(display_num)
            _PROCESS_RESERVED_DISPLAYS.discard(display_num)

    def _release_slot_resources(self, slot: _PoolSlot) -> None:
        """Return a slot's display number and remote worker. Idempotent; any thread."""
        with self._resources_lock:
            display_num, slot.display_num = slot.display_num, None
            remote_worker, slot.remote_worker = slot.remote_worker, None
            if remote_worker is not None:
                self._available_remotes.append(remote_worker)
        if display_num is not None:
            self._unreserve_display(display_num)

    def _destroy_in_background(self, slot: _PoolSlot) -> asyncio.Future[None]:
        """Start the slot's single teardown in a thread (or join the one already started).

        The worker itself releases the slot's resources, so nothing depends on a done-callback
        running; `close()` waits on the returned future.
        """
        if slot.teardown is not None:
            return slot.teardown

        def _teardown() -> None:
            try:
                slot.close()
            finally:
                self._release_slot_resources(slot)

        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(None, _teardown)
        except RuntimeError:
            # The loop's executor is shutting down (e.g. `asyncio.run` unwinding after Ctrl-C
            # while a cancelled launch was still finishing): close on a dedicated thread, which
            # the interpreter waits for, instead of leaking the slot.
            threading.Thread(target=_teardown, name="waybound-pool-teardown").start()
            future = loop.create_future()
            future.set_result(None)
            slot.teardown = future
            return future
        slot.teardown = future
        # Drop finished teardowns here and in a done-callback; correctness never depends on
        # that callback having run (see `_wait_for_teardowns`).
        self._background = {f for f in self._background if not f.done()}
        self._background.add(future)
        future.add_done_callback(self._background_done)
        return future

    def _background_done(self, future: asyncio.Future[None]) -> None:
        self._background.discard(future)

    async def _wait_for_teardowns(self) -> None:
        """Wait for every teardown still running, without ever spinning.

        Only futures that are not done are awaited. Looping while the set is merely non-empty
        would spin forever on Python 3.12+, where `gather()` of already-done futures completes
        synchronously, so the loop would never yield and their done-callbacks (which remove
        them) would never get to run. Shielded so cancelling `close()` cannot abandon them.
        """
        while True:
            self._background = {f for f in self._background if not f.done()}
            if not self._background:
                return
            await asyncio.shield(asyncio.gather(*self._background, return_exceptions=True))

    async def _destroy_slot(self, slot: _PoolSlot) -> None:
        # Shielded: cancelling the caller must not abandon a half-closed slot.
        await asyncio.shield(self._destroy_in_background(slot))

    def _track_background(self, future: asyncio.Future[None]) -> None:
        self._background = {f for f in self._background if not f.done()}
        self._background.add(future)
        future.add_done_callback(self._background_done)

    def _live_window_count(self) -> int:
        return len(self._idle) + len(self._active_slots) + sum(h.pending_opens for h in self._hosts)

    def _destroy_host_in_background(self, host: _BrowserHost) -> asyncio.Future[None]:
        """Start the host's single teardown in a thread (or join the one already started)."""
        if not host.ready_future.done():
            host.retired = True
            self._retiring_hosts.add(host)
            if host.launch_task is not None:
                return host.launch_task
            done: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            done.set_result(None)
            return done
        if host.teardown is not None:
            return host.teardown

        def _teardown() -> None:
            host.close()

        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(None, _teardown)
        except RuntimeError:
            threading.Thread(target=_teardown, name="waybound-host-teardown").start()
            future = loop.create_future()
            future.set_result(None)
            host.teardown = future
            self._retiring_hosts.discard(host)
            return future
        host.teardown = future
        self._track_background(future)

        def _on_teardown_done(_fut: asyncio.Future[None]) -> None:
            self._retiring_hosts.discard(host)

        future.add_done_callback(_on_teardown_done)
        return future

    async def _destroy_host(self, host: _BrowserHost) -> None:
        await asyncio.shield(self._destroy_host_in_background(host))

    def _close_page_in_background(self, page: Page) -> asyncio.Future[None]:
        """Close a single scoped window on a shared host in a worker thread."""
        loop = asyncio.get_running_loop()

        def _close_win() -> None:
            with contextlib.suppress(OSError, WayboundDaemonError, RuntimeError, ValueError):
                page.close_window()

        try:
            future = loop.run_in_executor(None, _close_win)
        except RuntimeError:
            threading.Thread(target=_close_win, name="waybound-window-close").start()
            future = loop.create_future()
            future.set_result(None)
            return future
        self._track_background(future)
        return future

    def _close_window_in_background(self, slot: _PoolSlot) -> asyncio.Future[None]:
        """Close a single window on a shared host in a worker thread."""
        return self._close_page_in_background(slot.page._inner)

    def _close_page_with_reservation(self, page: Page, host: _BrowserHost) -> None:
        """Close a single window while keeping capacity reserved until close completes."""
        host.closing_windows += 1
        future = self._close_page_in_background(page)

        def _on_close_done(_fut: asyncio.Future[None]) -> None:
            host.closing_windows -= 1
            if (
                (self._is_closed() or host.retired)
                and host.in_use_count == 0
                and host.ready_future.done()
            ):
                self._destroy_host_in_background(host)

        future.add_done_callback(_on_close_done)

    def _retire_host(self, host: _BrowserHost) -> None:
        """Mark `host` retired, drop its idle windows, and tear it down once no windows are live."""
        host.retired = True
        with contextlib.suppress(ValueError):
            self._hosts.remove(host)
        if host.idle_slots:
            stale = set(host.idle_slots)
            host.idle_slots.clear()
            self._idle = deque(s for s in self._idle if s not in stale)
        if host.teardown is None or not host.teardown.done():
            self._retiring_hosts.add(host)
        if host.in_use_count == 0 and host.ready_future.done():
            self._destroy_host_in_background(host)

    def _settle_unclaimed_host(self, host: _BrowserHost) -> bool:
        """Decide the fate of a launched host after all waiting acquires have departed.

        Returns `True` if `host` is retired and should be torn down.
        """
        if host.in_use_count != 0 or not host.ready_future.done():
            return False
        if self._is_closed() or host.retired:
            self._retire_host(host)
            return True
        if host.ready_future.cancelled() or host.ready_future.exception() is not None:
            return False
        if (
            not host.override_proxy
            and not host.initial_window_claimed
            and host.initial_window_id is not None
            and host.root_page is not None
            and self._live_window_count() < self._size
        ):
            host.initial_window_claimed = True
            slot = self._make_window_slot(host, host.initial_window_id)
            host.idle_slots.append(slot)
            self._idle.append(slot)
            return False
        if host.override_proxy or not host.initial_window_claimed or host.open_window_count == 0:
            self._retire_host(host)
            return True
        return False

    @staticmethod
    def _make_window_slot(host: _BrowserHost, window_id: int) -> _PoolSlot:
        if host.root_page is None:
            msg = "browser host has no active root page"
            raise RuntimeError(msg)
        scoped_page = Page(host.root_page._transport, window_id=window_id)
        return _PoolSlot(
            page=AsyncPage(scoped_page),
            proxy=host.proxy,
            override_proxy=host.override_proxy,
            host=host,
            window_id=window_id,
        )

    def _health_check_abandoned(
        self, slot: _PoolSlot, permit: _Permit
    ) -> Callable[[asyncio.Future[None]], None]:
        """Callback for a health check whose caller was cancelled: keep or destroy the slot.

        The cancelled acquire's permit is released only here, after the slot is back in the
        pool or on its way out, so the pool can never hold more than `size` live slots.
        """

        def _settle(future: asyncio.Future[None]) -> None:
            try:
                healthy = not future.cancelled() and future.exception() is None
                host = slot.host
                if host is not None:
                    host.active_slots.discard(slot)
                    live = self._live_window_count()
                    if healthy and not self._is_closed() and not host.retired and live < self._size:
                        host.idle_slots.append(slot)
                        self._idle.append(slot)
                        return
                    if not healthy:
                        self._failed += 1
                        self._recycled += 1
                        self._retire_host(host)
                    elif self._is_closed() or host.retired:
                        if host.in_use_count == 0 and host.ready_future.done():
                            self._destroy_host_in_background(host)
                    elif host.open_window_count == 0:
                        self._retire_host(host)
                    else:
                        self._close_page_with_reservation(slot.page._inner, host)
                    return

                live = self._live_window_count()
                if healthy and not self._is_closed() and live < self._size:
                    self._idle.append(slot)
                    return
                if not healthy:
                    self._failed += 1
                    self._recycled += 1
                self._destroy_in_background(slot)
            finally:
                self._give_back(permit)

        return _settle

    async def _pop_healthy_idle(self, proxy: str | None, permit: _Permit) -> _PoolSlot | None:
        if self._windows_per_browser > 1:
            return await self._pop_healthy_idle_stacked(proxy, permit)

        while self._idle:
            slot: _PoolSlot | None = None
            if proxy is not None:
                for idx, candidate in enumerate(self._idle):
                    if candidate.proxy == proxy:
                        del self._idle[idx]
                        slot = candidate
                        break
                if slot is None:
                    # Recycle an idle slot with a different proxy to make room for the override.
                    evicted = self._idle.popleft()
                    self._recycled += 1
                    await self._destroy_slot(evicted)
                    return None
            else:
                slot = self._idle.popleft()

            try:
                await _run_detached(slot.ping, self._health_check_abandoned(slot, permit))
            except asyncio.CancelledError:
                permit.transferred = True
                raise
            except (OSError, WayboundDaemonError, RuntimeError):
                self._failed += 1
                self._recycled += 1
                # Tear the dead slot down in the background (a hung daemon can take seconds
                # to stop) so this acquire can launch a replacement right away.
                self._destroy_in_background(slot)
                continue

            if self._is_closed():
                await self._destroy_slot(slot)
                return None
            return slot
        return None

    def _take_matching_idle_stacked(self, proxy: str | None) -> _PoolSlot | None:
        for idx, candidate in enumerate(self._idle):
            host = candidate.host
            if host is None or host.retired:
                continue
            matches = candidate.proxy == proxy if proxy is not None else not host.override_proxy
            if matches:
                del self._idle[idx]
                with contextlib.suppress(ValueError):
                    host.idle_slots.remove(candidate)
                return candidate
        return None

    async def _pop_healthy_idle_stacked(
        self, proxy: str | None, permit: _Permit
    ) -> _PoolSlot | None:
        while self._idle:
            slot = self._take_matching_idle_stacked(proxy)
            if slot is None:
                return None

            host = slot.host
            if host is None:
                continue
            host.active_slots.add(slot)
            try:
                await _run_detached(slot.ping, self._health_check_abandoned(slot, permit))
            except asyncio.CancelledError:
                permit.transferred = True
                raise
            except (OSError, WayboundDaemonError, RuntimeError):
                host.active_slots.discard(slot)
                self._failed += 1
                self._recycled += 1
                self._retire_host(host)
                continue

            if self._is_closed() or host.retired:
                host.active_slots.discard(slot)
                if host.in_use_count == 0 and host.ready_future.done():
                    await self._destroy_host(host)
                if self._is_closed():
                    return None
                continue
            return slot
        return None

    def _wait_for_initial_window(
        self, session: Session, root_page: Page, host: _BrowserHost
    ) -> int | None:
        windows = root_page.list_windows()
        if windows:
            return windows[0].id

        if self._launch_options.launch_chrome and self._launch_options.backend != "mock":
            timeout_s = max(0.0, self._launch_options.startup_timeout_s)
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                if self._is_closed() or host.retired:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not session.is_healthy(timeout_s=_HEALTH_CHECK_TIMEOUT_S):
                    msg = "browser host exited while waiting for initial window"
                    raise RuntimeError(msg)
                time.sleep(min(_INITIAL_WINDOW_POLL_INTERVAL_S, remaining))
                if self._is_closed() or host.retired:
                    return None
                windows = root_page.list_windows()
                if windows:
                    return windows[0].id

        if self._is_closed() or host.retired:
            return None
        opened = root_page.new_page()
        if opened.window_id is None:
            msg = "new_page() returned an unscoped Page"
            raise RuntimeError(msg)
        return opened.window_id

    def _start_local_host_sync(
        self, host: _BrowserHost
    ) -> tuple[Session, Page, _IsolatedDisplayStack | None, int | None]:
        use_wayland = self._display_backend == "wayland"
        use_isolated = self._isolated_displays and sys.platform.startswith("linux")
        display_stack: _IsolatedDisplayStack | None = None
        session: Session | None = None
        try:
            slot_opts = dataclasses.replace(self._launch_options, proxy=host.proxy)
            extra_env: dict[str, str] | None = None
            reap_pgid: int | None = None
            if use_wayland:
                if use_isolated:
                    display_stack = _IsolatedDisplayStack.start_wayland_dbus()
                    if display_stack is not None:
                        extra_env = display_stack.env
                        reap_pgid = display_stack.pgid
                slot_opts = dataclasses.replace(
                    slot_opts,
                    display=None,
                    headless_xvfb=False,
                    headless_wayland=True,
                )

            session = Session(slot_opts, extra_env=extra_env, _reap_pgid=reap_pgid)
            root_page = session.__enter__()
            initial_wid = self._wait_for_initial_window(session, root_page, host)
            return session, root_page, display_stack, initial_wid
        except BaseException:
            if session is not None:
                with contextlib.suppress(OSError, WayboundDaemonError, RuntimeError):
                    session.close()
            if display_stack is not None:
                with contextlib.suppress(OSError, RuntimeError):
                    display_stack.close()
            raise

    def _start_host_launch(self, host: _BrowserHost) -> None:
        """Launch `host`'s daemon/Chrome process on a background thread and track its task."""
        loop = asyncio.get_running_loop()

        async def _run_launch() -> None:
            try:
                session, root_page, display_stack, initial_wid = await asyncio.shield(
                    loop.run_in_executor(None, self._start_local_host_sync, host)
                )
            except BaseException as exc:
                host.retired = True
                with contextlib.suppress(ValueError):
                    self._hosts.remove(host)
                self._retiring_hosts.discard(host)
                self._failed += 1
                if not host.ready_future.done():
                    host.ready_future.set_exception(exc)
                return

            host.session = session
            host.root_page = root_page
            host.display_stack = display_stack
            host.initial_window_id = initial_wid
            self._launched += 1

            if self._is_closed() or host.retired or initial_wid is None:
                host.retired = True
                with contextlib.suppress(ValueError):
                    self._hosts.remove(host)
                self._retiring_hosts.add(host)
                if not host.ready_future.done():
                    host.ready_future.set_exception(RuntimeError("BrowserPool is closed"))
                await self._destroy_host(host)
                return

            if not host.ready_future.done():
                host.ready_future.set_result(None)

            # If every waiter was cancelled before launch finished, decide the host's fate.
            if host.in_use_count == 0 and self._settle_unclaimed_host(host):
                await self._destroy_host(host)

        task: asyncio.Task[None] = loop.create_task(_run_launch())
        host.launch_task = task
        self._track_background(task)

    def _find_host_with_capacity(self, proxy: str | None) -> _BrowserHost | None:
        for host in self._hosts:
            if host.retired or host.override_proxy:
                continue
            if host.capacity_used >= host.max_windows:
                continue
            if proxy is not None and host.proxy != proxy:
                continue
            return host
        return None

    async def _acquire_stacked_window(  # noqa: PLR0912, PLR0915
        self, proxy: str | None, permit: _Permit
    ) -> _PoolSlot:
        loop = asyncio.get_running_loop()
        evicted_once = False
        while True:
            if self._is_closed():
                msg = "BrowserPool is closed"
                raise RuntimeError(msg)

            host = self._find_host_with_capacity(proxy)
            if host is None:
                effective_proxy, is_override = self._next_proxy(proxy)
                if proxy is not None and not evicted_once:
                    # Evict one completely idle non-matching host so proxy overrides don't
                    # accumulate idle browser processes without bound.
                    evicted = False
                    for candidate in list(self._hosts):
                        if (
                            candidate.ready_future.done()
                            and candidate.in_use_count == 0
                            and candidate.proxy != effective_proxy
                        ):
                            self._recycled += 1
                            self._retire_host(candidate)
                            await self._destroy_host(candidate)
                            evicted = True
                            evicted_once = True
                            break
                    if self._is_closed():
                        msg = "BrowserPool is closed"
                        raise RuntimeError(msg)
                    if evicted:
                        continue

                host = _BrowserHost(
                    proxy=effective_proxy,
                    override_proxy=is_override,
                    max_windows=1 if is_override else self._windows_per_browser,
                    ready_future=loop.create_future(),
                )
                host.pending_opens = 1
                self._hosts.append(host)
                self._start_host_launch(host)
            else:
                host.pending_opens += 1

            # Wait for the host's browser/daemon process to finish launching.
            if not host.ready_future.done():
                try:
                    await asyncio.shield(host.ready_future)
                except BaseException:
                    host.pending_opens -= 1
                    if host.in_use_count == 0 and host.ready_future.done():
                        self._settle_unclaimed_host(host)
                    raise

            if self._is_closed():
                host.pending_opens -= 1
                if host.in_use_count == 0 and host.ready_future.done():
                    self._retire_host(host)
                    await self._destroy_host(host)
                msg = "BrowserPool is closed"
                raise RuntimeError(msg)

            if host.retired or host.root_page is None:
                host.pending_opens -= 1
                if host.in_use_count == 0 and host.ready_future.done():
                    self._retire_host(host)
                continue

            # First consumer of a newly launched host claims its initial window.
            if not host.initial_window_claimed and host.initial_window_id is not None:
                host.initial_window_claimed = True
                wid = host.initial_window_id
                host.pending_opens -= 1
                return self._make_window_slot(host, wid)

            # Subsequent windows on this host are opened via `new_page()`.
            root_page = host.root_page

            def _open_new_window(page: Page = root_page) -> Page:
                return page.new_page()

            def _abandoned_open(
                future: asyncio.Future[Page],
                bound_host: _BrowserHost = host,
                bound_permit: _Permit = permit,
            ) -> None:
                try:
                    bound_host.pending_opens -= 1
                    if future.cancelled() or future.exception() is not None:
                        if not future.cancelled():
                            self._failed += 1
                            self._retire_host(bound_host)
                        elif (
                            bound_host.retired
                            and bound_host.in_use_count == 0
                            and bound_host.ready_future.done()
                        ):
                            self._destroy_host_in_background(bound_host)
                        return

                    opened = future.result()
                    if self._is_closed() or bound_host.retired or bound_host.root_page is None:
                        if bound_host.in_use_count == 0 and bound_host.ready_future.done():
                            self._destroy_host_in_background(bound_host)
                        elif (
                            not self._is_closed()
                            and bound_host.root_page is not None
                            and opened.window_id is not None
                        ):
                            self._close_page_with_reservation(opened, bound_host)
                        return

                    if opened.window_id is None:
                        self._failed += 1
                        self._retire_host(bound_host)
                        return

                    live = self._live_window_count()
                    if not bound_host.override_proxy and live < self._size:
                        slot = self._make_window_slot(bound_host, opened.window_id)
                        bound_host.idle_slots.append(slot)
                        self._idle.append(slot)
                    elif bound_host.override_proxy or bound_host.open_window_count == 0:
                        self._retire_host(bound_host)
                    else:
                        self._close_page_with_reservation(opened, bound_host)
                finally:
                    self._give_back(bound_permit)

            try:
                opened_page = await _run_detached(_open_new_window, _abandoned_open)
            except asyncio.CancelledError:
                permit.transferred = True
                raise
            except BaseException:
                host.pending_opens -= 1
                self._failed += 1
                self._retire_host(host)
                raise

            host.pending_opens -= 1
            if self._is_closed() or host.is_retired() or not host.has_root_page():
                if host.in_use_count == 0 and host.ready_future.done():
                    await self._destroy_host(host)
                elif (
                    not self._is_closed()
                    and host.has_root_page()
                    and opened_page.window_id is not None
                ):
                    self._close_page_with_reservation(opened_page, host)
                if self._is_closed():
                    msg = "BrowserPool is closed"
                    raise RuntimeError(msg)
                continue

            if opened_page.window_id is None:
                self._failed += 1
                self._retire_host(host)
                msg = "new_page() returned an unscoped Page"
                raise RuntimeError(msg)

            return self._make_window_slot(host, opened_page.window_id)

    async def _launch_slot(self, *, proxy: str | None) -> _PoolSlot:
        if self._remote_endpoints:
            return await self._launch_remote_slot()
        return await self._launch_local_slot(proxy=proxy)

    async def _launch_remote_slot(self) -> _PoolSlot:
        if not self._available_remotes:
            msg = "no remote workers available"
            raise RuntimeError(msg)
        with self._resources_lock:
            raw_worker = self._available_remotes.popleft()
        tcp_addr = self._remote_endpoints[raw_worker]
        timeout_s = self._launch_options.startup_timeout_s

        def _connect() -> UnixSocketTransport:
            transport = UnixSocketTransport(tcp_addr=tcp_addr, timeout_s=timeout_s)
            try:
                transport.ping()
            except BaseException:
                transport.close()
                raise
            return transport

        def _return_worker() -> None:
            with self._resources_lock:
                self._available_remotes.append(raw_worker)

        def _abandoned(future: asyncio.Future[UnixSocketTransport]) -> None:
            if not future.cancelled() and future.exception() is None:
                with contextlib.suppress(OSError):
                    future.result().close()
            _return_worker()

        try:
            transport = await _run_detached(_connect, _abandoned)
        except asyncio.CancelledError:
            raise  # `_abandoned` returns the worker once the connection attempt finishes
        except BaseException:
            _return_worker()
            raise

        self._launched += 1
        return _PoolSlot(
            page=AsyncPage(Page(transport)),
            proxy=None,
            remote_transport=transport,
            remote_worker=raw_worker,
        )

    async def _launch_local_slot(self, *, proxy: str | None) -> _PoolSlot:  # noqa: PLR0915
        effective_proxy, is_override = self._next_proxy(proxy)
        self._slot_counter += 1
        use_wayland = self._display_backend == "wayland"
        use_isolated = self._isolated_displays and sys.platform.startswith("linux")

        display_num: int | None = None
        if use_isolated and not use_wayland:
            display_num = self._reserve_display()

        def _start_local() -> _PoolSlot:
            display_stack: _IsolatedDisplayStack | None = None
            session: Session | None = None
            try:
                slot_opts = dataclasses.replace(self._launch_options, proxy=effective_proxy)
                extra_env: dict[str, str] | None = None
                reap_pgid: int | None = None
                if use_wayland:
                    if use_isolated:
                        display_stack = _IsolatedDisplayStack.start_wayland_dbus()
                        if display_stack is not None:
                            extra_env = display_stack.env
                            reap_pgid = display_stack.pgid
                    slot_opts = dataclasses.replace(
                        slot_opts,
                        display=None,
                        headless_xvfb=False,
                        headless_wayland=True,
                    )
                elif display_num is not None:
                    display_stack = _IsolatedDisplayStack.start(display_num)
                    slot_opts = dataclasses.replace(
                        slot_opts,
                        display=display_stack.display,
                        headless_xvfb=False,
                    )
                    extra_env = display_stack.env
                    reap_pgid = display_stack.pgid

                session = Session(slot_opts, extra_env=extra_env, _reap_pgid=reap_pgid)
                page = session.__enter__()
                return _PoolSlot(
                    page=AsyncPage(page),
                    proxy=effective_proxy,
                    override_proxy=is_override,
                    session=session,
                    display_stack=display_stack,
                    display_num=display_num,
                )
            except BaseException:
                if session is not None:
                    with contextlib.suppress(OSError, WayboundDaemonError, RuntimeError):
                        session.close()
                if display_stack is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        display_stack.close()
                raise

        def _abandoned(future: asyncio.Future[_PoolSlot]) -> None:
            # The acquiring task was cancelled while the slot was starting: never leak it.
            if not future.cancelled() and future.exception() is None:
                self._destroy_in_background(future.result())
            elif display_num is not None:
                self._unreserve_display(display_num)

        try:
            slot = await _run_detached(_start_local, _abandoned)
        except asyncio.CancelledError:
            raise  # `_abandoned` cleans up once the launch thread finishes
        except BaseException:
            if display_num is not None:
                self._unreserve_display(display_num)
            raise

        self._launched += 1
        return slot

    @contextlib.asynccontextmanager
    async def acquire(  # noqa: PLR0912, PLR0915
        self,
        *,
        proxy: str | None = None,
        timeout_s: float | None = None,
    ) -> AsyncIterator[AsyncPage]:
        """Acquire a healthy [`AsyncPage`] from the pool, recycling it on error or wear-out."""
        if self._is_closed():
            msg = "BrowserPool is closed"
            raise RuntimeError(msg)

        if (
            not self._remote_endpoints
            and self._launch_options.profile_dir is not None
            and proxy is not None
        ):
            default_proxy = self._proxies[0] if self._proxies else self._launch_options.proxy
            if proxy != default_proxy:
                msg = (
                    "per-checkout proxy override cannot be used when launch_options.profile_dir "
                    "is set (multiple Chrome hosts cannot share one --user-data-dir)"
                )
                raise ValueError(msg)

        effective_timeout = self._acquire_timeout_s if timeout_s is None else timeout_s
        if effective_timeout <= 0:
            msg = f"timeout_s must be > 0, got {effective_timeout}"
            raise ValueError(msg)

        await self._acquire_permit(effective_timeout)
        permit = _Permit()
        slot: _PoolSlot | None = None
        try:
            if self._is_closed():
                msg = "BrowserPool is closed"
                raise RuntimeError(msg)

            slot = await self._pop_healthy_idle(proxy, permit)
            if self._is_closed():
                if slot is not None:
                    if slot.host is not None:
                        slot.host.active_slots.discard(slot)
                        self._retire_host(slot.host)
                        if slot.host.in_use_count == 0 and slot.host.ready_future.done():
                            await self._destroy_host(slot.host)
                    else:
                        await self._destroy_slot(slot)
                msg = "BrowserPool is closed"
                raise RuntimeError(msg)

            if slot is None:
                if self._windows_per_browser > 1:
                    slot = await self._acquire_stacked_window(proxy, permit)
                else:
                    try:
                        slot = await self._launch_slot(proxy=proxy)
                    except BaseException:
                        self._failed += 1
                        raise
                    if self._is_closed():
                        await self._destroy_slot(slot)
                        msg = "BrowserPool is closed"
                        raise RuntimeError(msg)

            self._active_slots.add(slot)
            if slot.host is not None:
                slot.host.active_slots.add(slot)
            slot.uses += 1
        except BaseException:
            if not permit.transferred:
                self._give_back(permit)
            raise

        had_error = False
        try:
            yield slot.page
        except BaseException:
            had_error = True
            raise
        finally:
            self._active_slots.discard(slot)
            try:
                await self._return_or_recycle(slot, had_error=had_error, permit=permit)
            finally:
                if not permit.transferred:
                    self._give_back(permit)

    async def _return_or_recycle(
        self, slot: _PoolSlot, *, had_error: bool, permit: _Permit
    ) -> None:
        if slot.host is not None:
            await self._return_or_recycle_stacked(slot, had_error=had_error, permit=permit)
            return

        if self._is_closed():
            await self._destroy_slot(slot)
            return

        reached_max_uses = (
            self._max_uses_per_slot is not None and slot.uses >= self._max_uses_per_slot
        )
        if had_error or reached_max_uses or slot.override_proxy:
            self._recycled += 1
            await self._destroy_slot(slot)
            return

        try:
            await _run_detached(slot.ping, self._health_check_abandoned(slot, permit))
        except asyncio.CancelledError:
            permit.transferred = True
            raise
        except (OSError, WayboundDaemonError, RuntimeError):
            self._failed += 1
            self._recycled += 1
            await self._destroy_slot(slot)
            return

        if self._is_closed():
            await self._destroy_slot(slot)
            return

        self._idle.append(slot)

    async def _recycle_stacked_window(  # noqa: PLR0915
        self, slot: _PoolSlot, host: _BrowserHost
    ) -> None:
        """Close only `slot`'s window, then verify `host` is still alive.

        If recycling `slot` leaves `host` with zero other windows, retire and destroy `host`
        directly instead of calling `close_window()` + `host.ping()`, since closing Chrome's
        last window causes Chrome to exit asynchronously.
        """
        self._recycled += 1
        if host.open_window_count == 0:
            self._retire_host(host)
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return

        host.closing_windows += 1
        close_fut = self._close_window_in_background(slot)
        released_closing = False

        def _release_closing(_fut: asyncio.Future[None] | None = None) -> None:
            nonlocal released_closing
            if released_closing:
                return
            released_closing = True
            host.closing_windows -= 1
            if (
                (self._is_closed() or host.retired)
                and host.in_use_count == 0
                and host.ready_future.done()
            ):
                self._destroy_host_in_background(host)

        try:
            await asyncio.shield(close_fut)
        except asyncio.CancelledError:
            close_fut.add_done_callback(_release_closing)
            raise
        except BaseException:
            _release_closing()
            raise

        if self._is_closed() or host.retired or host.open_window_count == 0:
            if host.open_window_count == 0 and not host.retired:
                self._retire_host(host)
            _release_closing()
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return

        loop = asyncio.get_running_loop()
        ping_fut = loop.run_in_executor(None, host.ping)
        self._track_background(ping_fut)

        def _ping_abandoned(fut: asyncio.Future[None]) -> None:
            try:
                if not fut.cancelled() and fut.exception() is not None:
                    self._failed += 1
                    self._retire_host(host)
            finally:
                _release_closing()

        try:
            await asyncio.shield(ping_fut)
        except asyncio.CancelledError:
            ping_fut.add_done_callback(_ping_abandoned)
            raise
        except (OSError, WayboundDaemonError, RuntimeError):
            self._failed += 1
            self._retire_host(host)
            _release_closing()
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return
        except BaseException:
            _release_closing()
            raise

        _release_closing()
        if (
            (self._is_closed() or host.retired)
            and host.in_use_count == 0
            and host.ready_future.done()
        ):
            await self._destroy_host(host)

    async def _return_or_recycle_stacked(  # noqa: PLR0912
        self, slot: _PoolSlot, *, had_error: bool, permit: _Permit
    ) -> None:
        host = slot.host
        if host is None:
            return

        if self._is_closed() or host.override_proxy:
            host.active_slots.discard(slot)
            if host.override_proxy and not self._is_closed():
                self._recycled += 1
            self._retire_host(host)
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return

        if host.retired:
            host.active_slots.discard(slot)
            self._recycled += 1
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return

        reached_max_uses = (
            self._max_uses_per_slot is not None and slot.uses >= self._max_uses_per_slot
        )
        if had_error or reached_max_uses:
            host.active_slots.discard(slot)
            await self._recycle_stacked_window(slot, host)
            return

        try:
            await _run_detached(slot.ping, self._health_check_abandoned(slot, permit))
        except asyncio.CancelledError:
            permit.transferred = True
            raise
        except (OSError, WayboundDaemonError, RuntimeError):
            host.active_slots.discard(slot)
            self._failed += 1
            self._recycled += 1
            self._retire_host(host)
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return
        except BaseException:
            host.active_slots.discard(slot)
            raise

        host.active_slots.discard(slot)
        if self._is_closed() or host.retired:
            if host.in_use_count == 0 and host.ready_future.done():
                await self._destroy_host(host)
            return

        host.idle_slots.append(slot)
        self._idle.append(slot)

    async def close(self) -> None:
        """Close all idle and active browser slots and terminate any isolated display stacks.

        Idempotent; a later call (for example after the first one was cancelled) waits for any
        teardown still running.
        """
        if self._closed:
            await self._wait_for_teardowns()
            return
        self._closed = True

        while self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_exception(RuntimeError("BrowserPool is closed"))

        slots_to_close: list[_PoolSlot] = [s for s in self._idle if s.host is None]
        self._idle.clear()
        slots_to_close.extend(s for s in self._active_slots if s.host is None)
        self._active_slots.clear()

        hosts_to_close = list(self._hosts)
        self._hosts.clear()
        hosts_to_close.extend(self._retiring_hosts)
        seen_hosts: set[_BrowserHost] = set()
        for host in hosts_to_close:
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            host.retired = True
            host.idle_slots.clear()
            host.active_slots.clear()
            if host.ready_future.done():
                if host.session is not None or host.display_stack is not None:
                    self._destroy_host_in_background(host)
                else:
                    self._retiring_hosts.discard(host)

        # Each slot has exactly one teardown: a borrower still holding a slot taken here joins
        # this teardown on exit instead of starting a second one.
        for slot in slots_to_close:
            self._destroy_in_background(slot)
        # Also waits for teardowns and in-flight host launches started by acquires.
        await self._wait_for_teardowns()
