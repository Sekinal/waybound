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
import contextlib
import dataclasses
import os
import select
import shutil
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self

from waybound.async_client import AsyncPage
from waybound.client import Page
from waybound.session import LaunchOptions, Session
from waybound.transport import UnixSocketTransport, WayboundDaemonError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence
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
_ATSPI_SETTLE_DELAY_S = 0.2
_CHILD_STOP_TIMEOUT_S = 2.0
_CHILD_KILL_TIMEOUT_S = 1.0
_ATSPI_LAUNCHER_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/libexec/at-spi-bus-launcher"),
    Path("/usr/lib/at-spi2-core/at-spi-bus-launcher"),
)
# X11 display lock files (`.X<N>-lock`) and sockets (`.X11-unix/X<N>`) are fixed by X11 spec.
_X11_LOCK_DIR = Path("/tmp")  # noqa: S108


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


def find_free_display_num(
    start: int = 100,
    *,
    reserved: AbstractSet[int] = frozenset(),
    lock_dir: Path = _X11_LOCK_DIR,
) -> int:
    """Find the lowest X11 display number `>= start` not in `reserved` or locked on disk."""
    if start < 0:
        msg = f"display_base must be non-negative, got {start}"
        raise ValueError(msg)
    for candidate in range(start, start + _MAX_DISPLAY_SCAN):
        if candidate in reserved:
            continue
        lock_file = lock_dir / f".X{candidate}-lock"
        x11_sock = lock_dir / ".X11-unix" / f"X{candidate}"
        if not lock_file.exists() and not x11_sock.exists():
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
            )
            processes.append(xvfb)
            cls._wait_for_xvfb(xvfb, display_num)

            dbus = subprocess.Popen(  # noqa: S603
                build_dbus_command(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
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
        sock_path = _X11_LOCK_DIR / ".X11-unix" / f"X{display_num}"
        deadline = time.monotonic() + _XVFB_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                msg = f"Xvfb :{display_num} exited prematurely (code {proc.returncode})"
                raise RuntimeError(msg)
            if sock_path.exists():
                return
            time.sleep(_XVFB_POLL_INTERVAL_S)
        if proc.poll() is not None:
            msg = f"Xvfb :{display_num} exited prematurely (code {proc.returncode})"
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
        for proc in reversed(processes):
            _terminate_process(proc)


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
    ) -> None:
        self.page = page
        self.proxy = proxy
        self.override_proxy = override_proxy
        self.uses = 0
        self.remote_worker = remote_worker
        self.display_num = display_num
        self._session = session
        self._remote_transport = remote_transport
        self._display_stack = display_stack

    def ping(self) -> str:
        """Verify that the slot's daemon connection is healthy."""
        if self._session is not None:
            return self._session.ping()
        if self._remote_transport is not None:
            return self._remote_transport.ping()
        msg = "slot has neither local session nor remote transport"
        raise RuntimeError(msg)

    def close(self) -> None:
        """Tear down this slot's daemon/connection and any isolated display stack."""
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
    ) -> None:
        if display_backend not in _DISPLAY_BACKENDS:
            msg = f"display_backend must be 'xvfb' or 'wayland', got {display_backend!r}"
            raise ValueError(msg)
        parsed_remotes = _parse_remote_workers(remote_workers)

        resolved_size = size if size is not None else (len(parsed_remotes) or 1)
        if resolved_size < 1:
            msg = f"size must be >= 1, got {resolved_size}"
            raise ValueError(msg)
        if parsed_remotes and resolved_size > len(parsed_remotes):
            msg = (
                f"size ({resolved_size}) cannot exceed number of remote_workers "
                f"({len(parsed_remotes)})"
            )
            raise ValueError(msg)

        resolved_options = launch_options if launch_options is not None else LaunchOptions()
        if not parsed_remotes and resolved_size > 1 and resolved_options.profile_dir is not None:
            msg = (
                "launch_options.profile_dir cannot be set when size > 1 "
                "(multiple Chrome slots cannot share one --user-data-dir)"
            )
            raise ValueError(msg)
        if max_uses_per_slot is not None and max_uses_per_slot < 1:
            msg = f"max_uses_per_slot must be >= 1, got {max_uses_per_slot}"
            raise ValueError(msg)
        if acquire_timeout_s <= 0:
            msg = f"acquire_timeout_s must be > 0, got {acquire_timeout_s}"
            raise ValueError(msg)
        if display_base < 0:
            msg = f"display_base must be >= 0, got {display_base}"
            raise ValueError(msg)

        self._size = resolved_size
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
        self._reserved_displays: set[int] = set()
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

    def _release_slot_resources(self, slot: _PoolSlot) -> None:
        if slot.display_num is not None:
            self._reserved_displays.discard(slot.display_num)
            slot.display_num = None
        if slot.remote_worker is not None:
            self._available_remotes.append(slot.remote_worker)
            slot.remote_worker = None

    async def _destroy_slot(self, slot: _PoolSlot) -> None:
        try:
            await asyncio.to_thread(slot.close)
        finally:
            self._release_slot_resources(slot)

    async def _pop_healthy_idle(self, proxy: str | None) -> _PoolSlot | None:
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
                await asyncio.to_thread(slot.ping)
            except (OSError, WayboundDaemonError, RuntimeError):
                self._failed += 1
                self._recycled += 1
                await self._destroy_slot(slot)
                continue

            if self._is_closed():
                await self._destroy_slot(slot)
                return None
            return slot
        return None

    async def _launch_slot(self, *, proxy: str | None) -> _PoolSlot:
        if self._remote_endpoints:
            return await self._launch_remote_slot()
        return await self._launch_local_slot(proxy=proxy)

    async def _launch_remote_slot(self) -> _PoolSlot:
        if not self._available_remotes:
            msg = "no remote workers available"
            raise RuntimeError(msg)
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

        try:
            transport = await asyncio.to_thread(_connect)
        except BaseException:
            self._available_remotes.append(raw_worker)
            raise

        self._launched += 1
        return _PoolSlot(
            page=AsyncPage(Page(transport)),
            proxy=None,
            remote_transport=transport,
            remote_worker=raw_worker,
        )

    async def _launch_local_slot(self, *, proxy: str | None) -> _PoolSlot:
        effective_proxy, is_override = self._next_proxy(proxy)
        self._slot_counter += 1
        use_wayland = self._display_backend == "wayland"
        use_isolated = self._isolated_displays and sys.platform.startswith("linux")

        display_num: int | None = None
        if use_isolated and not use_wayland:
            display_num = find_free_display_num(
                self._display_base,
                reserved=self._reserved_displays,
            )
            self._reserved_displays.add(display_num)

        def _start_local() -> _PoolSlot:
            display_stack: _IsolatedDisplayStack | None = None
            session: Session | None = None
            try:
                slot_opts = dataclasses.replace(self._launch_options, proxy=effective_proxy)
                extra_env: dict[str, str] | None = None
                if use_wayland:
                    if use_isolated:
                        display_stack = _IsolatedDisplayStack.start_wayland_dbus()
                        if display_stack is not None:
                            extra_env = display_stack.env
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

                session = Session(slot_opts, extra_env=extra_env)
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

        try:
            slot = await asyncio.to_thread(_start_local)
        except BaseException:
            if display_num is not None:
                self._reserved_displays.discard(display_num)
            raise

        self._launched += 1
        return slot

    @contextlib.asynccontextmanager
    async def acquire(
        self,
        *,
        proxy: str | None = None,
        timeout_s: float | None = None,
    ) -> AsyncIterator[AsyncPage]:
        """Acquire a healthy [`AsyncPage`] from the pool, recycling it on error or wear-out."""
        if self._is_closed():
            msg = "BrowserPool is closed"
            raise RuntimeError(msg)

        effective_timeout = self._acquire_timeout_s if timeout_s is None else timeout_s
        if effective_timeout <= 0:
            msg = f"timeout_s must be > 0, got {effective_timeout}"
            raise ValueError(msg)

        await self._acquire_permit(effective_timeout)
        slot: _PoolSlot | None = None
        try:
            if self._is_closed():
                msg = "BrowserPool is closed"
                raise RuntimeError(msg)

            slot = await self._pop_healthy_idle(proxy)
            if self._is_closed():
                if slot is not None:
                    await self._destroy_slot(slot)
                msg = "BrowserPool is closed"
                raise RuntimeError(msg)

            if slot is None:
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
            slot.uses += 1
        except BaseException:
            self._release_permit()
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
                await self._return_or_recycle(slot, had_error=had_error)
            finally:
                self._release_permit()

    async def _return_or_recycle(self, slot: _PoolSlot, *, had_error: bool) -> None:
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
            await asyncio.to_thread(slot.ping)
        except (OSError, WayboundDaemonError, RuntimeError):
            self._failed += 1
            self._recycled += 1
            await self._destroy_slot(slot)
            return

        if self._is_closed():
            await self._destroy_slot(slot)
            return

        self._idle.append(slot)

    async def close(self) -> None:
        """Close all idle and active browser slots and terminate any isolated display stacks."""
        if self._closed:
            return
        self._closed = True

        while self._waiters:
            waiter = self._waiters.popleft()
            if not waiter.done():
                waiter.set_exception(RuntimeError("BrowserPool is closed"))

        slots_to_close: list[_PoolSlot] = list(self._idle)
        self._idle.clear()
        slots_to_close.extend(self._active_slots)
        self._active_slots.clear()

        if slots_to_close:
            await asyncio.gather(
                *(self._destroy_slot(slot) for slot in slots_to_close),
                return_exceptions=True,
            )
