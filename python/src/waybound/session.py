"""High-level ergonomic session lifecycle manager (`waybound.launch`)."""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from waybound.binary import find_cached_daemon
from waybound.client import Page
from waybound.transport import UnixSocketTransport, WayboundDaemonError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import TracebackType

BackendName = Literal["mock", "macos", "linux", "windows", "android"]
BLOCK_PRESETS: frozenset[str] = frozenset({"analytics", "ads", "media"})
_MIN_WORKSPACE_PARENTS = 4


def _validate_block_presets(presets: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw in presets:
        name = raw.strip().lower()
        if name not in BLOCK_PRESETS:
            allowed = ", ".join(sorted(BLOCK_PRESETS))
            msg = f"unknown block preset {raw!r} (expected one of: {allowed})"
            raise ValueError(msg)
        normalized.append(name)
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class LaunchOptions:
    """Configuration options for launching a `waybound` automation session."""

    backend: BackendName = "mock"
    pid: int | None = None
    serial: str | None = None
    display: str | None = None
    headless_xvfb: bool = False
    headless_wayland: bool = False
    launch_chrome: bool = False
    launch_waydroid: bool = False
    instance_id: str | None = None
    adb_port: int | None = None
    url: str | None = None
    profile_dir: Path | str | None = None
    ssl_keylog: Path | str | None = None
    proxy: str | None = None
    block_hosts: tuple[str, ...] = ()
    block_presets: Sequence[str] = ()
    timezone: str | None = None
    locale: str | None = None
    focus: bool = False
    no_motion: bool = False
    use_tcp: bool = False
    daemon_binary: Path | str | None = None
    startup_timeout_s: float = 5.0

    def __post_init__(self) -> None:
        if self.headless_xvfb and self.headless_wayland:
            msg = "headless_xvfb and headless_wayland are mutually exclusive"
            raise ValueError(msg)
        if self.block_presets:
            _validate_block_presets(self.block_presets)


def _daemon_bin_name() -> str:
    return "waybound-daemon.exe" if sys.platform == "win32" else "waybound-daemon"


def _resolve_daemon_binary(explicit: Path | str | None) -> Path:
    if explicit is not None:
        return Path(explicit)

    env_bin = os.environ.get("WAYBOUND_DAEMON_BIN")
    if env_bin:
        return Path(env_bin)

    bin_name = _daemon_bin_name()
    on_path = shutil.which(bin_name)
    if on_path is not None:
        return Path(on_path)

    parents = Path(__file__).resolve().parents
    if len(parents) >= _MIN_WORKSPACE_PARENTS:
        repo_root = parents[3]
        for profile in ("release", "debug"):
            candidate = repo_root / "target" / profile / bin_name
            if candidate.exists():
                return candidate

    cached = find_cached_daemon()
    if cached is not None:
        return cached

    msg = (
        f"{bin_name} binary not found on PATH, in target/{{release,debug}}, or in ~/.cache/waybound"
    )
    raise FileNotFoundError(msg)


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        addr: tuple[str, int] = probe.getsockname()
        return addr[1]


def _connect_with_retry(
    *,
    socket_path: Path | None,
    tcp_addr: tuple[str, int] | None,
    stderr_log: Path,
    proc: subprocess.Popen[bytes],
    timeout_s: float,
) -> UnixSocketTransport:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr_text = ""
            if stderr_log.exists():
                stderr_text = stderr_log.read_text(encoding="utf-8", errors="replace").strip()
            msg = f"waybound-daemon exited early (code {proc.returncode}): {stderr_text}"
            raise RuntimeError(msg)
        if tcp_addr is not None:
            try:
                return UnixSocketTransport(tcp_addr=tcp_addr)
            except (ConnectionRefusedError, OSError):
                pass
        elif socket_path is not None and socket_path.exists():
            try:
                return UnixSocketTransport(socket_path)
            except (FileNotFoundError, ConnectionRefusedError, PermissionError):
                pass
        time.sleep(0.02)
    target = f"{tcp_addr[0]}:{tcp_addr[1]}" if tcp_addr is not None else str(socket_path)
    msg = f"timed out waiting for waybound-daemon at {target}"
    raise TimeoutError(msg)


_SDK_ONLY_ENV = ("WAYBOUND_EXIT_WITH_PARENT", "WAYBOUND_REAP_PGID")


def _daemon_env(
    proxy: str | None,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Builds the daemon's environment.

    The proxy URL may embed credentials, so it travels in the environment (readable only by
    the same user) rather than in argv (world-readable via `ps`). The daemon strips it from
    the environment of every process it spawns in turn.
    """
    env = os.environ.copy()
    # Lifetime controls can make the daemon signal other processes, so they are only ever set
    # by `Session` itself, never inherited (a stale value in the user's environment would
    # otherwise make a plain session kill an unrelated process group).
    for name in _SDK_ONLY_ENV:
        env.pop(name, None)
    if extra_env is not None:
        env.update(extra_env)
    if proxy is not None:
        env["WAYBOUND_PROXY"] = proxy
    return env


# Strong references: an unreferenced session (`page = launch().__enter__()`) must still be
# closed at interpreter exit. Entries are removed by `Session.close`.
_LIVE_SESSIONS: set[Session] = set()
_LIVE_SESSIONS_LOCK = threading.Lock()

# The daemon may need several seconds to stop Chrome gracefully (the `feat/profile-export`
# branch waits up to 5 s for Chrome before SIGKILL), so wait well past that before escalating.
_GRACEFUL_SHUTDOWN_S = 8.0
_TERMINATE_GRACE_S = 8.0
_KILL_GRACE_S = 1.0
_EXIT_POLL_S = 0.02


def _close_live_sessions() -> None:
    """At interpreter exit, shut down daemons whose sessions were never closed.

    The daemon runs in its own process group (see `Session`), so a Ctrl-C in the terminal no
    longer reaches it directly; this keeps an unhandled `KeyboardInterrupt` from leaving it
    (and its browser) running. Deaths that skip `atexit` (SIGTERM, SIGHUP, SIGKILL) are covered
    by the daemon itself, which exits when its parent process goes away.
    """
    with _LIVE_SESSIONS_LOCK:
        sessions = list(_LIVE_SESSIONS)
    for session in sessions:
        with contextlib.suppress(Exception):
            session.close()


def _forget_sessions_after_fork() -> None:
    """In a forked child, the parent's sessions are not ours to close."""
    global _LIVE_SESSIONS_LOCK  # noqa: PLW0603 - a lock held at fork time is unusable
    _LIVE_SESSIONS_LOCK = threading.Lock()
    _LIVE_SESSIONS.clear()


atexit.register(_close_live_sessions)
if sys.platform != "win32":
    os.register_at_fork(after_in_child=_forget_sessions_after_fork)


def _has_exited(proc: subprocess.Popen[bytes]) -> bool:
    """Return whether the daemon has exited, *without* reaping it where possible.

    An unreaped (zombie) daemon keeps its pid, which is also its process-group id, so the
    group can be killed afterwards without risking a reused id. Where `os.waitid` is missing
    (macOS) this falls back to `poll()`, which reaps; the group is then killed immediately
    afterwards, leaving only a very narrow window for the id to be reused.
    """
    if proc.returncode is not None:
        return True
    if sys.platform == "win32" or not hasattr(os, "waitid"):
        return proc.poll() is not None
    try:
        result = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:  # already reaped elsewhere
        return proc.poll() is not None
    return result is not None


def _wait_exited(proc: subprocess.Popen[bytes], timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while not _has_exited(proc):
        if time.monotonic() >= deadline:
            return False
        time.sleep(_EXIT_POLL_S)
    return True


# Temp directories a daemon creates under the system temp dir, named after its pid: its
# Wayland compositor runtime dir and its temporary Chrome profile. A daemon that is killed
# cannot remove them.
_DAEMON_TEMP_PREFIXES = ("waybound-wl-daemon-", "waybound-profile-")
_LOG = logging.getLogger("waybound")


def _daemon_temp_base(env: Mapping[str, str]) -> Path | None:
    """The directory the daemon's `std::env::temp_dir()` resolves to, given its environment.

    On Unix Rust reads only `TMPDIR` (no `TEMP`/`TMP`, no writability fallback), defaulting to
    `/tmp`; an empty value would be relative to the daemon's working directory, so it is not
    guessed. Windows is skipped: the daemon's temp dirs there are not cleaned up by the SDK.
    """
    if sys.platform == "win32":
        return None
    value = env.get("TMPDIR")
    if value is None:
        return Path("/tmp")  # noqa: S108 - Rust's documented Unix default
    return Path(value) if value else None


def _snapshot_daemon_temp_dirs(base: Path | None, pid: int) -> set[Path]:
    """List the temp dirs named after daemon `pid`.

    Call only while that daemon has not been reaped (alive or a zombie), so `pid` cannot belong
    to another process. Removal later touches only these exact paths, never a fresh glob, so a
    reused pid can never cause another session's directories to be deleted.
    """
    if base is None:
        return set()
    found: set[Path] = set()
    for prefix in _DAEMON_TEMP_PREFIXES:
        found.update(base.glob(f"{prefix}{pid}-*"))
    return found


def _kill_process_group(pgid: int | None) -> None:
    """SIGKILL what is left of a daemon's process group (its browser, Xvfb, helpers)."""
    if pgid is None or sys.platform == "win32":
        return
    if pgid == os.getpgrp():  # never our own group
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


class Session:
    """Context manager that starts `waybound-daemon`, connects, and cleans up on exit.

    On POSIX the daemon is started in a new session (its own process group) and told to exit
    when this process does (`WAYBOUND_EXIT_WITH_PARENT=<our pid>`): it runs its normal graceful
    shutdown as soon as its parent is gone, however the parent died (SIGINT, SIGTERM, SIGHUP
    or SIGKILL). `close` (also run by the ``with`` block and, for sessions still open, by an
    `atexit` hook) shuts the daemon down gracefully and then, only as a backstop once the
    daemon has exited, kills anything left in its process group (a browser or `Xvfb` it could
    not clean up because it was itself killed). On Windows the daemon is not detached and does
    not watch its parent.

    After `os.fork`, a session belongs to the process that created it: closing it (or the
    child's `atexit` hook) in the child only drops the child's references and never shuts the
    parent's daemon down.
    """

    def __init__(
        self,
        options: LaunchOptions | None = None,
        *,
        extra_env: Mapping[str, str] | None = None,
        _reap_pgid: int | None = None,
    ) -> None:
        opts = options if options is not None else LaunchOptions()
        if extra_env is not None and (reserved := set(extra_env) & set(_SDK_ONLY_ENV)):
            # Rejected rather than silently dropped: these make the daemon exit or signal a
            # process group, so a caller setting them is a bug worth surfacing.
            msg = f"extra_env must not set {sorted(reserved)}; the SDK manages them"
            raise ValueError(msg)
        if _reap_pgid is not None and (
            _reap_pgid <= 1 or _reap_pgid in (os.getpgrp(), os.getpid())
        ):
            msg = f"refusing to reap process group {_reap_pgid}: it is not a helper group"
            raise ValueError(msg)
        # Private (BrowserPool only): a process group of helpers the daemon stops if this
        # process dies without closing the session.
        self._reap_pgid = _reap_pgid
        self._options = opts
        self._extra_env: dict[str, str] | None = dict(extra_env) if extra_env is not None else None
        self._daemon_binary = _resolve_daemon_binary(opts.daemon_binary)
        self._tmp_dir: Path | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._pgid: int | None = None
        self._transport: UnixSocketTransport | None = None
        self._owner_pid = os.getpid()
        self._daemon_temp_base: Path | None = None
        # Temp dirs named after our daemon's pid, recorded while it is unreaped (see close).
        self._daemon_temp_dirs: set[Path] = set()
        # Single-flight `close`: a pool and a borrower (or two threads) closing at once must
        # not run two shutdown sequences against one daemon.
        self._close_lock = threading.Lock()

    def _build_daemon_cmd(
        self,
        *,
        socket_path: Path | None,
        tcp_addr: tuple[str, int] | None,
    ) -> list[str]:
        opts = self._options
        cmd = [str(self._daemon_binary)]
        if tcp_addr is not None:
            cmd.extend(["--tcp", f"{tcp_addr[0]}:{tcp_addr[1]}"])
        elif socket_path is not None:
            cmd.extend(["--socket", str(socket_path)])
        cmd.extend(["--backend", opts.backend])
        pairs: tuple[tuple[str, str | None], ...] = (
            ("--pid", str(opts.pid) if opts.pid is not None else None),
            ("--serial", opts.serial),
            ("--display", opts.display),
            ("--instance-id", opts.instance_id),
            ("--adb-port", str(opts.adb_port) if opts.adb_port is not None else None),
            ("--url", opts.url),
            (
                "--profile-dir",
                str(Path(opts.profile_dir)) if opts.profile_dir is not None else None,
            ),
            ("--ssl-keylog", str(Path(opts.ssl_keylog)) if opts.ssl_keylog is not None else None),
            ("--timezone", opts.timezone),
            ("--locale", opts.locale),
        )
        for flag, val in pairs:
            if val is not None:
                cmd.extend([flag, val])
        if opts.block_hosts:
            cmd.extend(["--block-hosts", ",".join(opts.block_hosts)])
        for preset in _validate_block_presets(opts.block_presets):
            cmd.extend(["--block-preset", preset])
        if opts.headless_xvfb:
            cmd.append("--headless-xvfb")
        if opts.headless_wayland:
            cmd.append("--headless-wayland")
        if opts.launch_chrome:
            cmd.append("--launch-chrome")
        if opts.launch_waydroid:
            cmd.append("--launch-waydroid")
        if opts.focus:
            cmd.append("--focus")
        if opts.no_motion:
            cmd.append("--no-motion")
        return cmd

    def __enter__(self) -> Page:
        if self._proc is not None or self._transport is not None:
            msg = "Session is already active and cannot be re-entered"
            raise RuntimeError(msg)

        opts = self._options
        use_tcp = opts.use_tcp or sys.platform == "win32" or not hasattr(socket, "AF_UNIX")
        self._owner_pid = os.getpid()

        if use_tcp:
            tmp_dir = Path(tempfile.mkdtemp(prefix="wb-"))
            socket_path: Path | None = None
            tcp_addr: tuple[str, int] | None = ("127.0.0.1", _reserve_loopback_port())
        else:
            # Keep socket path short to stay within macOS's 104-byte AF_UNIX sun_path limit.
            tmp_dir = Path(tempfile.mkdtemp(prefix="wb-", dir="/tmp"))
            socket_path = tmp_dir / "w.sock"
            tcp_addr = None

        # A plain directory (not `TemporaryDirectory`, whose exit-time finalizer would also
        # run in forked children and delete the parent's socket); `close` removes it.
        self._tmp_dir = tmp_dir
        stderr_log = tmp_dir / "daemon.stderr.log"
        cmd = self._build_daemon_cmd(socket_path=socket_path, tcp_addr=tcp_addr)

        child_env = _daemon_env(opts.proxy, self._extra_env)
        detach = sys.platform != "win32"
        if detach:
            # The pid to watch (alive or not, even through a wrapper script), so a parent that
            # dies before the daemon's watchdog starts is still noticed. Older daemons ignore
            # unknown variables.
            child_env["WAYBOUND_EXIT_WITH_PARENT"] = str(os.getpid())
            if self._reap_pgid is not None:
                child_env["WAYBOUND_REAP_PGID"] = str(self._reap_pgid)

        try:
            with _LIVE_SESSIONS_LOCK:
                _LIVE_SESSIONS.add(self)
            with stderr_log.open("wb") as stderr_file:
                proc = subprocess.Popen(  # noqa: S603
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_file,
                    env=child_env,
                    start_new_session=detach,
                )
            self._proc = proc
            self._daemon_temp_base = _daemon_temp_base(child_env)
            if detach:
                self._pgid = proc.pid
            transport = _connect_with_retry(
                socket_path=socket_path,
                tcp_addr=tcp_addr,
                stderr_log=stderr_log,
                proc=proc,
                timeout_s=opts.startup_timeout_s,
            )
            self._transport = transport
            # The daemon creates its temp dirs before it accepts connections, and it is alive
            # here, so every match is ours.
            self._daemon_temp_dirs = _snapshot_daemon_temp_dirs(self._daemon_temp_base, proc.pid)
            return Page(transport)
        except BaseException:
            self.close()
            raise

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def ping(self, *, timeout_s: float | None = None) -> str:
        """Send a health-check ping to the active daemon and return its version."""
        if self._transport is None:
            msg = "Session is not active"
            raise RuntimeError(msg)
        return self._transport.ping(timeout_s=timeout_s)

    @property
    def daemon_pid(self) -> int | None:
        """Return the OS pid of the running `waybound-daemon`, or `None` when not started."""
        proc = self._proc
        return proc.pid if proc is not None else None

    def _daemon_running(self) -> bool:
        proc = self._proc
        return proc is not None and not _has_exited(proc)

    def _terminate_daemon(self) -> None:
        """Send SIGTERM (graceful on the daemon side) without waiting; used to unblock I/O."""
        proc = self._proc
        if proc is not None and self._owner_pid == os.getpid() and not _has_exited(proc):
            with contextlib.suppress(OSError):
                proc.terminate()

    def is_healthy(self, *, timeout_s: float = 2.0) -> bool:
        """Return `True` if the daemon is running and answers a `ping` within `timeout_s`.

        A session whose daemon exited, or whose connection was closed after an I/O error or
        a request timeout (the SDK drops a connection it can no longer trust), is unhealthy
        and stays so: it must be closed and relaunched.
        """
        transport = self._transport
        if not self._daemon_running() or transport is None or transport.closed:
            return False
        try:
            browser_alive = transport.browser_alive(timeout_s=timeout_s)
        except (OSError, WayboundDaemonError):
            return False
        # `False` means the daemon launched a browser that has since exited (crashed, or handed
        # off to another instance that holds the profile lock): the page is dead.
        return browser_alive is not False

    def _abandon_inherited(self) -> None:
        """In a forked child: drop references without touching the parent's daemon.

        Closing the inherited socket descriptor does not end the parent's connection (the
        parent still holds it), and no `shutdown` request or signal is sent.
        """
        transport, self._transport = self._transport, None
        if transport is not None:
            with contextlib.suppress(OSError):
                transport.close()
        self._proc = None
        self._pgid = None
        self._tmp_dir = None
        self._daemon_temp_dirs = set()

    def close(self) -> None:
        """Gracefully shut down the daemon (unwinding browser & socket guards) and clean up.

        Idempotent and thread-safe: concurrent callers run one shutdown; the others wait for it
        and return. Escalation: `shutdown` request, then SIGTERM after 8 s, then SIGKILL after
        another 8 s. Once the daemon has exited (and before it is reaped, so its process-group
        id cannot have been reused), anything left in its process group is killed as a
        backstop. In a forked child this only drops the child's references.

        This normally takes well under a second, but can take up to about 46 s: if a page call
        abandoned in another thread still holds the connection, the `shutdown` request waits
        for it (up to the transport's 30 s timeout) before the 8 s + 8 s escalation.
        """
        if self._owner_pid != os.getpid():
            # Checked before taking the lock: a lock held by another thread at fork time
            # would never be released in the child.
            self._abandon_inherited()
            return
        with self._close_lock:
            self._close_locked()

    def _remove_recorded_temp_dirs(self, proc: subprocess.Popen[bytes]) -> None:
        """Remove the recorded temp dirs of a daemon that has exited; never of a live one."""
        dirs, self._daemon_temp_dirs = self._daemon_temp_dirs, set()
        if not dirs:
            return
        if not _has_exited(proc):
            # Never delete a profile from under a process that may still run.
            _LOG.warning(
                "waybound-daemon %d did not exit after SIGKILL; leaving its temp dirs in place: %s",
                proc.pid,
                ", ".join(sorted(map(str, dirs))),
            )
            return
        for path in dirs:
            shutil.rmtree(path, ignore_errors=True)

    def _close_locked(self) -> None:
        proc = self._proc
        if proc is not None and proc.returncode is None:
            # Not reaped yet (on macOS `_has_exited` reaps via `poll()`), so the pid is still
            # ours: complete the snapshot of its temp dirs before anything can reap it.
            self._daemon_temp_dirs |= _snapshot_daemon_temp_dirs(self._daemon_temp_base, proc.pid)
        shutdown_sent = False
        try:
            if self._transport is not None:
                with contextlib.suppress(OSError, WayboundDaemonError):
                    self._transport.shutdown()
                    shutdown_sent = True
                with contextlib.suppress(OSError):
                    self._transport.close()
                self._transport = None
            if proc is not None and not _has_exited(proc):
                if shutdown_sent:
                    _wait_exited(proc, _GRACEFUL_SHUTDOWN_S)
                if not _has_exited(proc):
                    with contextlib.suppress(OSError):
                        proc.terminate()
                    _wait_exited(proc, _TERMINATE_GRACE_S)
        finally:
            try:
                if proc is not None:
                    if not _has_exited(proc):  # graceful path timed out or was interrupted
                        with contextlib.suppress(OSError):
                            proc.kill()
                        _wait_exited(proc, _KILL_GRACE_S)
                    # Backstop only: the daemon has exited but is not reaped yet, so its pid
                    # (the group id, and the suffix of its temp dir names) cannot be reused.
                    _kill_process_group(self._pgid)
                    self._remove_recorded_temp_dirs(proc)
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=_KILL_GRACE_S)
                    self._proc = None
                self._pgid = None
            finally:
                if self._tmp_dir is not None:
                    shutil.rmtree(self._tmp_dir, ignore_errors=True)
                    self._tmp_dir = None
                with _LIVE_SESSIONS_LOCK:
                    _LIVE_SESSIONS.discard(self)


def launch(
    options: LaunchOptions | None = None,
    *,
    backend: BackendName = "mock",
    launch_chrome: bool = False,
    headless_wayland: bool = False,
    url: str | None = None,
) -> Session:
    """Create a `Session` context manager for ergonomic out-of-band browser automation."""
    resolved = (
        options
        if options is not None
        else LaunchOptions(
            backend=backend,
            launch_chrome=launch_chrome,
            headless_wayland=headless_wayland,
            url=url,
        )
    )
    return Session(resolved)
