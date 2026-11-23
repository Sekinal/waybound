"""High-level ergonomic session lifecycle manager (`waybound.launch`)."""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
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
    if extra_env is not None:
        env.update(extra_env)
    if proxy is not None:
        env["WAYBOUND_PROXY"] = proxy
    return env


_DESKTOP_BACKENDS = ("macos", "linux", "windows")


def _reject_unobservable_capture(opts: LaunchOptions) -> None:
    """Refuse `ssl_keylog` + `proxy` when attaching to a running desktop browser.

    When attaching (`pid=...` without `launch_chrome`), the daemon cannot route the browser
    through `proxy`, and its `tshark` fallback only sees direct HTTPS on port 443, so captures
    would silently stay empty. The daemon rejects the same combination given as `--proxy`; the
    SDK passes the proxy in `WAYBOUND_PROXY` (to keep credentials out of argv), which the
    daemon treats as inherited configuration, so the check is made here.
    """
    attaching = opts.backend in _DESKTOP_BACKENDS and not opts.launch_chrome
    if attaching and opts.proxy is not None and opts.ssl_keylog is not None:
        msg = (
            "ssl_keylog with proxy requires launch_chrome=True: when attaching to a running "
            "browser the proxy is not applied and the tshark fallback cannot see proxied traffic"
        )
        raise ValueError(msg)


class Session:
    """Context manager that starts `waybound-daemon`, connects, and cleans up on exit."""

    def __init__(
        self,
        options: LaunchOptions | None = None,
        *,
        extra_env: Mapping[str, str] | None = None,
    ) -> None:
        opts = options if options is not None else LaunchOptions()
        _reject_unobservable_capture(opts)
        self._options = opts
        self._extra_env: dict[str, str] | None = dict(extra_env) if extra_env is not None else None
        self._daemon_binary = _resolve_daemon_binary(opts.daemon_binary)
        self._tmp_dir: tempfile.TemporaryDirectory[str] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._transport: UnixSocketTransport | None = None

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

        if use_tcp:
            tmp_dir = tempfile.TemporaryDirectory(prefix="wb-")
            socket_path: Path | None = None
            tcp_addr: tuple[str, int] | None = ("127.0.0.1", _reserve_loopback_port())
        else:
            # Keep socket path short to stay within macOS's 104-byte AF_UNIX sun_path limit.
            tmp_dir = tempfile.TemporaryDirectory(prefix="wb-", dir="/tmp")
            socket_path = Path(tmp_dir.name) / "w.sock"
            tcp_addr = None

        self._tmp_dir = tmp_dir
        stderr_log = Path(tmp_dir.name) / "daemon.stderr.log"
        cmd = self._build_daemon_cmd(socket_path=socket_path, tcp_addr=tcp_addr)

        child_env = _daemon_env(opts.proxy, self._extra_env)

        try:
            with stderr_log.open("wb") as stderr_file:
                proc = subprocess.Popen(  # noqa: S603
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_file,
                    env=child_env,
                )
            self._proc = proc
            transport = _connect_with_retry(
                socket_path=socket_path,
                tcp_addr=tcp_addr,
                stderr_log=stderr_log,
                proc=proc,
                timeout_s=opts.startup_timeout_s,
            )
            self._transport = transport
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

    def ping(self) -> str:
        """Send a health-check ping to the active daemon and return its version."""
        if self._transport is None:
            msg = "Session is not active"
            raise RuntimeError(msg)
        return self._transport.ping()

    def close(self) -> None:
        """Gracefully shut down the daemon (unwinding browser & socket guards) and clean up."""
        shutdown_sent = False
        try:
            if self._transport is not None:
                with contextlib.suppress(OSError, WayboundDaemonError):
                    self._transport.shutdown()
                    shutdown_sent = True
                with contextlib.suppress(OSError):
                    self._transport.close()
                self._transport = None
        finally:
            try:
                if self._proc is not None:
                    proc = self._proc
                    self._proc = None
                    if proc.poll() is None:
                        if shutdown_sent:
                            with contextlib.suppress(subprocess.TimeoutExpired):
                                proc.wait(timeout=2.0)
                        if proc.poll() is None:
                            proc.terminate()
                            try:
                                proc.wait(timeout=2.0)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                with contextlib.suppress(subprocess.TimeoutExpired):
                                    proc.wait(timeout=1.0)
            finally:
                if self._tmp_dir is not None:
                    with contextlib.suppress(OSError):
                        self._tmp_dir.cleanup()
                    self._tmp_dir = None


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
