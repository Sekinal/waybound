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
    from types import TracebackType

BackendName = Literal["mock", "macos", "linux", "windows", "android"]
_MIN_WORKSPACE_PARENTS = 4


@dataclass(frozen=True, slots=True)
class LaunchOptions:
    """Configuration options for launching a `waybound` automation session."""

    backend: BackendName = "mock"
    pid: int | None = None
    serial: str | None = None
    display: str | None = None
    headless_xvfb: bool = False
    launch_chrome: bool = False
    launch_waydroid: bool = False
    instance_id: str | None = None
    adb_port: int | None = None
    url: str | None = None
    profile_dir: Path | str | None = None
    ssl_keylog: Path | str | None = None
    proxy: str | None = None
    block_hosts: tuple[str, ...] = ()
    timezone: str | None = None
    locale: str | None = None
    focus: bool = False
    no_motion: bool = False
    use_tcp: bool = False
    daemon_binary: Path | str | None = None
    startup_timeout_s: float = 5.0


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


class Session:
    """Context manager that starts `waybound-daemon`, connects, and cleans up on exit."""

    def __init__(self, options: LaunchOptions | None = None) -> None:
        opts = options if options is not None else LaunchOptions()
        self._options = opts
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
        if opts.headless_xvfb:
            cmd.append("--headless-xvfb")
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

        child_env = os.environ.copy()
        if opts.proxy is not None:
            # Pass proxy via env var so credentials do not appear in process argv (`ps`).
            child_env["WAYBOUND_PROXY"] = opts.proxy

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
    url: str | None = None,
) -> Session:
    """Create a `Session` context manager for ergonomic out-of-band browser automation."""
    resolved = (
        options
        if options is not None
        else LaunchOptions(backend=backend, launch_chrome=launch_chrome, url=url)
    )
    return Session(resolved)
