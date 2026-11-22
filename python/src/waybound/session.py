"""High-level ergonomic session lifecycle manager (`waybound.launch`)."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from waybound.client import Page
from waybound.transport import UnixSocketTransport, WayboundDaemonError

if TYPE_CHECKING:
    from types import TracebackType

BackendName = Literal["mock", "macos", "android"]
_MIN_WORKSPACE_PARENTS = 4


@dataclass(frozen=True, slots=True)
class LaunchOptions:
    """Configuration options for launching a `waybound` automation session."""

    backend: BackendName = "mock"
    pid: int | None = None
    serial: str | None = None
    launch_chrome: bool = False
    launch_waydroid: bool = False
    instance_id: str | None = None
    adb_port: int | None = None
    url: str | None = None
    profile_dir: Path | str | None = None
    ssl_keylog: Path | str | None = None
    proxy: str | None = None
    timezone: str | None = None
    locale: str | None = None
    focus: bool = False
    no_motion: bool = False
    daemon_binary: Path | str | None = None
    startup_timeout_s: float = 5.0


def _resolve_daemon_binary(explicit: Path | str | None) -> Path:
    if explicit is not None:
        return Path(explicit)

    env_bin = os.environ.get("WAYBOUND_DAEMON_BIN")
    if env_bin:
        return Path(env_bin)

    on_path = shutil.which("waybound-daemon")
    if on_path is not None:
        return Path(on_path)

    parents = Path(__file__).resolve().parents
    if len(parents) >= _MIN_WORKSPACE_PARENTS:
        repo_root = parents[3]
        for profile in ("release", "debug"):
            candidate = repo_root / "target" / profile / "waybound-daemon"
            if candidate.exists():
                return candidate

    msg = "waybound-daemon binary not found on PATH or in target/{release,debug}"
    raise FileNotFoundError(msg)


def _connect_with_retry(
    socket_path: Path,
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
        if socket_path.exists():
            try:
                return UnixSocketTransport(socket_path)
            except (FileNotFoundError, ConnectionRefusedError, PermissionError):
                pass
        time.sleep(0.02)
    msg = f"timed out waiting for waybound-daemon socket at {socket_path}"
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

    def _build_daemon_cmd(self, socket_path: Path) -> list[str]:
        opts = self._options
        cmd = [
            str(self._daemon_binary),
            "--socket",
            str(socket_path),
            "--backend",
            opts.backend,
        ]
        pairs: tuple[tuple[str, str | None], ...] = (
            ("--pid", str(opts.pid) if opts.pid is not None else None),
            ("--serial", opts.serial),
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

        # Keep socket path short to stay within macOS's 104-byte AF_UNIX sun_path limit.
        tmp_dir = tempfile.TemporaryDirectory(prefix="wb-", dir="/tmp")
        self._tmp_dir = tmp_dir
        socket_path = Path(tmp_dir.name) / "w.sock"
        stderr_log = Path(tmp_dir.name) / "daemon.stderr.log"

        opts = self._options
        cmd = self._build_daemon_cmd(socket_path)

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
            transport = _connect_with_retry(socket_path, stderr_log, proc, opts.startup_timeout_s)
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
