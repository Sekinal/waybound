"""High-level ergonomic session lifecycle manager (`waybound.launch`)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from waybound.client import Page
from waybound.transport import UnixSocketTransport

if TYPE_CHECKING:
    from types import TracebackType

BackendName = Literal["mock", "macos"]


def _resolve_daemon_binary(explicit: Path | str | None) -> Path:
    if explicit is not None:
        return Path(explicit)

    on_path = shutil.which("waybound-daemon")
    if on_path is not None:
        return Path(on_path)

    # Local workspace fallback for development checkouts.
    repo_root = Path(__file__).resolve().parents[3]
    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / "waybound-daemon"
        if candidate.exists():
            return candidate

    msg = "waybound-daemon binary not found on PATH or in target/{release,debug}"
    raise FileNotFoundError(msg)


def _wait_for_socket(socket_path: Path, proc: subprocess.Popen[bytes], timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        if proc.poll() is not None:
            msg = f"waybound-daemon exited early with code {proc.returncode}"
            raise RuntimeError(msg)
        time.sleep(0.02)
    msg = f"timed out waiting for waybound-daemon socket at {socket_path}"
    raise TimeoutError(msg)


class Session:
    """Context manager that starts `waybound-daemon`, connects, and cleans up on exit."""

    def __init__(
        self,
        *,
        backend: BackendName = "mock",
        pid: int | None = None,
        daemon_binary: Path | str | None = None,
        startup_timeout_s: float = 5.0,
    ) -> None:
        self._backend = backend
        self._pid = pid
        self._daemon_binary = _resolve_daemon_binary(daemon_binary)
        self._startup_timeout_s = startup_timeout_s
        self._tmp_dir: tempfile.TemporaryDirectory[str] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._transport: UnixSocketTransport | None = None

    def __enter__(self) -> Page:
        # Keep socket path short to stay within macOS's 104-byte AF_UNIX sun_path limit.
        tmp_dir = tempfile.TemporaryDirectory(prefix="wb-", dir="/tmp")
        self._tmp_dir = tmp_dir
        socket_path = Path(tmp_dir.name) / "w.sock"

        cmd = [
            str(self._daemon_binary),
            "--socket",
            str(socket_path),
            "--backend",
            self._backend,
        ]
        if self._pid is not None:
            cmd.extend(["--pid", str(self._pid)])

        try:
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._proc = proc
            _wait_for_socket(socket_path, proc, self._startup_timeout_s)
            transport = UnixSocketTransport(socket_path)
            self._transport = transport
            return Page(transport)
        except Exception:
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
        """Close the IPC transport, terminate the daemon, and clean up the socket dir."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=1.0)
            self._proc = None
        if self._tmp_dir is not None:
            self._tmp_dir.cleanup()
            self._tmp_dir = None


def launch(
    *,
    backend: BackendName = "mock",
    pid: int | None = None,
    daemon_binary: Path | str | None = None,
    startup_timeout_s: float = 5.0,
) -> Session:
    """Create a [`Session`] context manager for ergonomic out-of-band browser automation."""
    return Session(
        backend=backend,
        pid=pid,
        daemon_binary=daemon_binary,
        startup_timeout_s=startup_timeout_s,
    )
