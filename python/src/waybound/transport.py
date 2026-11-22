"""Unix domain socket transport for communicating with waybound-daemon."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Self

from waybound.types import Bounds, LocatorQuery, Role

if TYPE_CHECKING:
    from types import TracebackType


class WayboundDaemonError(RuntimeError):
    """Structured error returned by waybound-daemon over IPC."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class UnixSocketTransport:
    """Line-delimited JSON transport connected to waybound-daemon over AF_UNIX."""

    def __init__(self, socket_path: Path | str, *, timeout_s: float = 5.0) -> None:
        self._socket_path = Path(socket_path)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(timeout_s)
        self._sock.connect(str(self._socket_path))
        self._reader = self._sock.makefile("r", encoding="utf-8", newline="\n")
        self._writer = self._sock.makefile("w", encoding="utf-8", newline="\n")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying Unix domain socket."""
        self._reader.close()
        self._writer.close()
        self._sock.close()

    def ping(self) -> str:
        """Send a health-check ping and return the daemon version."""
        response = self._request({"method": "ping"})
        version = response.get("version")
        if not isinstance(version, str):
            msg = f"unexpected ping response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return version

    def snapshot_tree(self) -> list[tuple[str, Role, str | None, Bounds]]:
        """Fetch the current accessibility tree from the daemon."""
        response = self._request({"method": "snapshot_tree"})
        raw_nodes = response.get("nodes")
        if not isinstance(raw_nodes, list):
            msg = f"unexpected tree response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)

        parsed: list[tuple[str, Role, str | None, Bounds]] = []
        for item in raw_nodes:
            if not isinstance(item, dict):
                continue
            node_id = str(item.get("id", ""))
            role_raw = str(item.get("role", "unknown"))
            role = Role(role_raw) if role_raw in Role._value2member_map_ else Role.UNKNOWN
            name_val = item.get("name")
            name = str(name_val) if isinstance(name_val, str) else None
            raw_bounds = item.get("bounds")
            if isinstance(raw_bounds, dict):
                bounds = Bounds(
                    x=float(raw_bounds.get("x", 0.0)),
                    y=float(raw_bounds.get("y", 0.0)),
                    width=float(raw_bounds.get("width", 0.0)),
                    height=float(raw_bounds.get("height", 0.0)),
                )
            else:
                bounds = Bounds(0.0, 0.0, 0.0, 0.0)
            parsed.append((node_id, role, name, bounds))
        return parsed

    def click(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native click."""
        self._request({"method": "click", "query": _encode_query(query)})

    def fill(self, query: LocatorQuery, text: str) -> None:
        """Focus the target element and type text via native keyboard events."""
        self._request({"method": "fill", "query": _encode_query(query), "text": text})

    def _request(self, payload: dict[str, object]) -> dict[str, object]:
        self._writer.write(json.dumps(payload) + "\n")
        self._writer.flush()
        raw_line = self._reader.readline()
        if not raw_line:
            raise WayboundDaemonError("eof", "daemon closed connection unexpectedly")

        decoded: object = json.loads(raw_line)
        if not isinstance(decoded, dict):
            msg = f"expected JSON object from daemon, got {type(decoded).__name__}"
            raise WayboundDaemonError("protocol_error", msg)

        if decoded.get("status") == "error":
            code = str(decoded.get("code", "unknown"))
            message = str(decoded.get("message", "unknown error"))
            raise WayboundDaemonError(code, message)

        return decoded


def _encode_query(query: LocatorQuery) -> dict[str, object]:
    return {
        "role": query.role.value if query.role is not None else None,
        "name": query.name,
        "exact": query.exact,
    }
