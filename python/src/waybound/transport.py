"""Unix domain socket transport for communicating with waybound-daemon."""

from __future__ import annotations

import contextlib
import json
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Self

from waybound.types import AccessibilityNode, Bounds, LocatorQuery, Role

if TYPE_CHECKING:
    from io import TextIOWrapper
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
        self._sock: socket.socket | None = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._reader: TextIOWrapper | None = None
        self._writer: TextIOWrapper | None = None
        try:
            self._sock.settimeout(timeout_s)
            self._sock.connect(str(self._socket_path))
            self._reader = self._sock.makefile("r", encoding="utf-8", newline="\n")
            self._writer = self._sock.makefile("w", encoding="utf-8", newline="\n")
        except BaseException:
            self.close()
            raise

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
        """Close the underlying Unix domain socket and stream wrappers safely."""
        try:
            if self._writer is not None:
                with contextlib.suppress(OSError):
                    self._writer.close()
                self._writer = None
        finally:
            try:
                if self._reader is not None:
                    with contextlib.suppress(OSError):
                        self._reader.close()
                    self._reader = None
            finally:
                if self._sock is not None:
                    with contextlib.suppress(OSError):
                        self._sock.close()
                    self._sock = None

    def ping(self) -> str:
        """Send a health-check ping and return the daemon version."""
        response = self._request({"method": "ping"})
        version = response.get("version")
        if not isinstance(version, str):
            msg = f"unexpected ping response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return version

    def snapshot_tree(self) -> list[AccessibilityNode]:
        """Fetch the current accessibility tree from the daemon."""
        response = self._request({"method": "snapshot_tree"})
        raw_nodes = response.get("nodes")
        if not isinstance(raw_nodes, list):
            msg = f"unexpected tree response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)

        return [_parse_node(item) for item in raw_nodes if isinstance(item, dict)]

    def click(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native click."""
        response = self._request({"method": "click", "query": _encode_query(query)})
        if response.get("status") != "ok":
            msg = f"unexpected click response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)

    def fill(self, query: LocatorQuery, text: str) -> None:
        """Focus the target element and type text via native keyboard events."""
        response = self._request({"method": "fill", "query": _encode_query(query), "text": text})
        if response.get("status") != "ok":
            msg = f"unexpected fill response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)

    def _request(self, payload: dict[str, object]) -> dict[str, object]:
        if self._writer is None or self._reader is None:
            raise WayboundDaemonError("closed", "transport is closed")

        try:
            self._writer.write(json.dumps(payload) + "\n")
            self._writer.flush()
            raw_line = self._reader.readline()
        except OSError as exc:
            self.close()
            raise WayboundDaemonError("io_error", str(exc)) from exc

        if not raw_line:
            self.close()
            raise WayboundDaemonError("eof", "daemon closed connection unexpectedly")

        try:
            decoded: object = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            self.close()
            raise WayboundDaemonError("protocol_error", f"invalid JSON: {exc}") from exc

        if not isinstance(decoded, dict):
            self.close()
            msg = f"expected JSON object from daemon, got {type(decoded).__name__}"
            raise WayboundDaemonError("protocol_error", msg)

        if decoded.get("status") == "error":
            code = str(decoded.get("code", "unknown"))
            message = str(decoded.get("message", "unknown error"))
            raise WayboundDaemonError(code, message)

        return decoded


def _parse_role(raw: object) -> Role:
    if not isinstance(raw, str):
        return Role.UNKNOWN
    try:
        return Role(raw)
    except ValueError:
        return Role.UNKNOWN


def _parse_float(raw: object, field: str) -> float:
    if isinstance(raw, int | float) and not isinstance(raw, bool):
        return float(raw)
    msg = f"expected numeric bounds.{field}, got {raw!r}"
    raise WayboundDaemonError("protocol_error", msg)


def _parse_node(item: dict[object, object]) -> AccessibilityNode:
    node_id = str(item.get("id", ""))
    role = _parse_role(item.get("role"))
    name_val = item.get("name")
    name = name_val if isinstance(name_val, str) else None
    val = item.get("value")
    value = val if isinstance(val, str) else None
    focused = bool(item.get("focused", False))

    raw_bounds = item.get("bounds")
    if isinstance(raw_bounds, dict):
        bounds = Bounds(
            x=_parse_float(raw_bounds.get("x", 0.0), "x"),
            y=_parse_float(raw_bounds.get("y", 0.0), "y"),
            width=_parse_float(raw_bounds.get("width", 0.0), "width"),
            height=_parse_float(raw_bounds.get("height", 0.0), "height"),
        )
    else:
        bounds = Bounds(0.0, 0.0, 0.0, 0.0)

    return AccessibilityNode(
        id=node_id,
        role=role,
        name=name,
        value=value,
        bounds=bounds,
        focused=focused,
    )


def _encode_query(query: LocatorQuery) -> dict[str, object]:
    return {
        "role": query.role.value if query.role is not None else None,
        "name": query.name,
        "exact": query.exact,
    }
