"""Unix domain socket transport for communicating with waybound-daemon."""

from __future__ import annotations

import contextlib
import json
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Self

from waybound.types import AccessibilityNode, Bounds, KeyModifier, LocatorQuery, Role

if TYPE_CHECKING:
    from io import TextIOWrapper
    from types import TracebackType

_NAMED_KEYS = frozenset({"enter", "tab", "escape", "backspace"})


class WayboundDaemonError(RuntimeError):
    """Structured error returned by waybound-daemon over IPC."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class UnixSocketTransport:
    """Line-delimited JSON transport connected to waybound-daemon over AF_UNIX."""

    def __init__(self, socket_path: Path | str, *, timeout_s: float = 30.0) -> None:
        self._socket_path = Path(socket_path)
        self._base_timeout_s = timeout_s
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

    def locate_all(self, query: LocatorQuery) -> list[AccessibilityNode]:
        """Return all accessibility nodes matching `query`."""
        response = self._request({"method": "locate_all", "query": _encode_query(query)})
        raw_nodes = response.get("nodes")
        if not isinstance(raw_nodes, list):
            msg = f"unexpected locate_all response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return [_parse_node(item) for item in raw_nodes if isinstance(item, dict)]

    def current_url(self) -> str | None:
        """Return the active tab URL from the daemon, if available."""
        response = self._request({"method": "current_url"})
        url = response.get("url")
        if url is None or isinstance(url, str):
            return url
        msg = f"unexpected current_url response: {response!r}"
        raise WayboundDaemonError("protocol_error", msg)

    def wait_for(self, query: LocatorQuery, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        """Poll until an element matching `query` appears or `timeout_ms` elapses."""
        clamped_ms = max(0, timeout_ms)
        sock = self._sock
        if sock is not None:
            sock.settimeout(max(self._base_timeout_s, clamped_ms / 1000.0 + 5.0))
        try:
            response = self._request(
                {
                    "method": "wait_for",
                    "query": _encode_query(query),
                    "timeout_ms": clamped_ms,
                }
            )
        finally:
            if self._sock is not None:
                self._sock.settimeout(self._base_timeout_s)
        raw_node = response.get("node")
        if not isinstance(raw_node, dict):
            msg = f"unexpected wait_for response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return _parse_node(raw_node)

    def shutdown(self) -> None:
        """Request a graceful daemon shutdown so RAII browser & socket guards run."""
        self._expect_ok({"method": "shutdown"}, "shutdown")

    def click(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native click."""
        self._expect_ok({"method": "click", "query": _encode_query(query)}, "click")

    def fill(self, query: LocatorQuery, text: str) -> None:
        """Focus the target element and type text via native keyboard events."""
        self._expect_ok({"method": "fill", "query": _encode_query(query), "text": text}, "fill")

    def navigate(self, url: str) -> None:
        """Navigate the active browser tab to `url`."""
        self._expect_ok({"method": "navigate", "url": url}, "navigate")

    def scroll(self, delta_x: float, delta_y: float) -> None:
        """Emit a native scroll event."""
        self._expect_ok({"method": "scroll", "delta_x": delta_x, "delta_y": delta_y}, "scroll")

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        """Emit a key press (`enter`, `tab`, `escape`, `backspace`, or single char)."""
        encoded_key: object = key.lower() if key.lower() in _NAMED_KEYS else {"char": key}
        if isinstance(encoded_key, dict) and len(key) != 1:
            msg = f"key must be one of {sorted(_NAMED_KEYS)} or a single character, got {key!r}"
            raise ValueError(msg)
        self._expect_ok(
            {
                "method": "press",
                "key": encoded_key,
                "modifiers": [m.value for m in modifiers],
            },
            "press",
        )

    def _expect_ok(self, payload: dict[str, object], op: str) -> None:
        response = self._request(payload)
        if response.get("status") != "ok":
            msg = f"unexpected {op} response: {response!r}"
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
        "nth": max(0, query.nth),
    }
