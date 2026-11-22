"""Unix domain socket transport for communicating with waybound-daemon."""

from __future__ import annotations

import contextlib
import json
import socket
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Self

from waybound.types import (
    AccessibilityNode,
    Bounds,
    CapturedResponse,
    KeyModifier,
    LocatorQuery,
    Role,
)

if TYPE_CHECKING:
    from io import TextIOWrapper
    from types import TracebackType

_NAMED_KEYS = frozenset(
    {
        "enter",
        "tab",
        "escape",
        "backspace",
        "arrow_left",
        "arrow_right",
        "arrow_up",
        "arrow_down",
        "space",
        "delete",
        "home",
        "end",
        "page_up",
        "page_down",
    }
)
# The daemon paces typing at up to ~180 ms per key; allow headroom on top of the base timeout.
_FILL_SECONDS_PER_CHAR = 0.25


class WayboundDaemonError(RuntimeError):
    """Structured error returned by waybound-daemon over IPC."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class UnixSocketTransport:
    """Line-delimited JSON transport connected to waybound-daemon over AF_UNIX or loopback TCP."""

    def __init__(
        self,
        socket_path: Path | str | None = None,
        *,
        tcp_addr: tuple[str, int] | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        if (socket_path is None) == (tcp_addr is None):
            msg = "provide exactly one of `socket_path` or `tcp_addr`"
            raise ValueError(msg)

        self._socket_path = Path(socket_path) if socket_path is not None else None
        self._tcp_addr = tcp_addr
        self._base_timeout_s = timeout_s
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._reader: TextIOWrapper | None = None
        self._writer: TextIOWrapper | None = None
        try:
            if tcp_addr is not None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock = sock
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(timeout_s)
                sock.connect(tcp_addr)
            else:
                if not hasattr(socket, "AF_UNIX") or self._socket_path is None:
                    msg = "AF_UNIX sockets are not supported on this platform; use tcp_addr"
                    raise OSError(msg)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._sock = sock
                sock.settimeout(timeout_s)
                sock.connect(str(self._socket_path))
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
        response = self._request(
            {
                "method": "wait_for",
                "query": _encode_query(query),
                "timeout_ms": clamped_ms,
            },
            timeout_override_s=max(self._base_timeout_s, clamped_ms / 1000.0 + 5.0),
        )
        raw_node = response.get("node")
        if not isinstance(raw_node, dict):
            msg = f"unexpected wait_for response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return _parse_node(raw_node)

    def shutdown(self) -> None:
        """Request a graceful daemon shutdown so RAII browser & socket guards run."""
        self._expect_ok({"method": "shutdown"}, "shutdown")

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        """Return passively captured HTTP responses, optionally filtered by URL substring."""
        response = self._request({"method": "captured_responses", "url_contains": url_contains})
        raw_items = response.get("responses")
        if not isinstance(raw_items, list):
            msg = f"unexpected captured_responses payload: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return [_parse_http_response(item) for item in raw_items if isinstance(item, dict)]

    def wait_for_response(self, url_contains: str, *, timeout_ms: int = 10_000) -> CapturedResponse:
        """Wait until a passively captured HTTP response matches `url_contains`.

        Uses a dedicated short-lived Unix socket connection so concurrent `asyncio.gather`
        calls (e.g., `wait_for_response` + `click`) run in true parallel without blocking.
        """
        if self._sock is None:
            raise WayboundDaemonError("closed", "transport is closed")
        clamped_ms = max(0, timeout_ms)
        dedicated_timeout = max(self._base_timeout_s, clamped_ms / 1000.0 + 5.0)
        try:
            with UnixSocketTransport(
                self._socket_path,
                tcp_addr=self._tcp_addr,
                timeout_s=dedicated_timeout,
            ) as dedicated:
                response = dedicated._request(
                    {
                        "method": "wait_for_response",
                        "url_contains": url_contains,
                        "timeout_ms": clamped_ms,
                    }
                )
        except OSError as exc:
            raise WayboundDaemonError("io_error", str(exc)) from exc
        raw_resp = response.get("response")
        if not isinstance(raw_resp, dict):
            msg = f"unexpected wait_for_response payload: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return _parse_http_response(raw_resp)

    def hover(self, query: LocatorQuery) -> None:
        """Locate the target element and move the pointer over it without clicking."""
        self._expect_ok({"method": "hover", "query": _encode_query(query)}, "hover")

    def click(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native click."""
        self._expect_ok({"method": "click", "query": _encode_query(query)}, "click")

    def dblclick(self, query: LocatorQuery) -> None:
        """Locate the target element and dispatch a native double-click."""
        self._expect_ok({"method": "dblclick", "query": _encode_query(query)}, "dblclick")

    def select_option(
        self,
        query: LocatorQuery,
        *,
        label: str | None = None,
        index: int | None = None,
    ) -> None:
        """Select an option from a `<select>` or combobox by label or 0-based index."""
        self._expect_ok(
            {
                "method": "select_option",
                "query": _encode_query(query),
                "label": label,
                "index": index,
            },
            "select_option",
        )

    def wait_for_network_idle(self, *, idle_ms: int = 500, timeout_ms: int = 15_000) -> None:
        """Wait until zero HTTP/1.1 or HTTP/2 requests remain inflight for `idle_ms`."""
        clamped_ms = max(0, timeout_ms)
        self._expect_ok(
            {
                "method": "wait_for_network_idle",
                "idle_ms": max(50, idle_ms),
                "timeout_ms": clamped_ms,
            },
            "wait_for_network_idle",
            timeout_override_s=max(self._base_timeout_s, clamped_ms / 1000.0 + 5.0),
        )

    def fill(self, query: LocatorQuery, text: str) -> None:
        """Focus the target element and type text via native keyboard events."""
        self._expect_ok(
            {"method": "fill", "query": _encode_query(query), "text": text},
            "fill",
            timeout_override_s=self._base_timeout_s + _FILL_SECONDS_PER_CHAR * len(text),
        )

    def navigate(self, url: str) -> None:
        """Navigate the active browser tab to `url`."""
        self._expect_ok({"method": "navigate", "url": url}, "navigate")

    def reload(self) -> None:
        """Reload the active browser tab via native OS shortcut."""
        self._expect_ok({"method": "reload"}, "reload")

    def go_back(self) -> None:
        """Navigate back in browser history via native OS shortcut."""
        self._expect_ok({"method": "go_back"}, "go_back")

    def go_forward(self) -> None:
        """Navigate forward in browser history via native OS shortcut."""
        self._expect_ok({"method": "go_forward"}, "go_forward")

    def new_tab(self, url: str | None = None) -> None:
        """Open a new browser tab via native OS shortcut, optionally navigating to `url`."""
        self._expect_ok({"method": "new_tab", "url": url}, "new_tab")

    def close_tab(self) -> None:
        """Close the active browser tab via native OS shortcut."""
        self._expect_ok({"method": "close_tab"}, "close_tab")

    def next_tab(self) -> None:
        """Switch to the next browser tab (Ctrl+Tab)."""
        self._expect_ok({"method": "next_tab"}, "next_tab")

    def prev_tab(self) -> None:
        """Switch to the previous browser tab (Ctrl+Shift+Tab)."""
        self._expect_ok({"method": "prev_tab"}, "prev_tab")

    def screenshot(self, path: str) -> None:
        """Capture a native OS PNG screenshot to `path` (browser window on macOS, else screen)."""
        self._expect_ok({"method": "screenshot", "path": path}, "screenshot")

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

    def _expect_ok(
        self,
        payload: dict[str, object],
        op: str,
        *,
        timeout_override_s: float | None = None,
    ) -> None:
        response = self._request(payload, timeout_override_s=timeout_override_s)
        if response.get("status") != "ok":
            msg = f"unexpected {op} response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)

    def _request(
        self,
        payload: dict[str, object],
        *,
        timeout_override_s: float | None = None,
    ) -> dict[str, object]:
        with self._lock:
            if self._writer is None or self._reader is None or self._sock is None:
                raise WayboundDaemonError("closed", "transport is closed")

            if timeout_override_s is not None:
                self._sock.settimeout(timeout_override_s)
            try:
                try:
                    self._writer.write(json.dumps(payload) + "\n")
                    self._writer.flush()
                    raw_line = self._reader.readline()
                except OSError as exc:
                    self.close()
                    raise WayboundDaemonError("io_error", str(exc)) from exc
                except BaseException:
                    # Interrupted between write and read (e.g. KeyboardInterrupt): the reply
                    # is still in flight, so reusing this connection would hand the next
                    # request the previous request's reply.
                    self.close()
                    raise

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
            finally:
                if timeout_override_s is not None and self._sock is not None:
                    with contextlib.suppress(OSError):
                        self._sock.settimeout(self._base_timeout_s)


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


def _parse_http_response(item: dict[object, object]) -> CapturedResponse:
    url = str(item.get("url", ""))
    raw_status = item.get("status", 0)
    status = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else 0
    ct = item.get("content_type")
    content_type = ct if isinstance(ct, str) else None
    body_val = item.get("body")
    body = body_val if isinstance(body_val, str) else None
    return CapturedResponse(url=url, status=status, content_type=content_type, body=body)


def _encode_query(query: LocatorQuery) -> dict[str, object]:
    payload: dict[str, object] = {
        "role": query.role.value if query.role is not None else None,
        "name": query.name,
        "exact": query.exact,
        "nth": max(0, query.nth),
    }
    if query.within is not None:
        payload["within"] = _encode_query(query.within)
    return payload
