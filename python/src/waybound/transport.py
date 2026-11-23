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
    CapturedCookie,
    CapturedResponse,
    CapturedWebSocketFrame,
    HeaderEntry,
    Http2Fingerprint,
    Http2Setting,
    Http2StreamDependency,
    HttpHeader,
    KeyModifier,
    LocatorQuery,
    NetworkStats,
    Role,
    SessionFingerprint,
    TlsFingerprint,
    TreeSnapshot,
    WebSocketDirection,
    WebSocketOpcode,
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
# A drag waits up to `timeout_ms` for each of its two elements before moving.
_DRAG_WAITED_ELEMENTS = 2
# `set_checked` may wait 5 s for the element (and for it to become enabled) plus 2 s for the
# click to settle, on top of the click itself.
_SET_CHECKED_WAIT_S = 7.0


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

    @property
    def closed(self) -> bool:
        """Return `True` once the connection is closed (explicitly or after an I/O failure)."""
        return self._sock is None

    def ping(self, *, timeout_s: float | None = None) -> str:
        """Send a health-check ping and return the daemon version.

        `timeout_s` overrides the transport's base timeout for this one request.
        """
        return self._ping(timeout_s)[0]

    def browser_alive(self, *, timeout_s: float | None = None) -> bool | None:
        """Ping the daemon and return whether the browser it launched is still running.

        Returns `None` when the daemon did not launch a browser (or is too old to say).
        Raises like `ping` when the daemon itself does not answer.
        """
        return self._ping(timeout_s)[1]

    def _ping(self, timeout_s: float | None) -> tuple[str, bool | None]:
        response = self._request({"method": "ping"}, timeout_override_s=timeout_s)
        version = response.get("version")
        if not isinstance(version, str):
            msg = f"unexpected ping response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        alive = response.get("browser_alive")
        return version, alive if isinstance(alive, bool) else None

    def snapshot_tree(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        """Fetch the current accessibility tree from the daemon."""
        return self.snapshot_tree_with_meta(max_nodes=max_nodes).nodes

    def snapshot_tree_with_meta(self, *, max_nodes: int | None = None) -> TreeSnapshot:
        """Fetch the current accessibility tree along with truncation metadata."""
        payload: dict[str, object] = {"method": "snapshot_tree"}
        if max_nodes is not None:
            if max_nodes < 1:
                msg = f"max_nodes must be a positive integer, got {max_nodes}"
                raise ValueError(msg)
            payload["max_nodes"] = max_nodes
        response = self._request(payload)
        raw_nodes = response.get("nodes")
        if not isinstance(raw_nodes, list):
            msg = f"unexpected tree response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)

        nodes = [_parse_node(item) for item in raw_nodes if isinstance(item, dict)]
        truncated = response.get("truncated") is True
        return TreeSnapshot(nodes=nodes, truncated=truncated)

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

    def captured_websocket_frames(
        self, *, url_contains: str | None = None, limit: int | None = None
    ) -> list[CapturedWebSocketFrame]:
        """Return passively captured WebSocket messages (oldest first).

        Optionally filtered by URL substring and limited to the newest `limit` messages.
        """
        payload: dict[str, object] = {
            "method": "captured_websocket_frames",
            "url_contains": url_contains,
        }
        if limit is not None:
            payload["limit"] = max(0, limit)
        response = self._request(payload)
        raw_items = response.get("frames")
        if not isinstance(raw_items, list):
            msg = f"unexpected captured_websocket_frames payload: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        frames = (_parse_websocket_frame(item) for item in raw_items if isinstance(item, dict))
        return [frame for frame in frames if frame is not None]

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
        self._expect_ok({"method": "dbl_click", "query": _encode_query(query)}, "dblclick")

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

    def set_checked(self, query: LocatorQuery, *, checked: bool) -> AccessibilityNode:
        """Idempotently drive a checkbox/radio/switch to `checked`; return the re-read node.

        The daemon auto-waits for the element (and for it to become enabled when a click is
        needed), refuses elements that stay disabled (`element_disabled`), elements without a
        checked state and unchecking a radio button (`invalid_element_state`), clicks only
        when the state differs, and verifies the new state.
        """
        response = self._request(
            {"method": "set_checked", "query": _encode_query(query), "checked": checked},
            timeout_override_s=self._base_timeout_s + _SET_CHECKED_WAIT_S,
        )
        raw_node = response.get("node")
        if not isinstance(raw_node, dict):
            msg = f"unexpected set_checked response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return _parse_node(raw_node)

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

    def export_fingerprint(self) -> SessionFingerprint:
        """Export the live TLS, HTTP/2, header, and cookie fingerprint captured from the session."""
        response = self._request({"method": "export_session_fingerprint"})
        raw_fp = response.get("fingerprint")
        if response.get("status") != "session_fingerprint" or not isinstance(raw_fp, dict):
            msg = f"unexpected export_session_fingerprint response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return parse_session_fingerprint(raw_fp)

    def network_stats(self) -> NetworkStats:
        """Return per-session bandwidth and connection counters from the daemon proxy."""
        response = self._request({"method": "network_stats"})
        raw_stats = response.get("stats")
        if response.get("status") != "network_stats" or not isinstance(raw_stats, dict):
            msg = f"unexpected network_stats response: {response!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return NetworkStats(
            bytes_sent=_parse_int(raw_stats.get("bytes_sent")),
            bytes_received=_parse_int(raw_stats.get("bytes_received")),
            connections_total=_parse_int(raw_stats.get("connections_total")),
            connections_blocked=_parse_int(raw_stats.get("connections_blocked")),
        )

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

    def drag_to(
        self, source: LocatorQuery, target: LocatorQuery, *, timeout_ms: int = 5_000
    ) -> None:
        """Press on `source`, drag along a native pointer path to `target`, and release."""
        clamped_ms = max(0, timeout_ms)
        self._expect_ok(
            {
                "method": "drag_to",
                "source": _encode_query(source),
                "target": _encode_query(target),
                "timeout_ms": clamped_ms,
            },
            "drag_to",
            # Both element waits run back to back before the drag itself starts.
            timeout_override_s=self._base_timeout_s + _DRAG_WAITED_ELEMENTS * clamped_ms / 1000.0,
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
    checked = _parse_optional_bool(item.get("checked"))
    disabled = item.get("disabled") is True
    expanded = _parse_optional_bool(item.get("expanded"))
    url = _opt_str(item.get("url"))

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
        checked=checked,
        disabled=disabled,
        expanded=expanded,
        url=url,
    )


def _opt_str(raw: object) -> str | None:
    return raw if isinstance(raw, str) else None


def _opt_int(raw: object) -> int | None:
    return raw if isinstance(raw, int) and not isinstance(raw, bool) else None


def _parse_headers(raw: object) -> tuple[HttpHeader, ...]:
    if not isinstance(raw, list):
        return ()
    headers: list[HttpHeader] = []
    for item in raw:
        if isinstance(item, dict):
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                headers.append(HttpHeader(name=name, value=value))
    return tuple(headers)


def _parse_optional_bool(raw: object) -> bool | None:
    return raw if isinstance(raw, bool) else None


def _parse_http_response(item: dict[object, object]) -> CapturedResponse:
    url = str(item.get("url", ""))
    status = _opt_int(item.get("status", 0)) or 0
    return CapturedResponse(
        url=url,
        status=status,
        content_type=_opt_str(item.get("content_type")),
        body=_opt_str(item.get("body")),
        headers=_parse_headers(item.get("headers")),
        request_method=_opt_str(item.get("request_method")),
        request_headers=_parse_headers(item.get("request_headers")),
        request_body=_opt_str(item.get("request_body")),
        captured_at_ms=_opt_int(item.get("captured_at_ms")),
    )


def _parse_websocket_frame(item: dict[object, object]) -> CapturedWebSocketFrame | None:
    """Parse one WebSocket message, skipping items with an unknown direction or opcode."""
    raw_direction = item.get("direction")
    raw_opcode = item.get("opcode")
    if not isinstance(raw_direction, str) or not isinstance(raw_opcode, str):
        return None
    try:
        direction = WebSocketDirection(raw_direction)
        opcode = WebSocketOpcode(raw_opcode)
    except ValueError:
        return None
    return CapturedWebSocketFrame(
        url=str(item.get("url", "")),
        direction=direction,
        opcode=opcode,
        payload=_opt_str(item.get("payload")),
        payload_len=_opt_int(item.get("payload_len")) or 0,
        compressed=item.get("compressed") is True,
        truncated=item.get("truncated") is True,
        close_code=_opt_int(item.get("close_code")),
    )


def _parse_int(raw: object, default: int = 0) -> int:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return default


def _parse_int_tuple(raw: object) -> tuple[int, ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(x for x in raw if isinstance(x, int) and not isinstance(x, bool))


def _parse_str_tuple(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(x for x in raw if isinstance(x, str))


def _parse_header_entries(raw: object) -> tuple[HeaderEntry, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[HeaderEntry] = []
    for entry in raw:
        if isinstance(entry, dict):
            out.append(
                HeaderEntry(
                    name=str(entry.get("name", "")),
                    value=str(entry.get("value", "")),
                )
            )
    return tuple(out)


def parse_session_fingerprint(item: dict[object, object]) -> SessionFingerprint:
    """Parse a JSON dict matching `waybound_core::SessionFingerprint` into typed dataclasses."""
    raw_tls = item.get("tls")
    tls: TlsFingerprint | None = None
    if isinstance(raw_tls, dict):
        tls = TlsFingerprint(
            tls_version=_parse_int(raw_tls.get("tls_version")),
            cipher_suites=_parse_int_tuple(raw_tls.get("cipher_suites")),
            extensions=_parse_int_tuple(raw_tls.get("extensions")),
            supported_groups=_parse_int_tuple(raw_tls.get("supported_groups")),
            ec_point_formats=_parse_int_tuple(raw_tls.get("ec_point_formats")),
            signature_algorithms=_parse_int_tuple(raw_tls.get("signature_algorithms")),
            alpn_protocols=_parse_str_tuple(raw_tls.get("alpn_protocols")),
            supported_versions=_parse_int_tuple(raw_tls.get("supported_versions")),
            cert_compression_algorithms=_parse_int_tuple(
                raw_tls.get("cert_compression_algorithms")
            ),
            alps_protocols=_parse_str_tuple(raw_tls.get("alps_protocols")),
            alps_use_new_codepoint=bool(raw_tls.get("alps_use_new_codepoint", False)),
            psk_key_exchange_modes=_parse_int_tuple(raw_tls.get("psk_key_exchange_modes")),
            grease_present=bool(raw_tls.get("grease_present", False)),
            has_status_request=bool(raw_tls.get("has_status_request", False)),
            has_signed_cert_timestamp=bool(raw_tls.get("has_signed_cert_timestamp", False)),
            has_session_ticket=bool(raw_tls.get("has_session_ticket", False)),
            has_extended_master_secret=bool(raw_tls.get("has_extended_master_secret", False)),
            has_renegotiation_info=bool(raw_tls.get("has_renegotiation_info", False)),
            has_ech=bool(raw_tls.get("has_ech", False)),
            ja3_string=str(raw_tls.get("ja3_string", "")),
            ja3_hash=str(raw_tls.get("ja3_hash", "")),
            ja4=str(raw_tls.get("ja4", "")),
        )

    raw_h2 = item.get("http2")
    http2: Http2Fingerprint | None = None
    if isinstance(raw_h2, dict):
        raw_settings = raw_h2.get("settings")
        settings: list[Http2Setting] = []
        if isinstance(raw_settings, list):
            for entry in raw_settings:
                if isinstance(entry, dict):
                    settings.append(
                        Http2Setting(
                            id=_parse_int(entry.get("id")),
                            value=_parse_int(entry.get("value")),
                        )
                    )
        raw_wu = raw_h2.get("initial_window_update")
        wu = raw_wu if isinstance(raw_wu, int) and not isinstance(raw_wu, bool) else None
        raw_prio = raw_h2.get("headers_priority")
        headers_priority: Http2StreamDependency | None = None
        if isinstance(raw_prio, dict):
            headers_priority = Http2StreamDependency(
                dependency_id=_parse_int(raw_prio.get("dependency_id")),
                weight=_parse_int(raw_prio.get("weight")),
                exclusive=bool(raw_prio.get("exclusive", False)),
            )
        http2 = Http2Fingerprint(
            settings=tuple(settings),
            initial_window_update=wu,
            pseudo_header_order=_parse_str_tuple(raw_h2.get("pseudo_header_order")),
            headers_priority=headers_priority,
            akamai_fingerprint=str(raw_h2.get("akamai_fingerprint", "")),
        )

    default_headers = _parse_header_entries(item.get("default_headers"))
    api_headers = _parse_header_entries(item.get("api_headers"))

    cookies: list[CapturedCookie] = []
    raw_cookies = item.get("cookies")
    if isinstance(raw_cookies, list):
        for entry in raw_cookies:
            if isinstance(entry, dict):
                cookies.append(
                    CapturedCookie(
                        name=str(entry.get("name", "")),
                        value=str(entry.get("value", "")),
                        domain=str(entry.get("domain", "")),
                        path=str(entry.get("path", "/")),
                        secure=bool(entry.get("secure", False)),
                        http_only=bool(entry.get("http_only", False)),
                    )
                )

    return SessionFingerprint(
        tls=tls,
        http2=http2,
        default_headers=default_headers,
        api_headers=api_headers,
        cookies=tuple(cookies),
    )


def _encode_query(query: LocatorQuery) -> dict[str, object]:
    payload: dict[str, object] = {
        "role": query.role.value if query.role is not None else None,
        "name": query.name,
        "exact": query.exact,
        "nth": max(0, query.nth),
    }
    if query.within is not None:
        payload["within"] = _encode_query(query.within)
    if query.strict:
        payload["strict"] = True
    return payload
