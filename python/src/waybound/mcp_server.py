"""Zero-dependency stdio Model Context Protocol (MCP) server for `waybound`.

Exposes semantic, out-of-band browser automation tools to AI agents
(Antigravity, Claude Code, Cursor, Codex) over JSON-RPC 2.0 stdio.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import TYPE_CHECKING

from waybound.session import BackendName, LaunchOptions, launch
from waybound.types import Role

if TYPE_CHECKING:
    from collections.abc import Callable

    from waybound.client import Page
    from waybound.session import Session

PROTOCOL_VERSION = "2024-11-05"

TOOLS: list[dict[str, object]] = [
    {
        "name": "waybound_goto",
        "description": "Navigate the active browser tab to an http:// or https:// URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "waybound_url",
        "description": "Return the active tab URL.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "waybound_snapshot",
        "description": "Return the live semantic accessibility tree of the current page.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "waybound_click",
        "description": "Click an element matching semantic role and/or accessible name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {"type": "string"},
                "name": {"type": "string"},
                "nth": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "waybound_fill",
        "description": "Focus an input element and type text via native OS keyboard events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {"type": "string", "default": "text_box"},
                "name": {"type": "string"},
                "text": {"type": "string"},
                "nth": {"type": "integer", "default": 0},
            },
            "required": ["text"],
        },
    },
    {
        "name": "waybound_scroll",
        "description": "Scroll the viewport by (delta_x, delta_y) pixels.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "delta_x": {"type": "number", "default": 0.0},
                "delta_y": {"type": "number", "default": -300.0},
            },
        },
    },
    {
        "name": "waybound_screenshot",
        "description": "Capture a native OS PNG screenshot of the browser window.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "waybound_wait_for_response",
        "description": "Wait for a passively decrypted HTTP response matching url_contains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url_contains": {"type": "string"},
                "timeout_ms": {"type": "integer", "default": 10000},
            },
            "required": ["url_contains"],
        },
    },
]


def _parse_role(raw: object) -> Role | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return Role(raw)
    except ValueError:
        # Fail loudly: silently dropping an unknown role would turn the call into a
        # different, broader locator than the one the caller asked for.
        valid = ", ".join(sorted(r.value for r in Role))
        msg = f"unknown role {raw!r} (expected one of: {valid})"
        raise ValueError(msg) from None


def _as_int(raw: object, default: int) -> int:
    return raw if isinstance(raw, int) and not isinstance(raw, bool) else default


def _as_float(raw: object, default: float) -> float:
    if isinstance(raw, int | float) and not isinstance(raw, bool):
        return float(raw)
    return default


def _text_result(text: str) -> dict[str, object]:
    return {"content": [{"type": "text", "text": text}]}


def _tool_goto(page: Page, args: dict[str, object]) -> dict[str, object]:
    url = str(args.get("url", ""))
    page.goto(url)
    return _text_result(f"Navigated to {url}")


def _tool_url(page: Page, _args: dict[str, object]) -> dict[str, object]:
    return _text_result(page.url() or "")


def _tool_snapshot(page: Page, _args: dict[str, object]) -> dict[str, object]:
    nodes = [
        {
            "id": n.id,
            "role": n.role.value,
            "name": n.name,
            "value": n.value,
            "checked": n.checked,
            "disabled": n.disabled,
            "expanded": n.expanded,
            "bounds": {
                "x": n.bounds.x,
                "y": n.bounds.y,
                "width": n.bounds.width,
                "height": n.bounds.height,
            },
        }
        for n in page.snapshot_tree()
    ]
    return _text_result(json.dumps(nodes))


def _tool_click(page: Page, args: dict[str, object]) -> dict[str, object]:
    role = _parse_role(args.get("role"))
    label = args.get("name")
    label_str = label if isinstance(label, str) and label else None
    if role is None and label_str is None:
        msg = "waybound_click requires at least 'role' or 'name'"
        raise ValueError(msg)
    nth = max(0, _as_int(args.get("nth"), 0))
    loc = (
        page.get_by_role(role, name=label_str)
        if role is not None
        else page.get_by_text(label_str or "")
    )
    loc.nth(nth).click()
    return _text_result("Clicked element")


def _tool_fill(page: Page, args: dict[str, object]) -> dict[str, object]:
    role = _parse_role(args.get("role")) or Role.TEXTBOX
    label = args.get("name")
    label_str = label if isinstance(label, str) else None
    text = str(args.get("text", ""))
    nth = max(0, _as_int(args.get("nth"), 0))
    page.get_by_role(role, name=label_str).nth(nth).fill(text)
    return _text_result(f"Filled {len(text)} chars")


def _tool_scroll(page: Page, args: dict[str, object]) -> dict[str, object]:
    dx = _as_float(args.get("delta_x"), 0.0)
    dy = _as_float(args.get("delta_y"), -300.0)
    page.scroll(delta_x=dx, delta_y=dy)
    return _text_result(f"Scrolled ({dx}, {dy})")


def _tool_screenshot(page: Page, _args: dict[str, object]) -> dict[str, object]:
    png = page.screenshot()
    encoded = base64.b64encode(png).decode("ascii")
    return {"content": [{"type": "image", "data": encoded, "mimeType": "image/png"}]}


def _tool_wait_for_response(page: Page, args: dict[str, object]) -> dict[str, object]:
    needle = str(args.get("url_contains", ""))
    timeout_ms = _as_int(args.get("timeout_ms"), 10_000)
    resp = page.wait_for_response(needle, timeout_ms=timeout_ms)
    payload = {
        "url": resp.url,
        "status": resp.status,
        "content_type": resp.content_type,
        "body": resp.body,
    }
    return _text_result(json.dumps(payload))


_TOOL_HANDLERS: dict[str, Callable[[Page, dict[str, object]], dict[str, object]]] = {
    "waybound_goto": _tool_goto,
    "waybound_url": _tool_url,
    "waybound_snapshot": _tool_snapshot,
    "waybound_click": _tool_click,
    "waybound_fill": _tool_fill,
    "waybound_scroll": _tool_scroll,
    "waybound_screenshot": _tool_screenshot,
    "waybound_wait_for_response": _tool_wait_for_response,
}


def _handle_tools_call(
    page_provider: Callable[[], Page], req_id: object, params: object
) -> dict[str, object]:
    if not isinstance(params, dict):
        return _rpc_error(req_id, -32602, "missing params object")
    tool_name = params.get("name")
    if not isinstance(tool_name, str):
        return _rpc_error(req_id, -32602, "missing tool name")
    handler = _TOOL_HANDLERS.get(tool_name)
    if handler is None:
        return _rpc_error(req_id, -32602, f"unknown tool: {tool_name}")

    raw_args = params.get("arguments")
    args = raw_args if isinstance(raw_args, dict) else {}
    try:
        # The provider launches the browser on first use. A launch failure (daemon binary or
        # Chrome missing, Accessibility not granted) is reported as a tool error, like any
        # other tool failure, instead of taking the whole server down.
        result = handler(page_provider(), args)
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": str(exc)}], "isError": True},
        }
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def handle_rpc_message(
    page_provider: Callable[[], Page],
    msg: dict[str, object],
) -> dict[str, object] | None:
    """Process one JSON-RPC 2.0 MCP message; returns None for any notification."""
    method = msg.get("method")
    if "id" not in msg or method is None:
        # Notifications carry no id; a message with an id but no method is the client's
        # response to a server-initiated request. Neither is ever answered.
        return None
    req_id = msg.get("id")

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "waybound-mcp", "version": "0.1.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        return _handle_tools_call(page_provider, req_id, msg.get("params"))
    return _rpc_error(req_id, -32601, f"method not found: {method!r}")


def _rpc_error(req_id: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _options_from_env() -> LaunchOptions:
    raw = os.environ.get("WAYBOUND_BACKEND", "macos")
    backend: BackendName = "mock" if raw == "mock" else ("android" if raw == "android" else "macos")
    return LaunchOptions(
        backend=backend,
        launch_chrome=backend == "macos",
        serial=os.environ.get("WAYBOUND_SERIAL"),
        proxy=os.environ.get("WAYBOUND_PROXY"),
        timezone=os.environ.get("WAYBOUND_TIMEZONE"),
        locale=os.environ.get("WAYBOUND_LOCALE"),
        ssl_keylog=os.environ.get("WAYBOUND_SSL_KEYLOG"),
    )


def main() -> None:
    """Run the `waybound-mcp` stdio server, lazily launching the browser on first tool call."""
    session: Session | None = None
    active_page: Page | None = None

    def get_page() -> Page:
        nonlocal session, active_page
        if active_page is None:
            # Created lazily so a missing daemon binary surfaces as a tool error on the
            # first call rather than killing the server before `initialize`.
            candidate = launch(_options_from_env())
            try:
                active_page = candidate.__enter__()
            except BaseException:
                candidate.close()
                raise
            session = candidate
        return active_page

    try:
        for raw_line in sys.stdin:
            trimmed = raw_line.strip()
            if not trimmed:
                continue
            try:
                decoded: object = json.loads(trimmed)
            except json.JSONDecodeError as exc:
                sys.stdout.write(json.dumps(_rpc_error(None, -32700, str(exc))) + "\n")
                sys.stdout.flush()
                continue
            if not isinstance(decoded, dict):
                continue
            response = handle_rpc_message(get_page, decoded)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    main()
