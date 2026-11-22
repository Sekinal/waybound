"""Unit tests for the waybound Python SDK."""

from __future__ import annotations

import json

import pytest

from waybound import (
    AccessibilityNode,
    Bounds,
    CapturedResponse,
    CapturedWebSocketFrame,
    HttpHeader,
    KeyModifier,
    LocatorQuery,
    Page,
    Role,
    WebSocketDirection,
    WebSocketOpcode,
)
from waybound.mcp_server import handle_rpc_message
from waybound.transport import _parse_http_response, _parse_websocket_frame


class FakeTransport:
    """In-memory transport recording semantic commands."""

    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []

    def snapshot_tree(self) -> list[AccessibilityNode]:
        return []

    def locate_all(self, query: LocatorQuery) -> list[AccessibilityNode]:
        self.events.append(("locate_all", query))
        return []

    def current_url(self) -> str | None:
        return "https://example.com"

    def wait_for(self, query: LocatorQuery, *, timeout_ms: int = 10_000) -> AccessibilityNode:
        self.events.append(("wait_for", (query, timeout_ms)))
        return AccessibilityNode(
            id="n1",
            role=query.role or Role.UNKNOWN,
            name=query.name,
            value=None,
            bounds=Bounds(10.0, 20.0, 100.0, 30.0),
            focused=False,
        )

    def hover(self, query: LocatorQuery) -> None:
        self.events.append(("hover", query))

    def click(self, query: LocatorQuery) -> None:
        self.events.append(("click", query))

    def fill(self, query: LocatorQuery, text: str) -> None:
        self.events.append(("fill", (query, text)))

    def dblclick(self, query: LocatorQuery) -> None:
        self.events.append(("dblclick", query))

    def select_option(
        self,
        query: LocatorQuery,
        *,
        label: str | None = None,
        index: int | None = None,
    ) -> None:
        self.events.append(("select_option", (query, label, index)))

    def navigate(self, url: str) -> None:
        self.events.append(("navigate", url))

    def reload(self) -> None:
        self.events.append(("reload", None))

    def go_back(self) -> None:
        self.events.append(("go_back", None))

    def go_forward(self) -> None:
        self.events.append(("go_forward", None))

    def new_tab(self, url: str | None = None) -> None:
        self.events.append(("new_tab", url))

    def close_tab(self) -> None:
        self.events.append(("close_tab", None))

    def next_tab(self) -> None:
        self.events.append(("next_tab", None))

    def prev_tab(self) -> None:
        self.events.append(("prev_tab", None))

    def scroll(self, delta_x: float, delta_y: float) -> None:
        self.events.append(("scroll", (delta_x, delta_y)))

    def press(self, key: str, *, modifiers: tuple[KeyModifier, ...] = ()) -> None:
        self.events.append(("press", (key, modifiers)))

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        self.events.append(("captured_responses", url_contains))
        return []

    def wait_for_response(self, url_contains: str, *, timeout_ms: int = 10_000) -> CapturedResponse:
        self.events.append(("wait_for_response", (url_contains, timeout_ms)))
        return CapturedResponse(
            url=f"https://example.com/{url_contains}",
            status=200,
            content_type="application/json",
            body="{}",
            headers=(HttpHeader("set-cookie", "a=1"), HttpHeader("set-cookie", "b=2")),
            request_method="POST",
            request_headers=(HttpHeader("content-type", "application/json"),),
            request_body='{"q":1}',
        )

    def captured_websocket_frames(
        self, *, url_contains: str | None = None
    ) -> list[CapturedWebSocketFrame]:
        self.events.append(("captured_websocket_frames", url_contains))
        return [
            CapturedWebSocketFrame(
                url="wss://example.com/ws",
                direction=WebSocketDirection.SENT,
                opcode=WebSocketOpcode.TEXT,
                payload=f'{{"n":{n}}}',
                payload_len=7,
            )
            for n in range(3)
        ]

    def wait_for_network_idle(self, *, idle_ms: int = 500, timeout_ms: int = 15_000) -> None:
        self.events.append(("wait_for_network_idle", (idle_ms, timeout_ms)))

    def screenshot(self, path: str) -> None:
        self.events.append(("screenshot", path))


def test_bounds_center() -> None:
    bounds = Bounds(x=10.0, y=20.0, width=100.0, height=40.0)
    assert bounds.center == (60.0, 40.0)


def test_page_semantic_locators() -> None:
    transport = FakeTransport()
    page = Page(transport)

    page.goto("https://example.com")
    page.get_by_role(Role.TEXTBOX, name="Origin").fill("SFO")
    page.get_by_role(Role.BUTTON, name="Search", exact=True).click()
    page.scroll(delta_y=-250.0)
    page.press("enter")

    assert transport.events == [
        ("navigate", "https://example.com"),
        ("fill", (LocatorQuery(role=Role.TEXTBOX, name="Origin", exact=False), "SFO")),
        ("click", LocatorQuery(role=Role.BUTTON, name="Search", exact=True)),
        ("scroll", (0.0, -250.0)),
        ("press", ("enter", ())),
    ]


def test_parse_legacy_http_response_without_new_fields() -> None:
    resp = _parse_http_response(
        {"url": "https://a.test/x", "status": 200, "content_type": None, "body": "{}"}
    )
    assert resp == CapturedResponse(
        url="https://a.test/x", status=200, content_type=None, body="{}"
    )
    assert resp.headers == ()
    assert resp.request_method is None
    assert resp.request_headers == ()
    assert resp.request_body is None
    assert resp.header("content-type") is None
    with pytest.raises(ValueError, match="no body"):
        resp.request_json()


def test_parse_http_response_with_headers_and_request() -> None:
    resp = _parse_http_response(
        {
            "url": "https://a.test/login",
            "status": 200,
            "content_type": "application/json",
            "body": '{"ok":true}',
            "headers": [
                {"name": "Set-Cookie", "value": "sid=1; Path=/"},
                {"name": "set-cookie", "value": "theme=dark"},
                {"name": "ETag", "value": '"abc"'},
                {"name": 3, "value": "ignored"},
                "garbage",
            ],
            "request_method": "POST",
            "request_headers": [{"name": "content-type", "value": "application/json"}],
            "request_body": '{"user":"alice"}',
        }
    )
    assert len(resp.headers) == 3
    assert resp.header("set-cookie") == "sid=1; Path=/"
    assert resp.header_values("SET-COOKIE") == ["sid=1; Path=/", "theme=dark"]
    assert resp.header("etag") == '"abc"'
    assert resp.header("x-missing") is None
    assert resp.request_method == "POST"
    assert resp.request_header("Content-Type") == "application/json"
    assert resp.request_header_values("accept") == []
    assert resp.request_json() == {"user": "alice"}
    assert resp.json() == {"ok": True}


def test_parse_websocket_frames() -> None:
    frame = _parse_websocket_frame(
        {
            "url": "wss://a.test/ws",
            "direction": "received",
            "opcode": "close",
            "payload": "bye",
            "payload_len": 5,
            "close_code": 1000,
        }
    )
    assert frame == CapturedWebSocketFrame(
        url="wss://a.test/ws",
        direction=WebSocketDirection.RECEIVED,
        opcode=WebSocketOpcode.CLOSE,
        payload="bye",
        payload_len=5,
        close_code=1000,
    )
    compressed = _parse_websocket_frame(
        {"url": "wss://a.test/ws", "direction": "sent", "opcode": "text", "compressed": True}
    )
    assert compressed is not None
    assert compressed.compressed
    assert compressed.payload is None
    with pytest.raises(ValueError, match="no decoded payload"):
        compressed.json()
    assert (
        _parse_websocket_frame({"url": "wss://a.test", "direction": "sent", "opcode": "x"}) is None
    )
    assert _parse_websocket_frame({"url": "wss://a.test", "opcode": "text"}) is None


def test_page_network_accessors() -> None:
    transport = FakeTransport()
    page = Page(transport)

    resp = page.wait_for_response("api", timeout_ms=500)
    assert resp.header_values("set-cookie") == ["a=1", "b=2"]
    assert resp.request_json() == {"q": 1}

    frames = page.captured_websocket_frames(url_contains="example")
    assert [f.json() for f in frames] == [{"n": 0}, {"n": 1}, {"n": 2}]
    assert transport.events == [
        ("wait_for_response", ("api", 500)),
        ("captured_websocket_frames", "example"),
    ]


def _call_tool(page: Page, name: str, arguments: dict[str, object]) -> object:
    resp = handle_rpc_message(
        lambda: page,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert resp is not None
    result = resp["result"]
    assert isinstance(result, dict)
    content = result["content"]
    assert isinstance(content, list)
    return json.loads(content[0]["text"])


def test_mcp_tools_expose_headers_request_and_websocket_frames() -> None:
    page = Page(FakeTransport())

    payload = _call_tool(page, "waybound_wait_for_response", {"url_contains": "api"})
    assert isinstance(payload, dict)
    assert payload["headers"] == [
        {"name": "set-cookie", "value": "a=1"},
        {"name": "set-cookie", "value": "b=2"},
    ]
    assert payload["request_method"] == "POST"
    assert payload["request_body"] == '{"q":1}'

    frames = _call_tool(page, "waybound_websocket_frames", {"limit": 2})
    assert isinstance(frames, list)
    assert [f["payload"] for f in frames] == ['{"n":1}', '{"n":2}']
    assert frames[0]["direction"] == "sent"
    assert frames[0]["opcode"] == "text"
