"""Unit and live integration tests for `waybound.scrapy` (`WayboundDownloadHandler`)."""

from __future__ import annotations

import builtins
import contextlib
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from scrapy import Spider
from scrapy.crawler import Crawler
from scrapy.http import HtmlResponse, Request, Response, TextResponse

from waybound import (
    AccessibilityNode,
    Bounds,
    BrowserPool,
    CapturedCookie,
    CapturedResponse,
    HeaderEntry,
    Http2Fingerprint,
    HttpHeader,
    LaunchOptions,
    Role,
    SessionFingerprint,
    WayboundDaemonError,
)
from waybound.async_client import AsyncPage
from waybound.scrapy import WayboundDownloadHandler
from waybound.session import _resolve_daemon_binary

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Sequence


class _DummySpider(Spider):
    name = "waybound_dummy"


def _make_crawler(settings: dict[str, object] | None = None) -> Crawler:
    return Crawler(_DummySpider, settings=settings or {})


class _FakeFallbackHandler:
    """Async fallback download handler double for passthrough and close tests."""

    def __init__(self) -> None:
        self.seen_urls: list[str] = []
        self.closed = False

    async def download_request(self, request: Request) -> Response:
        self.seen_urls.append(request.url)
        return TextResponse(
            url=request.url,
            status=200,
            body=b"from-fallback",
            encoding="utf-8",
            request=request,
        )

    async def close(self) -> None:
        self.closed = True


class _FakeAsyncPage(AsyncPage):
    """Lightweight `AsyncPage` test double for browser-tier Scrapy handler tests."""

    def __init__(
        self,
        *,
        final_url: str | None = None,
        links: list[AccessibilityNode] | None = None,
        captured: list[CapturedResponse] | None = None,
        fingerprint: SessionFingerprint | None = None,
        fail_fingerprint: bool = False,
    ) -> None:
        self._final_url = final_url
        self._links = list(links or [])
        self._captured = list(captured or [])
        self._fingerprint = fingerprint or SessionFingerprint(
            tls=None,
            http2=Http2Fingerprint(
                settings=(),
                initial_window_update=65_536,
                pseudo_header_order=(":method", ":authority", ":scheme", ":path"),
                akamai_fingerprint="1:65536|65536|0|m,a,s,p",
            ),
            default_headers=(HeaderEntry(name="user-agent", value="waybound-scrapy-test"),),
            cookies=(),
        )
        self._fail_fingerprint = fail_fingerprint
        self.visited_urls: list[str] = []
        self._current_url: str | None = None

    async def goto(self, url: str) -> None:
        self._current_url = url
        self.visited_urls.append(url)

    async def url(self) -> str | None:
        return self._final_url or self._current_url

    async def links(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        if max_nodes is not None:
            return self._links[:max_nodes]
        return list(self._links)

    async def captured_responses(
        self, *, url_contains: str | None = None
    ) -> list[CapturedResponse]:
        if url_contains is None:
            return list(self._captured)
        needle = url_contains.lower()
        return [item for item in self._captured if needle in item.url.lower()]

    async def export_fingerprint(self) -> SessionFingerprint:
        if self._fail_fingerprint:
            raise WayboundDaemonError("unsupported", "fingerprint unavailable")
        return self._fingerprint


class _FakeBrowserPool(BrowserPool):
    """In-memory `BrowserPool` double recording acquire/proxy/close events."""

    def __init__(self, page: _FakeAsyncPage) -> None:
        super().__init__(size=1)
        self._page = page
        self.acquired_proxies: list[str | None] = []
        self.closed_flag = False

    async def close(self) -> None:
        self.closed_flag = True
        await super().close()

    @contextlib.asynccontextmanager
    async def acquire(
        self,
        *,
        proxy: str | None = None,
        timeout_s: float | None = None,
    ) -> AsyncIterator[AsyncPage]:
        _ = timeout_s
        self.acquired_proxies.append(proxy)
        yield self._page


class _LocalTestHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/html":
            body = b"<html><body><h1>Waybound Fast HTTP</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Waybound-Echo", self.headers.get("X-Custom", ""))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/bin":
            body = b"raw-bytes-payload"
            self.send_response(201)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        payload = {
            "method": "GET",
            "path": self.path,
            "user_agent": self.headers.get("User-Agent"),
            "cookie": self.headers.get("Cookie"),
            "custom": self.headers.get("X-Custom"),
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Server-Tag", "local-test")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        payload = {
            "method": "POST",
            "path": self.path,
            "body": raw_body,
            "custom": self.headers.get("X-Custom"),
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
        return


@pytest.fixture
def local_http_server_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalTestHttpHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _sample_fingerprint(user_agent: str = "WayboundScrapy/1.0") -> SessionFingerprint:
    return SessionFingerprint(
        tls=None,
        http2=None,
        default_headers=(HeaderEntry(name="user-agent", value=user_agent),),
        cookies=(
            CapturedCookie(
                name="session_id",
                value="abc123",
                domain="127.0.0.1",
                path="/",
                secure=False,
                http_only=False,
            ),
        ),
    )


def _link_node(node_id: int, name: str, url: str) -> AccessibilityNode:
    return AccessibilityNode(
        id=str(node_id),
        role=Role.LINK,
        name=name,
        value=None,
        bounds=Bounds(x=0.0, y=0.0, width=100.0, height=20.0),
        focused=False,
        url=url,
    )


def test_missing_scrapy_raises_helpful_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing `waybound.scrapy` without `scrapy` installed raises a helpful `ImportError`."""
    real_import = builtins.__import__

    def _blocked_import(
        name: str,
        globals_dict: dict[str, object] | None = None,
        locals_dict: dict[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> object:
        if name == "scrapy" or name.startswith("scrapy."):
            raise ModuleNotFoundError("No module named 'scrapy'", name="scrapy")
        return real_import(name, globals_dict, locals_dict, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    for mod_name in list(sys.modules):
        if mod_name == "scrapy" or mod_name.startswith("scrapy."):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    module_path = Path(__file__).resolve().parents[1] / "src" / "waybound" / "scrapy.py"
    spec = importlib.util.spec_from_file_location("_waybound_scrapy_missing_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"Install waybound\[scrapy\] to use waybound\.scrapy"):
        spec.loader.exec_module(module)


async def test_passthrough_delegates_to_fallback_handler() -> None:
    """Requests without `waybound` or `waybound_http` pass straight through to fallback."""
    fallback = _FakeFallbackHandler()
    handler = WayboundDownloadHandler(fallback_handler=fallback)
    request = Request("https://example.com/plain")

    response = await handler.download_request(request)

    assert isinstance(response, TextResponse)
    assert response.text == "from-fallback"
    assert fallback.seen_urls == ["https://example.com/plain"]

    await handler.close()
    assert fallback.closed


async def test_conflicting_meta_flags_raise_value_error() -> None:
    """Enabling both `waybound` and `waybound_http` on the same request fails fast."""
    handler = WayboundDownloadHandler(fallback_handler=_FakeFallbackHandler())
    request = Request("https://example.com/both", meta={"waybound": True, "waybound_http": True})
    with pytest.raises(ValueError, match="cannot enable both"):
        await handler.download_request(request)
    await handler.close()


async def test_browser_tier_html_response_callback_proxy_and_external_pool_kept_open() -> None:
    """Browser tier populates `HtmlResponse`, meta fields, runs callback, and forwards proxy."""
    link = _link_node(1, "Docs", "https://example.com/docs")
    doc_resp = CapturedResponse(
        url="https://example.com/final",
        status=200,
        content_type="text/html; charset=utf-8",
        body="<html><body><a href='/docs'>Docs</a></body></html>",
        headers=(HttpHeader(name="X-Origin", value="waybound"),),
    )
    api_resp = CapturedResponse(
        url="https://example.com/api/data",
        status=200,
        content_type="application/json",
        body='{"ok":true}',
    )
    fake_page = _FakeAsyncPage(
        final_url="https://example.com/final",
        links=[link],
        captured=[api_resp, doc_resp],
    )
    fake_pool = _FakeBrowserPool(fake_page)

    crawler = _make_crawler()
    crawler.settings.set("WAYBOUND_POOL", fake_pool)
    handler = WayboundDownloadHandler.from_crawler(crawler)
    assert handler.pool is fake_pool

    callback_events: list[str] = []

    async def on_page(page: AsyncPage, req: Request) -> None:
        current = await page.url()
        callback_events.append(f"{req.url}->{current}")

    request = Request(
        "https://example.com/start",
        meta={
            "waybound": True,
            "proxy": "http://proxy.internal:8080",
            "waybound_page_callback": on_page,
            "waybound_capture_fingerprint": True,
        },
    )

    response = await handler.download_request(request)

    assert isinstance(response, HtmlResponse)
    assert response.url == "https://example.com/final"
    assert response.status == 200
    assert response.headers.get(b"X-Origin") == b"waybound"
    assert "Docs" in response.text
    assert callback_events == ["https://example.com/start->https://example.com/final"]
    assert fake_pool.acquired_proxies == ["http://proxy.internal:8080"]
    assert response.meta["waybound_links"] == [link]
    assert response.meta["waybound_captured_responses"] == [api_resp, doc_resp]
    fp = response.meta["waybound_fingerprint"]
    assert isinstance(fp, SessionFingerprint)
    assert fp.http2 is not None
    assert fp.http2.akamai_fingerprint == "1:65536|65536|0|m,a,s,p"

    # External pool injected via WAYBOUND_POOL must NOT be closed by handler.close().
    await handler.close()
    assert not fake_pool.closed_flag
    await fake_pool.close()


async def test_browser_tier_fingerprint_capture_is_best_effort() -> None:
    """If `export_fingerprint()` fails, browser tier still succeeds with `None` fingerprint."""
    fake_page = _FakeAsyncPage(fail_fingerprint=True)
    fake_pool = _FakeBrowserPool(fake_page)
    handler = WayboundDownloadHandler(pool=fake_pool)

    request = Request(
        "https://example.com/no-fp",
        meta={"waybound": True, "waybound_capture_fingerprint": True},
    )
    response = await handler.download_request(request)

    assert isinstance(response, HtmlResponse)
    assert response.meta["waybound_fingerprint"] is None
    await handler.close()
    await fake_pool.close()


async def test_browser_tier_live_mock_daemon_e2e() -> None:
    """End-to-end browser tier against live `waybound-daemon --backend mock` + internal pool."""
    daemon_bin = _resolve_daemon_binary(None)
    crawler = _make_crawler(
        {
            "WAYBOUND_POOL_SIZE": 1,
            "WAYBOUND_LAUNCH_OPTIONS": LaunchOptions(backend="mock", daemon_binary=daemon_bin),
            "WAYBOUND_ISOLATED_DISPLAYS": False,
            "WAYBOUND_MAX_USES_PER_SLOT": 5,
        }
    )
    handler = WayboundDownloadHandler.from_crawler(crawler)
    callback_called = False

    async def inspect_page(page: AsyncPage, req: Request) -> None:
        nonlocal callback_called
        tree = await page.snapshot_tree()
        assert len(tree) > 0
        assert req.url == "https://example.com/mock-scrapy"
        callback_called = True

    request = Request(
        "https://example.com/mock-scrapy",
        meta={
            "waybound": True,
            "waybound_page_callback": inspect_page,
            "waybound_capture_fingerprint": True,
        },
    )
    response = await handler.download_request(request)

    assert isinstance(response, HtmlResponse)
    assert callback_called
    assert isinstance(response.meta["waybound_links"], list)
    assert isinstance(response.meta["waybound_captured_responses"], list)
    assert isinstance(response.meta["waybound_fingerprint"], SessionFingerprint)

    pool = handler.pool
    assert pool is not None
    await handler.close()

    # Internally created pool must be cleanly closed after handler.close().
    assert pool.stats().active == 0
    assert pool.stats().idle == 0
    with pytest.raises(RuntimeError, match="closed"):
        async with pool.acquire():
            pass


async def test_fast_http_tier_live_local_server(local_http_server_url: str) -> None:
    """Fast HTTP tier (`waybound_http=True`) executes GET/POST via `HandoffHttpClient`."""
    fp = _sample_fingerprint(user_agent="WayboundScrapyFast/2.0")
    crawler = _make_crawler({"WAYBOUND_FINGERPRINT": fp.to_json()})
    handler = WayboundDownloadHandler.from_crawler(crawler)
    try:
        # JSON GET request
        get_req = Request(
            f"{local_http_server_url}/api/items",
            headers={"X-Custom": "from-scrapy"},
            meta={"waybound_http": True},
        )
        get_resp = await handler.download_request(get_req)
        assert isinstance(get_resp, TextResponse)
        assert get_resp.status == 200
        assert get_resp.headers.get(b"X-Server-Tag") == b"local-test"
        parsed = json.loads(get_resp.text)
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/api/items"
        assert parsed["user_agent"] == "WayboundScrapyFast/2.0"
        assert parsed["custom"] == "from-scrapy"
        assert "session_id=abc123" in str(parsed["cookie"])

        # HTML GET request -> HtmlResponse
        html_req = Request(
            f"{local_http_server_url}/html",
            headers={"X-Custom": "html-echo"},
            meta={"waybound_http": True},
        )
        html_resp = await handler.download_request(html_req)
        assert isinstance(html_resp, HtmlResponse)
        assert html_resp.status == 200
        assert html_resp.headers.get(b"X-Waybound-Echo") == b"html-echo"
        assert html_resp.css("h1::text").get() == "Waybound Fast HTTP"

        # Binary GET request -> base Response (not TextResponse)
        bin_req = Request(
            f"{local_http_server_url}/bin",
            meta={"waybound_http": True},
        )
        bin_resp = await handler.download_request(bin_req)
        assert type(bin_resp) is Response
        assert bin_resp.status == 201
        assert bin_resp.body == b"raw-bytes-payload"

        # POST request with per-request fingerprint override
        override_fp = _sample_fingerprint(user_agent="OverrideAgent/3.0")
        post_req = Request(
            f"{local_http_server_url}/submit",
            method="POST",
            headers={"X-Custom": "post-hdr"},
            body=b'{"hello":"world"}',
            meta={"waybound_http": True, "waybound_fingerprint": override_fp},
        )
        post_resp = await handler.download_request(post_req)
        assert isinstance(post_resp, TextResponse)
        assert post_resp.status == 200
        post_data = json.loads(post_resp.text)
        assert post_data["method"] == "POST"
        assert post_data["body"] == '{"hello":"world"}'
        assert post_data["custom"] == "post-hdr"
    finally:
        await handler.close()


async def test_fast_http_tier_missing_fingerprint_raises_value_error() -> None:
    """Fast HTTP tier without `WAYBOUND_FINGERPRINT` or `meta['waybound_fingerprint']` fails."""
    handler = WayboundDownloadHandler()
    request = Request("http://127.0.0.1:9/no-fp", meta={"waybound_http": True})
    with pytest.raises(ValueError, match="WAYBOUND_FINGERPRINT"):
        await handler.download_request(request)
    await handler.close()


async def test_from_crawler_validates_settings_and_accepts_all_waybound_options() -> None:
    """`from_crawler()` validates setting types and parses all `WAYBOUND_*` options."""
    fp = _sample_fingerprint()
    crawler = _make_crawler(
        {
            "WAYBOUND_POOL_SIZE": 2,
            "WAYBOUND_ISOLATED_DISPLAYS": True,
            "WAYBOUND_REMOTE_WORKERS": ["127.0.0.1:9001", "127.0.0.1:9002"],
            "WAYBOUND_MAX_USES_PER_SLOT": 10,
            "WAYBOUND_PROXIES": ["http://p1.local:8080"],
            "WAYBOUND_FINGERPRINT": fp,
        }
    )
    handler = WayboundDownloadHandler.from_crawler(crawler)
    await handler.close()

    bad_pool_crawler = _make_crawler({"WAYBOUND_POOL": "not-a-pool"})
    with pytest.raises(TypeError, match="WAYBOUND_POOL"):
        WayboundDownloadHandler.from_crawler(bad_pool_crawler)

    bad_launch_crawler = _make_crawler({"WAYBOUND_LAUNCH_OPTIONS": "not-launch-options"})
    with pytest.raises(TypeError, match="WAYBOUND_LAUNCH_OPTIONS"):
        WayboundDownloadHandler.from_crawler(bad_launch_crawler)

    bad_proxies_crawler = _make_crawler({"WAYBOUND_PROXIES": "http://single-str"})
    with pytest.raises(TypeError, match="WAYBOUND_PROXIES"):
        WayboundDownloadHandler.from_crawler(bad_proxies_crawler)
