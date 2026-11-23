"""Unit and live mock-daemon tests for `waybound.crawlee` (`WayboundCrawler`)."""

from __future__ import annotations

import builtins
import contextlib
import importlib.util
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from crawlee import Glob
from crawlee.configuration import Configuration
from crawlee.proxy_configuration import ProxyConfiguration
from crawlee.storage_clients import FileSystemStorageClient
from crawlee.storages import Dataset

from waybound import (
    AccessibilityNode,
    Bounds,
    BrowserPool,
    CapturedResponse,
    HeaderEntry,
    Http2Fingerprint,
    LaunchOptions,
    Role,
    SessionFingerprint,
)
from waybound.async_client import AsyncPage
from waybound.crawlee import WayboundCrawler, WayboundCrawlingContext
from waybound.session import _resolve_daemon_binary

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence


def _make_config(tmp_path: Path) -> Configuration:
    return Configuration(storage_dir=str(tmp_path / "crawlee_storage"))


class _FakeAsyncPage(AsyncPage):
    """Lightweight `AsyncPage` test double for link discovery, capture, and error tests."""

    def __init__(
        self,
        *,
        links_by_url: dict[str, list[AccessibilityNode]] | None = None,
        responses_by_url: dict[str, list[CapturedResponse]] | None = None,
        fingerprint: SessionFingerprint | None = None,
    ) -> None:
        self._links_by_url = links_by_url or {}
        self._responses_by_url = responses_by_url or {}
        self._fingerprint = fingerprint or SessionFingerprint(
            tls=None,
            http2=Http2Fingerprint(
                settings=(),
                initial_window_update=65_536,
                pseudo_header_order=(":method", ":authority", ":scheme", ":path"),
                akamai_fingerprint="1:65536|65536|0|m,a,s,p",
            ),
            default_headers=(HeaderEntry(name="user-agent", value="waybound-test"),),
            cookies=(),
        )
        self.visited_urls: list[str] = []
        self._current_url: str | None = None

    async def goto(self, url: str) -> None:
        self._current_url = url
        self.visited_urls.append(url)

    async def url(self) -> str | None:
        return self._current_url

    async def links(self, *, max_nodes: int | None = None) -> list[AccessibilityNode]:
        nodes = list(self._links_by_url.get(self._current_url or "", []))
        if max_nodes is not None:
            return nodes[:max_nodes]
        return nodes

    async def captured_responses(
        self, *, url_contains: str | None = None
    ) -> list[CapturedResponse]:
        items = list(self._responses_by_url.get(self._current_url or "", []))
        if url_contains is None:
            return items
        needle = url_contains.lower()
        return [item for item in items if needle in item.url.lower()]

    async def export_fingerprint(self) -> SessionFingerprint:
        return self._fingerprint


class _FakeBrowserPool(BrowserPool):
    """In-memory `BrowserPool` test double recording acquire/proxy/recycle/close events."""

    def __init__(self, page: _FakeAsyncPage) -> None:
        super().__init__(size=1)
        self._page = page
        self.acquired_proxies: list[str | None] = []
        self.recycle_count = 0
        self.closed_flag = False
        self.started_flag = False

    async def start(self) -> None:
        self.started_flag = True

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
        try:
            yield self._page
        except BaseException:
            self.recycle_count += 1
            raise


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


def test_missing_crawlee_raises_helpful_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing `waybound.crawlee` without `crawlee` installed raises a helpful `ImportError`."""
    real_import = builtins.__import__

    def _blocked_import(
        name: str,
        globals_dict: dict[str, object] | None = None,
        locals_dict: dict[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> object:
        if name == "crawlee" or name.startswith("crawlee."):
            raise ModuleNotFoundError("No module named 'crawlee'", name="crawlee")
        return real_import(name, globals_dict, locals_dict, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    for mod_name in list(sys.modules):
        if mod_name == "crawlee" or mod_name.startswith("crawlee."):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    module_path = Path(__file__).resolve().parents[1] / "src" / "waybound" / "crawlee.py"
    spec = importlib.util.spec_from_file_location("_waybound_crawlee_missing_test", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"waybound\[crawlee\]"):
        spec.loader.exec_module(module)


def test_crawler_validation_rejects_pool_and_pool_options() -> None:
    """Supplying both an explicit `pool` and pool-creation kwargs fails fast."""
    pool = BrowserPool(size=1)
    with pytest.raises(ValueError, match="Cannot specify both `pool`"):
        WayboundCrawler(pool=pool, pool_size=2, configure_logging=False)


async def test_enqueue_links_strategies_patterns_and_dataset(tmp_path: Path) -> None:
    """`enqueue_links()` resolves relative links, filters by strategy/patterns, and crawls them."""
    fake_page = _FakeAsyncPage(
        links_by_url={
            "https://example.com/": [
                _link_node(1, "Article 1", "/articles/one"),
                _link_node(2, "Article 2", "https://example.com/articles/two"),
                _link_node(3, "Admin", "/admin/secret"),
                _link_node(4, "External", "https://other.org/page"),
                _link_node(5, "Mail", "mailto:hi@example.com"),
                _link_node(6, "Script", "javascript:void(0)"),
            ],
            "https://example.com/articles/one": [],
            "https://example.com/articles/two": [],
        },
        responses_by_url={
            "https://example.com/": [
                CapturedResponse(
                    url="https://example.com/api/feed",
                    status=200,
                    content_type="application/json",
                    body='{"items":2}',
                ),
            ],
        },
    )
    fake_pool = _FakeBrowserPool(fake_page)
    config = _make_config(tmp_path)
    storage_client = FileSystemStorageClient()

    async def handle(ctx: WayboundCrawlingContext) -> None:
        assert ctx.pool is fake_pool
        responses = await ctx.captured_responses(url_contains="/api/")
        fp = await ctx.session_fingerprint()
        await ctx.push_data(
            {
                "url": ctx.request.url,
                "api_count": len(responses),
                "akamai": fp.http2.akamai_fingerprint if fp.http2 is not None else None,
            }
        )
        if ctx.request.url == "https://example.com/":
            await ctx.enqueue_links(
                strategy="same-hostname",
                include=[Glob("https://example.com/articles/**")],
                exclude=[re.compile(r"/admin/")],
                limit=5,
            )

    crawler = WayboundCrawler(
        pool=fake_pool,
        request_handler=handle,
        configuration=config,
        storage_client=storage_client,
        configure_logging=False,
        use_session_pool=False,
    )
    stats = await crawler.run(["https://example.com/"])

    assert stats.requests_finished == 3
    assert stats.requests_failed == 0
    assert set(fake_page.visited_urls) == {
        "https://example.com/",
        "https://example.com/articles/one",
        "https://example.com/articles/two",
    }

    dataset = await Dataset.open(configuration=config, storage_client=storage_client)
    data = await dataset.get_data()
    urls = {item["url"] for item in data.items}
    assert urls == {
        "https://example.com/",
        "https://example.com/articles/one",
        "https://example.com/articles/two",
    }
    root_item = next(item for item in data.items if item["url"] == "https://example.com/")
    assert root_item["api_count"] == 1
    assert root_item["akamai"] == "1:65536|65536|0|m,a,s,p"
    # External pool must NOT be closed by WayboundCrawler.
    assert not fake_pool.closed_flag
    await fake_pool.close()


async def test_proxy_configuration_forwarded_to_pool(tmp_path: Path) -> None:
    """`ProxyConfiguration` URLs are forwarded into `pool.acquire(proxy=...)`."""
    fake_page = _FakeAsyncPage()
    fake_pool = _FakeBrowserPool(fake_page)
    config = _make_config(tmp_path)
    storage_client = FileSystemStorageClient()
    seen_proxy_urls: list[str | None] = []

    async def handle(ctx: WayboundCrawlingContext) -> None:
        seen_proxy_urls.append(ctx.proxy_info.url if ctx.proxy_info is not None else None)

    proxy_config = ProxyConfiguration(
        proxy_urls=["http://proxy-1.local:8080", "http://proxy-2.local:8080"]
    )
    crawler = WayboundCrawler(
        pool=fake_pool,
        proxy_configuration=proxy_config,
        request_handler=handle,
        configuration=config,
        storage_client=storage_client,
        configure_logging=False,
        use_session_pool=False,
    )
    await crawler.run(["https://example.com/a", "https://example.com/b"])

    assert len(fake_pool.acquired_proxies) == 2
    assert set(fake_pool.acquired_proxies) == {
        "http://proxy-1.local:8080",
        "http://proxy-2.local:8080",
    }
    assert seen_proxy_urls == fake_pool.acquired_proxies
    await fake_pool.close()


async def test_handler_error_recycles_slot_and_retries(tmp_path: Path) -> None:
    """Exceptions in `request_handler` trigger slot recycling and Crawlee retry."""
    fake_page = _FakeAsyncPage()
    fake_pool = _FakeBrowserPool(fake_page)
    config = _make_config(tmp_path)
    storage_client = FileSystemStorageClient()
    attempts = 0

    async def handle(ctx: WayboundCrawlingContext) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            msg = "transient page failure"
            raise RuntimeError(msg)
        await ctx.push_data({"url": ctx.request.url, "attempts": attempts})

    crawler = WayboundCrawler(
        pool=fake_pool,
        request_handler=handle,
        max_request_retries=2,
        configuration=config,
        storage_client=storage_client,
        configure_logging=False,
        use_session_pool=False,
    )
    stats = await crawler.run(["https://example.com/flaky"])

    assert attempts == 2
    assert fake_pool.recycle_count == 1
    assert stats.requests_finished == 1
    assert stats.requests_failed == 0
    await fake_pool.close()


async def test_navigate_false_skips_goto(tmp_path: Path) -> None:
    """Setting `navigate=False` skips automatic `page.goto(request.url)`."""
    fake_page = _FakeAsyncPage()
    fake_pool = _FakeBrowserPool(fake_page)
    config = _make_config(tmp_path)
    storage_client = FileSystemStorageClient()

    async def handle(ctx: WayboundCrawlingContext) -> None:
        await ctx.push_data({"url": ctx.request.url})

    crawler = WayboundCrawler(
        pool=fake_pool,
        navigate=False,
        request_handler=handle,
        configuration=config,
        storage_client=storage_client,
        configure_logging=False,
        use_session_pool=False,
    )
    await crawler.run(["https://example.com/no-nav"])

    assert fake_page.visited_urls == []
    await fake_pool.close()


async def test_waybound_crawler_live_mock_daemon_e2e(tmp_path: Path) -> None:
    """End-to-end `WayboundCrawler` run against `waybound-daemon --backend mock`."""
    daemon_bin = _resolve_daemon_binary(None)
    config = _make_config(tmp_path)
    storage_client = FileSystemStorageClient()

    async def handle(ctx: WayboundCrawlingContext) -> None:
        tree = await ctx.page.snapshot_tree()
        responses = await ctx.captured_responses()
        await ctx.push_data(
            {
                "url": ctx.request.url,
                "node_count": len(tree),
                "captured_count": len(responses),
            }
        )

    crawler = WayboundCrawler(
        pool_size=1,
        launch_options=LaunchOptions(backend="mock", daemon_binary=daemon_bin),
        request_handler=handle,
        configuration=config,
        storage_client=storage_client,
        configure_logging=False,
        use_session_pool=False,
    )
    stats = await crawler.run(["https://example.com/mock-1", "https://example.com/mock-2"])

    assert stats.requests_finished == 2
    assert stats.requests_failed == 0
    # Internally-created pool must be cleanly closed after `run()`.
    assert crawler.pool.stats().active == 0
    assert crawler.pool.stats().idle == 0
    with pytest.raises(RuntimeError, match="closed"):
        async with crawler.pool.acquire():
            pass

    dataset = await Dataset.open(configuration=config, storage_client=storage_client)
    data = await dataset.get_data()
    assert len(data.items) == 2
    for item in data.items:
        node_count = item["node_count"]
        assert isinstance(node_count, int)
        assert node_count > 0
