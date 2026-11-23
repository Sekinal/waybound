"""First-class Crawlee integration (`WayboundCrawler` and `WayboundCrawlingContext`).

Requires the optional `crawlee` extra:

    pip install "waybound[crawlee]"
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Unpack
from urllib.parse import urljoin, urlsplit

from waybound.pool import BrowserPool

try:
    from crawlee import Glob, Request
    from crawlee.crawlers import (
        BasicCrawler,
        BasicCrawlingContext,
        ContextPipeline,
    )
    from crawlee.statistics import StatisticsState
except ModuleNotFoundError as exc:
    if exc.name == "crawlee" or (exc.name is not None and exc.name.startswith("crawlee.")):
        msg = (
            "waybound.crawlee requires the optional 'crawlee' dependency. "
            "Install it with: pip install 'waybound[crawlee]'"
        )
        raise ImportError(msg) from exc
    raise

if TYPE_CHECKING:
    import re
    from collections.abc import AsyncGenerator, Sequence

    from crawlee import EnqueueStrategy
    from crawlee._types import EnqueueLinksKwargs
    from crawlee.crawlers import BasicCrawlerOptions
    from crawlee.statistics import FinalStatistics

    from waybound.async_client import AsyncPage
    from waybound.session import LaunchOptions
    from waybound.types import CapturedResponse, SessionFingerprint

__all__ = [
    "WayboundCrawler",
    "WayboundCrawlingContext",
]

_HTTP_SCHEMES = frozenset({"http", "https"})


class _HandlerFailedSignal(Exception):
    """Internal sentinel used to signal `BrowserPool.acquire()` to recycle an unhealthy slot."""


def _normalize_patterns(
    patterns: Sequence[re.Pattern[str] | Glob | str],
) -> list[re.Pattern[str] | Glob]:
    normalized: list[re.Pattern[str] | Glob] = []
    for pattern in patterns:
        if isinstance(pattern, str):
            normalized.append(Glob(pattern))
        else:
            normalized.append(pattern)
    return normalized


def _resolve_http_links(raw_urls: Sequence[str], base_url: str) -> list[str]:
    """Resolve relative link URLs against `base_url` and keep unique HTTP(S) URLs in order."""
    resolved: list[str] = []
    seen: set[str] = set()
    for raw in raw_urls:
        stripped = raw.strip()
        if not stripped:
            continue
        absolute = urljoin(base_url, stripped)
        parts = urlsplit(absolute)
        if parts.scheme.lower() not in _HTTP_SCHEMES or not parts.netloc:
            continue
        if absolute not in seen:
            seen.add(absolute)
            resolved.append(absolute)
    return resolved


@dataclass(frozen=True)
class WayboundCrawlingContext(BasicCrawlingContext):
    """Crawling context for `WayboundCrawler`, exposing the live `AsyncPage` and `BrowserPool`."""

    page: AsyncPage
    """The acquired `AsyncPage`, already navigated to `request.url` unless `navigate=False`."""

    pool: BrowserPool
    """The `BrowserPool` managing browser sessions for this crawler."""

    async def captured_responses(
        self,
        *,
        url_contains: str | None = None,
    ) -> list[CapturedResponse]:
        """Return passively captured HTTP responses from the current page."""
        return await self.page.captured_responses(url_contains=url_contains)

    async def session_fingerprint(self) -> SessionFingerprint:
        """Export the live TLS, HTTP/2, header, and cookie fingerprint from the current page."""
        return await self.page.export_fingerprint()

    async def enqueue_links(  # noqa: PLR0913
        self,
        *,
        strategy: EnqueueStrategy = "same-hostname",
        include: Sequence[re.Pattern[str] | Glob | str] | None = None,
        exclude: Sequence[re.Pattern[str] | Glob | str] | None = None,
        limit: int | None = None,
        max_nodes: int | None = None,
        base_url: str | None = None,
        label: str | None = None,
        rq_id: str | None = None,
        rq_name: str | None = None,
        rq_alias: str | None = None,
    ) -> None:
        """Discover links on the current page via `page.links()`, filter, and enqueue them."""
        resolved_base = base_url or self.request.loaded_url or self.request.url
        link_nodes = await self.page.links(max_nodes=max_nodes)
        raw_urls = [node.url for node in link_nodes if node.url]
        urls = _resolve_http_links(raw_urls, resolved_base)
        if not urls:
            return

        requests_to_add: list[str | Request] = (
            [Request.from_url(url, label=label) for url in urls]
            if label is not None
            else list(urls)
        )

        enqueue_kwargs: EnqueueLinksKwargs = {
            "base_url": resolved_base,
            "strategy": strategy,
        }
        if include is not None:
            enqueue_kwargs["include"] = _normalize_patterns(include)
        if exclude is not None:
            enqueue_kwargs["exclude"] = _normalize_patterns(exclude)
        if limit is not None:
            enqueue_kwargs["limit"] = limit

        await self.add_requests(
            requests_to_add,
            rq_id=rq_id,
            rq_name=rq_name,
            rq_alias=rq_alias,
            **enqueue_kwargs,
        )


class WayboundCrawler(BasicCrawler[WayboundCrawlingContext, StatisticsState]):
    """Crawlee `BasicCrawler` backed by a `waybound.BrowserPool` of real OS-driven browsers."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        pool: BrowserPool | None = None,
        pool_size: int | None = None,
        launch_options: LaunchOptions | None = None,
        proxies: Sequence[str] | None = None,
        isolated_displays: bool = False,
        display_base: int = 100,
        remote_workers: Sequence[str] | None = None,
        max_uses_per_slot: int | None = None,
        acquire_timeout_s: float = 60.0,
        navigate: bool = True,
        **kwargs: Unpack[BasicCrawlerOptions[WayboundCrawlingContext, StatisticsState]],
    ) -> None:
        if pool is not None and (
            pool_size is not None
            or launch_options is not None
            or proxies is not None
            or isolated_displays
            or remote_workers is not None
            or max_uses_per_slot is not None
        ):
            msg = (
                "Cannot specify both `pool` and pool-creation options "
                "(`pool_size`, `launch_options`, `proxies`, `isolated_displays`, "
                "`remote_workers`, `max_uses_per_slot`)."
            )
            raise ValueError(msg)

        self._owns_pool = pool is None
        self._pool_size = pool_size
        self._launch_options = launch_options
        self._proxies = tuple(proxies) if proxies is not None else None
        self._isolated_displays = isolated_displays
        self._display_base = display_base
        self._remote_workers = tuple(remote_workers) if remote_workers is not None else None
        self._max_uses_per_slot = max_uses_per_slot
        self._acquire_timeout_s = acquire_timeout_s
        self._navigate = navigate

        self._pool: BrowserPool = pool if pool is not None else self._build_pool()

        pipeline = ContextPipeline[BasicCrawlingContext]().compose(self._make_waybound_context)
        kwargs["_context_pipeline"] = pipeline
        super().__init__(**kwargs)

    @property
    def pool(self) -> BrowserPool:
        """The `BrowserPool` used by this crawler."""
        return self._pool

    def _build_pool(self) -> BrowserPool:
        return BrowserPool(
            size=self._pool_size,
            launch_options=self._launch_options,
            proxies=self._proxies,
            isolated_displays=self._isolated_displays,
            display_base=self._display_base,
            remote_workers=self._remote_workers,
            max_uses_per_slot=self._max_uses_per_slot,
            acquire_timeout_s=self._acquire_timeout_s,
        )

    async def _make_waybound_context(
        self,
        context: BasicCrawlingContext,
    ) -> AsyncGenerator[WayboundCrawlingContext, Exception | None]:
        proxy_url = context.proxy_info.url if context.proxy_info is not None else None

        with contextlib.suppress(_HandlerFailedSignal):
            async with self._pool.acquire(proxy=proxy_url) as page:
                if self._navigate:
                    await page.goto(context.request.url)
                    if context.request.loaded_url is None:
                        context.request.loaded_url = context.request.url

                waybound_context = WayboundCrawlingContext(
                    request=context.request,
                    session=context.session,
                    proxy_info=context.proxy_info,
                    send_request=context.send_request,
                    add_requests=context.add_requests,
                    push_data=context.push_data,
                    use_state=context.use_state,
                    get_key_value_store=context.get_key_value_store,
                    log=context.log,
                    register_deferred_cleanup=context.register_deferred_cleanup,
                    page=page,
                    pool=self._pool,
                )

                handler_exception = yield waybound_context
                if handler_exception is not None:
                    # Trigger `BrowserPool.acquire()` to recycle the slot without turning the
                    # original handler error into a `ContextPipelineFinalizationError`.
                    raise _HandlerFailedSignal

    async def run(
        self,
        requests: Sequence[str | Request] | None = None,
        *,
        purge_request_queue: bool = True,
    ) -> FinalStatistics:
        """Run the crawler, managing the internally-owned `BrowserPool` lifecycle."""
        if self._owns_pool:
            if self._pool._is_closed():
                self._pool = self._build_pool()
            await self._pool.start()
        try:
            return await super().run(requests, purge_request_queue=purge_request_queue)
        finally:
            if self._owns_pool:
                await self._pool.close()
