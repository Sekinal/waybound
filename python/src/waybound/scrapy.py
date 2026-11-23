"""First-class Scrapy Download Handler (`WayboundDownloadHandler`).

Supports three request tiers in a single Scrapy spider:
- **Passthrough** (default): requests without `meta["waybound"]` or `meta["waybound_http"]`
  are delegated directly to Scrapy's native HTTP download handler with zero overhead.
- **Browser tier** (`meta={"waybound": True}`): acquires an `AsyncPage` from a managed
  `waybound.BrowserPool`, navigates to `request.url`, runs optional
  `meta["waybound_page_callback"]`, and returns an `HtmlResponse` populated with
  captured responses, accessibility links, and optional exported `SessionFingerprint`.
- **Fast HTTP tier** (`meta={"waybound_http": True}`): replays a captured
  `SessionFingerprint` (TLS + HTTP/2 + cookies) via `waybound.HandoffHttpClient` on a
  worker thread (`asyncio.to_thread`) without spawning a browser.

Requires the optional `scrapy` extra:

    pip install "waybound[scrapy]"
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Protocol, Self, cast

from waybound.handoff import HandoffHttpClient, HandoffResponse
from waybound.pool import BrowserPool
from waybound.session import LaunchOptions
from waybound.transport import WayboundDaemonError, parse_session_fingerprint
from waybound.types import AccessibilityNode, CapturedResponse, SessionFingerprint

try:
    from scrapy.core.downloader.handlers.http11 import HTTP11DownloadHandler
    from scrapy.http import HtmlResponse, Request, Response, TextResponse
    from scrapy.utils.defer import maybe_deferred_to_future
    from twisted.internet.defer import Deferred
except ModuleNotFoundError as exc:
    if exc.name == "scrapy" or (exc.name is not None and exc.name.startswith("scrapy.")):
        msg = "Install waybound[scrapy] to use waybound.scrapy"
        raise ImportError(msg) from exc
    raise

if TYPE_CHECKING:
    from pathlib import Path

    from scrapy import Spider
    from scrapy.crawler import Crawler

    from waybound.async_client import AsyncPage

__all__ = [
    "PageCallback",
    "WayboundDownloadHandler",
]

type PageCallback = Callable[[AsyncPage, Request], Awaitable[None]]
type _FallbackDownloadResult = Awaitable[Response] | Deferred[Response] | Response

_TEXT_CONTENT_TYPE_TOKENS = ("text/", "json", "xml", "javascript")
_FATAL_HANDOFF_ERROR_CODES = frozenset({"closed", "eof", "io_error", "protocol_error"})


class _FallbackDownloadHandler(Protocol):
    """Minimal protocol satisfied by Scrapy's `HTTP11DownloadHandler` and test doubles."""

    def download_request(
        self, request: Request
    ) -> Awaitable[Response] | Deferred[Response] | Response: ...

    def close(self) -> Awaitable[None] | Deferred[None] | None: ...


def _parse_fingerprint(raw: object) -> SessionFingerprint:
    """Parse a `SessionFingerprint` instance or JSON string."""
    if isinstance(raw, SessionFingerprint):
        return raw
    if isinstance(raw, str):
        decoded: object = json.loads(raw)
        if not isinstance(decoded, dict):
            msg = "expected JSON object for SessionFingerprint"
            raise ValueError(msg)
        return parse_session_fingerprint(decoded)
    msg = (
        "WAYBOUND_FINGERPRINT / waybound_fingerprint must be a SessionFingerprint "
        f"or JSON string, got {type(raw).__name__}"
    )
    raise TypeError(msg)


def _parse_str_sequence(raw: object, setting_name: str) -> tuple[str, ...] | None:
    """Validate an optional sequence-of-strings Scrapy setting."""
    if raw is None:
        return None
    if isinstance(raw, str | bytes) or not isinstance(raw, Sequence):
        msg = f"{setting_name} must be a sequence of strings, got {type(raw).__name__}"
        raise TypeError(msg)
    result: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            msg = f"{setting_name} entries must be strings, got {type(item).__name__}"
            raise TypeError(msg)
        result.append(item)
    return tuple(result)


def _parse_optional_int(raw: object, setting_name: str) -> int | None:
    """Validate an optional integer Scrapy setting."""
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        msg = f"{setting_name} must be an int or None, got {type(raw).__name__}"
        raise TypeError(msg)
    return raw


def _normalize_url(url: str) -> str:
    return url.rstrip("/")


def _select_main_document(
    captured: Sequence[CapturedResponse],
    candidate_urls: Sequence[str],
) -> CapturedResponse | None:
    """Pick the most likely main HTML document response from passively captured responses."""
    normalized_targets = {_normalize_url(u) for u in candidate_urls if u}
    for resp in reversed(captured):
        if resp.body is not None and _normalize_url(resp.url) in normalized_targets:
            return resp
    for resp in reversed(captured):
        if (
            resp.body is not None
            and resp.content_type is not None
            and "html" in resp.content_type.lower()
        ):
            return resp
    return None


def _build_browser_response(
    request: Request,
    final_url: str,
    captured: list[CapturedResponse],
    links: list[AccessibilityNode],
    fingerprint: SessionFingerprint | None,
) -> HtmlResponse:
    """Construct a Scrapy `HtmlResponse` from a browser-tier page navigation."""
    main_doc = _select_main_document(captured, (final_url, request.url))
    status = main_doc.status if main_doc is not None else 200
    headers: list[tuple[str, str]] | None = (
        [(h.name, h.value) for h in main_doc.headers]
        if main_doc is not None and main_doc.headers
        else None
    )
    body = main_doc.body.encode("utf-8") if main_doc is not None and main_doc.body else b""
    response = HtmlResponse(
        url=final_url,
        status=status,
        headers=headers,
        body=body,
        encoding="utf-8",
        request=request,
    )
    response.meta["waybound_captured_responses"] = captured
    response.meta["waybound_links"] = links
    response.meta["waybound_fingerprint"] = fingerprint
    return response


def _extract_request_headers(request: Request) -> list[tuple[str, str]]:
    """Decode Scrapy `Request.headers` bytes into `(name, value)` string pairs."""
    pairs: list[tuple[str, str]] = []
    for raw_name, raw_values in request.headers.items():
        name = raw_name.decode("latin1")
        for raw_val in raw_values:
            pairs.append((name, raw_val.decode("latin1")))
    return pairs


def _extract_request_body(request: Request) -> bytes | None:
    """Return raw Scrapy `Request.body` bytes, or `None` if empty."""
    if not request.body:
        return None
    return bytes(request.body)


def _build_handoff_response(request: Request, handoff: HandoffResponse) -> Response:
    """Convert a `HandoffResponse` into the appropriate Scrapy `Response` subclass."""
    url = handoff.url or request.url
    headers = list(handoff.headers)
    body = handoff.content
    content_type = (handoff.header("content-type") or "").lower()

    if "html" in content_type:
        return HtmlResponse(
            url=url,
            status=handoff.status,
            headers=headers,
            body=body,
            encoding="utf-8",
            request=request,
        )
    if any(token in content_type for token in _TEXT_CONTENT_TYPE_TOKENS):
        return TextResponse(
            url=url,
            status=handoff.status,
            headers=headers,
            body=body,
            encoding="utf-8",
            request=request,
        )
    return Response(
        url=url,
        status=handoff.status,
        headers=headers,
        body=body,
        request=request,
    )


async def _await_maybe_deferred_response(
    result: Awaitable[Response] | Deferred[Response] | Response,
) -> Response:
    if isinstance(result, Response):
        return result
    if isinstance(result, Deferred):
        return await maybe_deferred_to_future(result)
    return await result


async def _await_maybe_deferred_none(
    result: Awaitable[None] | Deferred[None] | None,
) -> None:
    if result is None:
        return
    if isinstance(result, Deferred):
        await maybe_deferred_to_future(result)
        return
    await result


class WayboundDownloadHandler:
    """Scrapy Download Handler backed by `waybound.BrowserPool` and `waybound.HandoffHttpClient`.

    Configure in Scrapy settings:

        DOWNLOAD_HANDLERS = {
            "http": "waybound.scrapy.WayboundDownloadHandler",
            "https": "waybound.scrapy.WayboundDownloadHandler",
        }
        TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
    """

    lazy: bool = False

    def __init__(  # noqa: PLR0913
        self,
        crawler: Crawler | None = None,
        *,
        pool: BrowserPool | None = None,
        pool_size: int = 1,
        launch_options: LaunchOptions | None = None,
        isolated_displays: bool = False,
        remote_workers: Sequence[str] | None = None,
        max_uses_per_slot: int | None = None,
        proxies: Sequence[str] | None = None,
        fingerprint: SessionFingerprint | str | None = None,
        fallback_handler: _FallbackDownloadHandler | None = None,
    ) -> None:
        self._crawler = crawler
        self._owns_pool = pool is None
        self._pool: BrowserPool | None = pool
        self._pool_started = False
        self._pool_size = pool_size
        self._launch_options = launch_options
        self._isolated_displays = isolated_displays
        self._remote_workers = tuple(remote_workers) if remote_workers is not None else None
        self._max_uses_per_slot = max_uses_per_slot
        self._proxies = tuple(proxies) if proxies is not None else None
        self._default_fingerprint: SessionFingerprint | None = (
            _parse_fingerprint(fingerprint) if fingerprint is not None else None
        )
        self._daemon_binary: Path | str | None = (
            launch_options.daemon_binary if launch_options is not None else None
        )

        self._fallback_handler: _FallbackDownloadHandler | None = fallback_handler
        self._handoff_client: HandoffHttpClient | None = None
        self._handoff_client_proxy: str | None = None
        self._pool_lock = asyncio.Lock()
        self._handoff_lock = asyncio.Lock()

    @classmethod
    def from_crawler(cls, crawler: Crawler) -> Self:
        """Build a `WayboundDownloadHandler` from Scrapy `crawler.settings`."""
        settings = crawler.settings

        raw_pool: object = settings.get("WAYBOUND_POOL")
        pool: BrowserPool | None = None
        if raw_pool is not None:
            if not isinstance(raw_pool, BrowserPool):
                msg = f"WAYBOUND_POOL must be a BrowserPool, got {type(raw_pool).__name__}"
                raise TypeError(msg)
            pool = raw_pool

        pool_size = settings.getint("WAYBOUND_POOL_SIZE", 1)

        raw_launch: object = settings.get("WAYBOUND_LAUNCH_OPTIONS")
        launch_options: LaunchOptions | None = None
        if raw_launch is not None:
            if not isinstance(raw_launch, LaunchOptions):
                msg = (
                    "WAYBOUND_LAUNCH_OPTIONS must be a LaunchOptions instance, "
                    f"got {type(raw_launch).__name__}"
                )
                raise TypeError(msg)
            launch_options = raw_launch

        isolated_displays = settings.getbool("WAYBOUND_ISOLATED_DISPLAYS", False)
        remote_workers = _parse_str_sequence(
            settings.get("WAYBOUND_REMOTE_WORKERS"), "WAYBOUND_REMOTE_WORKERS"
        )
        max_uses_per_slot = _parse_optional_int(
            settings.get("WAYBOUND_MAX_USES_PER_SLOT"), "WAYBOUND_MAX_USES_PER_SLOT"
        )
        proxies = _parse_str_sequence(settings.get("WAYBOUND_PROXIES"), "WAYBOUND_PROXIES")
        raw_fingerprint: object = settings.get("WAYBOUND_FINGERPRINT")
        fingerprint = _parse_fingerprint(raw_fingerprint) if raw_fingerprint is not None else None

        return cls(
            crawler=crawler,
            pool=pool,
            pool_size=pool_size,
            launch_options=launch_options,
            isolated_displays=isolated_displays,
            remote_workers=remote_workers,
            max_uses_per_slot=max_uses_per_slot,
            proxies=proxies,
            fingerprint=fingerprint,
        )

    @property
    def pool(self) -> BrowserPool | None:
        """Return the configured `BrowserPool`, if initialized or injected."""
        return self._pool

    def _get_fallback_handler(self) -> _FallbackDownloadHandler:
        if self._fallback_handler is None:
            if self._crawler is None:
                msg = (
                    "WayboundDownloadHandler requires a Scrapy Crawler or explicit "
                    "fallback_handler for passthrough requests"
                )
                raise RuntimeError(msg)
            self._fallback_handler = HTTP11DownloadHandler.from_crawler(self._crawler)
        return self._fallback_handler

    async def _ensure_pool(self) -> BrowserPool:
        async with self._pool_lock:
            if self._pool is None:
                self._pool = BrowserPool(
                    size=self._pool_size,
                    launch_options=self._launch_options,
                    proxies=self._proxies,
                    isolated_displays=self._isolated_displays,
                    remote_workers=self._remote_workers,
                    max_uses_per_slot=self._max_uses_per_slot,
                )
            if self._owns_pool and not self._pool_started:
                await self._pool.start()
                self._pool_started = True
            return self._pool

    async def download_request(
        self,
        request: Request,
        spider: Spider | None = None,
    ) -> Response:
        """Download `request` using waybound browser tier, fast HTTP tier, or Scrapy fallback."""
        use_browser = bool(request.meta.get("waybound"))
        use_http = bool(request.meta.get("waybound_http"))

        if use_browser and use_http:
            msg = "Request meta cannot enable both 'waybound' and 'waybound_http'"
            raise ValueError(msg)

        if use_browser:
            return await self._download_browser(request)
        if use_http:
            return await self._download_fast_http(request)
        return await self._download_fallback(request, spider)

    async def _download_fallback(
        self,
        request: Request,
        spider: Spider | None,
    ) -> Response:
        handler = self._get_fallback_handler()
        download_fn = handler.download_request
        sig = inspect.signature(download_fn)
        positional_kinds = (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        params = [p for p in sig.parameters.values() if p.kind in positional_kinds]
        if len(params) >= 2 and spider is not None:  # noqa: PLR2004
            legacy_fn = cast("Callable[[Request, Spider], _FallbackDownloadResult]", download_fn)
            result = legacy_fn(request, spider)
        else:
            result = download_fn(request)
        return await _await_maybe_deferred_response(result)

    async def _download_browser(self, request: Request) -> HtmlResponse:
        pool = await self._ensure_pool()

        raw_proxy: object = request.meta.get("proxy")
        proxy: str | None = raw_proxy if isinstance(raw_proxy, str) and raw_proxy else None

        raw_callback: object = request.meta.get("waybound_page_callback")
        if raw_callback is not None and not callable(raw_callback):
            msg = (
                "request.meta['waybound_page_callback'] must be an async callable, "
                f"got {type(raw_callback).__name__}"
            )
            raise TypeError(msg)

        capture_fp = bool(request.meta.get("waybound_capture_fingerprint"))

        async with pool.acquire(proxy=proxy) as page:
            await page.goto(request.url)

            if raw_callback is not None and callable(raw_callback):
                maybe_coro: object = raw_callback(page, request)
                if inspect.isawaitable(maybe_coro):
                    await maybe_coro

            links = await page.links()
            captured = await page.captured_responses()

            fingerprint: SessionFingerprint | None = None
            if capture_fp:
                try:
                    fingerprint = await page.export_fingerprint()
                except (WayboundDaemonError, OSError, RuntimeError):
                    fingerprint = None

            final_url = (await page.url()) or request.url

        return _build_browser_response(
            request=request,
            final_url=final_url,
            captured=captured,
            links=links,
            fingerprint=fingerprint,
        )

    async def _resolve_handoff_client(
        self,
        fingerprint: SessionFingerprint,
        proxy: str | None,
    ) -> tuple[HandoffHttpClient, bool]:
        """Return `(client, should_close_after_request)`."""
        can_cache = proxy is None and (
            self._default_fingerprint is None or fingerprint == self._default_fingerprint
        )
        async with self._handoff_lock:
            if self._handoff_client is None and can_cache:
                self._handoff_client = await asyncio.to_thread(
                    HandoffHttpClient,
                    fingerprint,
                    proxy=None,
                    daemon_binary=self._daemon_binary,
                )
                self._handoff_client_proxy = None
                return (self._handoff_client, False)

            if (
                self._handoff_client is not None
                and self._handoff_client.fingerprint == fingerprint
                and self._handoff_client_proxy == proxy
            ):
                return (self._handoff_client, False)

        ephemeral = await asyncio.to_thread(
            HandoffHttpClient,
            fingerprint,
            proxy=proxy,
            daemon_binary=self._daemon_binary,
        )
        return (ephemeral, True)

    async def _evict_handoff_client(self, client: HandoffHttpClient) -> None:
        async with self._handoff_lock:
            if self._handoff_client is client:
                self._handoff_client = None
                self._handoff_client_proxy = None
        with contextlib.suppress(OSError, WayboundDaemonError, RuntimeError):
            await asyncio.to_thread(client.close)

    async def _download_fast_http(self, request: Request) -> Response:
        raw_meta_fp: object = request.meta.get("waybound_fingerprint")
        if raw_meta_fp is not None:
            fingerprint = _parse_fingerprint(raw_meta_fp)
        elif self._default_fingerprint is not None:
            fingerprint = self._default_fingerprint
        else:
            msg = (
                "meta['waybound_http'] requires a SessionFingerprint via "
                "request.meta['waybound_fingerprint'] or the WAYBOUND_FINGERPRINT setting"
            )
            raise ValueError(msg)

        raw_proxy: object = request.meta.get("proxy")
        proxy: str | None = raw_proxy if isinstance(raw_proxy, str) and raw_proxy else None

        client, ephemeral = await self._resolve_handoff_client(fingerprint, proxy)
        req_headers = _extract_request_headers(request)
        req_body = _extract_request_body(request)
        try:
            handoff_resp = await asyncio.to_thread(
                client.request,
                request.method,
                request.url,
                headers=req_headers or None,
                body=req_body,
            )
        except WayboundDaemonError as exc:
            if not ephemeral and exc.code in _FATAL_HANDOFF_ERROR_CODES:
                await self._evict_handoff_client(client)
            raise
        finally:
            if ephemeral:
                await asyncio.to_thread(client.close)

        return _build_handoff_response(request, handoff_resp)

    async def close(self) -> None:
        """Close internally-owned `BrowserPool`, `HandoffHttpClient`, and fallback handler."""
        try:
            if self._owns_pool and self._pool is not None:
                await self._pool.close()
        finally:
            try:
                if self._handoff_client is not None:
                    client = self._handoff_client
                    self._handoff_client = None
                    await asyncio.to_thread(client.close)
            finally:
                if self._fallback_handler is not None:
                    await _await_maybe_deferred_none(self._fallback_handler.close())
