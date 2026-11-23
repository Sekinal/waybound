"""Opt-in production trace bundle recorder and HAR 1.2 exporter."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import shutil
import time
from datetime import UTC, datetime
from http import HTTPStatus
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import TYPE_CHECKING, Self
from urllib.parse import parse_qsl, urlsplit

from waybound.async_client import AsyncPage

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import TracebackType

    from waybound.client import Page
    from waybound.types import AccessibilityNode, CapturedResponse, HttpHeader

SENSITIVE_HEADERS: tuple[str, ...] = (
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
)
REDACTED_VALUE = "[REDACTED]"
TRACE_MANIFEST_VERSION = 1

_SLUG_RE = re.compile(r"[^a-z0-9_-]+")
_MAX_SLUG_LEN = 64


def _sdk_version() -> str:
    try:
        return package_version("waybound")
    except PackageNotFoundError:
        return "0.5.0"


def _iso_utc_from_ms(ts_ms: int | None) -> str:
    if ts_ms is not None:
        try:
            dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=UTC)
        except (ValueError, OverflowError, OSError):
            dt = datetime.now(UTC)
    else:
        dt = datetime.now(UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _status_text(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ""


def _parse_query_string(url: str) -> list[dict[str, str]]:
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    if not query:
        return []
    return [{"name": k, "value": v} for k, v in parse_qsl(query, keep_blank_values=True)]


def _format_headers(
    headers: Sequence[HttpHeader],
    redacted: frozenset[str],
) -> list[dict[str, str]]:
    return [
        {
            "name": h.name,
            "value": REDACTED_VALUE if h.name.lower() in redacted else h.value,
        }
        for h in headers
    ]


def _first_header(headers: Sequence[HttpHeader], name: str) -> str | None:
    wanted = name.lower()
    for header in headers:
        if header.name.lower() == wanted:
            return header.value
    return None


def _utf8_byte_len(text: str | None) -> int:
    return len(text.encode("utf-8")) if text is not None else 0


def responses_to_har(
    responses: Sequence[CapturedResponse],
    *,
    redact_headers: Sequence[str] = (),
) -> dict[str, object]:
    """Convert captured HTTP responses into a HAR 1.2 compliant dictionary.

    Pass `redact_headers=SENSITIVE_HEADERS` (or custom header names) to replace
    matching request and response header values with `"[REDACTED]"`.
    """
    redacted = frozenset(name.lower() for name in redact_headers)
    entries: list[dict[str, object]] = []

    for resp in responses:
        req_body_size = _utf8_byte_len(resp.request_body)
        request_obj: dict[str, object] = {
            "method": resp.request_method or "GET",
            "url": resp.url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _format_headers(resp.request_headers, redacted),
            "queryString": _parse_query_string(resp.url),
            "headersSize": -1,
            "bodySize": req_body_size,
        }
        if resp.request_body is not None:
            req_mime = (
                _first_header(resp.request_headers, "content-type") or "application/octet-stream"
            )
            request_obj["postData"] = {
                "mimeType": req_mime,
                "text": resp.request_body,
            }

        resp_body_size = _utf8_byte_len(resp.body)
        resp_mime = (
            resp.content_type
            or _first_header(resp.headers, "content-type")
            or "application/octet-stream"
        )
        response_obj: dict[str, object] = {
            "status": resp.status,
            "statusText": _status_text(resp.status),
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": _format_headers(resp.headers, redacted),
            "content": {
                "size": resp_body_size,
                "mimeType": resp_mime,
                "text": resp.body if resp.body is not None else "",
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": resp_body_size,
        }

        entries.append(
            {
                "startedDateTime": _iso_utc_from_ms(resp.captured_at_ms),
                "time": 0,
                "request": request_obj,
                "response": response_obj,
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
        )

    return {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "waybound",
                "version": _sdk_version(),
            },
            "entries": entries,
        }
    }


def _slugify(label: str) -> str:
    slug = _SLUG_RE.sub("_", label.strip().lower()).strip("_")
    if not slug:
        return "snapshot"
    return slug[:_MAX_SLUG_LEN]


def _serialize_node(node: AccessibilityNode) -> dict[str, object]:
    return {
        "id": node.id,
        "role": node.role.value,
        "name": node.name,
        "value": node.value,
        "bounds": {
            "x": node.bounds.x,
            "y": node.bounds.y,
            "width": node.bounds.width,
            "height": node.bounds.height,
        },
        "focused": node.focused,
        "checked": node.checked,
        "disabled": node.disabled,
        "expanded": node.expanded,
        "url": node.url,
    }


def _join_errors(base: str | None, extra: list[str]) -> str | None:
    parts: list[str] = []
    if base:
        parts.append(base)
    parts.extend(extra)
    return "; ".join(parts) if parts else None


class TraceRecorder:
    """Opt-in production trace bundle recorder for sync `Page` and async `AsyncPage`.

    Writes a self-contained directory containing:
    - `manifest.json`: trace metadata (`version`, `failed`, `event_count`, `har_entries`,
      `created_at`)
    - `timeline.jsonl`: ordered action/snapshot events
    - `screenshots/*.png`: PNG window/screen captures
    - `trees/*.json`: OS accessibility tree snapshots
    - `network.har`: HAR 1.2 archive of passively decrypted HTTP responses
    """

    def __init__(  # noqa: PLR0913
        self,
        page: Page | AsyncPage,
        output_dir: str | Path,
        *,
        on_error_only: bool = False,
        capture_screenshots: bool = True,
        capture_trees: bool = True,
        capture_har: bool = True,
        redact_headers: Sequence[str] = (),
    ) -> None:
        self._page = page
        self._output_dir = Path(output_dir)
        self._on_error_only = on_error_only
        self._capture_screenshots = capture_screenshots
        self._capture_trees = capture_trees
        self._capture_har = capture_har
        self._redact_headers = tuple(redact_headers)
        self._seq = 0
        self._event_count = 0
        self._finalized = False
        self._finalized_path: Path | None = None
        self._checked_output_dir = False
        self._created_output_dir = False
        self._created_files: set[Path] = set()
        self._created_subdirs: set[Path] = set()

    @property
    def output_dir(self) -> Path:
        """Directory where the trace bundle is staged and written."""
        return self._output_dir

    def _ensure_output_dir(self) -> None:
        if not self._checked_output_dir:
            self._checked_output_dir = True
            self._created_output_dir = not self._output_dir.exists()
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_dirs(self) -> None:
        self._ensure_output_dir()
        if self._capture_screenshots:
            shots_dir = self._output_dir / "screenshots"
            if not shots_dir.exists():
                self._created_subdirs.add(shots_dir)
            shots_dir.mkdir(parents=True, exist_ok=True)
        if self._capture_trees:
            trees_dir = self._output_dir / "trees"
            if not trees_dir.exists():
                self._created_subdirs.add(trees_dir)
            trees_dir.mkdir(parents=True, exist_ok=True)

    def _cleanup_on_success(self) -> None:
        if self._created_output_dir:
            shutil.rmtree(self._output_dir, ignore_errors=True)
            return
        for file_path in self._created_files:
            with contextlib.suppress(OSError):
                file_path.unlink(missing_ok=True)
        for subdir in self._created_subdirs:
            with contextlib.suppress(OSError):
                subdir.rmdir()

    def _append_event(  # noqa: PLR0913
        self,
        *,
        seq: int,
        action: str,
        url: str | None = None,
        metadata: Mapping[str, object] | None = None,
        screenshot: str | None = None,
        tree: str | None = None,
        error: str | None = None,
    ) -> dict[str, object]:
        self._ensure_output_dir()
        event: dict[str, object] = {
            "ts_ms": int(time.time() * 1000),
            "seq": seq,
            "action": action,
            "url": url,
            "metadata": dict(metadata) if metadata is not None else {},
            "screenshot": screenshot,
            "tree": tree,
            "error": error,
        }
        timeline_path = self._output_dir / "timeline.jsonl"
        if not timeline_path.exists():
            self._created_files.add(timeline_path)
        with timeline_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
        self._event_count += 1
        return event

    def record_action(
        self,
        name: str,
        *,
        metadata: Mapping[str, object] | None = None,
        error: str | None = None,
        url: str | None = None,
    ) -> dict[str, object]:
        """Append a structured action event to `timeline.jsonl`."""
        self._seq += 1
        return self._append_event(
            seq=self._seq,
            action=name,
            url=url,
            metadata=metadata,
            error=error,
        )

    def record_snapshot(
        self,
        label: str,
        *,
        metadata: Mapping[str, object] | None = None,
        error: str | None = None,
    ) -> dict[str, object]:
        """Capture URL, PNG screenshot, and AX tree JSON (sync `Page` only)."""
        if isinstance(self._page, AsyncPage):
            msg = "TraceRecorder.record_snapshot() requires a sync Page; use arecord_snapshot()"
            raise TypeError(msg)

        self._ensure_dirs()
        self._seq += 1
        seq = self._seq
        slug = _slugify(label)
        capture_errors: list[str] = []

        url: str | None = None
        try:
            url = self._page.url()
        except Exception as exc:
            capture_errors.append(f"url capture failed: {exc}")

        screenshot_rel: str | None = None
        if self._capture_screenshots:
            rel = f"screenshots/{seq:03d}_{slug}.png"
            shot_path = self._output_dir / rel
            try:
                self._page.screenshot(shot_path)
                self._created_files.add(shot_path)
                screenshot_rel = rel
            except Exception as exc:
                capture_errors.append(f"screenshot capture failed: {exc}")

        tree_rel: str | None = None
        if self._capture_trees:
            rel = f"trees/{seq:03d}_{slug}.json"
            tree_path = self._output_dir / rel
            try:
                nodes = self._page.snapshot_tree()
                serialized = [_serialize_node(node) for node in nodes]
                tree_path.write_text(json.dumps(serialized), encoding="utf-8")
                self._created_files.add(tree_path)
                tree_rel = rel
            except Exception as exc:
                capture_errors.append(f"tree capture failed: {exc}")

        return self._append_event(
            seq=seq,
            action=f"snapshot:{label}",
            url=url,
            metadata=metadata,
            screenshot=screenshot_rel,
            tree=tree_rel,
            error=_join_errors(error, capture_errors),
        )

    async def arecord_snapshot(
        self,
        label: str,
        *,
        metadata: Mapping[str, object] | None = None,
        error: str | None = None,
    ) -> dict[str, object]:
        """Capture URL, PNG screenshot, and AX tree JSON asynchronously."""
        if not isinstance(self._page, AsyncPage):
            return await asyncio.to_thread(
                self.record_snapshot, label, metadata=metadata, error=error
            )

        self._ensure_dirs()
        self._seq += 1
        seq = self._seq
        slug = _slugify(label)
        capture_errors: list[str] = []

        url: str | None = None
        try:
            url = await self._page.url()
        except Exception as exc:
            capture_errors.append(f"url capture failed: {exc}")

        screenshot_rel: str | None = None
        if self._capture_screenshots:
            rel = f"screenshots/{seq:03d}_{slug}.png"
            shot_path = self._output_dir / rel
            try:
                await self._page.screenshot(shot_path)
                self._created_files.add(shot_path)
                screenshot_rel = rel
            except Exception as exc:
                capture_errors.append(f"screenshot capture failed: {exc}")

        tree_rel: str | None = None
        if self._capture_trees:
            rel = f"trees/{seq:03d}_{slug}.json"
            tree_path = self._output_dir / rel
            try:
                nodes = await self._page.snapshot_tree()
                serialized = [_serialize_node(node) for node in nodes]
                tree_path.write_text(json.dumps(serialized), encoding="utf-8")
                self._created_files.add(tree_path)
                tree_rel = rel
            except Exception as exc:
                capture_errors.append(f"tree capture failed: {exc}")

        return self._append_event(
            seq=seq,
            action=f"snapshot:{label}",
            url=url,
            metadata=metadata,
            screenshot=screenshot_rel,
            tree=tree_rel,
            error=_join_errors(error, capture_errors),
        )

    def _write_har(self, responses: Sequence[CapturedResponse]) -> int:
        har = responses_to_har(responses, redact_headers=self._redact_headers)
        (self._output_dir / "network.har").write_text(json.dumps(har, indent=2), encoding="utf-8")
        return len(responses)

    def _write_manifest(self, *, failed: bool, har_entries: int) -> None:
        manifest: dict[str, object] = {
            "version": TRACE_MANIFEST_VERSION,
            "failed": failed,
            "event_count": self._event_count,
            "har_entries": har_entries,
            "created_at": _iso_utc_from_ms(None),
        }
        (self._output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

    def finalize(self, *, failed: bool = False, error: str | None = None) -> Path | None:
        """Finalize the trace bundle (sync `Page`). Returns the bundle `Path` or `None`."""
        if self._finalized:
            return self._finalized_path
        self._finalized = True

        if self._on_error_only and not failed:
            self._cleanup_on_success()
            self._finalized_path = None
            return None

        if isinstance(self._page, AsyncPage):
            msg = "TraceRecorder.finalize() requires a sync Page; use afinalize()"
            raise TypeError(msg)

        self._ensure_dirs()
        if failed:
            self.record_snapshot("failure", error=error)

        har_entries = 0
        if self._capture_har:
            responses: list[CapturedResponse] = []
            try:
                responses = self._page.captured_responses()
            except Exception as exc:
                self.record_action("capture_har_error", error=str(exc))
            har_entries = self._write_har(responses)

        self._write_manifest(failed=failed, har_entries=har_entries)
        self._finalized_path = self._output_dir
        return self._output_dir

    async def afinalize(self, *, failed: bool = False, error: str | None = None) -> Path | None:
        """Finalize the trace bundle asynchronously. Returns the bundle `Path` or `None`."""
        if self._finalized:
            return self._finalized_path
        self._finalized = True

        if self._on_error_only and not failed:
            self._cleanup_on_success()
            self._finalized_path = None
            return None

        if not isinstance(self._page, AsyncPage):
            # Reset flag briefly so sync finalize executes cleanly on worker thread.
            self._finalized = False
            return await asyncio.to_thread(self.finalize, failed=failed, error=error)

        self._ensure_dirs()
        if failed:
            await self.arecord_snapshot("failure", error=error)

        har_entries = 0
        if self._capture_har:
            responses: list[CapturedResponse] = []
            try:
                responses = await self._page.captured_responses()
            except Exception as exc:
                self.record_action("capture_har_error", error=str(exc))
            har_entries = self._write_har(responses)

        self._write_manifest(failed=failed, har_entries=har_entries)
        self._finalized_path = self._output_dir
        return self._output_dir

    def __enter__(self) -> Self:
        self._ensure_dirs()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        failed = exc_type is not None
        error = f"{exc_type.__name__}: {exc_val}" if exc_type is not None else None
        if failed:
            with contextlib.suppress(Exception):
                self.finalize(failed=True, error=error)
        else:
            self.finalize(failed=False)

    async def __aenter__(self) -> Self:
        self._ensure_dirs()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        failed = exc_type is not None
        error = f"{exc_type.__name__}: {exc_val}" if exc_type is not None else None
        if failed:
            with contextlib.suppress(Exception):
                await self.afinalize(failed=True, error=error)
        else:
            await self.afinalize(failed=False)
