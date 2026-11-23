"""Unit and live daemon E2E tests for HAR 1.2 export and `TraceRecorder`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

import pytest

from waybound import (
    REDACTED_VALUE,
    SENSITIVE_HEADERS,
    CapturedResponse,
    HttpHeader,
    LaunchOptions,
    Page,
    Role,
    TraceRecorder,
    launch,
    launch_async,
    responses_to_har,
)
from waybound.async_client import AsyncPage

if TYPE_CHECKING:
    from pathlib import Path

    from waybound.types import AccessibilityNode, LocatorQuery, Transport

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
DAEMON_BIN = REPO_ROOT / "target" / "debug" / "waybound-daemon"


def _as_dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def _as_list(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast("list[object]", value)


def test_responses_to_har_spec_structure_and_query_parsing() -> None:
    responses = [
        CapturedResponse(
            url="https://api.example.com/search?q=tokyo&tag=a&tag=b&empty=",
            status=200,
            content_type="application/json; charset=utf-8",
            body='{"ok":true,"city":"東京"}',
            headers=(
                HttpHeader("Content-Type", "application/json; charset=utf-8"),
                HttpHeader("X-Trace", "abc123"),
            ),
            request_method="GET",
            request_headers=(HttpHeader("Accept", "application/json"),),
            captured_at_ms=1_700_000_000_123,
        ),
        CapturedResponse(
            url="https://api.example.com/submit",
            status=201,
            content_type=None,
            body=None,
            headers=(),
            request_method="POST",
            request_headers=(HttpHeader("Content-Type", "application/json"),),
            request_body='{"x":1}',
            captured_at_ms=1_700_000_001_000,
        ),
        CapturedResponse(
            url="https://api.example.com/raw",
            status=599,
            content_type=None,
            body="raw",
            request_method=None,
            request_body="bytes",
        ),
    ]

    har = responses_to_har(responses)
    log = _as_dict(har["log"])
    assert log["version"] == "1.2"
    creator = _as_dict(log["creator"])
    assert creator["name"] == "waybound"
    assert isinstance(creator["version"], str)
    assert creator["version"]

    entries = _as_list(log["entries"])
    assert len(entries) == 3

    first = _as_dict(entries[0])
    assert first["startedDateTime"] == "2023-11-14T22:13:20.123Z"
    assert first["time"] == 0
    assert first["cache"] == {}
    assert first["timings"] == {"send": 0, "wait": 0, "receive": 0}

    req0 = _as_dict(first["request"])
    assert req0["method"] == "GET"
    assert req0["httpVersion"] == "HTTP/1.1"
    assert req0["headersSize"] == -1
    assert req0["bodySize"] == 0
    assert "postData" not in req0
    assert req0["queryString"] == [
        {"name": "q", "value": "tokyo"},
        {"name": "tag", "value": "a"},
        {"name": "tag", "value": "b"},
        {"name": "empty", "value": ""},
    ]

    resp0 = _as_dict(first["response"])
    assert resp0["status"] == 200
    assert resp0["statusText"] == "OK"
    assert resp0["redirectURL"] == ""
    content0 = _as_dict(resp0["content"])
    expected_bytes = len('{"ok":true,"city":"東京"}'.encode())
    assert content0["size"] == expected_bytes
    assert resp0["bodySize"] == expected_bytes
    assert content0["mimeType"] == "application/json; charset=utf-8"
    assert content0["text"] == '{"ok":true,"city":"東京"}'

    second = _as_dict(entries[1])
    req1 = _as_dict(second["request"])
    assert req1["method"] == "POST"
    assert req1["bodySize"] == len('{"x":1}')
    assert req1["postData"] == {"mimeType": "application/json", "text": '{"x":1}'}
    resp1 = _as_dict(second["response"])
    assert resp1["statusText"] == "Created"
    assert _as_dict(resp1["content"])["text"] == ""

    third = _as_dict(entries[2])
    assert isinstance(third["startedDateTime"], str)
    assert third["startedDateTime"].endswith("Z")
    req2 = _as_dict(third["request"])
    assert req2["method"] == "GET"
    assert req2["postData"] == {"mimeType": "application/octet-stream", "text": "bytes"}
    resp2 = _as_dict(third["response"])
    assert resp2["statusText"] == ""


def test_responses_to_har_redacts_sensitive_headers() -> None:
    resp = CapturedResponse(
        url="https://secure.example.com/me",
        status=200,
        content_type="application/json",
        body="{}",
        headers=(
            HttpHeader("Set-Cookie", "sid=secret-cookie; HttpOnly"),
            HttpHeader("X-Request-Id", "req-42"),
        ),
        request_method="GET",
        request_headers=(
            HttpHeader("Authorization", "Bearer super-secret"),
            HttpHeader("Cookie", "sid=secret-cookie"),
            HttpHeader("X-API-Key", "key-123"),
            HttpHeader("Accept", "*/*"),
        ),
    )

    unredacted = responses_to_har([resp])
    entry_raw = _as_dict(_as_list(_as_dict(unredacted["log"])["entries"])[0])
    req_headers_raw = _as_list(_as_dict(entry_raw["request"])["headers"])
    assert {"name": "Authorization", "value": "Bearer super-secret"} in req_headers_raw

    redacted = responses_to_har([resp], redact_headers=SENSITIVE_HEADERS)
    entry = _as_dict(_as_list(_as_dict(redacted["log"])["entries"])[0])
    req_headers = _as_list(_as_dict(entry["request"])["headers"])
    resp_headers = _as_list(_as_dict(entry["response"])["headers"])

    assert req_headers == [
        {"name": "Authorization", "value": REDACTED_VALUE},
        {"name": "Cookie", "value": REDACTED_VALUE},
        {"name": "X-API-Key", "value": REDACTED_VALUE},
        {"name": "Accept", "value": "*/*"},
    ]
    assert resp_headers == [
        {"name": "Set-Cookie", "value": REDACTED_VALUE},
        {"name": "X-Request-Id", "value": "req-42"},
    ]


class _CrashingTransport:
    """Minimal transport stub whose capture methods all fail to test crash resilience."""

    def snapshot_tree(self) -> list[AccessibilityNode]:
        msg = "daemon crashed during snapshot_tree"
        raise RuntimeError(msg)

    def current_url(self) -> str | None:
        msg = "daemon crashed during current_url"
        raise RuntimeError(msg)

    def screenshot(self, path: str) -> None:
        msg = f"daemon crashed during screenshot({path})"
        raise RuntimeError(msg)

    def captured_responses(self, *, url_contains: str | None = None) -> list[CapturedResponse]:
        _ = url_contains
        msg = "daemon crashed during captured_responses"
        raise RuntimeError(msg)

    def locate_all(self, query: LocatorQuery) -> list[AccessibilityNode]:
        raise NotImplementedError


def test_trace_recorder_never_masks_original_exception_when_captures_fail(tmp_path: Path) -> None:
    page = Page(cast("Transport", _CrashingTransport()))
    trace_dir = tmp_path / "crashed-trace"

    class _CallerError(ValueError):
        pass

    def _run_crashing() -> None:
        with TraceRecorder(page, trace_dir, on_error_only=True) as trace:
            trace.record_action("click_submit", metadata={"step": 1})
            msg = "original failure"
            raise _CallerError(msg)

    with pytest.raises(_CallerError, match="original failure"):
        _run_crashing()

    assert trace_dir.exists()
    manifest = _as_dict(json.loads((trace_dir / "manifest.json").read_text(encoding="utf-8")))
    assert manifest["failed"] is True
    assert manifest["har_entries"] == 0

    lines = (trace_dir / "timeline.jsonl").read_text(encoding="utf-8").strip().splitlines()
    events = [_as_dict(json.loads(line)) for line in lines]
    assert events[0]["action"] == "click_submit"
    failure_events = [e for e in events if e["action"] == "snapshot:failure"]
    assert len(failure_events) == 1
    err_text = str(failure_events[0]["error"])
    assert "_CallerError: original failure" in err_text
    assert "screenshot capture failed" in err_text
    assert "tree capture failed" in err_text
    assert any(e["action"] == "capture_har_error" for e in events)


async def test_async_trace_recorder_never_masks_original_exception(tmp_path: Path) -> None:
    page = AsyncPage(Page(cast("Transport", _CrashingTransport())))
    trace_dir = tmp_path / "async-crashed-trace"

    async def _run_async_crashing() -> None:
        async with TraceRecorder(page, trace_dir, on_error_only=True) as trace:
            trace.record_action("async_step")
            msg = "async boom"
            raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="async boom"):
        await _run_async_crashing()

    assert trace_dir.exists()
    manifest = _as_dict(json.loads((trace_dir / "manifest.json").read_text(encoding="utf-8")))
    assert manifest["failed"] is True


def test_sync_trace_bundle_e2e_mock_daemon(tmp_path: Path) -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    trace_dir = tmp_path / "sync-full"
    with (
        launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page,
        TraceRecorder(page, trace_dir, redact_headers=SENSITIVE_HEADERS) as trace,
    ):
        trace.record_action("navigate", metadata={"target": "mock"})
        page.get_by_role(Role.TEXTBOX, name="Origin").fill("NRT")
        snap_event = trace.record_snapshot("after fill", metadata={"field": "Origin"})
        assert snap_event["url"] == "https://mock.waybound.local/"
        assert snap_event["screenshot"] == "screenshots/002_after_fill.png"
        assert snap_event["tree"] == "trees/002_after_fill.json"

    manifest = _as_dict(json.loads((trace_dir / "manifest.json").read_text(encoding="utf-8")))
    assert manifest["version"] == 1
    assert manifest["failed"] is False
    assert manifest["event_count"] == 2
    assert manifest["har_entries"] == 0
    assert isinstance(manifest["created_at"], str)

    shot_bytes = (trace_dir / "screenshots" / "002_after_fill.png").read_bytes()
    assert shot_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    tree_nodes = _as_list(
        json.loads((trace_dir / "trees" / "002_after_fill.json").read_text(encoding="utf-8"))
    )
    assert len(tree_nodes) == 5
    assert _as_dict(tree_nodes[0])["name"] == "Origin"

    har = _as_dict(json.loads((trace_dir / "network.har").read_text(encoding="utf-8")))
    assert _as_dict(har["log"])["version"] == "1.2"
    assert _as_list(_as_dict(har["log"])["entries"]) == []

    timeline = (trace_dir / "timeline.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(timeline) == 2


def test_sync_trace_on_error_only_e2e_mock_daemon(tmp_path: Path) -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    ok_dir = tmp_path / "ok-discarded"
    fail_dir = tmp_path / "fail-retained"

    with launch(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        with TraceRecorder(page, ok_dir, on_error_only=True) as trace:
            trace.record_snapshot("before_ok")
        assert not ok_dir.exists()

        def _run_failing_checkout() -> None:
            with TraceRecorder(page, fail_dir, on_error_only=True) as trace:
                trace.record_action("submit_order")
                msg = "checkout failed"
                raise ValueError(msg)

        with pytest.raises(ValueError, match="checkout failed"):
            _run_failing_checkout()

    assert fail_dir.exists()
    manifest = _as_dict(json.loads((fail_dir / "manifest.json").read_text(encoding="utf-8")))
    assert manifest["failed"] is True
    assert manifest["event_count"] == 2

    lines = (fail_dir / "timeline.jsonl").read_text(encoding="utf-8").strip().splitlines()
    fail_event = _as_dict(json.loads(lines[-1]))
    assert fail_event["action"] == "snapshot:failure"
    assert "ValueError: checkout failed" in str(fail_event["error"])
    assert fail_event["screenshot"] == "screenshots/002_failure.png"
    assert (
        (fail_dir / "screenshots" / "002_failure.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    )
    assert (fail_dir / "trees" / "002_failure.json").exists()
    assert (fail_dir / "network.har").exists()


async def test_async_trace_bundle_e2e_mock_daemon(tmp_path: Path) -> None:
    if not DAEMON_BIN.exists():
        pytest.skip("waybound-daemon binary not built yet (run cargo build)")

    ok_dir = tmp_path / "async-ok-discarded"
    full_dir = tmp_path / "async-full"
    fail_dir = tmp_path / "async-fail"

    async with launch_async(LaunchOptions(backend="mock", daemon_binary=DAEMON_BIN)) as page:
        async with TraceRecorder(page, ok_dir, on_error_only=True) as trace:
            await trace.arecord_snapshot("ok_step")
        assert not ok_dir.exists()

        async with TraceRecorder(page, full_dir) as trace:
            trace.record_action("start")
            await page.get_by_role(Role.BUTTON, name="Search").click()
            ev = await trace.arecord_snapshot("after_click")
            assert ev["screenshot"] == "screenshots/002_after_click.png"
            assert ev["tree"] == "trees/002_after_click.json"

        async def _run_async_fail() -> None:
            async with TraceRecorder(page, fail_dir, on_error_only=True) as trace:
                trace.record_action("about_to_fail")
                msg = "async failure"
                raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="async failure"):
            await _run_async_fail()

    assert (full_dir / "manifest.json").exists()
    assert (
        (full_dir / "screenshots" / "002_after_click.png")
        .read_bytes()
        .startswith(b"\x89PNG\r\n\x1a\n")
    )
    assert (full_dir / "trees" / "002_after_click.json").exists()
    assert (full_dir / "network.har").exists()

    fail_manifest = _as_dict(json.loads((fail_dir / "manifest.json").read_text(encoding="utf-8")))
    assert fail_manifest["failed"] is True
    assert (fail_dir / "screenshots" / "002_failure.png").exists()
