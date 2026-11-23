"""End-to-end tests for SessionFingerprint export and BoringSSL/H2 HandoffHttpClient."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

import pytest

from waybound import (
    AsyncHandoffHttpClient,
    CapturedCookie,
    HandoffHttpClient,
    HeaderEntry,
    LaunchOptions,
    SessionFingerprint,
    launch,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/protected":
            cookie_hdr = self.headers.get("Cookie", "")
            if "token=fresh" not in cookie_hdr:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"expired"}')
                return

        payload = {
            "path": self.path,
            "user_agent": self.headers.get("User-Agent"),
            "cookie": self.headers.get("Cookie"),
            "custom": self.headers.get("X-Test-Header"),
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "server_ck=hello; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
        return


@pytest.fixture
def local_http_url() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_export_fingerprint_ipc_roundtrip() -> None:
    with launch(LaunchOptions(backend="mock")) as page:
        fp = page.export_fingerprint()
        assert fp.tls is None
        assert fp.http2 is None
        assert fp.default_headers == ()
        assert fp.cookies == ()


def test_handoff_client_replays_headers_cookies_and_auto_refreshes(
    local_http_url: str,
) -> None:
    stale_fp = SessionFingerprint(
        tls=None,
        http2=None,
        default_headers=(
            HeaderEntry(name="user-agent", value="WayboundTestChrome/140.0"),
            HeaderEntry(name="accept-language", value="en-US,en;q=0.9"),
        ),
        cookies=(
            CapturedCookie(
                name="token",
                value="stale",
                domain="127.0.0.1",
                path="/",
                secure=False,
                http_only=False,
            ),
        ),
    )

    refreshed_calls = 0

    def refresh_session() -> SessionFingerprint:
        nonlocal refreshed_calls
        refreshed_calls += 1
        return SessionFingerprint(
            tls=None,
            http2=None,
            default_headers=stale_fp.default_headers,
            cookies=(
                CapturedCookie(
                    name="token",
                    value="fresh",
                    domain="127.0.0.1",
                    path="/",
                    secure=False,
                    http_only=False,
                ),
            ),
        )

    with HandoffHttpClient.from_json(
        stale_fp.to_json(),
        on_refresh=refresh_session,
        refresh_statuses=(403,),
    ) as client:
        resp = client.get(f"{local_http_url}/echo", headers={"X-Test-Header": "ok"})
        assert resp.status == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert data["user_agent"] == "WayboundTestChrome/140.0"
        assert data["custom"] == "ok"
        assert "token=stale" in str(data["cookie"])

        # Server Set-Cookie should now appear in client.cookies()
        cookie_names = {c.name for c in client.cookies()}
        assert "server_ck" in cookie_names

        # Hitting /protected returns 403 with stale cookie -> auto-refreshes -> retries -> 200
        protected = client.get(f"{local_http_url}/protected")
        assert protected.status == 200
        assert refreshed_calls == 1


@pytest.mark.asyncio
async def test_async_handoff_client_requests(local_http_url: str) -> None:
    fp = SessionFingerprint(
        tls=None,
        http2=None,
        default_headers=(HeaderEntry(name="user-agent", value="WayboundAsync/1.0"),),
        cookies=(),
    )
    async with AsyncHandoffHttpClient(fp) as client:
        resp = await client.get(f"{local_http_url}/async-check")
        assert resp.status == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert data["path"] == "/async-check"
        assert data["user_agent"] == "WayboundAsync/1.0"
