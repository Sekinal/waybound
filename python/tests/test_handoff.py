"""End-to-end tests for SessionFingerprint export and BoringSSL/H2 HandoffHttpClient."""

from __future__ import annotations

import base64
import json
import threading
from email.parser import BytesParser
from email.policy import default as email_default_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self) -> None:
        raw_body = self._read_body()
        if self.path == "/binary":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(raw_body)))
            self.end_headers()
            self.wfile.write(raw_body)
            return

        if self.path == "/multipart":
            content_type = self.headers.get("Content-Type", "")
            raw_mime = (
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin1")
                + raw_body
            )
            msg = BytesParser(policy=email_default_policy).parsebytes(raw_mime)
            parts: list[dict[str, object]] = []
            if msg.is_multipart():
                for part in msg.iter_parts():
                    part_bytes = part.get_payload(decode=True)
                    parts.append(
                        {
                            "name": part.get_param("name", header="content-disposition"),
                            "filename": part.get_filename(),
                            "content_type": part.get_content_type(),
                            "payload_b64": base64.b64encode(
                                part_bytes if isinstance(part_bytes, bytes) else b""
                            ).decode("ascii"),
                        }
                    )
            reply = json.dumps({"content_type": content_type, "parts": parts}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
            return

        self.send_response(404)
        self.end_headers()

    def do_PATCH(self) -> None:
        raw_body = self._read_body()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(raw_body)))
        self.end_headers()
        self.wfile.write(raw_body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: ARG002
        return


@pytest.fixture
def local_http_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
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
        assert resp.text == resp.body
        assert resp.content == resp.body.encode("utf-8")


def test_handoff_binary_roundtrip_and_patch(local_http_url: str) -> None:
    fp = SessionFingerprint(tls=None, http2=None, default_headers=(), cookies=())
    payload = bytes(range(256))

    with HandoffHttpClient(fp) as client:
        resp = client.post(
            f"{local_http_url}/binary",
            headers={"Content-Type": "application/octet-stream"},
            body=payload,
        )
        assert resp.status == 200
        assert resp.content == payload

        patched = client.patch(
            f"{local_http_url}/patch",
            headers={"Content-Type": "application/octet-stream"},
            body=payload[::-1],
        )
        assert patched.status == 200
        assert patched.content == payload[::-1]


def test_handoff_multipart_form_upload(local_http_url: str) -> None:
    fp = SessionFingerprint(tls=None, http2=None, default_headers=(), cookies=())
    binary_doc = bytes(range(256))
    raw_blob = b"\x00\xfe\xff\x10"

    with HandoffHttpClient(fp) as client:
        resp = client.post(
            f"{local_http_url}/multipart",
            data={"title": "Quarterly Report", "tag": "finance"},
            files={
                "doc": ("sample.bin", binary_doc, "application/octet-stream"),
                "raw": raw_blob,
            },
        )
        assert resp.status == 200
        parsed = resp.json()
        assert isinstance(parsed, dict)
        assert str(parsed["content_type"]).startswith("multipart/form-data; boundary=")

        parts = parsed["parts"]
        assert isinstance(parts, list)
        by_name: dict[str, dict[str, object]] = {}
        for entry in parts:
            assert isinstance(entry, dict)
            by_name[str(entry["name"])] = entry

        assert set(by_name.keys()) == {"title", "tag", "doc", "raw"}
        assert base64.b64decode(str(by_name["title"]["payload_b64"])) == b"Quarterly Report"
        assert base64.b64decode(str(by_name["tag"]["payload_b64"])) == b"finance"

        assert by_name["doc"]["filename"] == "sample.bin"
        assert by_name["doc"]["content_type"] == "application/octet-stream"
        assert base64.b64decode(str(by_name["doc"]["payload_b64"])) == binary_doc

        assert by_name["raw"]["filename"] == "raw"
        assert by_name["raw"]["content_type"] == "application/octet-stream"
        assert base64.b64decode(str(by_name["raw"]["payload_b64"])) == raw_blob

        with pytest.raises(ValueError, match="specify at most one"):
            client.post(f"{local_http_url}/multipart", body=b"abc", files={"raw": b"def"})
