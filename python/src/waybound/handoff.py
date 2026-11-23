"""Browser-to-HTTP handoff client replaying captured BoringSSL + HTTP/2 fingerprints."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import secrets
import subprocess
import threading
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from waybound.transport import WayboundDaemonError, parse_session_fingerprint
from waybound.types import CapturedCookie, SessionFingerprint

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping
    from pathlib import Path
    from types import TracebackType

type MultipartFile = tuple[str, bytes] | tuple[str, bytes, str] | bytes


@dataclass(frozen=True, slots=True)
class HandoffResponse:
    """HTTP response returned by [`HandoffHttpClient`] or [`AsyncHandoffHttpClient`]."""

    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: str
    content: bytes = b""

    def __post_init__(self) -> None:
        if not self.content and self.body:
            object.__setattr__(self, "content", self.body.encode("utf-8"))

    @property
    def text(self) -> str:
        """Return the response body decoded as UTF-8 text."""
        return self.body

    def json(self) -> object:
        """Parse and return the response body as JSON."""
        return json.loads(self.body)

    def header(self, name: str) -> str | None:
        """Return the first response header value matching `name` (case-insensitive)."""
        target = name.lower()
        for k, v in self.headers:
            if k.lower() == target:
                return v
        return None


def _normalize_headers(
    headers: Mapping[str, str] | list[tuple[str, str]] | None,
) -> list[list[str]]:
    if headers is None:
        return []
    if isinstance(headers, list):
        return [[str(k), str(v)] for k, v in headers]
    return [[str(k), str(v)] for k, v in headers.items()]


def _escape_disposition_param(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", "")


def _sanitize_header_value(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


def _encode_multipart(
    *,
    data: Mapping[str, str] | None,
    files: Mapping[str, MultipartFile],
) -> tuple[bytes, str]:
    """Encode `data` and `files` as an RFC 7578 `multipart/form-data` payload."""
    boundary = f"----WayboundBoundary{secrets.token_hex(16)}"
    boundary_bytes = boundary.encode("ascii")
    chunks: list[bytes] = []

    if data is not None:
        for field_name, field_value in data.items():
            escaped_name = _escape_disposition_param(field_name)
            chunks.append(b"--" + boundary_bytes + b"\r\n")
            chunks.append(f'Content-Disposition: form-data; name="{escaped_name}"\r\n\r\n'.encode())
            chunks.append(field_value.encode("utf-8"))
            chunks.append(b"\r\n")

    for field_name, file_spec in files.items():
        match file_spec:
            case bytes() as payload:
                filename = field_name
                content_type = "application/octet-stream"
            case (filename, payload):
                content_type = "application/octet-stream"
            case (filename, payload, content_type):
                pass

        escaped_name = _escape_disposition_param(field_name)
        escaped_filename = _escape_disposition_param(filename)
        clean_ct = _sanitize_header_value(content_type)
        chunks.append(b"--" + boundary_bytes + b"\r\n")
        chunks.append(
            (
                f'Content-Disposition: form-data; name="{escaped_name}"; '
                f'filename="{escaped_filename}"\r\n'
            ).encode()
        )
        chunks.append(f"Content-Type: {clean_ct}\r\n\r\n".encode())
        chunks.append(payload)
        chunks.append(b"\r\n")

    chunks.append(b"--" + boundary_bytes + b"--\r\n")
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _prepare_request_payload(
    headers: Mapping[str, str] | list[tuple[str, str]] | None,
    *,
    body: str | bytes | None,
    json_body: object | None,
    data: Mapping[str, str] | None,
    files: Mapping[str, MultipartFile] | None,
) -> tuple[list[list[str]], str | bytes | None]:
    encoded_headers = _normalize_headers(headers)
    specified = sum(
        (
            body is not None,
            json_body is not None,
            data is not None or files is not None,
        )
    )
    if specified > 1:
        msg = "specify at most one of 'body', 'json_body', or 'data'/'files'"
        raise ValueError(msg)

    has_content_type = any(k.lower() == "content-type" for k, _ in encoded_headers)

    if files is not None:
        multipart_body, content_type = _encode_multipart(data=data, files=files)
        if not has_content_type:
            encoded_headers.append(["content-type", content_type])
        return encoded_headers, multipart_body

    if data is not None:
        form_body = urllib.parse.urlencode(list(data.items()))
        if not has_content_type:
            encoded_headers.append(["content-type", "application/x-www-form-urlencoded"])
        return encoded_headers, form_body

    if json_body is not None:
        if not has_content_type:
            encoded_headers.append(["content-type", "application/json"])
        return encoded_headers, json.dumps(json_body)

    return encoded_headers, body


_PAIR_LEN = 2


def _parse_handoff_response(raw: dict[object, object]) -> HandoffResponse:
    url = str(raw.get("url", ""))
    raw_status = raw.get("status", 0)
    status = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else 0
    raw_headers = raw.get("headers")
    parsed_headers: list[tuple[str, str]] = []
    if isinstance(raw_headers, list):
        for pair in raw_headers:
            if isinstance(pair, list) and len(pair) == _PAIR_LEN:
                parsed_headers.append((str(pair[0]), str(pair[1])))
    raw_body_b64 = raw.get("body_base64")
    raw_body = raw.get("body")
    if isinstance(raw_body_b64, str):
        content = base64.b64decode(raw_body_b64)
        body = str(raw_body) if raw_body is not None else content.decode("utf-8", errors="replace")
    else:
        body = str(raw_body) if raw_body is not None else ""
        content = body.encode("utf-8")
    return HandoffResponse(
        url=url,
        status=status,
        headers=tuple(parsed_headers),
        body=body,
        content=content,
    )


class HandoffHttpClient:
    """High-throughput BoringSSL + HTTP/2 client replaying a live browser `SessionFingerprint`.

    Runs as a lightweight `waybound-daemon --replay` worker (~5 MB RAM) with zero browser
    process required once the fingerprint has been exported from Chrome.
    """

    def __init__(  # noqa: PLR0913
        self,
        fingerprint: SessionFingerprint,
        *,
        proxy: str | None = None,
        timeout_ms: int = 30_000,
        follow_redirects: bool = True,
        http3: bool = False,
        daemon_binary: Path | str | None = None,
        on_refresh: Callable[[], SessionFingerprint] | None = None,
        refresh_statuses: tuple[int, ...] = (403,),
    ) -> None:
        from waybound.session import _resolve_daemon_binary  # noqa: PLC0415

        self._fingerprint = fingerprint
        self._proxy = proxy
        self._timeout_ms = timeout_ms
        self._follow_redirects = follow_redirects
        self._http3 = http3
        self._on_refresh = on_refresh
        self._refresh_statuses = refresh_statuses
        self._lock = threading.Lock()

        binary = _resolve_daemon_binary(daemon_binary)
        self._proc: subprocess.Popen[str] | None = subprocess.Popen(  # noqa: S603
            [str(binary), "--replay"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        try:
            self._init_worker(fingerprint)
        except BaseException:
            self.close()
            raise

    @classmethod
    def from_json(  # noqa: PLR0913
        cls,
        raw_json: str,
        *,
        proxy: str | None = None,
        timeout_ms: int = 30_000,
        follow_redirects: bool = True,
        http3: bool = False,
        daemon_binary: Path | str | None = None,
        on_refresh: Callable[[], SessionFingerprint] | None = None,
        refresh_statuses: tuple[int, ...] = (403,),
    ) -> HandoffHttpClient:
        """Construct a [`HandoffHttpClient`] from a JSON-serialized [`SessionFingerprint`]."""
        decoded: object = json.loads(raw_json)
        if not isinstance(decoded, dict):
            msg = "expected JSON object for SessionFingerprint"
            raise ValueError(msg)
        fp = parse_session_fingerprint(decoded)
        return cls(
            fp,
            proxy=proxy,
            timeout_ms=timeout_ms,
            follow_redirects=follow_redirects,
            http3=http3,
            daemon_binary=daemon_binary,
            on_refresh=on_refresh,
            refresh_statuses=refresh_statuses,
        )

    @property
    def fingerprint(self) -> SessionFingerprint:
        """Return the active [`SessionFingerprint`] configured on this client."""
        return self._fingerprint

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def _init_worker(self, fingerprint: SessionFingerprint) -> None:
        resp = self._rpc(
            {
                "method": "init",
                "fingerprint": fingerprint.to_dict(),
                "options": {
                    "proxy": self._proxy,
                    "timeout_ms": self._timeout_ms,
                    "follow_redirects": self._follow_redirects,
                    "http3": self._http3,
                },
            }
        )
        if resp.get("status") != "ok":
            msg = f"unexpected replay init response: {resp!r}"
            raise WayboundDaemonError("protocol_error", msg)

    def update_fingerprint(self, fingerprint: SessionFingerprint) -> None:
        """Hot-swap the active TLS/HTTP2 fingerprint and cookie jar without restarting."""
        self._fingerprint = fingerprint
        self._init_worker(fingerprint)

    def request(  # noqa: PLR0913
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an HTTP request replaying the captured browser fingerprint and cookies."""
        encoded_headers, payload_body = _prepare_request_payload(
            headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

        result = self._execute_once(method, url, encoded_headers, payload_body)
        if self._on_refresh is not None and result.status in self._refresh_statuses:
            refreshed = self._on_refresh()
            self.update_fingerprint(refreshed)
            result = self._execute_once(method, url, encoded_headers, payload_body)
        return result

    def _execute_once(
        self,
        method: str,
        url: str,
        headers: list[list[str]],
        body: str | bytes | None,
    ) -> HandoffResponse:
        rpc_payload: dict[str, object] = {
            "method": "request",
            "http_method": method,
            "url": url,
            "headers": headers,
        }
        if isinstance(body, bytes):
            rpc_payload["body_base64"] = base64.b64encode(body).decode("ascii")
        elif body is not None:
            rpc_payload["body"] = body

        resp = self._rpc(rpc_payload)
        raw_resp = resp.get("response")
        if resp.get("status") != "response" or not isinstance(raw_resp, dict):
            msg = f"unexpected replay request response: {resp!r}"
            raise WayboundDaemonError("protocol_error", msg)
        return _parse_handoff_response(raw_resp)

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
    ) -> HandoffResponse:
        """Send an HTTP `GET` request."""
        return self.request("GET", url, headers=headers)

    def post(  # noqa: PLR0913
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an HTTP `POST` request."""
        return self.request(
            "POST",
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

    def put(  # noqa: PLR0913
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an HTTP `PUT` request."""
        return self.request(
            "PUT",
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

    def patch(  # noqa: PLR0913
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an HTTP `PATCH` request."""
        return self.request(
            "PATCH",
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

    def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
    ) -> HandoffResponse:
        """Send an HTTP `DELETE` request."""
        return self.request("DELETE", url, headers=headers)

    def cookies(self) -> list[CapturedCookie]:
        """Return all cookies currently held by the handoff client."""
        resp = self._rpc({"method": "cookies"})
        raw_list = resp.get("cookies")
        if resp.get("status") != "cookies" or not isinstance(raw_list, list):
            msg = f"unexpected replay cookies response: {resp!r}"
            raise WayboundDaemonError("protocol_error", msg)
        out: list[CapturedCookie] = []
        for entry in raw_list:
            if isinstance(entry, dict):
                out.append(
                    CapturedCookie(
                        name=str(entry.get("name", "")),
                        value=str(entry.get("value", "")),
                        domain=str(entry.get("domain", "")),
                        path=str(entry.get("path", "/")),
                        secure=bool(entry.get("secure", False)),
                        http_only=bool(entry.get("http_only", False)),
                    )
                )
        return out

    def close(self) -> None:
        """Shut down the underlying `waybound-daemon --replay` worker process."""
        proc = self._proc
        if proc is None:
            return
        self._proc = None
        if proc.poll() is None:
            with contextlib.suppress(OSError, ValueError):
                if proc.stdin is not None:
                    proc.stdin.write('{"method":"shutdown"}\n')
                    proc.stdin.flush()
                    proc.stdin.close()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2.0)
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
        if proc.stdout is not None:
            with contextlib.suppress(OSError):
                proc.stdout.close()
        if proc.stderr is not None:
            with contextlib.suppress(OSError):
                proc.stderr.close()

    def _read_stderr_tail(self, proc: subprocess.Popen[str]) -> str:
        if proc.stderr is None:
            return ""
        try:
            proc.wait(timeout=1.0)
            raw = proc.stderr.read()
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return raw.strip()[-500:]

    def _rpc(self, payload: dict[str, object]) -> dict[str, object]:
        with self._lock:
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                raise WayboundDaemonError("closed", "handoff HTTP client is closed")
            try:
                proc.stdin.write(json.dumps(payload) + "\n")
                proc.stdin.flush()
                raw_line = proc.stdout.readline()
            except OSError as exc:
                detail = self._read_stderr_tail(proc)
                self.close()
                msg = f"{exc}: {detail}" if detail else str(exc)
                raise WayboundDaemonError("io_error", msg) from exc

            if not raw_line:
                detail = self._read_stderr_tail(proc)
                self.close()
                msg = (
                    f"replay worker closed unexpectedly: {detail}"
                    if detail
                    else "replay worker closed unexpectedly"
                )
                raise WayboundDaemonError("eof", msg)

            try:
                decoded: object = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                self.close()
                raise WayboundDaemonError("protocol_error", f"invalid JSON: {exc}") from exc

            if not isinstance(decoded, dict):
                self.close()
                msg = f"expected JSON object from replay worker, got {type(decoded).__name__}"
                raise WayboundDaemonError("protocol_error", msg)

            if decoded.get("status") == "error":
                code = str(decoded.get("code", "unknown"))
                message = str(decoded.get("message", "unknown error"))
                raise WayboundDaemonError(code, message)

            return decoded


class AsyncHandoffHttpClient:
    """Async wrapper around [`HandoffHttpClient`] for `asyncio` workloads."""

    def __init__(  # noqa: PLR0913
        self,
        fingerprint: SessionFingerprint,
        *,
        proxy: str | None = None,
        timeout_ms: int = 30_000,
        follow_redirects: bool = True,
        http3: bool = False,
        daemon_binary: Path | str | None = None,
        on_refresh: Callable[[], Awaitable[SessionFingerprint]] | None = None,
        refresh_statuses: tuple[int, ...] = (403,),
    ) -> None:
        self._inner = HandoffHttpClient(
            fingerprint,
            proxy=proxy,
            timeout_ms=timeout_ms,
            follow_redirects=follow_redirects,
            http3=http3,
            daemon_binary=daemon_binary,
        )
        self._async_on_refresh = on_refresh
        self._refresh_statuses = refresh_statuses

    @property
    def fingerprint(self) -> SessionFingerprint:
        """Return the active [`SessionFingerprint`] configured on this client."""
        return self._inner.fingerprint

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def update_fingerprint(self, fingerprint: SessionFingerprint) -> None:
        """Hot-swap the active TLS/HTTP2 fingerprint and cookie jar without restarting."""
        await asyncio.to_thread(self._inner.update_fingerprint, fingerprint)

    async def request(  # noqa: PLR0913
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an async HTTP request replaying the captured browser fingerprint."""
        result = await asyncio.to_thread(
            self._inner.request,
            method,
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )
        if self._async_on_refresh is not None and result.status in self._refresh_statuses:
            refreshed = await self._async_on_refresh()
            await self.update_fingerprint(refreshed)
            result = await asyncio.to_thread(
                self._inner.request,
                method,
                url,
                headers=headers,
                body=body,
                json_body=json_body,
                data=data,
                files=files,
            )
        return result

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
    ) -> HandoffResponse:
        """Send an async HTTP `GET` request."""
        return await self.request("GET", url, headers=headers)

    async def post(  # noqa: PLR0913
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an async HTTP `POST` request."""
        return await self.request(
            "POST",
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

    async def put(  # noqa: PLR0913
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an async HTTP `PUT` request."""
        return await self.request(
            "PUT",
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

    async def patch(  # noqa: PLR0913
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
        body: str | bytes | None = None,
        json_body: object | None = None,
        data: Mapping[str, str] | None = None,
        files: Mapping[str, MultipartFile] | None = None,
    ) -> HandoffResponse:
        """Send an async HTTP `PATCH` request."""
        return await self.request(
            "PATCH",
            url,
            headers=headers,
            body=body,
            json_body=json_body,
            data=data,
            files=files,
        )

    async def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | list[tuple[str, str]] | None = None,
    ) -> HandoffResponse:
        """Send an async HTTP `DELETE` request."""
        return await self.request("DELETE", url, headers=headers)

    async def cookies(self) -> list[CapturedCookie]:
        """Return all cookies currently held by the handoff client."""
        return await asyncio.to_thread(self._inner.cookies)

    async def close(self) -> None:
        """Shut down the underlying `waybound-daemon --replay` worker process."""
        await asyncio.to_thread(self._inner.close)
