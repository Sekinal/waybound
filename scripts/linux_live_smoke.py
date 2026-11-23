"""Live end-to-end smoke test for `waybound-driver-linux` against real Chrome/Chromium."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import waybound

INDEX_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Waybound Linux Smoke</title></head>
<body>
  <h1 id="title">Hello Linux Waybound</h1>
  <button id="fetch-btn" type="button" onclick="
    fetch('/api/data')
      .then(function(r) { return r.json(); })
      .then(function(d) { document.getElementById('title').textContent = d.status; });
  ">Fetch Data</button>
  <input aria-label="Search" value="old">
  <label><input type="checkbox" aria-label="Agree"> Agree</label>
  <a href="/page2">Go to Page Two</a>
</body>
</html>
"""

PAGE2_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Page Two</title></head>
<body>
  <h1>Page Two</h1>
</body>
</html>
"""


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/data":
            body = json.dumps({"status": "Loaded!", "ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/page2":
            body = PAGE2_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def main() -> int:
    """Launch real Linux Chrome/Chromium via waybound and verify AT-SPI2 + X11 + screenshot."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="wb-linux-smoke-") as tmp_dir:
            keylog = Path(tmp_dir) / "ssl.keylog"
            opts = waybound.LaunchOptions(
                backend="linux",
                launch_chrome=True,
                url=base_url,
                ssl_keylog=keylog,
                startup_timeout_s=20.0,
            )
            with waybound.launch(opts) as page:
                heading = page.get_by_role(
                    waybound.Role.HEADING, name="Hello Linux Waybound"
                ).wait_for(timeout_ms=15_000)
                sys.stdout.write(f"1. Found HEADING: {heading.name!r} {heading.bounds}\n")

                snap = page.snapshot_tree_with_meta()
                sys.stdout.write(
                    f"2. AT-SPI2 tree nodes: {len(snap.nodes)} (truncated={snap.truncated})\n"
                )
                assert len(snap.nodes) > 0, "expected non-empty AT-SPI2 tree"

                inp = page.get_by_role(waybound.Role.TEXTBOX, name="Search", strict=True)
                inp.fill("linux works")
                time.sleep(0.3)
                after = inp.input_value()
                sys.stdout.write(f"3. After fill -> input_value: {after!r}\n")
                assert after == "linux works", f"expected 'linux works', got {after!r}"

                cb = page.get_by_role(waybound.Role.CHECKBOX, name="Agree", strict=True)
                assert cb.is_checked() is False, "checkbox should start unchecked"
                cb.check()
                assert cb.is_checked() is True, "checkbox should be checked after check()"
                sys.stdout.write("4. Checkbox checked=True\n")

                btn = page.get_by_role(waybound.Role.BUTTON, name="Fetch Data", strict=True)
                btn.click()
                loaded = page.get_by_role(waybound.Role.HEADING, name="Loaded!").wait_for(
                    timeout_ms=10_000
                )
                sys.stdout.write(f"5. After fetch click -> HEADING: {loaded.name!r}\n")

                responses = page.captured_responses()
                sys.stdout.write(f"6. Passive captured_responses count: {len(responses)}\n")
                assert isinstance(responses, list)

                link = page.get_by_role(waybound.Role.LINK, name="Go to Page Two", strict=True)
                link.click()
                page2 = page.get_by_role(waybound.Role.HEADING, name="Page Two").wait_for(
                    timeout_ms=15_000
                )
                sys.stdout.write(f"7. After link click (/page2) -> HEADING: {page2.name!r}\n")

                png = page.screenshot()
                assert png[:8] == b"\x89PNG\r\n\x1a\n", "screenshot must be valid PNG"
                sys.stdout.write(f"8. Native Linux PNG: {len(png)} bytes, valid=True\n")
    finally:
        server.shutdown()
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
