"""Live end-to-end smoke test for `waybound-driver-windows` against real Chrome.

Passes:
1. The main pass with whatever `WAYBOUND_WINDOWS_UIA` selects (CI: `native-strict`): UIA,
   SendInput, screenshot, then a cross-site navigation that forces a new renderer process,
   during which no snapshot may be rooted at the browser window.
2. A fresh Chrome on the PowerShell walker; its initial tree must equal the main pass's.
3. A fresh Chrome on native COM with the test-only level-walk switch; same tree again.
"""

from __future__ import annotations

import http.server
import os
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import waybound

if TYPE_CHECKING:
    from collections.abc import Callable

HTML_URL = (
    "data:text/html,<html><body>"
    "<h1>Hello Waybound</h1>"
    "<button onclick=\"document.querySelector('h1').textContent='Clicked!'\">Click Me</button>"
    '<input aria-label="Search" value="old">'
    "</body></html>"
)
SECOND_PAGE = b"<html><body><h1>Second Waybound page</h1><p>new renderer</p></body></html>"
FIRST_TREE_TIMEOUT_S = 15.0
POWERSHELL_TREE_TIMEOUT_S = 30.0
NAVIGATION_TIMEOUT_S = 20.0
# Browser-frame controls that must never appear in a tree rooted at the web document.
BROWSER_FRAME_BUTTONS = frozenset({"Minimize", "Maximize", "Restore", "Close"})

NodeKey = tuple[str, str | None, str | None]


def _launch_options() -> waybound.LaunchOptions:
    return waybound.LaunchOptions(
        backend="windows",
        launch_chrome=True,
        url=HTML_URL,
        startup_timeout_s=15.0,
    )


def _keys(tree: list[waybound.AccessibilityNode]) -> list[NodeKey]:
    return [(node.role.value, node.name, node.value) for node in tree]


def _has_browser_frame(tree: list[waybound.AccessibilityNode]) -> bool:
    return any(
        node.role == waybound.Role.BUTTON and node.name in BROWSER_FRAME_BUTTONS for node in tree
    )


def _snapshot_or_none(page: waybound.Page) -> list[waybound.AccessibilityNode] | None:
    """A snapshot, or `None` when the daemon reports `transient` (page between documents)."""
    try:
        return page.snapshot_tree()
    except waybound.WayboundDaemonError as err:
        if err.code != "transient":
            raise
        sys.stdout.write(f"   (transient: {err.message})\n")
        return None


def _settled_tree(
    page: waybound.Page, timeout_s: float
) -> tuple[list[waybound.AccessibilityNode], int, float]:
    """Poll until the tree is non-empty and rooted at the page, not the browser frame."""
    started = time.perf_counter()
    calls = 0
    while True:
        tree = _snapshot_or_none(page) or []
        calls += 1
        settled = bool(tree) and not _has_browser_frame(tree)
        if settled or time.perf_counter() - started >= timeout_s:
            return tree, calls, (time.perf_counter() - started) * 1000.0
        time.sleep(0.25)


def _print_tree(label: str, tree: list[waybound.AccessibilityNode]) -> None:
    sys.stdout.write(f"   {label} ({len(tree)} nodes):\n")
    for role, name, value in _keys(tree)[:60]:
        sys.stdout.write(f"     {role}: name={name!r} val={value!r}\n")


def _timed_ms(call: Callable[[], object], runs: int = 7) -> str:
    """Median/min/max wall time of `call` in milliseconds, IPC to the daemon included."""
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        call()
        samples.append((time.perf_counter() - started) * 1000.0)
    return f"median={statistics.median(samples):.1f} min={min(samples):.1f} max={max(samples):.1f}"


def _print_daemon_uia_log(since: float, *, contains: str = "UIAutomation", tail: int = 0) -> None:
    """Echo the daemon's log lines containing `contains` (all of the first 40, or the last
    `tail` ones).

    The SDK writes daemon stderr to `<tmp>/wb-*/daemon.stderr.log`; the newest one written
    after `since` is taken to be the open session's. That holds on a CI runner, which runs one
    smoke at a time; on a developer machine with other sessions open it may pick theirs.
    """
    logs = [
        p
        for p in Path(tempfile.gettempdir()).glob("wb-*/daemon.stderr.log")
        if p.stat().st_mtime >= since
    ]
    if not logs:
        sys.stdout.write("   (daemon log not found)\n")
        return
    newest = max(logs, key=lambda p: p.stat().st_mtime)
    lines = newest.read_text(encoding="utf-8", errors="replace").splitlines()
    shown = [line for line in lines if contains in line]
    for line in shown[-tail:] if tail else shown[:40]:
        sys.stdout.write(f"   daemon: {line}\n")


class _SecondPage(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(SECOND_PAGE)))
        self.end_headers()
        self.wfile.write(SECOND_PAGE)

    def log_message(self, format: str, *args: object) -> None:
        """Keep the smoke output clean."""


def _cross_site_navigation(page: waybound.Page, launched_at: float) -> None:
    """data: -> http://127.0.0.1 is cross-site, so Chrome commits it in a new renderer
    process: the old document goes away before the new one is in the control view.
    """
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SecondPage)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/second.html"
        page.goto(url)
        started = time.perf_counter()
        snapshots = transient = 0
        while True:
            tree = _snapshot_or_none(page)
            snapshots += 1
            if tree is None:
                transient += 1
            else:
                assert not _has_browser_frame(tree), (
                    "a snapshot during the cross-site navigation was rooted at the browser "
                    f"window: {_keys(tree)[:10]!r}"
                )
                if any(node.name == "Second Waybound page" for node in tree):
                    break
            assert time.perf_counter() - started < NAVIGATION_TIMEOUT_S, (
                "the second page never appeared in the tree"
            )
            time.sleep(0.05)
        sys.stdout.write(
            f"8. Cross-site navigation: {snapshots} snapshots, {transient} transient, "
            f"none rooted at the browser window\n"
        )
        _print_daemon_uia_log(launched_at, contains="root=", tail=5)
    finally:
        server.shutdown()
        server.server_close()


def _native_pass() -> list[NodeKey]:
    """Main smoke pass; returns the initial tree for the backend comparisons."""
    backend = os.environ.get("WAYBOUND_WINDOWS_UIA", "")
    sys.stdout.write(f"UIA backend requested: WAYBOUND_WINDOWS_UIA={backend!r}\n")
    launched_at = time.time()
    session = waybound.launch(_launch_options())
    with session as page:
        time.sleep(3.0)
        tree, calls, waited_ms = _settled_tree(page, FIRST_TREE_TIMEOUT_S)
        sys.stdout.write(
            f"0. UIA tree nodes: {len(tree)} (snapshot calls: {calls}, {waited_ms:.0f} ms)\n"
        )
        _print_tree("initial tree", tree)
        assert tree, "the UIA tree stayed empty after launch"
        assert not _has_browser_frame(tree), (
            "the snapshot is rooted at the browser window, not the web document"
        )
        # Latency through the daemon. `ping` is the IPC baseline, so snapshot minus ping is
        # roughly the time spent in UIAutomation plus serializing the tree.
        sys.stdout.write(f"   ping latency ms:     {_timed_ms(session.ping)}\n")
        sys.stdout.write(f"   snapshot latency ms: {_timed_ms(page.snapshot_tree)}\n")
        sys.stdout.write(f"   url latency ms:      {_timed_ms(page.url)}\n")

        heading = page.get_by_role(waybound.Role.HEADING, name="Hello Waybound").wait_for(
            timeout_ms=15_000
        )
        sys.stdout.write(f"1. Found HEADING: {heading.name!r} {heading.bounds}\n")
        sys.stdout.write(f"2. URL: {page.url()!r}\n")

        btn = page.get_by_role(waybound.Role.BUTTON, name="Click Me")
        assert btn.is_visible(), "Click Me button should be visible"
        sys.stdout.write(f"3. Button visible={btn.is_visible()} count={btn.count()}\n")
        btn.click()

        clicked = page.get_by_role(waybound.Role.HEADING, name="Clicked!").wait_for(
            timeout_ms=10_000
        )
        sys.stdout.write(f"4. After SendInput click -> HEADING: {clicked.name!r}\n")

        inp = page.get_by_role(waybound.Role.TEXTBOX, name="Search")
        before = inp.input_value()
        sys.stdout.write(f"5. Input before fill: {before!r}\n")
        assert before == "old", f"expected web input value 'old', got {before!r}"
        inp.fill("windows works")
        time.sleep(0.4)
        after = inp.input_value()
        sys.stdout.write(f"6. After SendInput fill -> input_value: {after!r}\n")
        assert after == "windows works", f"expected 'windows works', got {after!r}"

        png = page.screenshot()
        assert png[:8] == b"\x89PNG\r\n\x1a\n", "screenshot must be valid PNG"
        sys.stdout.write(f"7. Native Windows PNG: {len(png)} bytes, valid=True\n")
        _print_daemon_uia_log(launched_at)
        _cross_site_navigation(page, launched_at)
    return _keys(tree)


def _print_diff(label: str, expected: list[NodeKey], actual: list[NodeKey]) -> None:
    sys.stdout.write(f"   {label} trees DIFFER (role, name, value):\n")
    for idx in range(max(len(expected), len(actual))):
        left = expected[idx] if idx < len(expected) else None
        right = actual[idx] if idx < len(actual) else None
        marker = "  " if left == right else "!="
        sys.stdout.write(f"   {marker} native={left!r} {label}={right!r}\n")


def _compare_pass(step: str, label: str, env: dict[str, str], native: list[NodeKey]) -> None:
    """Launch a fresh Chrome with `env`, wait for its tree to settle and compare it with the
    main pass's initial tree, re-reading once before failing on a difference.
    """
    session = waybound.Session(_launch_options(), extra_env=env)
    with session as page:
        time.sleep(3.0)
        tree, calls, waited_ms = _settled_tree(page, POWERSHELL_TREE_TIMEOUT_S)
        sys.stdout.write(
            f"{step}. {label} tree nodes: {len(tree)} "
            f"(snapshot calls: {calls}, {waited_ms:.0f} ms)\n"
        )
        _print_tree(f"{label} initial tree", tree)
        assert tree, f"the {label} tree stayed empty"
        assert not _has_browser_frame(tree), f"the {label} tree never left the browser window"
        keys = _keys(tree)
        if keys != native:
            _print_diff(label, native, keys)
            time.sleep(1.0)
            keys = _keys(_settled_tree(page, POWERSHELL_TREE_TIMEOUT_S)[0])
        if keys != native:
            _print_diff(f"{label} (re-read)", native, keys)
        assert keys == native, f"native COM and {label} trees differ for the same page"
        sys.stdout.write(f"   {label} latency ms: {_timed_ms(page.snapshot_tree, 3)}\n")
        sys.stdout.write(f"   native and {label} trees match ({len(native)} nodes)\n")


def main() -> int:
    """Launch real Windows Chrome via waybound and verify UIA + SendInput + screenshot."""
    native = _native_pass()
    _compare_pass("9", "PowerShell", {"WAYBOUND_WINDOWS_UIA": "powershell"}, native)
    _compare_pass(
        "10",
        "level-walk",
        {"WAYBOUND_WINDOWS_UIA": "native-strict", "WAYBOUND_WINDOWS_UIA_FORCE_LEVEL_WALK": "1"},
        native,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
