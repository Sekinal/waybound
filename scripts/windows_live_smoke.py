"""Live end-to-end smoke test for `waybound-driver-windows` against real Chrome.

The main pass uses whatever `WAYBOUND_WINDOWS_UIA` selects (CI: `native-strict`). A second
pass launches a fresh Chrome on the PowerShell walker and compares the two initial trees,
which is the only equivalence check between the backends that runs against real Chrome.
"""

from __future__ import annotations

import os
import statistics
import sys
import tempfile
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
FIRST_TREE_TIMEOUT_S = 15.0
POWERSHELL_TREE_TIMEOUT_S = 30.0
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


def _settled_tree(
    page: waybound.Page, timeout_s: float
) -> tuple[list[waybound.AccessibilityNode], int, float]:
    """Poll until the tree is non-empty and rooted at the page, not the browser frame."""
    started = time.perf_counter()
    calls = 0
    while True:
        tree = page.snapshot_tree()
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


def _print_daemon_uia_log(since: float) -> None:
    """Echo the daemon's UIAutomation log lines (backend choice, walk root, phase timings).

    The SDK writes daemon stderr to `<tmp>/wb-*/daemon.stderr.log`; the newest one written
    after `since` belongs to the session that is still open.
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
    shown = [line for line in lines if "UIAutomation" in line]
    for line in shown[:40]:
        sys.stdout.write(f"   daemon: {line}\n")


def _native_pass() -> list[NodeKey]:
    """Main smoke pass; returns the initial tree for the backend comparison."""
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
    return _keys(tree)


def _powershell_pass() -> list[NodeKey]:
    """Fresh Chrome on the PowerShell walker; returns its initial tree."""
    session = waybound.Session(_launch_options(), extra_env={"WAYBOUND_WINDOWS_UIA": "powershell"})
    with session as page:
        time.sleep(3.0)
        tree, calls, waited_ms = _settled_tree(page, POWERSHELL_TREE_TIMEOUT_S)
        sys.stdout.write(
            f"8. PowerShell backend tree nodes: {len(tree)} "
            f"(snapshot calls: {calls}, {waited_ms:.0f} ms)\n"
        )
        _print_tree("PowerShell initial tree", tree)
        sys.stdout.write(f"   PowerShell snapshot latency ms: {_timed_ms(page.snapshot_tree, 3)}\n")
    return _keys(tree)


def main() -> int:
    """Launch real Windows Chrome via waybound and verify UIA + SendInput + screenshot."""
    native = _native_pass()
    powershell = _powershell_pass()
    if native != powershell:
        sys.stdout.write("9. Backend trees DIFFER (role, name, value):\n")
        for idx in range(max(len(native), len(powershell))):
            left = native[idx] if idx < len(native) else None
            right = powershell[idx] if idx < len(powershell) else None
            marker = "  " if left == right else "!="
            sys.stdout.write(f"   {marker} native={left!r} powershell={right!r}\n")
    assert native == powershell, "native COM and PowerShell trees differ for the same page"
    sys.stdout.write(f"9. Native and PowerShell trees match ({len(native)} nodes)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
