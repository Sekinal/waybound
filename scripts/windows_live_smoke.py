"""Live end-to-end smoke test for `waybound-driver-windows` against real Chrome."""

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

FIRST_TREE_TIMEOUT_S = 15.0

HTML_URL = (
    "data:text/html,<html><body>"
    "<h1>Hello Waybound</h1>"
    "<button onclick=\"document.querySelector('h1').textContent='Clicked!'\">Click Me</button>"
    '<input aria-label="Search" value="old">'
    "</body></html>"
)


def _timed_ms(call: Callable[[], object], runs: int = 7) -> str:
    """Median/min/max wall time of `call` in milliseconds, IPC to the daemon included."""
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        call()
        samples.append((time.perf_counter() - started) * 1000.0)
    return f"median={statistics.median(samples):.1f} min={min(samples):.1f} max={max(samples):.1f}"


def _print_daemon_uia_log(since: float) -> None:
    """Echo the daemon's UIAutomation log lines (backend choice, snapshot phase timings).

    The SDK writes daemon stderr to `<tmp>/wb-*/daemon.stderr.log`; the newest one written
    after `since` belongs to this run.
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


def main() -> int:
    """Launch real Windows Chrome via waybound and verify UIA + SendInput + screenshot."""
    backend = os.environ.get("WAYBOUND_WINDOWS_UIA", "")
    sys.stdout.write(f"UIA backend requested: WAYBOUND_WINDOWS_UIA={backend!r}\n")
    opts = waybound.LaunchOptions(
        backend="windows",
        launch_chrome=True,
        url=HTML_URL,
        startup_timeout_s=15.0,
    )
    launched_at = time.time()
    session = waybound.launch(opts)
    with session as page:
        time.sleep(3.0)
        # The first snapshot right after launch: Chrome builds its accessibility tree lazily
        # on the first UIA query. It must not stay empty.
        started = time.perf_counter()
        tree = page.snapshot_tree()
        attempts = 1
        while not tree and time.perf_counter() - started < FIRST_TREE_TIMEOUT_S:
            time.sleep(0.25)
            tree = page.snapshot_tree()
            attempts += 1
        waited_ms = (time.perf_counter() - started) * 1000.0
        sys.stdout.write(
            f"0. UIA tree nodes: {len(tree)} (snapshot calls: {attempts}, {waited_ms:.0f} ms)\n"
        )
        assert tree, "the UIA tree stayed empty for 15 s after launch"
        # Latency through the daemon. `ping` is the IPC baseline, so snapshot minus ping is
        # roughly the time spent in UIAutomation plus serializing the tree.
        sys.stdout.write(f"   ping latency ms:     {_timed_ms(session.ping)}\n")
        sys.stdout.write(f"   snapshot latency ms: {_timed_ms(page.snapshot_tree)}\n")
        sys.stdout.write(f"   url latency ms:      {_timed_ms(page.url)}\n")
        for node in tree[:20]:
            if node.name or node.value:
                sys.stdout.write(f"   {node.role.value}: name={node.name!r} val={node.value!r}\n")

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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
