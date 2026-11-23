"""Live end-to-end smoke test for `waybound-driver-windows` against real Chrome."""

from __future__ import annotations

import sys
import time

import waybound

HTML_URL = (
    "data:text/html,<html><body>"
    "<h1>Hello Waybound</h1>"
    "<button onclick=\"document.querySelector('h1').textContent='Clicked!'\">Click Me</button>"
    '<input aria-label="Search" value="old">'
    "</body></html>"
)


def main() -> int:
    """Launch real Windows Chrome via waybound and verify UIA + SendInput + screenshot."""
    opts = waybound.LaunchOptions(
        backend="windows",
        launch_chrome=True,
        url=HTML_URL,
        startup_timeout_s=15.0,
    )
    with waybound.launch(opts) as page:
        time.sleep(3.0)
        tree = page.snapshot_tree()
        sys.stdout.write(f"0. UIA tree nodes: {len(tree)}\n")
        # Round-trip latency of a full snapshot through the daemon (IPC included). The
        # in-process COM backend should be far below the old PowerShell walker's ~300-400 ms;
        # WAYBOUND_WINDOWS_UIA=powershell restores the old backend for comparison.
        timings_ms = []
        for _ in range(5):
            started = time.perf_counter()
            page.snapshot_tree()
            timings_ms.append((time.perf_counter() - started) * 1000.0)
        timings_ms.sort()
        sys.stdout.write(
            f"   snapshot latency ms: median={timings_ms[2]:.1f} min={timings_ms[0]:.1f} "
            f"max={timings_ms[-1]:.1f}\n"
        )
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
