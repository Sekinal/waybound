"""Reproducible public diagnostic benchmark suite for `waybound`.

Runs an unmodified stock browser via `waybound` against public TLS/browser-integrity
diagnostic pages (`tls.peet.ws`, `bot.sannysoft.com`, `creepjs`) and prints a
Markdown scorecard (plus optional JSON export).

Usage:
    uv run --project python python benchmarks/run_benchmarks.py --backend macos
    uv run --project python python benchmarks/run_benchmarks.py --backend linux --headless-xvfb
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from waybound import LaunchOptions, launch
from waybound.session import BackendName


@dataclass(slots=True)
class BenchmarkReport:
    """Structured summary of live diagnostic checks."""

    platform: str
    backend: str
    ja4: str | None
    sannysoft_webdriver_missing: bool
    sannysoft_chrome_present: bool
    sannysoft_headless_detected: bool
    creepjs_headless_pct: str | None
    creepjs_stealth_pct: str | None


def _collect_text(nodes: list[object]) -> str:
    parts: list[str] = []
    for node in nodes:
        name = getattr(node, "name", None)
        value = getattr(node, "value", None)
        if isinstance(name, str) and name:
            parts.append(name)
        if isinstance(value, str) and value and value != name:
            parts.append(value)
    return "\n".join(parts)


def run_suite(backend: BackendName, *, headless_xvfb: bool, focus: bool) -> BenchmarkReport:
    """Execute the live diagnostic suite against unmodified Chrome."""
    opts = LaunchOptions(
        backend=backend,
        launch_chrome=True,
        headless_xvfb=headless_xvfb,
        focus=focus,
        url="https://tls.peet.ws/api/clean",
    )
    ja4: str | None = None
    webdriver_missing = False
    chrome_present = False
    headless_detected = False
    creep_headless: str | None = None
    creep_stealth: str | None = None

    with launch(opts) as page:
        time.sleep(3.5)
        tls_text = _collect_text(page.snapshot_tree())
        try:
            start = tls_text.find("{")
            end = tls_text.rfind("}")
            if start != -1 and end > start:
                parsed = json.loads(tls_text[start : end + 1])
                if isinstance(parsed, dict):
                    raw_ja4 = parsed.get("ja4")
                    if isinstance(raw_ja4, str):
                        ja4 = raw_ja4
        except json.JSONDecodeError:
            pass

        page.goto("https://bot.sannysoft.com/")
        time.sleep(4.0)
        sanny_text = _collect_text(page.snapshot_tree()).lower()
        webdriver_missing = "missing (passed)" in sanny_text
        chrome_present = "present (passed)" in sanny_text
        headless_detected = "headlesschrome" in sanny_text

        page.goto("https://abrahamjuliot.github.io/creepjs/")
        time.sleep(8.0)
        creep_lines = _collect_text(page.snapshot_tree()).splitlines()
        for line in creep_lines:
            low = line.lower()
            if "headless" in low and "%" in low and creep_headless is None:
                creep_headless = line.strip()
            if "stealth" in low and "%" in low and creep_stealth is None:
                creep_stealth = line.strip()

    return BenchmarkReport(
        platform=f"{platform.system()} {platform.machine()}",
        backend=backend,
        ja4=ja4,
        sannysoft_webdriver_missing=webdriver_missing,
        sannysoft_chrome_present=chrome_present,
        sannysoft_headless_detected=headless_detected,
        creepjs_headless_pct=creep_headless,
        creepjs_stealth_pct=creep_stealth,
    )


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run waybound public diagnostic benchmarks.")
    parser.add_argument(
        "--backend",
        choices=("macos", "linux", "windows", "android"),
        default="macos",
    )
    parser.add_argument("--headless-xvfb", action="store_true")
    parser.add_argument("--focus", action="store_true")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    report = run_suite(
        args.backend,
        headless_xvfb=bool(args.headless_xvfb),
        focus=bool(args.focus),
    )

    print("\n### waybound Diagnostic Scorecard\n")
    print("| Check | Result |")
    print("|---|---|")
    print(f"| Platform / Backend | `{report.platform}` (`{report.backend}`) |")
    print(f"| `tls.peet.ws` JA4 | `{report.ja4 or 'unavailable'}` |")
    print(f"| `bot.sannysoft.com` WebDriver missing | `{report.sannysoft_webdriver_missing}` |")
    print(f"| `bot.sannysoft.com` Chrome present | `{report.sannysoft_chrome_present}` |")
    print(f"| `bot.sannysoft.com` HeadlessChrome | `{report.sannysoft_headless_detected}` |")
    print(f"| `CreepJS` Headless | `{report.creepjs_headless_pct or 'n/a'}` |")
    print(f"| `CreepJS` Stealth | `{report.creepjs_stealth_pct or 'n/a'}` |")

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
        print(f"\nSaved JSON report -> {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
