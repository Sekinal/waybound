"""CLI utilities for `waybound` (`waybound doctor`)."""

from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

from waybound.session import _resolve_daemon_binary


def _check_chrome() -> str:
    candidates = (
        [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
        ]
        if sys.platform == "darwin"
        else ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium"]
    )
    for path in candidates:
        if Path(path).exists():
            return f"ok ({path})"
    return "missing (install official Google Chrome or set WAYBOUND_CHROME_BIN)"


def _check_daemon() -> str:
    try:
        resolved = _resolve_daemon_binary(None)
    except FileNotFoundError:
        return "missing (run `cargo build --workspace` or install prebuilt binary)"
    return f"ok ({resolved})"


def _check_tshark() -> str:
    tshark = shutil.which("tshark")
    if tshark is None:
        return "missing (optional: install tshark for passive SSLKEYLOGFILE capture)"
    return f"ok ({tshark})"


def _check_android() -> str:
    adb = shutil.which("adb")
    waydroid = shutil.which("waydroid")
    if adb is None:
        return "missing adb (optional: required only for --backend android)"
    wd_status = f", waydroid={waydroid}" if waydroid else " (waydroid not installed)"
    return f"ok (adb={adb}{wd_status})"


def run_doctor() -> dict[str, str]:
    """Collect environment readiness diagnostics for `waybound`."""
    return {
        "platform": f"{platform.system()} {platform.machine()}",
        "python": platform.python_version(),
        "daemon": _check_daemon(),
        "chrome": _check_chrome(),
        "tshark": _check_tshark(),
        "android": _check_android(),
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `waybound` CLI."""
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] == "doctor":
        report = run_doctor()
        for key, value in report.items():
            sys.stdout.write(f"{key:>10}: {value}\n")
        return 0

    sys.stderr.write(f"usage: waybound [doctor] (unknown command: {args[0]})\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
