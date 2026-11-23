"""CLI utilities for `waybound` (`waybound doctor`)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from waybound.binary import DEFAULT_VERSION, download_daemon_binary
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


# Same lookup as the daemon (`find_executable` in `net_tap.rs`), in the same order: the
# absolute entries of `PATH`, then these well-known install locations.
_TSHARK_FALLBACK_PATHS: tuple[str, ...] = (
    (r"C:\Program Files\Wireshark\tshark.exe",)
    if sys.platform == "win32"
    else (
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        "/opt/local/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/run/current-system/sw/bin/tshark",
    )
)
_TSHARK_SCOPE = "only needed to capture when attaching to a desktop browser with pid + ssl_keylog"

ProbeRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _find_tshark(path_var: str | None = None) -> str | None:
    """Find tshark like the daemon does.

    Unlike `shutil.which`, empty and relative `PATH` entries are skipped: they resolve against
    the current directory, so a planted `./tshark` would otherwise be found and executed.
    """
    search = os.environ.get("PATH", "") if path_var is None else path_var
    name = "tshark.exe" if sys.platform == "win32" else "tshark"
    for entry in search.split(os.pathsep):
        if not entry or not Path(entry).is_absolute():
            continue
        candidate = Path(entry) / name
        if _is_executable_file(candidate):
            return str(candidate)
    return next((p for p in _TSHARK_FALLBACK_PATHS if _is_executable_file(Path(p))), None)


def _parse_route_interface(output: str) -> str | None:
    """Extract the interface from `route -n get default` output (macOS)."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface:"):
            iface = stripped.removeprefix("interface:").strip()
            return iface or None
    return None


def _default_route_interface() -> str | None:
    """Interface of the default route on macOS (`route -n get default`)."""
    try:
        result = subprocess.run(
            ["/sbin/route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _parse_route_interface(result.stdout)


def _capture_interface() -> str | None:
    """Interface the daemon's tshark fallback would capture on (mirrors `capture_interface`).

    Linux captures on `any`; macOS has no `any` device and uses the default-route interface;
    Windows (Npcap) has no `any` device either and needs `WAYBOUND_NET_IFACE`.
    """
    explicit = os.environ.get("WAYBOUND_NET_IFACE", "").strip()
    if explicit:
        iface: str | None = explicit
    elif sys.platform == "darwin":
        iface = _default_route_interface()
    elif sys.platform == "win32":
        iface = None
    else:
        iface = "any"
    return iface


def _run_probe(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, timeout=15, check=False
    )


def _check_tshark(
    find: Callable[[], str | None] = _find_tshark,
    interface: Callable[[], str | None] = _capture_interface,
    probe: ProbeRunner = _run_probe,
) -> str:
    tshark = find()
    if tshark is None:
        return f"missing ({_TSHARK_SCOPE}; launch_chrome taps traffic in-process)"
    iface = interface()
    if iface is None:
        return f"found {tshark}, but no capture interface (set WAYBOUND_NET_IFACE; see tshark -D)"
    # `-L` opens the capture device to list its link types without capturing packets, so it
    # fails exactly when capture permission (BPF access / CAP_NET_RAW) or the device is missing.
    try:
        result = probe([tshark, "-L", "-i", iface])
    except (OSError, subprocess.SubprocessError) as exc:
        return f"found {tshark}, but probing interface {iface} failed: {exc}"
    if result.returncode != 0:
        detail = next((ln.strip() for ln in result.stderr.splitlines() if ln.strip()), "")
        return f"found {tshark}, but cannot open interface {iface}: {detail}"
    return f"ok ({tshark}; can open interface {iface}; {_TSHARK_SCOPE})"


def _check_android() -> str:
    adb = shutil.which("adb")
    waydroid = shutil.which("waydroid")
    if adb is None:
        return "missing adb (optional: required only for --backend android)"
    wd_status = f", waydroid={waydroid}" if waydroid else " (waydroid not installed)"
    return f"ok (adb={adb}{wd_status})"


def run_doctor(check_tshark: Callable[[], str] | None = None) -> dict[str, str]:
    """Collect environment readiness diagnostics for `waybound`."""
    tshark_check = _check_tshark if check_tshark is None else check_tshark
    return {
        "platform": f"{platform.system()} {platform.machine()}",
        "python": platform.python_version(),
        "daemon": _check_daemon(),
        "chrome": _check_chrome(),
        "tshark": tshark_check(),
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

    if args[0] == "fetch":
        version = args[1] if len(args) > 1 else DEFAULT_VERSION
        try:
            path = download_daemon_binary(version=version)
        except (RuntimeError, ValueError, OSError) as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 1
        sys.stdout.write(f"Installed waybound-daemon ({version}) -> {path}\n")
        return 0

    sys.stderr.write(f"usage: waybound [doctor|fetch [version]] (unknown command: {args[0]})\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
