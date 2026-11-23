"""CLI utilities for `waybound` (`waybound doctor`, `fetch`, `profile export|import|inspect`)."""

from __future__ import annotations

import argparse
import platform
import shutil
import sys
from pathlib import Path

from waybound.binary import DEFAULT_VERSION, download_daemon_binary
from waybound.profile import (
    DEFAULT_MAX_BYTES,
    PASSWORD_STORE_KINDS,
    Compatibility,
    Manifest,
    OsName,
    ProfileError,
    assess_compatibility,
    current_os,
    export_profile,
    import_profile,
    read_manifest,
)
from waybound.session import _resolve_daemon_binary

_USAGE = "usage: waybound [doctor | fetch [version] | profile {export,import,inspect} ...]"
_BUNDLE_NOTICE = (
    "SECURITY: this bundle contains live session cookies for every site the profile is "
    "logged into. Anyone with the file can act as you. It was written with mode 0600; keep it "
    "out of git, images, logs and shared storage, and delete it when no longer needed.\n"
)


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


def _positive_int(text: str) -> int:
    value = int(text)
    if value <= 0:
        msg = f"must be a positive integer, got {text}"
        raise argparse.ArgumentTypeError(msg)
    return value


def _add_max_bytes(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_BYTES,
        help=f"refuse bundles larger than this when uncompressed (default {DEFAULT_MAX_BYTES})",
    )


def _add_ignore_lock(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ignore-lock",
        action="store_true",
        help="accept a SingletonLock written by Chrome on another host (e.g. a finished "
        "container); never overrides a lock held by a local Chrome",
    )


def _profile_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="waybound profile",
        description="Export or import a portable Chrome session bundle (no CDP, no network).",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    exp = sub.add_parser("export", help="snapshot a Chrome --user-data-dir into a bundle")
    exp.add_argument("profile_dir", type=Path, help="Chrome --user-data-dir (Chrome closed)")
    exp.add_argument("bundle", type=Path, help="output .tar.gz bundle (written 0600)")
    exp.add_argument(
        "--include-credentials",
        action="store_true",
        help="also export saved passwords and autofill (Login Data, Web Data)",
    )
    exp.add_argument(
        "--password-store",
        choices=PASSWORD_STORE_KINDS,
        help="cookie key store to record when it cannot be detected (a value that "
        "contradicts the cookie database is ignored)",
    )
    exp.add_argument("--force", action="store_true", help="overwrite an existing bundle")
    _add_ignore_lock(exp)

    imp = sub.add_parser("import", help="restore a bundle into a Chrome --user-data-dir")
    imp.add_argument("bundle", type=Path)
    imp.add_argument("profile_dir", type=Path)
    imp.add_argument(
        "--force",
        action="store_true",
        help="replace an existing Chrome user-data-dir or previous import (old one is "
        "removed only after the new one is in place)",
    )
    imp.add_argument(
        "--allow-incompatible",
        action="store_true",
        help="import even if cookies cannot decrypt on this OS",
    )
    _add_ignore_lock(imp)
    _add_max_bytes(imp)

    ins = sub.add_parser("inspect", help="print a bundle's manifest summary")
    ins.add_argument("bundle", type=Path)
    _add_max_bytes(ins)
    return parser


_LEVEL_TEXT = {
    "portable": "expected to work (not verified against a real Chrome)",
    "same_machine_only": "only on the original machine and OS user",
    "incompatible": "cookies will not decrypt",
    "unknown": "unknown",
}


def _describe(manifest: Manifest) -> str:
    return (
        f"  source: {manifest.source_os}/{manifest.source_arch}, "
        f"chrome {manifest.chrome_version or 'unknown'}, "
        f"cookie key store {manifest.password_store or 'unknown'}\n"
        f"  files: {len(manifest.files)} ({manifest.total_bytes} bytes uncompressed), "
        f"saved passwords/autofill {'INCLUDED' if manifest.include_credentials else 'excluded'}\n"
    )


def _compat(manifest: Manifest, target: OsName) -> Compatibility:
    return assess_compatibility(
        manifest.source_os,
        manifest.password_store,
        target,
        prefixes=manifest.cookie_encryption_prefixes,
    )


def _cmd_export(ns: argparse.Namespace) -> None:
    res = export_profile(
        ns.profile_dir,
        ns.bundle,
        include_credentials=ns.include_credentials,
        password_store=ns.password_store,
        overwrite=ns.force,
        ignore_lock=ns.ignore_lock,
    )
    for warning in res.warnings:
        sys.stderr.write(f"warning: {warning}\n")
    if res.skipped:
        sys.stderr.write(
            f"note: skipped {len(res.skipped)} symlink(s), special file(s) or "
            "non-portable name(s)\n"
        )
    sys.stdout.write(f"Wrote {res.bundle}\n{_describe(res.manifest)}")
    targets: tuple[OsName, ...] = ("linux", "macos", "windows")
    for target in targets:
        level = _compat(res.manifest, target).level
        sys.stdout.write(f"  restore on {target}: {_LEVEL_TEXT[level]}\n")
    sys.stderr.write(_BUNDLE_NOTICE)


def _cmd_import(ns: argparse.Namespace) -> None:
    imported = import_profile(
        ns.bundle,
        ns.profile_dir,
        force=ns.force,
        allow_incompatible=ns.allow_incompatible,
        ignore_lock=ns.ignore_lock,
        max_bytes=ns.max_bytes,
    )
    for warning in imported.warnings:
        sys.stderr.write(f"WARNING: {warning}\n")
    sys.stdout.write(
        f"Restored {imported.profile_dir} (dirs 0700, files 0600)\n"
        f"{_describe(imported.manifest)}"
        f"  session on this {current_os()} machine: "
        f"{_LEVEL_TEXT[imported.compatibility.level]}\n"
        "  launch with LaunchOptions(profile_dir=...) pointing at this directory\n"
    )
    sys.stderr.write(
        "SECURITY: the restored profile holds live session cookies; the bundle file still "
        "does too.\n"
    )


def _cmd_inspect(ns: argparse.Namespace) -> None:
    manifest = read_manifest(ns.bundle, max_bytes=ns.max_bytes)
    sys.stdout.write(f"{ns.bundle}\n  created {manifest.created_at} by waybound ")
    sys.stdout.write(f"{manifest.waybound_version}\n{_describe(manifest)}")
    compat = _compat(manifest, current_os())
    sys.stdout.write(
        f"  on this {current_os()} machine: {_LEVEL_TEXT[compat.level]}: {compat.message}\n"
    )


def _run_profile(args: list[str]) -> int:
    try:
        ns = _profile_parser().parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    commands = {"export": _cmd_export, "import": _cmd_import, "inspect": _cmd_inspect}
    try:
        commands[ns.action](ns)
    except (ProfileError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    return 0


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

    if args[0] == "profile":
        return _run_profile(args[1:])

    sys.stderr.write(f"{_USAGE} (unknown command: {args[0]})\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
