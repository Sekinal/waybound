"""Unit tests for the `waybound doctor` CLI."""

from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from waybound.cli import _check_tshark, _find_tshark, _parse_route_interface, main, run_doctor

if TYPE_CHECKING:
    from pathlib import Path


def test_doctor_returns_expected_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # Do not run (or depend on) a real tshark on the developer machine.
    monkeypatch.setattr("waybound.cli._check_tshark", lambda: "stubbed")
    report = run_doctor()
    assert set(report.keys()) == {"platform", "python", "daemon", "chrome", "tshark", "android"}
    assert report["tshark"] == "stubbed"
    assert main(["doctor"]) == 0
    assert main(["unknown-cmd"]) == 2


def _completed(returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


def test_check_tshark_reports_missing_unopenable_and_ok() -> None:
    assert _check_tshark(find=lambda: None).startswith("missing")

    def no_iface() -> str | None:
        return None

    assert "no capture interface" in _check_tshark(find=lambda: "/x/tshark", interface=no_iface)

    calls: list[list[str]] = []

    def denied(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return _completed(2, "tshark: You don't have permission to capture on that device\n")

    report = _check_tshark(find=lambda: "/x/tshark", interface=lambda: "en9", probe=denied)
    assert report == (
        "found /x/tshark, but cannot open interface en9: "
        "tshark: You don't have permission to capture on that device"
    )
    assert calls == [["/x/tshark", "-L", "-i", "en9"]]

    ok = _check_tshark(
        find=lambda: "/x/tshark", interface=lambda: "en9", probe=lambda _: _completed(0)
    )
    assert ok.startswith("ok (/x/tshark; can open interface en9")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bits")
def test_find_tshark_skips_relative_entries_and_non_executables(tmp_path: Path) -> None:
    planted = tmp_path / "tshark"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o644)
    absolute = str(tmp_path)
    found = _find_tshark(os.pathsep.join(["", ".", "relative/bin", absolute]))
    assert found != str(planted)
    planted.chmod(0o755)
    assert _find_tshark(os.pathsep.join(["", ".", absolute])) == str(planted)


def test_parse_route_interface() -> None:
    output = "   route to: default\n    gateway: 10.8.0.1\n  interface: utun4\n  flags: <UP>\n"
    assert _parse_route_interface(output) == "utun4"
    assert _parse_route_interface("route: writing to routing socket: not in table") is None
    assert _parse_route_interface("  interface: \n") is None
