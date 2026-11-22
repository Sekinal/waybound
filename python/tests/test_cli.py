"""Unit tests for the `waybound doctor` CLI."""

from __future__ import annotations

from waybound.cli import main, run_doctor


def test_doctor_returns_expected_keys() -> None:
    report = run_doctor()
    assert set(report.keys()) == {"platform", "python", "daemon", "chrome", "tshark", "android"}
    assert main(["doctor"]) == 0
    assert main(["unknown-cmd"]) == 2
