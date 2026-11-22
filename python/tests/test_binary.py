"""Unit tests for prebuilt daemon discovery and SHA-256 verification."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from waybound.binary import (
    _FALLBACK_VERSION,
    DEFAULT_VERSION,
    cached_daemon_path,
    download_daemon_binary,
    platform_artifact_name,
)


def test_default_version_matches_the_package_version() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    package_version = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert f"v{package_version}" == DEFAULT_VERSION
    assert f"v{package_version}" == _FALLBACK_VERSION


def test_platform_artifact_name_returns_known_target() -> None:
    name = platform_artifact_name()
    assert name.startswith("waybound-daemon-")


def test_cached_daemon_path_validates_version() -> None:
    path = cached_daemon_path("v0.1.0")
    assert path.name == "waybound-daemon"
    assert path.parent.name == "v0.1.0"

    with pytest.raises(ValueError, match="invalid version tag"):
        cached_daemon_path("../escape")


def test_download_daemon_binary_rejects_invalid_repo() -> None:
    with pytest.raises(ValueError, match="invalid GitHub repository slug"):
        download_daemon_binary(repo="not-a-valid-repo-slug")
    with pytest.raises(ValueError, match="invalid GitHub repository slug"):
        download_daemon_binary(repo="../..")
