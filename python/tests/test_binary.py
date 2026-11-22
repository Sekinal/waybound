"""Unit tests for prebuilt daemon discovery and SHA-256 verification."""

from __future__ import annotations

import pytest

from waybound.binary import cached_daemon_path, download_daemon_binary, platform_artifact_name


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
