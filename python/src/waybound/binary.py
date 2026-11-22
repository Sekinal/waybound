"""Prebuilt `waybound-daemon` release artifact discovery and SHA-256 verified downloader."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

DEFAULT_REPO = "Sekinal/waybound"
DEFAULT_VERSION = "v0.1.0"
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SAFE_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def platform_artifact_name() -> str:
    """Return the GitHub Release artifact base name for the current host OS/arch."""
    machine = platform.machine().lower()
    if sys.platform == "darwin" and machine in ("arm64", "aarch64"):
        return "waybound-daemon-macos-arm64"
    if sys.platform.startswith("linux"):
        if machine in ("x86_64", "amd64"):
            return "waybound-daemon-linux-x86_64"
        if machine in ("aarch64", "arm64"):
            return "waybound-daemon-linux-arm64"
    msg = (
        f"no prebuilt waybound-daemon binary for {sys.platform}/{machine}; "
        "build with `cargo build --release`"
    )
    raise RuntimeError(msg)


def cached_daemon_path(version: str = DEFAULT_VERSION) -> Path:
    """Return the local user-cache path for a downloaded `waybound-daemon` binary."""
    if not _SAFE_VERSION_RE.match(version) or version in (".", ".."):
        msg = f"invalid version tag: {version!r}"
        raise ValueError(msg)
    return Path.home() / ".cache" / "waybound" / version / "waybound-daemon"


def download_daemon_binary(
    *,
    version: str = DEFAULT_VERSION,
    repo: str = DEFAULT_REPO,
    force: bool = False,
) -> Path:
    """Download, SHA-256 verify, and install the prebuilt `waybound-daemon` binary."""
    if not _SAFE_REPO_RE.match(repo):
        msg = f"invalid GitHub repository slug: {repo!r}"
        raise ValueError(msg)

    dest = cached_daemon_path(version)
    if dest.exists() and not force:
        return dest

    artifact = platform_artifact_name()
    base_url = f"https://github.com/{repo}/releases/download/{version}"
    tar_url = f"{base_url}/{artifact}.tar.gz"
    sha_url = f"{base_url}/{artifact}.tar.gz.sha256"

    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="waybound-dl-") as tmp:
        tmp_dir = Path(tmp)
        tar_path = tmp_dir / f"{artifact}.tar.gz"
        sha_path = tmp_dir / f"{artifact}.tar.gz.sha256"

        urllib.request.urlretrieve(tar_url, tar_path)  # noqa: S310
        urllib.request.urlretrieve(sha_url, sha_path)  # noqa: S310

        sha_tokens = sha_path.read_text(encoding="utf-8").strip().split()
        expected_sha = sha_tokens[0].lower() if sha_tokens else ""
        if not _SHA256_RE.match(expected_sha):
            msg = f"invalid SHA-256 checksum file for {artifact}.tar.gz"
            raise RuntimeError(msg)

        actual_sha = hashlib.sha256(tar_path.read_bytes()).hexdigest().lower()
        if actual_sha != expected_sha:
            msg = (
                f"SHA-256 mismatch for {artifact}.tar.gz: expected {expected_sha}, got {actual_sha}"
            )
            raise RuntimeError(msg)

        with tarfile.open(tar_path, "r:gz") as archive:
            member = archive.getmember("waybound-daemon")
            if not member.isfile():
                msg = "archive entry waybound-daemon is not a regular file"
                raise RuntimeError(msg)
            extracted = archive.extractfile(member)
            if extracted is None:
                msg = "archive missing waybound-daemon binary"
                raise RuntimeError(msg)
            data = extracted.read()

        staged_fd, staged_name = tempfile.mkstemp(
            prefix=".waybound-daemon-",
            dir=dest.parent,
        )
        staged_path = Path(staged_name)
        try:
            with os.fdopen(staged_fd, "wb") as handle:
                handle.write(data)
            staged_path.chmod(0o755)
            staged_path.replace(dest)
        except BaseException:
            staged_path.unlink(missing_ok=True)
            raise

    return dest
