"""Prebuilt `waybound-daemon` release artifact discovery and SHA-256 verified downloader."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import re
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

DEFAULT_REPO = "Sekinal/waybound"
_FALLBACK_VERSION = "v0.6.0"


def _default_version() -> str:
    """Return the release tag matching the installed SDK, so the daemon never lags behind it."""
    try:
        return f"v{importlib.metadata.version('waybound')}"
    except importlib.metadata.PackageNotFoundError:
        return _FALLBACK_VERSION


DEFAULT_VERSION = _default_version()
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SAFE_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DOWNLOAD_TIMEOUT_S = 60.0
_MAX_TARBALL_BYTES = 100 * 1024 * 1024
_MAX_BINARY_BYTES = 100 * 1024 * 1024
_MAX_SHA_BYTES = 4096
_CHUNK_BYTES = 65536


def _daemon_filename() -> str:
    return "waybound-daemon.exe" if sys.platform == "win32" else "waybound-daemon"


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
    if sys.platform == "win32" and machine in ("x86_64", "amd64"):
        return "waybound-daemon-windows-x86_64"
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
    return Path.home() / ".cache" / "waybound" / version / _daemon_filename()


def find_cached_daemon() -> Path | None:
    """Locate the default or most recently installed cached `waybound-daemon` binary."""
    default_path = cached_daemon_path()
    if default_path.exists():
        return default_path

    cache_root = Path.home() / ".cache" / "waybound"
    if not cache_root.is_dir():
        return None

    bin_name = _daemon_filename()
    candidates = [p for p in cache_root.glob(f"*/{bin_name}") if p.is_file()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _download_bounded(url: str, dest: Path, *, max_bytes: int) -> str:
    """Download an HTTPS URL to `dest` with a timeout and size cap; return hex SHA-256."""
    if not url.startswith("https://"):
        msg = f"refusing non-HTTPS download URL: {url!r}"
        raise ValueError(msg)

    digest = hashlib.sha256()
    total = 0
    with (
        urllib.request.urlopen(url, timeout=_DOWNLOAD_TIMEOUT_S) as resp,  # noqa: S310
        dest.open("wb") as out,
    ):
        while True:
            chunk = resp.read(_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                msg = f"download exceeded maximum allowed size ({max_bytes} bytes): {url}"
                raise RuntimeError(msg)
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest().lower()


def _extract_and_install(tar_path: Path, dest: Path) -> None:
    """Extract `waybound-daemon` from `tar_path` and atomically install to `dest`."""
    bin_name = _daemon_filename()
    valid_names = (bin_name, f"./{bin_name}")
    with tarfile.open(tar_path, "r:gz") as archive:
        member = next((m for m in archive.getmembers() if m.name in valid_names), None)
        if member is None or not member.isfile():
            msg = "archive missing regular file waybound-daemon"
            raise RuntimeError(msg)
        if member.size > _MAX_BINARY_BYTES:
            msg = f"extracted binary exceeds size cap ({_MAX_BINARY_BYTES} bytes)"
            raise RuntimeError(msg)
        extracted = archive.extractfile(member)
        if extracted is None:
            msg = "archive missing waybound-daemon binary"
            raise RuntimeError(msg)
        with extracted:
            data = extracted.read(_MAX_BINARY_BYTES + 1)
        if len(data) > _MAX_BINARY_BYTES:
            msg = f"extracted binary exceeds size cap ({_MAX_BINARY_BYTES} bytes)"
            raise RuntimeError(msg)

    staged_fd, staged_name = tempfile.mkstemp(prefix=".waybound-daemon-", dir=dest.parent)
    staged_path = Path(staged_name)
    try:
        with os.fdopen(staged_fd, "wb") as handle:
            handle.write(data)
        staged_path.chmod(0o755)
        staged_path.replace(dest)
    except BaseException:
        staged_path.unlink(missing_ok=True)
        raise


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
    owner, repo_name = repo.split("/", 1)
    if owner in (".", "..") or repo_name in (".", ".."):
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

        actual_sha = _download_bounded(tar_url, tar_path, max_bytes=_MAX_TARBALL_BYTES)
        _download_bounded(sha_url, sha_path, max_bytes=_MAX_SHA_BYTES)

        sha_tokens = sha_path.read_text(encoding="utf-8").strip().split()
        expected_sha = sha_tokens[0].lower() if sha_tokens else ""
        if not _SHA256_RE.match(expected_sha):
            msg = f"invalid SHA-256 checksum file for {artifact}.tar.gz"
            raise RuntimeError(msg)

        if actual_sha != expected_sha:
            msg = (
                f"SHA-256 mismatch for {artifact}.tar.gz: expected {expected_sha}, got {actual_sha}"
            )
            raise RuntimeError(msg)

        _extract_and_install(tar_path, dest)

    return dest
