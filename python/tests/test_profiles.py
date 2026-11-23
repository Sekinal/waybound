"""Unit tests for `waybound.profiles.ProfileStore`."""

from __future__ import annotations

import io
import shutil
import tarfile
from typing import TYPE_CHECKING

import pytest

from waybound import EXCLUDED_PROFILE_NAMES, ProfileStore, validate_profile_name

if TYPE_CHECKING:
    from pathlib import Path


def _populate_mock_chrome_profile(profile_dir: Path) -> None:
    """Create a realistic Chrome `--user-data-dir` fixture with locks, caches, and state."""
    (profile_dir / "Default" / "Local Storage" / "leveldb").mkdir(parents=True)
    (profile_dir / "Default" / "Cache").mkdir(parents=True)
    (profile_dir / "Default" / "Cache_Data").mkdir(parents=True)
    (profile_dir / "Default" / "Code Cache").mkdir(parents=True)
    (profile_dir / "Default" / "GPUCache").mkdir(parents=True)
    (profile_dir / "Default" / "DawnCache").mkdir(parents=True)
    (profile_dir / "Crashpad").mkdir(parents=True)
    (profile_dir / "ShaderCache").mkdir(parents=True)
    (profile_dir / "GrShaderCache").mkdir(parents=True)
    (profile_dir / "GraphiteDawnCache").mkdir(parents=True)
    (profile_dir / "BrowserMetrics").mkdir(parents=True)

    # Valuable session files that must survive clone / snapshot round-trips.
    (profile_dir / "Local State").write_text('{"os_crypt":{}}', encoding="utf-8")
    (profile_dir / "Default" / "Preferences").write_text('{"profile":{"name":"Work"}}')
    (profile_dir / "Default" / "Cookies").write_bytes(b"SQLite format 3\x00cookie-data")
    (profile_dir / "Default" / "Local Storage" / "leveldb" / "000003.log").write_bytes(
        b"leveldb-records"
    )

    # Ephemeral lock / cache / crash artifacts that must be excluded.
    (profile_dir / "SingletonLock").symlink_to("mockhost-99999")  # dangling symlink like Chrome
    (profile_dir / "SingletonCookie").write_text("cookie-lock", encoding="utf-8")
    (profile_dir / "SingletonSocket").write_text("socket-lock", encoding="utf-8")
    (profile_dir / "Crashpad" / "dump.dmp").write_bytes(b"crash-dump")
    (profile_dir / "ShaderCache" / "shader.bin").write_bytes(b"shader-bytes")
    (profile_dir / "GrShaderCache" / "gr.bin").write_bytes(b"gr-bytes")
    (profile_dir / "GraphiteDawnCache" / "dawn.bin").write_bytes(b"graphite-bytes")
    (profile_dir / "BrowserMetrics" / "metrics.pma").write_bytes(b"metrics")
    (profile_dir / "Default" / "LOCK").write_text("", encoding="utf-8")
    (profile_dir / "Default" / "lockfile").write_text("", encoding="utf-8")
    (profile_dir / "Default" / "Local Storage" / "leveldb" / "LOCK").write_text(
        "", encoding="utf-8"
    )
    (profile_dir / "Default" / "Cache" / "f_000001").write_bytes(b"x" * 4096)
    (profile_dir / "Default" / "Cache_Data" / "data_0").write_bytes(b"y" * 4096)
    (profile_dir / "Default" / "Code Cache" / "js.bin").write_bytes(b"z" * 4096)
    (profile_dir / "Default" / "GPUCache" / "gpu.bin").write_bytes(b"g" * 1024)
    (profile_dir / "Default" / "DawnCache" / "dawn.bin").write_bytes(b"d" * 1024)


def _assert_clean_profile_copy(dest: Path) -> None:
    assert (dest / "Local State").read_text(encoding="utf-8") == '{"os_crypt":{}}'
    assert (dest / "Default" / "Preferences").read_text(encoding="utf-8") == (
        '{"profile":{"name":"Work"}}'
    )
    assert (dest / "Default" / "Cookies").read_bytes() == b"SQLite format 3\x00cookie-data"
    assert (
        dest / "Default" / "Local Storage" / "leveldb" / "000003.log"
    ).read_bytes() == b"leveldb-records"

    for excluded in EXCLUDED_PROFILE_NAMES:
        assert not (dest / excluded).exists()
        assert not (dest / excluded).is_symlink()
        assert not (dest / "Default" / excluded).exists()
        assert not (dest / "Default" / excluded).is_symlink()

    assert not (dest / "Default" / "Local Storage" / "leveldb" / "LOCK").exists()


@pytest.mark.parametrize("name", ["default", "work_1", "prod-us.west", "A0", "_lead", "-dash"])
def test_validate_profile_name_accepts_valid(name: str) -> None:
    assert validate_profile_name(name) == name


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        ".",
        "..",
        ".hidden",
        "a/b",
        r"a\b",
        "foo..bar",
        "../escape",
        "has space",
        "bad\x00name",
        "a" * 256,
    ],
)
def test_validate_profile_name_rejects_invalid(bad_name: str, tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    with pytest.raises(ValueError, match="invalid profile name"):
        validate_profile_name(bad_name)
    with pytest.raises(ValueError, match="invalid profile name"):
        store.profile_path(bad_name)
    with pytest.raises(ValueError, match="invalid profile name"):
        store.exists(bad_name)
    with pytest.raises(ValueError, match="invalid profile name"):
        store.delete(bad_name)


def test_list_exists_and_delete(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "profiles")
    assert store.list_profiles() == []
    assert not store.exists("alpha")

    (store.profile_path("beta")).mkdir(parents=True)
    (store.profile_path("alpha")).mkdir(parents=True)
    # Hidden staging dirs and regular files should not appear in list_profiles().
    (store.root_dir / ".staging-tmp").mkdir()
    (store.root_dir / "not-a-dir").write_text("file", encoding="utf-8")

    assert store.list_profiles() == ["alpha", "beta"]
    assert store.exists("alpha")
    assert store.exists("beta")

    store.delete("alpha")
    assert not store.exists("alpha")
    assert store.list_profiles() == ["beta"]
    # Deleting a missing profile is idempotent.
    store.delete("alpha")


@pytest.mark.parametrize("prefer_cow", [True, False])
def test_clone_excludes_ephemeral_files(tmp_path: Path, prefer_cow: bool) -> None:
    store = ProfileStore(tmp_path / "store")
    src = store.profile_path("chrome-main")
    _populate_mock_chrome_profile(src)

    dest = tmp_path / f"cloned-{prefer_cow}"
    out = store.clone("chrome-main", dest_dir=dest, prefer_cow=prefer_cow)
    assert out == dest
    _assert_clean_profile_copy(dest)

    # Also test cloning directly from an explicit Path into an auto-created temp dir.
    temp_clone = store.clone(src, prefer_cow=prefer_cow)
    try:
        assert temp_clone.is_dir()
        _assert_clean_profile_copy(temp_clone)
    finally:
        shutil.rmtree(temp_clone, ignore_errors=True)


def test_clone_rejects_self_or_missing_source(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "store")
    with pytest.raises(FileNotFoundError):
        store.clone("missing")

    src = store.profile_path("main")
    src.mkdir(parents=True)
    with pytest.raises(ValueError, match="cannot clone profile into itself"):
        store.clone("main", dest_dir=src)
    with pytest.raises(ValueError, match="cannot clone profile into itself"):
        store.clone("main", dest_dir=src / "nested")


def test_ephemeral_clone_cleans_up_on_exit_and_error(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "store")
    _populate_mock_chrome_profile(store.profile_path("main"))

    with store.ephemeral_clone("main") as cloned:
        assert cloned.is_dir()
        _assert_clean_profile_copy(cloned)
        captured_path = cloned
    assert not captured_path.exists()

    err_paths: list[Path] = []

    def _raise_inside_clone() -> None:
        with store.ephemeral_clone("main") as cloned_err:
            err_paths.append(cloned_err)
            assert cloned_err.is_dir()
            msg = "boom"
            raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="boom"):
        _raise_inside_clone()
    assert len(err_paths) == 1
    assert not err_paths[0].exists()


def test_export_and_import_snapshot_roundtrip(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "store")
    _populate_mock_chrome_profile(store.profile_path("source"))

    archive = tmp_path / "snapshots" / "source.tar.gz"
    exported = store.export_snapshot("source", archive)
    assert exported == archive
    assert archive.is_file()
    # No leftover temporary files.
    assert list(archive.parent.iterdir()) == [archive]

    restored = store.import_snapshot(archive, "restored")
    assert restored == store.profile_path("restored")
    assert store.exists("restored")
    _assert_clean_profile_copy(restored)


def test_import_snapshot_overwrite_behavior(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "store")
    src = store.profile_path("v1")
    src.mkdir(parents=True)
    (src / "marker.txt").write_text("version-1", encoding="utf-8")
    snap_v1 = tmp_path / "v1.tar.gz"
    store.export_snapshot("v1", snap_v1)

    src_v2 = store.profile_path("v2")
    src_v2.mkdir(parents=True)
    (src_v2 / "marker.txt").write_text("version-2", encoding="utf-8")
    snap_v2 = tmp_path / "v2.tar.gz"
    store.export_snapshot("v2", snap_v2)

    store.import_snapshot(snap_v1, "active")
    assert (store.profile_path("active") / "marker.txt").read_text(encoding="utf-8") == "version-1"

    with pytest.raises(FileExistsError):
        store.import_snapshot(snap_v2, "active", overwrite=False)
    assert (store.profile_path("active") / "marker.txt").read_text(encoding="utf-8") == "version-1"

    store.import_snapshot(snap_v2, "active", overwrite=True)
    assert (store.profile_path("active") / "marker.txt").read_text(encoding="utf-8") == "version-2"


@pytest.mark.parametrize(
    "evil_member_name",
    [
        "../evil.txt",
        "Default/../../escape.txt",
        "/etc/passwd",
        r"\Windows\System32\evil.dll",
        "C:/evil.txt",
    ],
)
def test_import_snapshot_rejects_path_traversal(tmp_path: Path, evil_member_name: str) -> None:
    store = ProfileStore(tmp_path / "store")
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        payload = b"pwned"
        info = tarfile.TarInfo(name=evil_member_name)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    with pytest.raises(ValueError, match=r"path traversal|absolute path"):
        store.import_snapshot(archive, "victim")
    assert not store.exists("victim")
    assert not (tmp_path / "evil.txt").exists()


def test_import_snapshot_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "store")

    sym_archive = tmp_path / "symlink.tar.gz"
    with tarfile.open(sym_archive, "w:gz") as tf:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)

    with pytest.raises(ValueError, match="disallowed type"):
        store.import_snapshot(sym_archive, "sym-victim")
    assert not store.exists("sym-victim")

    hard_archive = tmp_path / "hardlink.tar.gz"
    with tarfile.open(hard_archive, "w:gz") as tf:
        info = tarfile.TarInfo(name="hard")
        info.type = tarfile.LNKTYPE
        info.linkname = "target"
        tf.addfile(info)

    with pytest.raises(ValueError, match="disallowed type"):
        store.import_snapshot(hard_archive, "hard-victim")
    assert not store.exists("hard-victim")


def test_import_snapshot_enforces_max_bytes(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "store")
    archive = tmp_path / "large.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for idx in range(3):
            payload = b"a" * 512
            info = tarfile.TarInfo(name=f"chunk_{idx}.bin")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    with pytest.raises(ValueError, match="exceeds max_bytes"):
        store.import_snapshot(archive, "too-big", max_bytes=1024)
    assert not store.exists("too-big")
    # Staging directory must be cleaned up on failure.
    assert list(store.root_dir.iterdir()) == []

    with pytest.raises(ValueError, match="max_bytes must be positive"):
        store.import_snapshot(archive, "bad-cap", max_bytes=0)

    # Succeeds when within cap.
    restored = store.import_snapshot(archive, "fits", max_bytes=2048)
    assert (restored / "chunk_2.bin").read_bytes() == b"a" * 512
