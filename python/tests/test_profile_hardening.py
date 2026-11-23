"""Hostile-input, crash-safety and data-loss tests for `waybound.profile` (synthetic only)."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import tarfile
import unicodedata
from pathlib import Path

import pytest

from waybound import profile as wp
from waybound.cli import main
from waybound.profile import (
    IMPORT_MARKER,
    MANIFEST_NAME,
    MAX_MANIFEST_BYTES,
    BundleVerificationError,
    ProfileError,
    ProfileLockedError,
    assess_compatibility,
    current_os,
    detect_cookie_encryption,
    export_profile,
    import_profile,
    read_manifest,
    verify_bundle,
)

MiB = 1024 * 1024


# ---------------------------------------------------------------------------- helpers


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _cookie_db(path: Path, prefix: bytes = b"v10") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute("CREATE TABLE cookies (host_key TEXT, encrypted_value BLOB)")
        conn.execute("INSERT INTO cookies VALUES ('.example.com', ?)", (prefix + b"secret",))
        conn.commit()


def _profile(root: Path) -> Path:
    _write(root / "Local State", b"{}")
    _write(root / "Last Version", b"150.0.1.2\n")
    _cookie_db(root / "Default" / "Cookies")
    _write(root / "Default" / "Preferences", b'{"a": 1}')
    _write(root / "Default" / "Local Storage" / "leveldb" / "000003.log", b"tokens" * 100)
    return root


def _tree(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink() and p.name != IMPORT_MARKER
    }


def _portable_bundle(tmp_path: Path) -> tuple[Path, Path]:
    src = _profile(tmp_path / "src")
    bundle = tmp_path / "bundle.tar.gz"
    export_profile(src, bundle)
    return src, bundle


def _old_profile(target: Path) -> None:
    _write(target / "Local State", b"OLD")
    _write(target / "Default" / "Preferences", b"OLD PREFS")


def _no_staging_left(parent: Path) -> None:
    assert not [p.name for p in parent.iterdir() if ".waybound-import-" in p.name]


def _manifest_doc(entries: list[tuple[str, bytes]], **overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "kind": "waybound-profile-bundle",
        "format_version": 1,
        "waybound_version": "test",
        "created_at": "2026-01-01T00:00:00+00:00",
        "source": {"os": current_os(), "arch": "x86_64"},
        "chrome_version": "1.2.3",
        "password_store": None,
        "cookie_encryption_prefixes": [],
        "include_credentials": False,
        "files": [
            {"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in entries
        ],
    }
    doc.update(overrides)
    return doc


def _bundle_from(path: Path, members: list[tuple[str, bytes]], **overrides: object) -> Path:
    raw = json.dumps(_manifest_doc(members, **overrides)).encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
        for name, data in members:
            member = tarfile.TarInfo("profile/" + name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return path


class _Counter:
    """Wraps the decompressed stream and records how many bytes were requested and read."""

    def __init__(self, inner: wp._Readable) -> None:
        self.inner = inner
        self.read_bytes = 0
        self.largest_request = 0

    def read(self, size: int = -1, /) -> bytes:
        self.largest_request = max(self.largest_request, size)
        data = self.inner.read(size)
        self.read_bytes += len(data)
        return data

    def close(self) -> None:
        self.inner.close()


@pytest.fixture
def counter(monkeypatch: pytest.MonkeyPatch) -> list[_Counter]:
    seen: list[_Counter] = []
    real = wp._open_gzip

    def counting(bundle: Path) -> wp._Readable:
        wrapped = _Counter(real(bundle))
        seen.append(wrapped)
        return wrapped

    monkeypatch.setattr(wp, "_open_gzip", counting)
    return seen


def _raw_header(name: str, size: int, kind: bytes) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = size
    info.type = kind
    return info.tobuf(format=tarfile.USTAR_FORMAT)


def _bomb(path: Path, first: bytes, filler: int) -> Path:
    """A tiny .tar.gz whose first header announces `filler` bytes of zeros."""
    with gzip.open(path, "wb") as gz:
        gz.write(first)
        zeros = bytes(MiB)
        remaining = filler
        while remaining > 0:
            gz.write(zeros[: min(MiB, remaining)])
            remaining -= MiB
    return path


# ---------------------------------------------------------------------------- H1 / H3


def test_force_import_with_relative_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, bundle = _portable_bundle(tmp_path)
    work = tmp_path / "work"
    _old_profile(work / "rel-target")
    monkeypatch.chdir(work)
    result = import_profile(bundle, "rel-target", force=True)
    assert result.profile_dir == work / "rel-target"
    assert _tree(work / "rel-target") == _tree(src)
    assert sorted(p.name for p in work.iterdir()) == ["rel-target"]


def test_import_into_new_relative_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src, bundle = _portable_bundle(tmp_path)
    monkeypatch.chdir(tmp_path)
    import_profile(bundle, Path("fresh") / ".." / "fresh2")
    assert _tree(tmp_path / "fresh2") == _tree(src)
    assert not (tmp_path / "fresh").exists()


def _fail_rename(monkeypatch: pytest.MonkeyPatch, marker: str, exc: BaseException) -> None:
    real = Path.rename

    def fake(self: Path, target: str | os.PathLike[str]) -> Path:
        if marker in self.name:
            raise exc
        return real(self, target)

    monkeypatch.setattr(Path, "rename", fake)


@pytest.mark.parametrize("step", ["move-old-aside", "move-new-in"])
def test_force_failure_at_each_rename_keeps_old_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    _, bundle = _portable_bundle(tmp_path)
    parent = tmp_path / "dest"
    target = parent / "profile"
    _old_profile(target)
    before = _tree(target)
    marker = "profile" if step == "move-old-aside" else ".waybound-import-"
    _fail_rename(monkeypatch, marker, OSError(28, "simulated failure"))
    with pytest.raises(ProfileError, match="kept at") as info:
        import_profile(bundle, target, force=True)
    monkeypatch.undo()
    assert _tree(target) == before, "the original profile must survive"
    staged = [p for p in parent.iterdir() if ".waybound-import-" in p.name]
    assert len(staged) == 1, "the verified import must be kept for the user"
    assert str(staged[0]) in str(info.value)
    assert (staged[0] / "Default" / "Preferences").read_bytes() == b'{"a": 1}'
    assert not [p for p in parent.iterdir() if ".waybound-backup-" in p.name]


def test_ctrl_c_while_moving_in_rolls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "dest" / "profile"
    _old_profile(target)
    before = _tree(target)
    _fail_rename(monkeypatch, ".waybound-import-", KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        import_profile(bundle, target, force=True)
    monkeypatch.undo()
    assert _tree(target) == before
    assert not [p for p in target.parent.iterdir() if ".waybound-backup-" in p.name]


def test_ctrl_c_during_extraction_leaves_target_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "dest" / "profile"
    _old_profile(target)
    before = _tree(target)
    real = wp._copy_verified
    calls = {"n": 0}

    def interrupt(*args: object, **kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(wp, "_copy_verified", interrupt)
    with pytest.raises(KeyboardInterrupt):
        import_profile(bundle, target, force=True)
    assert _tree(target) == before
    _no_staging_left(target.parent)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX non-root")
def test_undeletable_old_profile_is_left_aside_with_warning(tmp_path: Path) -> None:
    src, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "dest" / "profile"
    _old_profile(target)
    locked = target / "Default" / "locked"
    _write(locked / "file", b"x")
    locked.chmod(0o500)
    try:
        result = import_profile(bundle, target, force=True)
        assert _tree(target) == _tree(src)
        backups = [p for p in target.parent.iterdir() if ".waybound-backup-" in p.name]
        assert len(backups) == 1
        assert any(str(backups[0]) in w for w in result.warnings)
    finally:
        for path in target.parent.rglob("locked"):
            path.chmod(0o700)


def test_force_does_not_follow_symlinks_in_old_target(tmp_path: Path) -> None:
    _, bundle = _portable_bundle(tmp_path)
    outside = tmp_path / "precious"
    _write(outside / "data.txt", b"keep me")
    target = tmp_path / "dest" / "profile"
    _old_profile(target)
    (target / "Default" / "link").symlink_to(outside)
    (target / "file-link").symlink_to(outside / "data.txt")
    import_profile(bundle, target, force=True)
    assert (outside / "data.txt").read_bytes() == b"keep me"


def test_empty_existing_target_uses_same_swap(tmp_path: Path) -> None:
    src, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "empty"
    target.mkdir()
    import_profile(bundle, target)
    assert _tree(target) == _tree(src)
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".")) == []


def test_created_parents_are_private_and_removed_on_failure(tmp_path: Path) -> None:
    _, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "a" / "b" / "profile"
    import_profile(bundle, target)
    assert stat.S_IMODE((tmp_path / "a").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "a" / "b").stat().st_mode) == 0o700

    bad = _bundle_from(
        tmp_path / "bad.tar.gz", [("Default/Preferences", b"{}")], files=[]
    )  # manifest lists nothing but the archive carries a member
    with pytest.raises(BundleVerificationError):
        import_profile(bad, tmp_path / "x" / "y" / "profile")
    assert not (tmp_path / "x").exists()


# ---------------------------------------------------------------------------- M1


def test_force_refuses_directories_that_are_not_profiles(tmp_path: Path) -> None:
    _, bundle = _portable_bundle(tmp_path)
    docs = tmp_path / "Documents"
    _write(docs / "thesis.txt", b"important")
    with pytest.raises(ProfileError, match="only replaces"):
        import_profile(bundle, docs, force=True)
    assert (docs / "thesis.txt").read_bytes() == b"important"


def test_force_accepts_a_previous_import(tmp_path: Path) -> None:
    src, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "again"
    import_profile(bundle, target)
    (target / "Local State").unlink()
    shutil.rmtree(target / "Default")
    _write(target / "junk", b"x")
    import_profile(bundle, target, force=True)
    assert _tree(target) == _tree(src)


@pytest.mark.parametrize("which", ["home", "home-parent", "root"])
def test_force_refuses_home_ancestors_and_roots(tmp_path: Path, which: str) -> None:
    _, bundle = _portable_bundle(tmp_path)
    home = Path.home()
    target = {"home": home, "home-parent": home.parent, "root": Path(home.anchor)}[which]
    with pytest.raises(ProfileError, match="refusing to import"):
        import_profile(bundle, target, force=True)


def test_import_ignore_lock_for_foreign_target_lock(tmp_path: Path) -> None:
    src, bundle = _portable_bundle(tmp_path)
    target = tmp_path / "t"
    _old_profile(target)
    (target / "SingletonLock").symlink_to("container-host-77")
    with pytest.raises(ProfileLockedError, match="another host"):
        import_profile(bundle, target, force=True)
    import_profile(bundle, target, force=True, ignore_lock=True)
    assert _tree(target) == _tree(src)


# ---------------------------------------------------------------------------- H2


def test_pax_header_bomb_is_refused_without_reading_it(
    tmp_path: Path, counter: list[_Counter]
) -> None:
    bomb = _bomb(tmp_path / "pax.tar.gz", _raw_header("x", 64 * MiB, tarfile.XHDTYPE), 64 * MiB)
    assert bomb.stat().st_size < MiB
    for action in (
        lambda: read_manifest(bomb),
        lambda: verify_bundle(bomb),
        lambda: import_profile(bomb, tmp_path / "t"),
    ):
        with pytest.raises(BundleVerificationError, match="extended header"):
            action()
    assert counter
    assert all(c.read_bytes <= 4096 and c.largest_request <= MiB for c in counter)
    assert not (tmp_path / "t").exists()


@pytest.mark.parametrize("kind", [tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, b"g"])
def test_gnu_and_global_headers_are_refused(
    tmp_path: Path, counter: list[_Counter], kind: bytes
) -> None:
    bomb = _bomb(tmp_path / "gnu.tar.gz", _raw_header("x", 32 * MiB, kind), 32 * MiB)
    with pytest.raises(BundleVerificationError, match="unsupported"):
        read_manifest(bomb)
    assert counter[0].read_bytes <= 4096


def test_giant_manifest_is_refused_without_reading_it(
    tmp_path: Path, counter: list[_Counter]
) -> None:
    size = MAX_MANIFEST_BYTES + 1
    bomb = _bomb(tmp_path / "m.tar.gz", _raw_header(MANIFEST_NAME, size, tarfile.REGTYPE), size)
    with pytest.raises(BundleVerificationError, match="manifest is too large"):
        read_manifest(bomb)
    assert counter[0].read_bytes <= 4096


def test_member_larger_than_declared_is_refused_without_reading_it(
    tmp_path: Path, counter: list[_Counter]
) -> None:
    raw = json.dumps(_manifest_doc([("Default/Preferences", b"{}")])).encode()
    head = _raw_header(MANIFEST_NAME, len(raw), tarfile.REGTYPE) + raw.ljust(
        (len(raw) + 511) // 512 * 512, b"\0"
    )
    head += _raw_header("profile/Default/Preferences", 64 * MiB, tarfile.REGTYPE)
    bomb = _bomb(tmp_path / "big.tar.gz", head, 64 * MiB)
    with pytest.raises(BundleVerificationError, match="size mismatch"):
        verify_bundle(bomb)
    assert counter[0].read_bytes < 64 * 1024


def test_inspect_honours_max_bytes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, bundle = _portable_bundle(tmp_path)
    assert main(["profile", "inspect", str(bundle), "--max-bytes", "10"]) == 1
    assert "larger than" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX non-root")
def test_unreadable_bundle_is_not_called_corrupt(tmp_path: Path) -> None:
    _, bundle = _portable_bundle(tmp_path)
    bundle.chmod(0)
    try:
        with pytest.raises(ProfileError, match="cannot read bundle") as info:
            read_manifest(bundle)
        assert not isinstance(info.value, BundleVerificationError)
    finally:
        bundle.chmod(0o600)


def test_max_bytes_must_be_positive(tmp_path: Path) -> None:
    _, bundle = _portable_bundle(tmp_path)
    with pytest.raises(ProfileError, match="positive"):
        read_manifest(bundle, max_bytes=0)


# ---------------------------------------------------------------------------- M3


@pytest.mark.parametrize(
    "files",
    [
        [
            ("Default/Local Storage/" + unicodedata.normalize("NFC", "é"), b"1"),
            ("Default/Local Storage/" + unicodedata.normalize("NFD", "é"), b"2"),
        ],
        [("Default/Local Storage/a", b"1"), ("Default/Local Storage/A/b", b"2")],
        [("Default/Local Storage/A/b", b"1"), ("Default/Local Storage/a", b"2")],
        [("Default/Local Storage/x", b"1"), ("Default/Local Storage/X", b"2")],
    ],
)
def test_unicode_and_file_dir_collisions_refused(
    tmp_path: Path, files: list[tuple[str, bytes]]
) -> None:
    bundle = _bundle_from(tmp_path / "b.tar.gz", files)
    with pytest.raises(BundleVerificationError, match="collides"):
        import_profile(bundle, tmp_path / "t")
    assert not (tmp_path / "t").exists()


@pytest.mark.parametrize(
    "name",
    ["CON", "nul.txt", "com1.log", "Lpt9", "trailing.", "trailing ", "a" * 256, "tab\there", "q?"],
)
def test_non_portable_names_refused(tmp_path: Path, name: str) -> None:
    bundle = _bundle_from(tmp_path / "b.tar.gz", [(f"Default/Local Storage/{name}", b"x")])
    with pytest.raises(BundleVerificationError, match="unsafe path"):
        import_profile(bundle, tmp_path / "t")


def test_extraction_oserror_is_wrapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, bundle = _portable_bundle(tmp_path)

    def boom(_self: wp._Sink, rel: str) -> io.BufferedWriter:
        raise OSError(63, "File name too long", rel)

    monkeypatch.setattr(wp._Sink, "open", boom)
    with pytest.raises(ProfileError, match="could not extract"):
        import_profile(bundle, tmp_path / "t")
    assert not (tmp_path / "t").exists()
    _no_staging_left(tmp_path)


# ---------------------------------------------------------------------------- M2


def test_wal_only_prefixes_are_detected_without_touching_source(tmp_path: Path) -> None:
    db = tmp_path / "p" / "Default" / "Cookies"
    db.parent.mkdir(parents=True)
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE cookies (host_key TEXT, encrypted_value BLOB)")
        conn.execute("INSERT INTO cookies VALUES ('a', x'7631300000')")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("INSERT INTO cookies VALUES ('b', x'7631310000')")
        conn.commit()
        wal = Path(f"{db}-wal")
        assert wal.stat().st_size > 0
        before = {p.name: p.read_bytes() for p in db.parent.iterdir()}
        assert detect_cookie_encryption(tmp_path / "p") == ("v10", "v11")
        after = {p.name: p.read_bytes() for p in db.parent.iterdir()}
        assert before == after


def test_unreadable_cookie_db_is_unknown(tmp_path: Path) -> None:
    _write(tmp_path / "p" / "Default" / "Cookies", b"not sqlite at all" * 100)
    assert detect_cookie_encryption(tmp_path / "p") is None


# ---------------------------------------------------------------------------- L1 / L2 / L4 / L5


def test_export_skips_names_the_importer_would_reject(tmp_path: Path) -> None:
    src = _profile(tmp_path / "src")
    _write(src / "Default" / "Local Storage" / "leveldb" / "a:b", b"x")
    _write(src / "Default" / "Local Storage" / "leveldb" / "CON", b"x")
    result = export_profile(src, tmp_path / "b.tar.gz")
    paths = {f.path for f in result.manifest.files}
    assert "Default/Local Storage/leveldb/a:b" in result.skipped
    assert "Default/Local Storage/leveldb/CON" in result.skipped
    assert not any(p.endswith(("a:b", "CON")) for p in paths)
    import_profile(tmp_path / "b.tar.gz", tmp_path / "restored")


def test_export_enforces_file_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _profile(tmp_path / "src")
    monkeypatch.setattr(wp, "MAX_FILES", 2)
    with pytest.raises(ProfileError, match="limit"):
        export_profile(src, tmp_path / "b.tar.gz")
    assert not (tmp_path / "b.tar.gz").exists()


def test_manifest_is_compact_json(tmp_path: Path) -> None:
    _, bundle = _portable_bundle(tmp_path)
    with tarfile.open(bundle) as tar:
        member = tar.extractfile(MANIFEST_NAME)
        assert member is not None
        raw = member.read()
    assert b"\n" not in raw
    assert b", " not in raw


def test_bundle_inside_profile_refused(tmp_path: Path) -> None:
    src = _profile(tmp_path / "src")
    with pytest.raises(ProfileError, match="inside the profile"):
        export_profile(src, src / "Default" / "b.tar.gz")
    with pytest.raises(ProfileError, match="inside the profile"):
        export_profile(src, src / "b.tar.gz")


def test_export_parents_private_and_cleaned_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _profile(tmp_path / "src")
    export_profile(src, tmp_path / "o1" / "o2" / "b.tar.gz")
    assert stat.S_IMODE((tmp_path / "o1").stat().st_mode) == 0o700

    def broken(*_args: object, **_kwargs: object) -> None:
        raise BundleVerificationError("simulated")

    monkeypatch.setattr(wp, "verify_bundle", broken)
    with pytest.raises(BundleVerificationError):
        export_profile(src, tmp_path / "n1" / "n2" / "b.tar.gz")
    assert not (tmp_path / "n1").exists()


# ---------------------------------------------------------------------------- L6 / L7 / M4


def test_mislabelled_manifest_cannot_look_portable() -> None:
    compat = assess_compatibility("linux", "basic", "linux", prefixes=("v10", "v11"))
    assert compat.level == "same_machine_only"


def test_cross_os_bundle_without_encrypted_cookies_is_not_refused(tmp_path: Path) -> None:
    other = "windows" if current_os() != "windows" else "linux"
    bundle = _bundle_from(
        tmp_path / "b.tar.gz",
        [("Default/Preferences", b"{}")],
        source={"os": other, "arch": "x"},
        cookie_encryption_prefixes=[],
    )
    result = import_profile(bundle, tmp_path / "t")
    assert result.compatibility.level == "unknown"
    assert any("no encrypted cookies" in w for w in result.warnings)


def test_portable_verdict_says_unverified() -> None:
    compat = assess_compatibility("linux", "basic", "linux", prefixes=("v10",))
    assert compat.level == "portable"
    assert "not verified" in compat.message


def test_cli_export_output_says_unverified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = _profile(tmp_path / "src")
    assert main(["profile", "export", str(src), str(tmp_path / "b.tar.gz")]) == 0
    out = capsys.readouterr().out
    if current_os() == "linux":
        assert "expected to work (not verified" in out
    else:
        assert "restore on linux: cookies will not decrypt" in out
