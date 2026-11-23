"""Second-review tests for `waybound.profile`: races, foreign archives, malformed headers."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest

from waybound import profile as wp
from waybound.cli import main
from waybound.profile import (
    IMPORT_MARKER,
    MANIFEST_NAME,
    BundleVerificationError,
    ProfileError,
    ProfileLockedError,
    current_os,
    export_profile,
    import_profile,
    verify_bundle,
)

BSDTAR = shutil.which("bsdtar")


# ---------------------------------------------------------------------------- helpers


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _profile(root: Path) -> Path:
    _write(root / "Local State", b"{}")
    db = root / "Default" / "Cookies"
    db.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE cookies (host_key TEXT, encrypted_value BLOB)")
        conn.execute("INSERT INTO cookies VALUES ('.example.com', x'7631300102')")
        conn.commit()
    _write(root / "Default" / "Preferences", b'{"a": 1}')
    _write(root / "Default" / "Local Storage" / "leveldb" / "000003.log", b"tokens" * 50)
    return root


def _tree(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink() and p.name != IMPORT_MARKER
    }


def _bundle(tmp_path: Path) -> tuple[Path, Path]:
    src = _profile(tmp_path / "src")
    out = tmp_path / "bundle.tar.gz"
    export_profile(src, out)
    return src, out


def _siblings(parent: Path, marker: str) -> list[Path]:
    return [p for p in parent.iterdir() if marker in p.name]


def _manifest(files: list[tuple[str, bytes]], **overrides: object) -> bytes:
    doc: dict[str, object] = {
        "kind": "waybound-profile-bundle",
        "format_version": 1,
        "waybound_version": "test",
        "created_at": "2026-01-01T00:00:00+00:00",
        "source": {"os": current_os(), "arch": "x86_64"},
        "chrome_version": None,
        "password_store": None,
        "cookie_encryption_prefixes": [],
        "include_credentials": False,
        "files": [
            {"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in files
        ],
    }
    doc.update(overrides)
    return json.dumps(doc).encode()


def _tar_bytes(
    files: list[tuple[str, bytes]],
    *,
    fmt: int = tarfile.PAX_FORMAT,
    pax: dict[str, str] | None = None,
) -> bytes:
    buf = io.BytesIO()
    raw = _manifest(files)
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
        for name, data in files:
            member = tarfile.TarInfo("profile/" + name)
            member.size = len(data)
            if pax is not None:
                member.pax_headers = dict(pax)
            tar.addfile(member, io.BytesIO(data))
    return buf.getvalue()


def _gz(path: Path, data: bytes) -> Path:
    path.write_bytes(gzip.compress(data))
    return path


def _pax_record(key: str, value: str) -> bytes:
    body = f" {key}={value}\n".encode()
    length = len(body) + 1
    while len(str(length).encode()) + len(body) != length:
        length = len(str(length).encode()) + len(body)
    return str(length).encode() + body


def _raw_pax_bundle(path: Path, pax_data: bytes, name: str, payload: bytes) -> Path:
    """Manifest, then a PAX header with `pax_data` verbatim, then one regular member."""
    raw = _manifest([(name, payload)])
    out = io.BytesIO()

    def add(info: tarfile.TarInfo, data: bytes) -> None:
        out.write(info.tobuf(format=tarfile.USTAR_FORMAT))
        out.write(data + b"\0" * (-len(data) % 512))

    manifest = tarfile.TarInfo(MANIFEST_NAME)
    manifest.size = len(raw)
    add(manifest, raw)
    header = tarfile.TarInfo("././@PaxHeader")
    header.type = tarfile.XHDTYPE
    header.size = len(pax_data)
    add(header, pax_data)
    member = tarfile.TarInfo("profile/" + name)
    member.size = len(payload)
    add(member, payload)
    out.write(b"\0" * 1024)
    return _gz(path, out.getvalue())


# ---------------------------------------------------------------------------- N2 races


def _hook_after_extraction(monkeypatch: pytest.MonkeyPatch, action: object) -> None:
    real = wp._fix_permissions

    def hooked(root: Path) -> None:
        real(root)
        assert callable(action)
        action()

    monkeypatch.setattr(wp, "_fix_permissions", hooked)


def test_content_appearing_in_empty_target_is_not_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _bundle(tmp_path)
    target = tmp_path / "empty"
    target.mkdir()
    _hook_after_extraction(monkeypatch, lambda: _write(target / "intruder", b"precious"))
    with pytest.raises(ProfileError, match=r"not empty.*kept at") as info:
        import_profile(bundle, target)
    assert (target / "intruder").read_bytes() == b"precious"
    staged = _siblings(tmp_path, ".waybound-import-")
    assert len(staged) == 1
    assert str(staged[0]) in str(info.value)
    assert not _siblings(tmp_path, ".waybound-backup-")


def test_rename_onto_empty_dir_fails_if_content_appears_after_recheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _bundle(tmp_path)
    target = tmp_path / "empty"
    target.mkdir()
    real = wp._recheck

    def late(*args: object, **kwargs: object) -> wp.TargetState:
        state = real(*args, **kwargs)  # type: ignore[arg-type]
        _write(target / "late", b"x")
        return state

    monkeypatch.setattr(wp, "_recheck", late)
    with pytest.raises(ProfileError, match="kept at"):
        import_profile(bundle, target)
    assert (target / "late").read_bytes() == b"x"
    assert len(_siblings(tmp_path, ".waybound-import-")) == 1


def test_lock_appearing_during_forced_import_is_honoured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _bundle(tmp_path)
    target = tmp_path / "live"
    _write(target / "Local State", b"OLD")
    lock = target / "SingletonLock"
    _hook_after_extraction(
        monkeypatch, lambda: lock.symlink_to(f"{socket.gethostname()}-{os.getpid()}")
    )
    with pytest.raises(ProfileLockedError, match="kept at"):
        import_profile(bundle, target, force=True)
    assert (target / "Local State").read_bytes() == b"OLD"
    assert os.path.lexists(lock)
    assert not _siblings(tmp_path, ".waybound-backup-")


def test_target_appearing_as_file_is_not_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _bundle(tmp_path)
    target = tmp_path / "new"
    _hook_after_extraction(monkeypatch, lambda: _write(target, b"a file"))
    with pytest.raises(ProfileError, match="not a directory"):
        import_profile(bundle, target)
    assert target.read_bytes() == b"a file"


# ---------------------------------------------------------------------------- N3


@pytest.mark.parametrize("layout", ["default-dir-only", "local-state-dir", "prefs-symlink"])
def test_force_guard_needs_real_profile_files(tmp_path: Path, layout: str) -> None:
    _, bundle = _bundle(tmp_path)
    target = tmp_path / "src-tree"
    _write(target / "main.c", b"int main(){}")
    if layout == "default-dir-only":
        _write(target / "Default" / "config.h", b"x")
    elif layout == "local-state-dir":
        (target / "Local State").mkdir()
    else:
        (target / "Default").mkdir()
        _write(tmp_path / "elsewhere", b"{}")
        (target / "Default" / "Preferences").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ProfileError, match="only replaces"):
        import_profile(bundle, target, force=True)
    assert (target / "main.c").exists()


def test_force_guard_accepts_default_preferences(tmp_path: Path) -> None:
    src, bundle = _bundle(tmp_path)
    target = tmp_path / "old"
    _write(target / "Default" / "Preferences", b"{}")
    import_profile(bundle, target, force=True)
    assert _tree(target) == _tree(src)


# ---------------------------------------------------------------------------- N4


@pytest.mark.parametrize(
    "record",
    [
        _pax_record("size", "١٢"),  # Arabic-Indic digits pass str.isdigit()
        _pax_record("size", "9" * 5000),  # beyond int()'s default digit limit
        _pax_record("size", "-1"),
        b"\xd9\xa1\xd9\xa1 size=1\n",  # non-ASCII length field
        b"99999999999999999999999 size=1\n",
    ],
)
def test_malformed_pax_numbers_are_clean_errors(
    tmp_path: Path, record: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _raw_pax_bundle(tmp_path / "b.tar.gz", record, "Default/Preferences", b"{}")
    with pytest.raises(BundleVerificationError):
        verify_bundle(bundle)
    with pytest.raises(BundleVerificationError):
        import_profile(bundle, tmp_path / "t")
    assert main(["profile", "import", str(bundle), str(tmp_path / "t")]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err


def test_octal_field_with_trailing_newline_is_rejected() -> None:
    with pytest.raises(BundleVerificationError):
        wp._octal(b"0000644\n", "mode")


# ---------------------------------------------------------------------------- N5


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("comment", "hi"),
        ("GNU.sparse.size", "10"),
        ("linkpath", "/etc/passwd"),
        ("hdrcharset", "BINARY"),
    ],
)
def test_unknown_pax_keys_are_refused(tmp_path: Path, key: str, value: str) -> None:
    record = _pax_record(key, value)
    bundle = _raw_pax_bundle(tmp_path / "b.tar.gz", record, "Default/Preferences", b"{}")
    with pytest.raises(BundleVerificationError, match="unsupported PAX"):
        verify_bundle(bundle)


def test_harmless_pax_keys_are_accepted(tmp_path: Path) -> None:
    pax = {"mtime": "1700000000.25", "atime": "1.5", "SCHILY.xattr.user.test": "x"}
    data = _tar_bytes([("Default/Preferences", b"{}")], pax=pax)
    assert verify_bundle(_gz(tmp_path / "b.tar.gz", data)).files


def test_oversized_pax_header_per_member_is_refused(tmp_path: Path) -> None:
    record = _pax_record("path", "profile/Default/Local Storage/" + "a" * 5000)
    bundle = _raw_pax_bundle(tmp_path / "b.tar.gz", record, "Default/Preferences", b"{}")
    with pytest.raises(BundleVerificationError, match="exceeds the limit"):
        verify_bundle(bundle)


def test_long_and_unicode_names_round_trip(tmp_path: Path) -> None:
    src = _profile(tmp_path / "src")
    long_dir = src / "Default" / "IndexedDB" / ("https_" + "sub." * 40 + "example.com_0.leveldb")
    _write(long_dir / "000001.log", b"idb")
    _write(src / "Default" / "Local Storage" / "leveldb" / "café-日本.log", b"u")
    bundle = tmp_path / "b.tar.gz"
    export_profile(src, bundle)
    import_profile(bundle, tmp_path / "restored")
    assert _tree(tmp_path / "restored") == _tree(src)


# ---------------------------------------------------------------------------- foreign tools


def test_ustar_written_by_tarfile_is_accepted(tmp_path: Path) -> None:
    data = _tar_bytes([("Default/Preferences", b"{}")], fmt=tarfile.USTAR_FORMAT)
    assert verify_bundle(_gz(tmp_path / "b.tar.gz", data)).files


def test_gnu_long_names_are_refused(tmp_path: Path) -> None:
    name = "Default/Local Storage/" + "x" * 120
    data = _tar_bytes([(name, b"1")], fmt=tarfile.GNU_FORMAT)
    with pytest.raises(BundleVerificationError, match="unsupported tar extended header"):
        verify_bundle(_gz(tmp_path / "b.tar.gz", data))


@pytest.mark.skipif(BSDTAR is None, reason="bsdtar not installed")
@pytest.mark.parametrize("fmt", ["pax", "ustar", "gnutar"])
def test_bundles_written_by_bsdtar_are_accepted(tmp_path: Path, fmt: str) -> None:
    files = [("Default/Preferences", b'{"x": 1}'), ("Local State", b"{}")]
    root = tmp_path / "tree"
    _write(root / MANIFEST_NAME, _manifest(files))
    for name, data in files:
        _write(root / "profile" / name, data)
    out = tmp_path / f"bsd-{fmt}.tar.gz"
    assert BSDTAR is not None
    subprocess.run(  # noqa: S603
        [
            BSDTAR,
            "--no-mac-metadata",
            "--no-xattrs",
            f"--format={fmt}",
            "-czf",
            str(out),
            "-C",
            str(root),
            MANIFEST_NAME,
            *[f"profile/{name}" for name, _ in files],
        ],
        check=True,
    )
    manifest = verify_bundle(out)
    assert {f.path for f in manifest.files} == {n for n, _ in files}
    import_profile(out, tmp_path / "restored")
    assert (tmp_path / "restored" / "Default" / "Preferences").read_bytes() == b'{"x": 1}'


# ---------------------------------------------------------------------------- N7


def test_concatenated_gzip_member_is_refused(tmp_path: Path) -> None:
    _, bundle = _bundle(tmp_path)
    bundle.write_bytes(bundle.read_bytes() + gzip.compress(b"\0" * 1024))
    with pytest.raises(BundleVerificationError, match="after the gzip stream"):
        verify_bundle(bundle)


def test_trailing_garbage_after_gzip_is_refused(tmp_path: Path) -> None:
    _, bundle = _bundle(tmp_path)
    bundle.write_bytes(bundle.read_bytes() + b"garbage")
    with pytest.raises(BundleVerificationError, match="after the gzip stream"):
        verify_bundle(bundle)


def test_bad_gzip_crc_is_refused(tmp_path: Path) -> None:
    _, bundle = _bundle(tmp_path)
    data = bytearray(bundle.read_bytes())
    data[-8] ^= 0xFF  # CRC-32 in the gzip trailer
    bundle.write_bytes(bytes(data))
    with pytest.raises(BundleVerificationError, match="corrupt"):
        verify_bundle(bundle)


def test_data_after_tar_end_marker_is_refused(tmp_path: Path) -> None:
    data = _tar_bytes([("Default/Preferences", b"{}")]) + b"X" * 512
    with pytest.raises(BundleVerificationError, match="after the end of the archive"):
        verify_bundle(_gz(tmp_path / "b.tar.gz", data))


# ---------------------------------------------------------------------------- N6


def test_leftovers_from_interrupted_imports_are_reported(tmp_path: Path) -> None:
    _, bundle = _bundle(tmp_path)
    backup = tmp_path / ".t.waybound-backup-abc123"
    staging = tmp_path / ".t.waybound-import-xyz"
    _write(backup / "Local State", b"old")
    staging.mkdir()
    result = import_profile(bundle, tmp_path / "t")
    joined = "\n".join(result.warnings)
    assert str(backup) in joined
    assert "rename it to" in joined
    assert str(staging) in joined
    assert backup.exists()
    assert staging.exists()


def test_interrupt_during_swap_notes_where_the_copies_are(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _bundle(tmp_path)
    target = tmp_path / "p"
    _write(target / "Local State", b"OLD")
    real = Path.rename

    def fake(self: Path, dest: str | os.PathLike[str]) -> Path:
        if ".waybound-import-" in self.name:
            raise KeyboardInterrupt
        return real(self, dest)

    monkeypatch.setattr(Path, "rename", fake)
    with pytest.raises(KeyboardInterrupt) as info:
        import_profile(bundle, target, force=True)
    monkeypatch.undo()
    notes = "\n".join(getattr(info.value, "__notes__", []))
    staged = _siblings(tmp_path, ".waybound-import-")
    assert len(staged) == 1
    assert str(staged[0]) in notes
    assert (target / "Local State").read_bytes() == b"OLD"


# ---------------------------------------------------------------------------- N8


@pytest.fixture
def fake_mount(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    mount = tmp_path / "volume"
    mount.mkdir()
    real = os.path.ismount
    resolved = mount.resolve()

    def ismount(path: str | os.PathLike[str]) -> bool:
        return Path(path) == resolved or real(path)

    monkeypatch.setattr(os.path, "ismount", ismount)
    return mount


def test_empty_mount_point_is_filled_in_place(tmp_path: Path, fake_mount: Path) -> None:
    src, bundle = _bundle(tmp_path)
    result = import_profile(bundle, fake_mount)
    assert result.profile_dir == fake_mount
    assert _tree(fake_mount) == _tree(src)
    assert not [p for p in fake_mount.iterdir() if ".waybound-import-" in p.name]
    assert stat.S_IMODE(fake_mount.stat().st_mode) == 0o700


def test_non_empty_mount_point_is_refused_even_with_force(tmp_path: Path, fake_mount: Path) -> None:
    _, bundle = _bundle(tmp_path)
    _write(fake_mount / "Local State", b"OLD")
    with pytest.raises(ProfileError, match="mount point"):
        import_profile(bundle, fake_mount, force=True)
    assert (fake_mount / "Local State").read_bytes() == b"OLD"


def test_failed_mount_fill_removes_only_what_it_created(
    tmp_path: Path, fake_mount: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, bundle = _bundle(tmp_path)
    real = Path.rename
    calls = {"n": 0}

    def flaky(self: Path, dest: str | os.PathLike[str]) -> Path:
        if ".waybound-import-" in str(self.parent):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(5, "simulated I/O error")
        return real(self, dest)

    monkeypatch.setattr(Path, "rename", flaky)
    with pytest.raises(OSError, match="simulated"):
        import_profile(bundle, fake_mount)
    monkeypatch.undo()
    assert list(fake_mount.iterdir()) == []


# ---------------------------------------------------------------------------- N9


def test_cookie_copy_lives_next_to_the_bundle_and_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _profile(tmp_path / "src")
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(system_tmp))
    seen: list[str] = []
    real = wp._read_prefixes

    def spy(db: Path, scratch_dir: Path | str | None) -> set[str] | None:
        seen.append(str(scratch_dir))
        return real(db, scratch_dir)

    monkeypatch.setattr(wp, "_read_prefixes", spy)
    out = tmp_path / "out" / "b.tar.gz"
    result = export_profile(src, out)
    assert result.manifest.cookie_encryption_prefixes == ("v10",)
    assert seen == [str(out.parent)]
    assert list(system_tmp.iterdir()) == []
    assert sorted(p.name for p in out.parent.iterdir()) == ["b.tar.gz"]
