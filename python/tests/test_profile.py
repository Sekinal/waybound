"""Tests for portable profile bundles (`waybound.profile`). No real Chrome is used."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
from typing import TYPE_CHECKING

import pytest

from waybound.cli import main
from waybound.profile import (
    IMPORT_MARKER,
    MANIFEST_NAME,
    BundleVerificationError,
    IncompatibleBundleError,
    OsName,
    PasswordStoreKind,
    ProfileError,
    ProfileLockedError,
    assess_compatibility,
    current_os,
    export_profile,
    import_profile,
    infer_password_store,
    is_included,
    profile_lock_state,
    read_manifest,
    verify_bundle,
)
from waybound.session import LaunchOptions, PasswordStore, Session

if TYPE_CHECKING:
    from pathlib import Path

COOKIE_SECRET = b"SUPER-SECRET-COOKIE-VALUE"
BASIC: PasswordStoreKind = "basic"
DPAPI: PasswordStoreKind = "dpapi"
CHROME_BASIC: PasswordStore = "basic"

EXPECTED_DEFAULT = {
    "Local State",
    "Last Version",
    "First Run",
    "Default/Cookies",
    "Default/Cookies-journal",
    "Default/Preferences",
    "Default/Secure Preferences",
    "Default/Local Storage/leveldb/000003.log",
    "Default/Local Storage/leveldb/CURRENT",
    "Default/Local Storage/leveldb/MANIFEST-000001",
    "Default/Session Storage/000001.log",
    "Default/IndexedDB/https_example.com_0.indexeddb.leveldb/000001.log",
    "Default/Service Worker/Database/000001.log",
    "Default/Service Worker/ScriptCache/index",
    "Default/WebStorage/QuotaManager",
    "Default/Network/Cookies",
    "Profile 1/Preferences",
}
CREDENTIAL_FILES = {"Default/Login Data", "Default/Login Data-journal", "Default/Web Data"}
EXCLUDED = {
    "SingletonCookie",
    "BrowserMetrics-spare.pma",
    "Crashpad/settings.dat",
    "GrShaderCache/data_0",
    "Safe Browsing/UrlCsdAllowlist.store",
    "WidevineCdm/manifest.json",
    "Default/Cookies-shm",
    "Default/Local Storage/leveldb/LOCK",
    "Default/Local Storage/leveldb/LOG",
    "Default/Local Storage/leveldb/LOG.old",
    "Default/IndexedDB/https_example.com_0.indexeddb.leveldb/LOCK",
    "Default/Service Worker/CacheStorage/abc/blob",
    "Default/Cache/Cache_Data/data_0",
    "Default/Code Cache/js/index",
    "Default/GPUCache/data_0",
    "Default/History",
    "Default/Favicons",
    "Default/Sessions/Session_1",
    "Default/Extensions/abc/manifest.json",
    "Default/Device Bound Sessions",
}


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _make_cookie_db(path: Path, prefix: bytes = b"v10") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)"
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?)",
            (".example.com", "sid", "", prefix + COOKIE_SECRET),
        )
        conn.commit()


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    root = tmp_path / "user-data"
    _write(root / "Local State", b'{"profile": {}}')
    _write(root / "Last Version", b"157.0.8103.79\n")
    _write(root / "First Run", b"")
    _make_cookie_db(root / "Default" / "Cookies")
    _make_cookie_db(root / "Default" / "Network" / "Cookies")
    _write(root / "Default" / "Cookies-journal", b"")
    _write(root / "Default" / "Preferences", b'{"x": 1}')
    _write(root / "Default" / "Secure Preferences", b"{}")
    for rel in sorted(EXPECTED_DEFAULT | CREDENTIAL_FILES | EXCLUDED):
        target = root / rel
        if not target.exists():
            _write(target, f"payload of {rel}\n".encode() * 3)
    (root / "Default" / "Local Storage" / "leveldb" / "evil-link").symlink_to("/etc/hosts")
    (root / "Default" / "linked-dir").symlink_to(tmp_path)
    return root


def _export(profile: Path, tmp_path: Path) -> tuple[Path, set[str]]:
    bundle = tmp_path / "out" / "session.tar.gz"
    result = export_profile(profile, bundle)
    return bundle, {f.path for f in result.manifest.files}


# ---------------------------------------------------------------------------- policy


def test_include_exclude_policy(profile: Path, tmp_path: Path) -> None:
    bundle, paths = _export(profile, tmp_path)
    assert paths == EXPECTED_DEFAULT
    with tarfile.open(bundle) as tar:
        names = tar.getnames()
    assert names[0] == MANIFEST_NAME
    assert set(names[1:]) == {f"profile/{p}" for p in EXPECTED_DEFAULT}
    assert not any("evil-link" in n or "linked-dir" in n for n in names)


def test_is_included_rejects_odd_paths() -> None:
    assert is_included("Default/Cookies")
    assert not is_included("Default/../Cookies")
    assert not is_included("Guest Profile/Cookies")
    assert not is_included("Default/Login Data")
    assert is_included("Default/Login Data", include_credentials=True)
    assert not is_included("Default/Local Storage/leveldb/LOCK")
    assert not is_included("NativeMessagingHosts/x.json")


def test_symlinks_are_reported_as_skipped(profile: Path, tmp_path: Path) -> None:
    result = export_profile(profile, tmp_path / "b.tar.gz")
    assert "Default/Local Storage/leveldb/evil-link" in result.skipped


def test_password_exclusion_default_and_opt_in(profile: Path, tmp_path: Path) -> None:
    _, default_paths = _export(profile, tmp_path)
    assert not default_paths & CREDENTIAL_FILES
    result = export_profile(profile, tmp_path / "creds.tar.gz", include_credentials=True)
    paths = {f.path for f in result.manifest.files}
    assert paths == EXPECTED_DEFAULT | CREDENTIAL_FILES
    assert result.manifest.include_credentials


# ---------------------------------------------------------------------------- manifest


def test_manifest_content(profile: Path, tmp_path: Path) -> None:
    bundle, _ = _export(profile, tmp_path)
    manifest = read_manifest(bundle)
    assert manifest.format_version == 1
    assert manifest.source_os == current_os()
    assert manifest.chrome_version == "157.0.8103.79"
    assert manifest.cookie_encryption_prefixes == ("v10",)
    assert manifest.password_store == infer_password_store(current_os(), ("v10",))
    assert manifest.include_credentials is False
    assert manifest.created_at.endswith("+00:00")
    for entry in manifest.files:
        data = (profile / entry.path).read_bytes()
        assert entry.size == len(data)
        assert entry.sha256 == hashlib.sha256(data).hexdigest()
    with tarfile.open(bundle) as tar:
        member = tar.extractfile(MANIFEST_NAME)
        assert member is not None
        raw = member.read()
    assert COOKIE_SECRET not in raw
    doc = json.loads(raw)
    assert doc["kind"] == "waybound-profile-bundle"
    assert doc["source"]["os"] == current_os()


def test_password_store_override_cannot_contradict_detection(profile: Path, tmp_path: Path) -> None:
    detected = infer_password_store(current_os(), ("v10",))
    assert detected is not None
    override: PasswordStoreKind = "keyring" if detected != "keyring" else "dpapi"
    result = export_profile(profile, tmp_path / "b.tar.gz", password_store=override)
    assert result.manifest.password_store == detected
    assert any("contradicts" in w for w in result.warnings)


def test_password_store_override_used_when_nothing_detected(profile: Path, tmp_path: Path) -> None:
    for db in ("Cookies", "Network/Cookies"):
        (profile / "Default" / db).unlink()
    result = export_profile(profile, tmp_path / "b.tar.gz", password_store=DPAPI)
    assert result.manifest.cookie_encryption_prefixes == ()
    assert result.manifest.password_store == DPAPI


def test_bundle_is_private_and_not_overwritten(profile: Path, tmp_path: Path) -> None:
    bundle, _ = _export(profile, tmp_path)
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    with pytest.raises(ProfileError, match="already exists"):
        export_profile(profile, bundle)
    export_profile(profile, bundle, overwrite=True)
    assert verify_bundle(bundle).files


def test_export_rejects_non_profile_dirs(profile: Path, tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="pass its parent"):
        export_profile(profile / "Default", tmp_path / "x.tar.gz")
    with pytest.raises(ProfileError, match="does not exist"):
        export_profile(tmp_path / "missing", tmp_path / "x.tar.gz")


# ---------------------------------------------------------------------------- locks


def test_export_refuses_live_lock(profile: Path, tmp_path: Path) -> None:
    (profile / "SingletonLock").symlink_to(f"{socket.gethostname()}-{os.getpid()}")
    assert profile_lock_state(profile) == "live"
    with pytest.raises(ProfileLockedError, match="running"):
        export_profile(profile, tmp_path / "b.tar.gz")
    with pytest.raises(ProfileLockedError, match="running"):
        export_profile(profile, tmp_path / "b.tar.gz", ignore_lock=True)
    assert not (tmp_path / "b.tar.gz").exists()


def test_foreign_lock_needs_ignore_lock(profile: Path, tmp_path: Path) -> None:
    (profile / "SingletonLock").symlink_to("some-other-host-4242")
    assert profile_lock_state(profile) == "foreign"
    with pytest.raises(ProfileLockedError, match="another host"):
        export_profile(profile, tmp_path / "b.tar.gz")
    result = export_profile(profile, tmp_path / "b.tar.gz", ignore_lock=True)
    assert any("another host" in w for w in result.warnings)


def test_unparseable_lock_is_live(profile: Path) -> None:
    (profile / "SingletonLock").symlink_to("garbage")
    assert profile_lock_state(profile) == "live"


def test_windows_lockfile_is_a_lock(profile: Path) -> None:
    _write(profile / "lockfile", b"")
    assert profile_lock_state(profile) == ("live" if os.name == "nt" else "foreign")


@pytest.mark.skipif(os.name != "posix", reason="SingletonLock pid probing is POSIX only")
def test_stale_lock_is_ignored_with_warning(profile: Path, tmp_path: Path) -> None:
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    (profile / "SingletonLock").symlink_to(f"{socket.gethostname()}-{dead.pid}")
    assert profile_lock_state(profile) == "stale"
    result = export_profile(profile, tmp_path / "b.tar.gz")
    assert any("stale" in w for w in result.warnings)
    assert "SingletonLock" not in {f.path for f in result.manifest.files}


# ---------------------------------------------------------------------------- import


def _tree(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink() and p.name != IMPORT_MARKER
    }


def _portable(profile: Path, tmp_path: Path) -> Path:
    bundle = tmp_path / "portable.tar.gz"
    store: PasswordStoreKind | None = "basic" if current_os() == "linux" else None
    export_profile(profile, bundle, password_store=store)
    return bundle


def test_round_trip_bytes_and_permissions(profile: Path, tmp_path: Path) -> None:
    bundle = _portable(profile, tmp_path)
    target = tmp_path / "restored"
    result = import_profile(bundle, target)
    assert (target / IMPORT_MARKER).is_file()
    restored = _tree(target)
    assert set(restored) == EXPECTED_DEFAULT
    for rel, data in restored.items():
        assert data == (profile / rel).read_bytes(), rel
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    for path in target.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), path
    assert not any(p.name.startswith(".waybound-import-") for p in target.iterdir())
    assert result.manifest.chrome_version == "157.0.8103.79"


def test_import_refuses_non_empty_target_without_force(profile: Path, tmp_path: Path) -> None:
    bundle = _portable(profile, tmp_path)
    target = tmp_path / "existing"
    _write(target / "old-file", b"old")
    outside = tmp_path / "outside-keep"
    _write(outside, b"keep")
    with pytest.raises(ProfileError, match="not empty"):
        import_profile(bundle, target)
    assert (target / "old-file").read_bytes() == b"old"
    with pytest.raises(ProfileError, match="only replaces a Chrome user-data-dir"):
        import_profile(bundle, target, force=True)
    assert (target / "old-file").read_bytes() == b"old"

    _write(target / "Local State", b"{}")
    import_profile(bundle, target, force=True)
    assert not (target / "old-file").exists()
    assert set(_tree(target)) == EXPECTED_DEFAULT
    assert outside.read_bytes() == b"keep"


def test_import_into_empty_existing_dir(profile: Path, tmp_path: Path) -> None:
    bundle = _portable(profile, tmp_path)
    target = tmp_path / "empty"
    target.mkdir()
    import_profile(bundle, target)
    assert set(_tree(target)) == EXPECTED_DEFAULT


def test_import_refuses_symlink_target(profile: Path, tmp_path: Path) -> None:
    bundle = _portable(profile, tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ProfileError, match="symlink"):
        import_profile(bundle, link)


def test_import_refuses_live_target_even_with_force(profile: Path, tmp_path: Path) -> None:
    bundle = _portable(profile, tmp_path)
    target = tmp_path / "live"
    _write(target / "Local State", b"{}")
    (target / "SingletonLock").symlink_to(f"{socket.gethostname()}-{os.getpid()}")
    with pytest.raises(ProfileLockedError):
        import_profile(bundle, target, force=True)
    assert os.path.lexists(target / "SingletonLock")


# ---------------------------------------------------------------------------- hostile bundles


def _manifest_doc(files: list[tuple[str, bytes]], **overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "kind": "waybound-profile-bundle",
        "format_version": 1,
        "waybound_version": "test",
        "created_at": "2026-01-01T00:00:00+00:00",
        "source": {"os": current_os(), "arch": "x86_64"},
        "chrome_version": "1.2.3",
        "password_store": "basic" if current_os() == "linux" else None,
        "cookie_encryption_prefixes": [],
        "include_credentials": False,
        "files": [
            {"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in files
        ],
    }
    doc.update(overrides)
    return doc


def _member(name: str, data: bytes = b"", kind: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
        info.linkname = "/etc/passwd"
    return info


def _hostile(
    path: Path,
    doc: dict[str, object],
    members: list[tuple[tarfile.TarInfo, bytes]],
) -> Path:
    raw = json.dumps(doc).encode()
    with tarfile.open(path, "w:gz") as tar:
        tar.addfile(_member(MANIFEST_NAME, raw), io.BytesIO(raw))
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return path


def _assert_rejected(bundle: Path, target: Path, match: str) -> None:
    with pytest.raises(BundleVerificationError, match=match):
        import_profile(bundle, target)
    assert not target.exists(), "a rejected import must not leave the target behind"
    leftovers = [p.name for p in target.parent.iterdir() if ".waybound-" in p.name]
    assert not leftovers, f"staging left behind: {leftovers}"


GOOD = ("Default/Preferences", b"{}")


@pytest.mark.parametrize(
    "bad_path",
    ["Default/../../evil", "/etc/passwd", "Default/./Preferences", "C:/x", "Default\\Cookies"],
)
def test_manifest_path_traversal_refused(tmp_path: Path, bad_path: str) -> None:
    bundle = _hostile(tmp_path / "b.tar.gz", _manifest_doc([(bad_path, b"x")]), [])
    _assert_rejected(bundle, tmp_path / "t", "unsafe path")


def test_member_path_traversal_refused(tmp_path: Path) -> None:
    doc = _manifest_doc([GOOD])
    members = [(_member("profile/../../evil", b"{}"), b"{}")]
    bundle = _hostile(tmp_path / "b.tar.gz", doc, members)
    _assert_rejected(bundle, tmp_path / "t", "unsafe path")
    assert not (tmp_path / "evil").exists()


def test_path_outside_policy_refused(tmp_path: Path) -> None:
    doc = _manifest_doc([("NativeMessagingHosts/evil.json", b"{}")])
    bundle = _hostile(tmp_path / "b.tar.gz", doc, [])
    _assert_rejected(bundle, tmp_path / "t", "include policy")


@pytest.mark.parametrize(
    "kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]
)
def test_links_and_devices_refused(tmp_path: Path, kind: bytes) -> None:
    doc = _manifest_doc([GOOD])
    bundle = _hostile(
        tmp_path / "b.tar.gz", doc, [(_member("profile/Default/Preferences", kind=kind), b"")]
    )
    _assert_rejected(bundle, tmp_path / "t", "non-regular")


def test_hash_mismatch_refused(tmp_path: Path) -> None:
    doc = _manifest_doc([GOOD])
    bundle = _hostile(
        tmp_path / "b.tar.gz", doc, [(_member("profile/Default/Preferences", b"[]"), b"[]")]
    )
    _assert_rejected(bundle, tmp_path / "t", "hash mismatch")


def test_unlisted_and_missing_members_refused(tmp_path: Path) -> None:
    doc = _manifest_doc([GOOD])
    extra = _hostile(
        tmp_path / "extra.tar.gz",
        doc,
        [
            (_member("profile/Default/Preferences", b"{}"), b"{}"),
            (_member("profile/Default/Secure Preferences", b"{}"), b"{}"),
        ],
    )
    _assert_rejected(extra, tmp_path / "t1", "not listed")
    missing = _hostile(tmp_path / "missing.tar.gz", doc, [])
    _assert_rejected(missing, tmp_path / "t2", "missing 1 file")


def test_oversize_refused(profile: Path, tmp_path: Path) -> None:
    bundle = _portable(profile, tmp_path)
    with pytest.raises(BundleVerificationError, match=r"larger than|more than"):
        import_profile(bundle, tmp_path / "t", max_bytes=64)
    assert not (tmp_path / "t").exists()


def test_oversize_manifest_total_refused(tmp_path: Path) -> None:
    doc = _manifest_doc([GOOD])
    files = doc["files"]
    assert isinstance(files, list)
    files[0]["size"] = 10**12
    bundle = _hostile(tmp_path / "b.tar.gz", doc, [])
    _assert_rejected(bundle, tmp_path / "t", "more than")


def test_manifest_must_come_first(tmp_path: Path) -> None:
    bundle = tmp_path / "b.tar.gz"
    with tarfile.open(bundle, "w:gz") as tar:
        tar.addfile(_member("profile/Default/Preferences", b"{}"), io.BytesIO(b"{}"))
    _assert_rejected(bundle, tmp_path / "t", "must start with")


def test_case_colliding_paths_refused(tmp_path: Path) -> None:
    doc = _manifest_doc([GOOD, ("Default/Local Storage/a", b""), ("Default/Local Storage/A", b"")])
    bundle = _hostile(tmp_path / "b.tar.gz", doc, [])
    _assert_rejected(bundle, tmp_path / "t", "collides")


def test_credentials_must_be_declared(tmp_path: Path) -> None:
    doc = _manifest_doc([("Default/Login Data", b"x")])
    bundle = _hostile(tmp_path / "b.tar.gz", doc, [])
    _assert_rejected(bundle, tmp_path / "t", "include_credentials")


def test_garbage_bundle_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "b.tar.gz"
    bundle.write_bytes(b"not a tarball at all")
    _assert_rejected(bundle, tmp_path / "t", "corrupt|readable")


def test_failed_import_with_force_keeps_existing_contents(tmp_path: Path) -> None:
    doc = _manifest_doc([GOOD])
    bundle = _hostile(
        tmp_path / "b.tar.gz", doc, [(_member("profile/Default/Preferences", b"[]"), b"[]")]
    )
    target = tmp_path / "t"
    _write(target / "keep", b"keep")
    _write(target / "Local State", b"{}")
    with pytest.raises(BundleVerificationError):
        import_profile(bundle, target, force=True)
    assert (target / "keep").read_bytes() == b"keep"
    assert sorted(p.name for p in target.iterdir()) == ["Local State", "keep"]
    assert not [p for p in tmp_path.iterdir() if ".waybound-" in p.name]


# ---------------------------------------------------------------------------- compatibility


def _other_os() -> OsName:
    return "windows" if current_os() != "windows" else "linux"


@pytest.mark.parametrize(
    ("source", "store", "target", "level"),
    [
        ("linux", "basic", "linux", "portable"),
        ("linux", "basic", "macos", "incompatible"),
        ("linux", "keyring", "linux", "same_machine_only"),
        ("macos", "keychain", "macos", "same_machine_only"),
        ("macos", "keychain", "linux", "incompatible"),
        ("windows", "dpapi", "windows", "same_machine_only"),
        ("windows", "app-bound", "windows", "same_machine_only"),
        ("windows", "dpapi", "linux", "incompatible"),
        ("linux", None, "linux", "unknown"),
        ("macos", None, "linux", "incompatible"),
    ],
)
def test_assess_compatibility(
    source: OsName, store: PasswordStoreKind | None, target: OsName, level: str
) -> None:
    compat = assess_compatibility(source, store, target)
    assert compat.level == level
    assert compat.message


@pytest.mark.parametrize(
    ("os_name", "prefixes", "expected"),
    [
        ("linux", ("v10",), "basic"),
        ("linux", ("v10", "v11"), "keyring"),
        ("macos", ("v10",), "keychain"),
        ("windows", ("v10",), "dpapi"),
        ("windows", ("v10", "v20"), "app-bound"),
        ("linux", (), None),
    ],
)
def test_infer_password_store(
    os_name: OsName, prefixes: tuple[str, ...], expected: PasswordStoreKind | None
) -> None:
    assert infer_password_store(os_name, prefixes) == expected


def test_incompatible_bundle_refused_unless_allowed(tmp_path: Path) -> None:
    doc = _manifest_doc(
        [GOOD],
        source={"os": _other_os(), "arch": "x"},
        password_store=None,
        cookie_encryption_prefixes=["v10"],
    )
    members = [(_member("profile/Default/Preferences", b"{}"), b"{}")]
    bundle = _hostile(tmp_path / "b.tar.gz", doc, members)
    with pytest.raises(IncompatibleBundleError):
        import_profile(bundle, tmp_path / "t")
    assert not (tmp_path / "t").exists()
    result = import_profile(bundle, tmp_path / "t", allow_incompatible=True)
    assert result.compatibility.level == "incompatible"
    assert result.warnings


# ---------------------------------------------------------------------------- CLI


def test_cli_round_trip(profile: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle = tmp_path / "cli.tar.gz"
    args = ["profile", "export", str(profile), str(bundle)]
    if current_os() == "linux":
        args += ["--password-store", "basic"]
    assert main(args) == 0
    out = capsys.readouterr()
    assert "live session cookies" in out.err
    assert "excluded" in out.out
    assert COOKIE_SECRET.decode() not in out.out + out.err

    assert main(["profile", "inspect", str(bundle)]) == 0
    assert "157.0.8103.79" in capsys.readouterr().out

    target = tmp_path / "cli-restored"
    assert main(["profile", "import", str(bundle), str(target)]) == 0
    out = capsys.readouterr()
    assert "Restored" in out.out
    assert COOKIE_SECRET.decode() not in out.out + out.err
    assert set(_tree(target)) == EXPECTED_DEFAULT

    assert main(["profile", "import", str(bundle), str(target)]) == 1
    assert "not empty" in capsys.readouterr().err
    assert main(["profile", "import", str(bundle), str(target), "--force"]) == 0


def test_cli_errors(profile: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (profile / "SingletonLock").symlink_to("other-host-1")
    assert main(["profile", "export", str(profile), str(tmp_path / "x.tar.gz")]) == 1
    assert "--ignore-lock" in capsys.readouterr().err
    args = ["profile", "export", str(profile), str(tmp_path / "x.tar.gz"), "--ignore-lock"]
    assert main(args) == 0
    capsys.readouterr()
    assert main(["profile", "inspect", str(tmp_path / "x.tar.gz"), "--max-bytes", "0"]) == 2
    assert main(["profile", "import", str(tmp_path / "x.tar.gz"), "t", "--max-bytes", "-1"]) == 2
    assert main(["profile"]) == 2
    assert main(["profile", "bogus"]) == 2
    capsys.readouterr()


def test_cli_include_credentials_flag(profile: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "creds.tar.gz"
    assert main(["profile", "export", str(profile), str(bundle), "--include-credentials"]) == 0
    assert {f.path for f in read_manifest(bundle).files} >= CREDENTIAL_FILES


# ---------------------------------------------------------------------------- launch options


def test_launch_options_password_store_flag(tmp_path: Path) -> None:
    fake = tmp_path / "waybound-daemon"
    default_cmd = Session(LaunchOptions(daemon_binary=fake))._build_daemon_cmd(
        socket_path=tmp_path / "s", tcp_addr=None
    )
    assert "--password-store" not in default_cmd
    cmd = Session(LaunchOptions(daemon_binary=fake, password_store=CHROME_BASIC))._build_daemon_cmd(
        socket_path=tmp_path / "s", tcp_addr=None
    )
    idx = cmd.index("--password-store")
    assert cmd[idx + 1] == "basic"
