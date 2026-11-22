"""Portable Chrome session bundles: export and import a clean profile snapshot.

A waybound-launched Chrome keeps its state in a `--user-data-dir`. This module copies the
part of that directory that carries an authenticated web session (cookies, Local/Session
Storage, IndexedDB, service worker registrations, preferences) into a `.tar.gz` bundle with
a JSON manifest, and restores it safely somewhere else. No CDP, no extensions, no network,
and no attempt to decrypt anything: cookie values stay encrypted exactly as Chrome wrote
them, which is why portability depends on the OS key store (see
`docs/profile-portability.md` and :func:`assess_compatibility`).

The bundle contains live session cookies. It is written with mode 0600 and must be handled
like a password.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import IO, TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator

FORMAT_VERSION = 1
BUNDLE_KIND = "waybound-profile-bundle"
MANIFEST_NAME = "waybound-profile.json"
PAYLOAD_PREFIX = "profile/"

DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
"""Default cap on the total uncompressed size of a bundle accepted by :func:`import_profile`."""
MAX_FILES = 200_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_PATH_LEN = 1024
_CHUNK = 1024 * 1024

OsName = Literal["macos", "linux", "windows", "unknown"]
PasswordStoreKind = Literal["basic", "keyring", "keychain", "dpapi", "app-bound"]
CompatibilityLevel = Literal["portable", "same_machine_only", "incompatible", "unknown"]
LockState = Literal["none", "live", "stale"]

PASSWORD_STORE_KINDS: tuple[PasswordStoreKind, ...] = (
    "basic",
    "keyring",
    "keychain",
    "dpapi",
    "app-bound",
)
_OS_NAMES: tuple[OsName, ...] = ("macos", "linux", "windows", "unknown")

# --------------------------------------------------------------------------------------
# Include / exclude policy. This is an allowlist: anything not matched here stays behind.
# --------------------------------------------------------------------------------------

ROOT_FILES = frozenset({"Local State", "Last Version", "First Run"})
"""Files kept from the top of the user-data-dir."""

_PROFILE_DIR_RE = re.compile(r"^(Default|Profile [0-9]{1,4})$")

PROFILE_FILES = frozenset({"Preferences", "Secure Preferences"})
"""Plain files kept from each profile directory (`Default`, `Profile N`)."""

COOKIE_DATABASES = ("Cookies", "Network/Cookies")
"""Cookie SQLite databases (`Network/Cookies` is where Chrome 96+ puts it on Windows)."""

CREDENTIAL_DATABASES = ("Login Data", "Login Data For Account", "Web Data", "Account Web Data")
"""Saved passwords and autofill. Exported only with `include_credentials=True`."""

PROFILE_TREES = (
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "WebStorage",
    "Service Worker/Database",
    "Service Worker/ScriptCache",
)
"""Directories copied recursively from each profile directory."""

_SQLITE_SIDECARS = ("", "-journal", "-wal")

EXCLUDED_NAMES = frozenset({"LOCK", "LOG", "LOG.old", ".DS_Store"})
"""Names dropped everywhere, including inside kept trees (leveldb locks and logs)."""

LOCK_FILES = ("SingletonLock", "lockfile")
"""Files whose presence means a Chrome process may own the profile (POSIX, Windows)."""


def _profile_and_rest(rel: str) -> tuple[str, str] | None:
    head, sep, rest = rel.partition("/")
    if not sep or not _PROFILE_DIR_RE.match(head):
        return None
    return head, rest


def _sqlite_match(sub: str, databases: tuple[str, ...]) -> bool:
    return any(sub == db + suffix for db in databases for suffix in _SQLITE_SIDECARS)


def is_included(rel_path: str, *, include_credentials: bool = False) -> bool:
    """Return whether a user-data-dir relative POSIX path belongs in a bundle."""
    parts = rel_path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if len(parts) == 1:
        return parts[0] in ROOT_FILES
    split = _profile_and_rest(rel_path)
    name = parts[-1]
    if split is None or name in EXCLUDED_NAMES or name.endswith("-shm"):
        return False
    sub = split[1]
    if _sqlite_match(sub, CREDENTIAL_DATABASES):
        return include_credentials
    return (
        sub in PROFILE_FILES
        or _sqlite_match(sub, COOKIE_DATABASES)
        or any(sub.startswith(tree + "/") for tree in PROFILE_TREES)
    )


def _is_credential_path(rel_path: str) -> bool:
    split = _profile_and_rest(rel_path)
    return split is not None and _sqlite_match(split[1], CREDENTIAL_DATABASES)


def _dir_may_contain_included(rel_dir: str) -> bool:
    if "/" not in rel_dir:
        return bool(_PROFILE_DIR_RE.match(rel_dir))
    split = _profile_and_rest(rel_dir)
    if split is None:
        return False
    sub = split[1]
    if sub == "Network":
        return True
    return any(
        sub == tree or sub.startswith(tree + "/") or tree.startswith(sub + "/")
        for tree in PROFILE_TREES
    )


# --------------------------------------------------------------------------------------
# Errors and result types
# --------------------------------------------------------------------------------------


class ProfileError(Exception):
    """Base class for profile export/import failures."""


class ProfileLockedError(ProfileError):
    """Raised when a Chrome process appears to be using the profile."""


class BundleVerificationError(ProfileError):
    """Raised when a bundle is malformed, unsafe, oversized, or fails hash checks."""


class IncompatibleBundleError(ProfileError):
    """Raised when a bundle's cookies cannot be decrypted by Chrome on this machine."""


@dataclass(frozen=True, slots=True)
class ManifestFile:
    """One file in a bundle: relative POSIX path, size in bytes, SHA-256 hex digest."""

    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """The bundle manifest (`waybound-profile.json`)."""

    format_version: int
    waybound_version: str
    created_at: str
    source_os: OsName
    source_arch: str
    chrome_version: str | None
    password_store: PasswordStoreKind | None
    cookie_encryption_prefixes: tuple[str, ...]
    include_credentials: bool
    files: tuple[ManifestFile, ...]

    @property
    def total_bytes(self) -> int:
        """Total uncompressed size of all payload files."""
        return sum(f.size for f in self.files)

    def to_json(self) -> str:
        """Serialize to the on-disk JSON form."""
        doc = {
            "kind": BUNDLE_KIND,
            "format_version": self.format_version,
            "waybound_version": self.waybound_version,
            "created_at": self.created_at,
            "source": {"os": self.source_os, "arch": self.source_arch},
            "chrome_version": self.chrome_version,
            "password_store": self.password_store,
            "cookie_encryption_prefixes": list(self.cookie_encryption_prefixes),
            "include_credentials": self.include_credentials,
            "files": [{"path": f.path, "size": f.size, "sha256": f.sha256} for f in self.files],
        }
        return json.dumps(doc, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True, slots=True)
class Compatibility:
    """Whether cookies in a bundle can be decrypted by Chrome on the importing machine."""

    level: CompatibilityLevel
    message: str


@dataclass(frozen=True, slots=True)
class ExportResult:
    """Outcome of :func:`export_profile`."""

    bundle: Path
    manifest: Manifest
    skipped: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ImportResult:
    """Outcome of :func:`import_profile`."""

    profile_dir: Path
    manifest: Manifest
    compatibility: Compatibility
    warnings: tuple[str, ...]


# --------------------------------------------------------------------------------------
# Environment helpers
# --------------------------------------------------------------------------------------


_PLATFORM_OS: dict[str, OsName] = {"darwin": "macos", "linux": "linux", "win32": "windows"}


def current_os() -> OsName:
    """Return this machine's OS in manifest vocabulary."""
    return _PLATFORM_OS.get(sys.platform, "unknown")


def _waybound_version() -> str:
    try:
        return importlib.metadata.version("waybound")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


_VERSION_RE = re.compile(r"^[0-9][0-9.]{0,31}$")


def read_chrome_version(profile_dir: Path | str) -> str | None:
    """Read the Chrome version that last used this profile from its `Last Version` file."""
    path = Path(profile_dir) / "Last Version"
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as fh:
            raw = fh.read(64)
    except OSError:
        return None
    text = raw.decode("ascii", errors="replace").strip()
    return text if _VERSION_RE.match(text) else None


def profile_lock_state(profile_dir: Path | str) -> LockState:
    """Report whether a Chrome process may own the profile.

    `SingletonLock` is a symlink to `<hostname>-<pid>` on macOS and Linux. It is reported
    `"stale"` only when the hostname is this machine's and that pid no longer exists; any
    lock that cannot be proven stale (another host, a Windows `lockfile`, unreadable
    target, pid alive or not ours to signal) is `"live"`.
    """
    root = Path(profile_dir)
    if os.path.lexists(root / "lockfile"):
        return "live"
    lock = root / "SingletonLock"
    if not os.path.lexists(lock):
        return "none"
    try:
        target = str(lock.readlink())
    except OSError:
        return "live"
    return _singleton_target_state(target)


def _singleton_target_state(target: str) -> LockState:
    host, sep, pid_text = target.rpartition("-")
    if not sep or not pid_text.isdigit() or host != socket.gethostname() or os.name != "posix":
        return "live"
    try:
        os.kill(int(pid_text), 0)
    except ProcessLookupError:
        return "stale"
    except (PermissionError, OverflowError, OSError):
        return "live"
    return "live"


_PREFIX_RE = re.compile(rb"^v[0-9]{2}$")


def detect_cookie_encryption(profile_dir: Path | str) -> tuple[str, ...]:
    """Return the distinct version prefixes (`v10`, `v11`, `v20`) of encrypted cookies.

    Only the first three bytes of each `encrypted_value` are read, via a read-only,
    immutable SQLite connection. Cookie names and values are never read or decrypted.
    """
    root = Path(profile_dir)
    prefixes: set[str] = set()
    for entry in sorted(root.iterdir()) if root.is_dir() else []:
        if entry.is_symlink() or not _PROFILE_DIR_RE.match(entry.name):
            continue
        for db in COOKIE_DATABASES:
            path = entry / db
            if path.is_symlink() or not path.is_file():
                continue
            prefixes.update(_read_prefixes(path))
    return tuple(sorted(prefixes))


def _read_prefixes(path: Path) -> set[str]:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    found: set[str] = set()
    try:
        with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
            rows = conn.execute(
                "SELECT DISTINCT substr(encrypted_value, 1, 3) FROM cookies "
                "WHERE length(encrypted_value) > 0"
            ).fetchall()
    except sqlite3.Error:
        return found
    for (prefix,) in rows:
        if isinstance(prefix, bytes) and _PREFIX_RE.match(prefix):
            found.add(prefix.decode("ascii"))
        else:
            found.add("unversioned")
    return found


def infer_password_store(os_name: OsName, prefixes: tuple[str, ...]) -> PasswordStoreKind | None:
    """Map the source OS and cookie prefixes to the key store that protects them."""
    if not prefixes:
        return None
    if os_name == "linux":
        if "v11" in prefixes:
            return "keyring"
        return "basic" if "v10" in prefixes else None
    if os_name == "macos":
        return "keychain"
    if os_name == "windows":
        return "app-bound" if "v20" in prefixes else "dpapi"
    return None


def assess_compatibility(
    source_os: OsName,
    store: PasswordStoreKind | None,
    target_os: OsName,
) -> Compatibility:
    """Decide whether Chrome on `target_os` can decrypt cookies from a bundle (pure).

    `store` is the key-store kind recorded in the manifest (`Manifest.password_store`).
    """
    if store == "basic" and source_os == "linux":
        if target_os == "linux":
            return Compatibility(
                "portable",
                "cookies use Chrome's fixed Linux 'basic' key (v10) and decrypt on any Linux "
                "Chrome, including containers",
            )
        return Compatibility(
            "incompatible",
            f"cookies use the Linux 'basic' key; Chrome on {target_os} does not use it, so "
            "every cookie would fail to decrypt and be dropped",
        )
    if "unknown" not in {source_os, target_os} and source_os != target_os:
        return Compatibility(
            "incompatible",
            f"bundle was exported on {source_os} but this machine runs {target_os}; cookie "
            "encryption keys are OS specific, so the session will not survive",
        )
    hints: dict[str, str] = {
        "keyring": "cookies are encrypted with a key held in the source machine's Secret "
        "Service/KWallet keyring (v11); they decrypt only where that same keyring entry "
        "exists. Re-create the profile with LaunchOptions(password_store='basic') for a "
        "portable bundle",
        "keychain": "cookies are encrypted with the 'Chrome Safe Storage' key in the source "
        "user's macOS login Keychain; they decrypt only for that user on that Mac",
        "dpapi": "cookies are encrypted with a DPAPI-protected key bound to the source "
        "Windows user account; they decrypt only for that user",
        "app-bound": "cookies use Chrome's Windows App-Bound Encryption (v20), which is tied "
        "to the source machine; they decrypt only on that machine",
    }
    if store is not None and store in hints:
        return Compatibility("same_machine_only", hints[store])
    return Compatibility(
        "unknown",
        "could not determine how the bundle's cookies are encrypted (no encrypted cookies "
        "found or store not recorded); the session may not survive the move",
    )


# --------------------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------------------


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            msg = f"not a regular file: {path}"
            raise ProfileError(msg)
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _collect(root: Path, include_credentials: bool) -> tuple[list[str], list[str]]:
    included: list[str] = []
    skipped: list[str] = []

    def walk(directory: Path, rel_dir: str) -> None:
        with os.scandir(directory) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            if entry.is_symlink():
                if is_included(rel, include_credentials=True) or _dir_may_contain_included(rel):
                    skipped.append(rel)
                continue
            if entry.is_dir(follow_symlinks=False):
                if _dir_may_contain_included(rel):
                    walk(Path(entry.path), rel)
                continue
            if not is_included(rel, include_credentials=include_credentials):
                continue
            if entry.is_file(follow_symlinks=False):
                included.append(rel)
            else:
                skipped.append(rel)

    walk(root, "")
    return included, skipped


def export_profile(
    profile_dir: Path | str,
    bundle: Path | str,
    *,
    include_credentials: bool = False,
    password_store: PasswordStoreKind | None = None,
    overwrite: bool = False,
) -> ExportResult:
    """Write a portable session bundle (`.tar.gz`, mode 0600) from a Chrome user-data-dir.

    `profile_dir` is the directory given to Chrome as `--user-data-dir` (the one holding
    `Local State` and `Default/`). Chrome must not be running against it. Saved passwords
    and autofill (`Login Data`, `Web Data`) are left out unless `include_credentials` is
    set. `password_store` overrides the key-store kind recorded in the manifest; by default
    it is inferred from the cookie database's encryption prefixes.
    """
    root = Path(profile_dir)
    out = Path(bundle)
    if root.is_symlink() or not root.is_dir():
        msg = f"profile directory does not exist or is a symlink: {root}"
        raise ProfileError(msg)
    if not (root / "Local State").is_file() and not (root / "Default").is_dir():
        hint = (
            " (it looks like a single profile; pass its parent, the --user-data-dir)"
            if (root / "Preferences").is_file()
            else ""
        )
        msg = f"not a Chrome user data directory: {root}{hint}"
        raise ProfileError(msg)

    warnings: list[str] = []
    lock = profile_lock_state(root)
    if lock == "live":
        msg = (
            f"Chrome appears to be running with this profile ({root / 'SingletonLock'} or "
            "lockfile exists). Quit Chrome (or end the waybound session) and retry. If you "
            "are certain no Chrome uses it, delete the stale lock file yourself."
        )
        raise ProfileLockedError(msg)
    if lock == "stale":
        warnings.append("ignored a stale SingletonLock left by a Chrome process that has exited")

    if out.exists() and not overwrite:
        msg = f"bundle already exists: {out} (pass overwrite=True / --force to replace it)"
        raise ProfileError(msg)
    if out.is_symlink():
        msg = f"refusing to write the bundle through a symlink: {out}"
        raise ProfileError(msg)

    rel_paths, skipped = _collect(root, include_credentials)
    if not any(
        p.endswith(("/Cookies", "/Network/Cookies")) and _profile_and_rest(p) for p in rel_paths
    ):
        warnings.append("no Cookies database found; the bundle will not carry a logged-in session")

    files = []
    for rel in rel_paths:
        digest, size = _sha256_file(root / rel)
        files.append(ManifestFile(rel, size, digest))

    os_name = current_os()
    prefixes = detect_cookie_encryption(root)
    store = (
        password_store if password_store is not None else infer_password_store(os_name, prefixes)
    )
    manifest = Manifest(
        format_version=FORMAT_VERSION,
        waybound_version=_waybound_version(),
        created_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        source_os=os_name,
        source_arch=platform.machine() or "unknown",
        chrome_version=read_chrome_version(root),
        password_store=store,
        cookie_encryption_prefixes=prefixes,
        include_credentials=include_credentials,
        files=tuple(files),
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".waybound-bundle-", suffix=".tmp", dir=out.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
            _add_bytes(tar, MANIFEST_NAME, manifest.to_json().encode("utf-8"))
            for entry in manifest.files:
                info = _tarinfo(PAYLOAD_PREFIX + entry.path, entry.size)
                with (root / entry.path).open("rb") as fh:
                    tar.addfile(info, fh)
        tmp.chmod(0o600)
        # Re-read what was written: catches a file that changed between hashing and archiving.
        verify_bundle(tmp, max_bytes=max(DEFAULT_MAX_BYTES, manifest.total_bytes))
        tmp.replace(out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    out.chmod(0o600)
    return ExportResult(out, manifest, tuple(skipped), tuple(warnings))


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.type = tarfile.REGTYPE
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    tar.addfile(_tarinfo(name, len(data)), io.BytesIO(data))


# --------------------------------------------------------------------------------------
# Manifest parsing and validation
# --------------------------------------------------------------------------------------

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PREFIX_LEN = 16
_MAX_FIELD_LEN = 256


def validate_member_path(path: str) -> str:
    """Return `path` if it is a safe, normalized, policy-allowed relative POSIX path."""
    bad = (
        not path
        or len(path) > MAX_PATH_LEN
        or "\x00" in path
        or "\\" in path
        or ":" in path
        or path.startswith("/")
        or PurePosixPath(path).as_posix() != path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    )
    if bad:
        msg = f"unsafe path in bundle: {path!r}"
        raise BundleVerificationError(msg)
    if not is_included(path, include_credentials=True):
        msg = f"path not allowed by the profile include policy: {path!r}"
        raise BundleVerificationError(msg)
    return path


def _str_field(doc: dict[object, object], key: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str) or len(value) > _MAX_FIELD_LEN:
        msg = f"manifest field {key!r} must be a short string"
        raise BundleVerificationError(msg)
    return value


def _fail(msg: str) -> BundleVerificationError:
    return BundleVerificationError(msg)


def _parse_files(
    raw_files: object, include_credentials: bool, max_bytes: int
) -> tuple[ManifestFile, ...]:
    if not isinstance(raw_files, list) or len(raw_files) > MAX_FILES:
        raise _fail(f"manifest 'files' must be a list of at most {MAX_FILES} entries")
    files: list[ManifestFile] = []
    seen: set[str] = set()
    total = 0
    for item in raw_files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise _fail("manifest file entries must be objects with a path")
        path = validate_member_path(str(item["path"]))
        size = item.get("size")
        digest = item.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise _fail(f"invalid size for {path!r}")
        if not isinstance(digest, str) or not _SHA_RE.match(digest):
            raise _fail(f"invalid sha256 for {path!r}")
        # Case-folded so two entries cannot collide on case-insensitive file systems.
        if path.casefold() in seen:
            raise _fail(f"duplicate path in manifest: {path!r}")
        seen.add(path.casefold())
        if _is_credential_path(path) and not include_credentials:
            raise _fail(f"credential file {path!r} present but include_credentials is false")
        total += size
        if total > max_bytes:
            raise _fail(f"bundle expands to more than {max_bytes} bytes; raise max_bytes")
        files.append(ManifestFile(path, size, digest))
    return tuple(files)


def _parse_source_os(doc: dict[object, object]) -> tuple[OsName, str]:
    source = doc.get("source")
    if not isinstance(source, dict):
        raise _fail("manifest field 'source' must be an object")
    raw_os = _str_field(source, "os")
    os_name = next((o for o in _OS_NAMES if o == raw_os), None)
    if os_name is None:
        raise _fail(f"unknown source OS {raw_os!r}")
    return os_name, _str_field(source, "arch")


def _parse_store(doc: dict[object, object]) -> PasswordStoreKind | None:
    raw = doc.get("password_store")
    store = next((s for s in PASSWORD_STORE_KINDS if s == raw), None)
    if raw is not None and store is None:
        raise _fail(f"unknown password_store {raw!r}")
    return store


def _parse_prefixes(doc: dict[object, object]) -> tuple[str, ...]:
    raw = doc.get("cookie_encryption_prefixes")
    if not isinstance(raw, list) or not all(
        isinstance(p, str) and len(p) <= _MAX_PREFIX_LEN for p in raw
    ):
        raise _fail("manifest field 'cookie_encryption_prefixes' is malformed")
    return tuple(str(p) for p in raw)


def parse_manifest(data: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Manifest:
    """Parse and strictly validate manifest JSON."""
    try:
        doc: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("kind") != BUNDLE_KIND:
        raise _fail("not a waybound profile bundle")
    version = doc.get("format_version")
    if version != FORMAT_VERSION or isinstance(version, bool):
        raise _fail(f"unsupported bundle format_version {version!r} (expected {FORMAT_VERSION})")
    os_name, arch = _parse_source_os(doc)
    chrome_version = doc.get("chrome_version")
    if chrome_version is not None and (
        not isinstance(chrome_version, str) or not _VERSION_RE.match(chrome_version)
    ):
        raise _fail("manifest field 'chrome_version' is malformed")
    include_credentials = doc.get("include_credentials")
    if not isinstance(include_credentials, bool):
        raise _fail("manifest field 'include_credentials' must be a boolean")
    return Manifest(
        format_version=FORMAT_VERSION,
        waybound_version=_str_field(doc, "waybound_version"),
        created_at=_str_field(doc, "created_at"),
        source_os=os_name,
        source_arch=arch,
        chrome_version=chrome_version,
        password_store=_parse_store(doc),
        cookie_encryption_prefixes=_parse_prefixes(doc),
        include_credentials=include_credentials,
        files=_parse_files(doc.get("files"), include_credentials, max_bytes),
    )


# --------------------------------------------------------------------------------------
# Reading bundles
# --------------------------------------------------------------------------------------


def _open_bundle(bundle: Path, max_bytes: int) -> tarfile.TarFile:
    if not bundle.is_file():
        msg = f"bundle not found: {bundle}"
        raise ProfileError(msg)
    if bundle.stat().st_size > max_bytes:
        msg = f"bundle file is larger than {max_bytes} bytes"
        raise BundleVerificationError(msg)
    try:
        # Stream mode: members are read strictly in order and never seeked or pre-scanned.
        return tarfile.open(bundle, mode="r|gz")
    except (tarfile.TarError, OSError) as exc:
        msg = f"bundle is not a readable .tar.gz: {exc}"
        raise BundleVerificationError(msg) from exc


def _read_manifest_member(
    tar: tarfile.TarFile, members: Iterator[tarfile.TarInfo], max_bytes: int
) -> Manifest:
    first = next(members, None)
    if first is None or first.name != MANIFEST_NAME or not first.isreg():
        msg = f"bundle must start with a regular {MANIFEST_NAME} entry"
        raise BundleVerificationError(msg)
    if first.size > MAX_MANIFEST_BYTES:
        msg = "manifest is too large"
        raise BundleVerificationError(msg)
    fh = tar.extractfile(first)
    if fh is None:
        msg = "manifest entry is unreadable"
        raise BundleVerificationError(msg)
    return parse_manifest(fh.read(MAX_MANIFEST_BYTES + 1), max_bytes=max_bytes)


def read_manifest(bundle: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Manifest:
    """Read and validate a bundle's manifest without extracting anything."""
    try:
        with _open_bundle(Path(bundle), max_bytes) as tar:
            return _read_manifest_member(tar, iter(tar), max_bytes)
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        msg = f"corrupt bundle: {exc}"
        raise BundleVerificationError(msg) from exc


def _iter_payload(
    tar: tarfile.TarFile,
    members: Iterator[tarfile.TarInfo],
    manifest: Manifest,
    sink: _Sink | None,
) -> None:
    expected = {f.path: f for f in manifest.files}
    seen: set[str] = set()
    for member in members:
        name = member.name
        if not name.startswith(PAYLOAD_PREFIX):
            msg = f"unexpected entry outside {PAYLOAD_PREFIX!r}: {name!r}"
            raise BundleVerificationError(msg)
        rel = validate_member_path(name[len(PAYLOAD_PREFIX) :])
        if not member.isreg():
            msg = f"refusing non-regular entry (link, device, fifo or dir): {name!r}"
            raise BundleVerificationError(msg)
        spec = expected.get(rel)
        if spec is None or rel in seen:
            msg = f"entry not listed in the manifest (or repeated): {name!r}"
            raise BundleVerificationError(msg)
        if member.size != spec.size:
            msg = f"size mismatch for {rel!r}"
            raise BundleVerificationError(msg)
        seen.add(rel)
        src = tar.extractfile(member)
        if src is None:
            msg = f"unreadable entry: {name!r}"
            raise BundleVerificationError(msg)
        _copy_verified(src, spec, sink)
    missing = sorted(set(expected) - seen)
    if missing:
        msg = (
            f"bundle is missing {len(missing)} file(s) listed in the manifest, e.g. {missing[0]!r}"
        )
        raise BundleVerificationError(msg)


class _Sink:
    """Writes verified payload files under a private staging root."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def open(self, rel: str) -> IO[bytes]:
        target = self.root
        parts = rel.split("/")
        for part in parts[:-1]:
            target = target / part
            if target.is_symlink():
                msg = f"symlink in staging path: {target}"
                raise BundleVerificationError(msg)
            if not target.exists():
                target.mkdir(mode=0o700)
        target = target / parts[-1]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        return os.fdopen(os.open(target, flags, 0o600), "wb")


def _copy_verified(src: IO[bytes], spec: ManifestFile, sink: _Sink | None) -> None:
    digest = hashlib.sha256()
    remaining = spec.size
    dst = sink.open(spec.path) if sink is not None else None
    try:
        while remaining > 0:
            chunk = src.read(min(_CHUNK, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
            if dst is not None:
                dst.write(chunk)
    finally:
        if dst is not None:
            dst.close()
    if remaining != 0 or digest.hexdigest() != spec.sha256:
        msg = f"hash mismatch for {spec.path!r}; the bundle is corrupt or was modified"
        raise BundleVerificationError(msg)


def verify_bundle(bundle: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Manifest:
    """Fully verify a bundle (structure, paths, sizes, SHA-256) without writing anything."""
    try:
        with _open_bundle(Path(bundle), max_bytes) as tar:
            members = iter(tar)
            manifest = _read_manifest_member(tar, members, max_bytes)
            _iter_payload(tar, members, manifest, None)
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        msg = f"corrupt bundle: {exc}"
        raise BundleVerificationError(msg) from exc
    return manifest


# --------------------------------------------------------------------------------------
# Import
# --------------------------------------------------------------------------------------


def _check_target(target: Path, force: bool) -> bool:
    """Validate the destination; return True when it already had content."""
    if target.is_symlink():
        msg = f"refusing to import into a symlink: {target}"
        raise ProfileError(msg)
    if not target.exists():
        return False
    if not target.is_dir():
        msg = f"target exists and is not a directory: {target}"
        raise ProfileError(msg)
    resolved = target.resolve()
    if resolved == Path(resolved.anchor) or resolved == Path.home().resolve():
        msg = f"refusing to import into {resolved}"
        raise ProfileError(msg)
    has_content = any(target.iterdir())
    if has_content and not force:
        msg = (
            f"target directory is not empty: {target} (pass force=True / --force to replace "
            "its contents)"
        )
        raise ProfileError(msg)
    if has_content and profile_lock_state(target) == "live":
        msg = f"Chrome appears to be running with the target profile {target}; quit it first"
        raise ProfileLockedError(msg)
    return has_content


def _clear_dir(target: Path, keep: Path) -> None:
    for entry in target.iterdir():
        if entry == keep:
            continue
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            shutil.rmtree(entry)


def _fix_permissions(root: Path) -> None:
    root.chmod(0o700)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            (Path(dirpath) / name).chmod(0o700)
        for name in filenames:
            (Path(dirpath) / name).chmod(0o600)


def import_profile(
    bundle: Path | str,
    profile_dir: Path | str,
    *,
    force: bool = False,
    allow_incompatible: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ImportResult:
    """Verify a bundle and restore it as a Chrome user-data-dir.

    Everything is extracted and hash-checked inside a private staging directory within
    `profile_dir` before the existing contents are touched. A non-empty `profile_dir` is
    refused unless `force` is set, in which case its contents (and nothing outside it) are
    replaced. Bundles whose cookies cannot decrypt on this OS are refused unless
    `allow_incompatible` is set. Restored directories are 0700 and files 0600.
    """
    src = Path(bundle)
    target = Path(profile_dir)
    manifest = read_manifest(src, max_bytes=max_bytes)

    compat = assess_compatibility(manifest.source_os, manifest.password_store, current_os())
    warnings: list[str] = []
    if compat.level == "incompatible":
        if not allow_incompatible:
            msg = f"{compat.message} (pass allow_incompatible=True to import anyway)"
            raise IncompatibleBundleError(msg)
        warnings.append(f"importing anyway: {compat.message}")
    elif compat.level != "portable":
        warnings.append(compat.message)

    had_content = _check_target(target, force)
    created = not target.exists()
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".waybound-import-", dir=target))
    try:
        try:
            with _open_bundle(src, max_bytes) as tar:
                members = iter(tar)
                staged_manifest = _read_manifest_member(tar, members, max_bytes)
                if staged_manifest != manifest:
                    msg = "bundle changed while it was being imported"
                    raise BundleVerificationError(msg)
                _iter_payload(tar, members, manifest, _Sink(staging))
        except (tarfile.TarError, EOFError, ValueError) as exc:
            msg = f"corrupt bundle: {exc}"
            raise BundleVerificationError(msg) from exc
        if had_content:
            _clear_dir(target, keep=staging)
        for entry in staging.iterdir():
            entry.replace(target / entry.name)
        staging.rmdir()
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        if created:
            with contextlib.suppress(OSError):
                target.rmdir()
        raise
    _fix_permissions(target)
    return ImportResult(target, manifest, compat, tuple(warnings))
