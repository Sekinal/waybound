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

Bundles are read with a small, strict tar parser of our own rather than :mod:`tarfile`:
`tarfile` buffers whole extended (PAX/GNU) header records in memory before any caller can
check them, which lets a tiny bundle demand gigabytes of RAM. Here every decompressed byte
is counted against a budget derived from the manifest, and extended headers are capped.
"""

from __future__ import annotations

import contextlib
import glob
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import stat
import sys
import tarfile
import tempfile
import unicodedata
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import IO, TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterator

FORMAT_VERSION = 1
BUNDLE_KIND = "waybound-profile-bundle"
MANIFEST_NAME = "waybound-profile.json"
PAYLOAD_PREFIX = "profile/"
IMPORT_MARKER = ".waybound-import.json"
"""Written into every imported profile so a later `--force` import recognises it."""

DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
"""Default cap on the total uncompressed size of a bundle's payload."""
MAX_FILES = 200_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_PAX_HEADER_BYTES = 4 * 1024
"""Largest PAX extended header accepted per entry (normally one long path, < 1.1 KiB)."""
MAX_PATH_LEN = 1024
MAX_COMPONENT_BYTES = 255
_BLOCK = 512
_CHUNK = 1024 * 1024

OsName = Literal["macos", "linux", "windows", "unknown"]
PasswordStoreKind = Literal["basic", "keyring", "keychain", "dpapi", "app-bound"]
CompatibilityLevel = Literal["portable", "same_machine_only", "incompatible", "unknown"]
LockState = Literal["none", "live", "stale", "foreign"]

PASSWORD_STORE_KINDS: tuple[PasswordStoreKind, ...] = (
    "basic",
    "keyring",
    "keychain",
    "dpapi",
    "app-bound",
)
_OS_NAMES: tuple[OsName, ...] = ("macos", "linux", "windows", "unknown")

UNVERIFIED = "expected, not verified against a real Chrome"

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

_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)
_WINDOWS_BAD_CHARS = frozenset('<>:"|?*\\')


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


def _fail(msg: str) -> BundleVerificationError:
    return BundleVerificationError(msg)


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
    cookie_encryption_prefixes: tuple[str, ...] | None
    """Distinct `encrypted_value` prefixes; `()` = no encrypted cookies, `None` = unknown."""
    include_credentials: bool
    files: tuple[ManifestFile, ...]

    @property
    def total_bytes(self) -> int:
        """Total uncompressed size of all payload files."""
        return sum(f.size for f in self.files)

    def to_json(self) -> str:
        """Serialize to the compact on-disk JSON form."""
        prefixes = self.cookie_encryption_prefixes
        doc = {
            "kind": BUNDLE_KIND,
            "format_version": self.format_version,
            "waybound_version": self.waybound_version,
            "created_at": self.created_at,
            "source": {"os": self.source_os, "arch": self.source_arch},
            "chrome_version": self.chrome_version,
            "password_store": self.password_store,
            "cookie_encryption_prefixes": None if prefixes is None else list(prefixes),
            "include_credentials": self.include_credentials,
            "files": [{"path": f.path, "size": f.size, "sha256": f.sha256} for f in self.files],
        }
        return json.dumps(doc, separators=(",", ":"), sort_keys=True)


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
# Path safety
# --------------------------------------------------------------------------------------


def _component_problem(part: str) -> str | None:
    if part in {"", ".", ".."}:
        return "empty, '.' or '..' component"
    if len(part.encode("utf-8", errors="surrogatepass")) > MAX_COMPONENT_BYTES:
        return f"component longer than {MAX_COMPONENT_BYTES} bytes"
    if any(ch in _WINDOWS_BAD_CHARS or ord(ch) < 0x20 for ch in part):  # noqa: PLR2004
        return "character not allowed on Windows"
    if part[-1] in {".", " "}:
        return "trailing dot or space"
    if part.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_RESERVED:
        return "reserved Windows device name"
    return None


def _path_problem(path: str) -> str | None:
    if not path or len(path) > MAX_PATH_LEN or "\x00" in path:
        return "empty, too long, or contains NUL"
    if path.startswith("/") or PurePosixPath(path).as_posix() != path:
        return "absolute or not normalized"
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "not valid UTF-8"
    for part in path.split("/"):
        problem = _component_problem(part)
        if problem is not None:
            return problem
    return None


def validate_member_path(path: str) -> str:
    """Return `path` if it is a safe, portable, policy-allowed relative POSIX path."""
    problem = _path_problem(path)
    if problem is not None:
        msg = f"unsafe path in bundle ({problem}): {path!r}"
        raise BundleVerificationError(msg)
    if not is_included(path, include_credentials=True):
        msg = f"path not allowed by the profile include policy: {path!r}"
        raise BundleVerificationError(msg)
    return path


class _PathRegistry:
    """Detects paths that would collide on case-insensitive or normalizing file systems.

    Every prefix is keyed by NFC + casefold and remembered as a file or a directory, so two
    files, or a file and a directory, that differ only in case or Unicode normalization are
    caught (APFS and NTFS would merge them).
    """

    def __init__(self) -> None:
        self._kinds: dict[str, bool] = {}

    def add_file(self, path: str) -> None:
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            is_file = i == len(parts)
            key = unicodedata.normalize("NFC", "/".join(parts[:i])).casefold()
            existing = self._kinds.get(key)
            if existing is None:
                self._kinds[key] = is_file
            elif existing or is_file:
                msg = f"path collides with another entry (case or Unicode form): {path!r}"
                raise BundleVerificationError(msg)


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

    `SingletonLock` is a symlink to `<hostname>-<pid>` on macOS and Linux.

    * `"none"`: no lock file.
    * `"stale"`: the lock names this host and that pid no longer exists.
    * `"foreign"`: the lock names another host (for example a finished container), or a
      Windows `lockfile` is seen on a non-Windows machine. Whether that Chrome still runs
      cannot be checked from here.
    * `"live"`: anything else, including locks that cannot be parsed.
    """
    root = Path(profile_dir)
    if os.path.lexists(root / "lockfile"):
        return "live" if os.name == "nt" else "foreign"
    lock = root / "SingletonLock"
    if not os.path.lexists(lock):
        return "none"
    try:
        target = str(lock.readlink())
    except OSError:
        return "live"
    return _singleton_target_state(target)


_MAX_PID_DIGITS = 10


def _singleton_target_state(target: str) -> LockState:
    host, sep, pid_text = target.rpartition("-")
    if (
        not sep
        or not host
        or not (pid_text.isascii() and pid_text.isdigit() and len(pid_text) <= _MAX_PID_DIGITS)
    ):
        return "live"
    pid = int(pid_text)
    if pid <= 0:
        return "live"
    if host != socket.gethostname():
        return "foreign"
    if os.name != "posix":
        return "live"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "stale"
    except (PermissionError, OverflowError, OSError):
        pass
    return "live"


def _check_lock(root: Path, *, ignore_lock: bool) -> list[str]:
    state = profile_lock_state(root)
    if state == "none":
        return []
    if state == "stale":
        return ["ignored a stale SingletonLock left by a Chrome process that has exited"]
    if state == "foreign" and ignore_lock:
        return [
            "ignored a lock file written by Chrome on another host (--ignore-lock); make sure "
            "that Chrome has exited"
        ]
    if state == "foreign":
        msg = (
            f"{root} holds a lock file from Chrome on another host (for example a finished "
            "container). If that Chrome has exited, rerun with --ignore-lock "
            "(ignore_lock=True)."
        )
        raise ProfileLockedError(msg)
    msg = (
        f"Chrome appears to be running with {root} (SingletonLock or lockfile exists). Close "
        "the waybound session (or quit Chrome), wait for it to exit, and retry."
    )
    raise ProfileLockedError(msg)


_PREFIX_RE = re.compile(rb"^v[0-9]{2}$")


def _open_regular_nofollow(path: Path) -> io.BufferedReader:
    """Open `path` without following a final symlink and verify it is a regular file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    fh = os.fdopen(fd, "rb")
    try:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            msg = f"not a regular file: {path}"
            raise ProfileError(msg)
    except BaseException:
        fh.close()
        raise
    return fh


def _has_symlink_component(base: Path, rel: str) -> bool:
    cur = base
    for part in rel.split("/"):
        cur = cur / part
        if cur.is_symlink():
            return True
    return False


def detect_cookie_encryption(
    profile_dir: Path | str, *, scratch_dir: Path | str | None = None
) -> tuple[str, ...] | None:
    """Return the distinct version prefixes (`v10`, `v11`, `v20`) of encrypted cookies.

    Returns `()` when there are no encrypted cookies and `None` when a cookie database
    exists but cannot be read. Each database is copied, with its `-wal` and `-journal`
    files, into a private (0700) temporary directory under `scratch_dir` (default: the
    system temp dir), opened there and removed afterwards, so rows still in the WAL are
    seen and the source files are never touched. (`-shm` is not copied: SQLite rebuilds the
    WAL index from the `-wal` file.) Only the first three bytes of each `encrypted_value`
    are read; cookie names and values are never read or decrypted.
    """
    root = Path(profile_dir)
    prefixes: set[str] = set()
    entries = sorted(root.iterdir()) if root.is_dir() and not root.is_symlink() else []
    for entry in entries:
        if entry.is_symlink() or not _PROFILE_DIR_RE.match(entry.name):
            continue
        for db in COOKIE_DATABASES:
            if _has_symlink_component(entry, db):
                continue
            path = entry / db
            if not path.is_file():
                continue
            found = _read_prefixes(path, scratch_dir)
            if found is None:
                return None
            prefixes.update(found)
    return tuple(sorted(prefixes))


def _read_prefixes(db: Path, scratch_dir: Path | str | None) -> set[str] | None:
    found: set[str] = set()
    with tempfile.TemporaryDirectory(prefix=".waybound-cookies-", dir=scratch_dir) as tmp:
        copy = Path(tmp) / "Cookies"
        try:
            for suffix in _SQLITE_SIDECARS:
                src = Path(f"{db}{suffix}")
                try:
                    with (
                        _open_regular_nofollow(src) as in_fh,
                        Path(f"{copy}{suffix}").open("wb") as out_fh,
                    ):
                        shutil.copyfileobj(in_fh, out_fh, _CHUNK)
                except FileNotFoundError:
                    if suffix == "":
                        return None
            with contextlib.closing(sqlite3.connect(copy)) as conn:
                rows = conn.execute(
                    "SELECT DISTINCT substr(encrypted_value, 1, 3) FROM cookies "
                    "WHERE length(encrypted_value) > 0"
                ).fetchall()
        except (sqlite3.Error, OSError, ProfileError):
            return None
    for (prefix,) in rows:
        if isinstance(prefix, bytes) and _PREFIX_RE.match(prefix):
            found.add(prefix.decode("ascii"))
        else:
            found.add("unversioned")
    return found


def infer_password_store(
    os_name: OsName, prefixes: tuple[str, ...] | None
) -> PasswordStoreKind | None:
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


_SAME_MACHINE_HINTS: dict[str, str] = {
    "keyring": "cookies are encrypted with a key held in the source machine's Secret "
    "Service/KWallet keyring (v11); they decrypt only where that same keyring entry exists "
    "(and not between Chrome and Chromium, which use different entries). Re-create the "
    "profile with LaunchOptions(password_store='basic') for a portable bundle",
    "keychain": "cookies are encrypted with the 'Chrome Safe Storage' key in the source "
    "user's macOS login Keychain; they decrypt only for that user on that Mac",
    "dpapi": "cookies are encrypted with a DPAPI-protected key bound to the source "
    "Windows user account; they decrypt only for that user",
    "app-bound": "cookies use Chrome's Windows App-Bound Encryption (v20), which is tied "
    "to the source machine; they decrypt only on that machine",
}


def assess_compatibility(
    source_os: OsName,
    store: PasswordStoreKind | None,
    target_os: OsName,
    *,
    prefixes: tuple[str, ...] | None = None,
) -> Compatibility:
    """Decide whether Chrome on `target_os` can decrypt cookies from a bundle (pure).

    `store` is the key-store kind recorded in the manifest and `prefixes` its
    `cookie_encryption_prefixes`. When the prefixes imply a different store than the one
    recorded, the prefixes win, so a mislabelled bundle cannot look portable.
    """
    if prefixes == ():
        return Compatibility(
            "unknown",
            "the bundle has no encrypted cookies, so there is no cookie session to carry "
            f"over; Local Storage and IndexedDB data should carry over ({UNVERIFIED}); "
            "saved passwords, if included, will not decrypt on another machine",
        )
    store = infer_password_store(source_os, prefixes) or store
    if store == "basic" and source_os == "linux":
        if target_os == "linux":
            return Compatibility(
                "portable",
                "cookies use Chrome's fixed Linux 'basic' key (v10) and should decrypt on any "
                f"Linux Chrome, including containers ({UNVERIFIED})",
            )
        return Compatibility(
            "incompatible",
            f"cookies use the Linux 'basic' key; Chrome on {target_os} does not use it, so "
            "the cookies will not decrypt and Chrome drops them",
        )
    if "unknown" not in {source_os, target_os} and source_os != target_os:
        return Compatibility(
            "incompatible",
            f"bundle was exported on {source_os} but this machine runs {target_os}; cookie "
            "encryption keys are OS specific, so the cookie session will not carry over",
        )
    if store is not None and store in _SAME_MACHINE_HINTS:
        return Compatibility("same_machine_only", _SAME_MACHINE_HINTS[store])
    return Compatibility(
        "unknown",
        "could not determine how the bundle's cookies are encrypted; the session may not "
        "survive the move",
    )


# --------------------------------------------------------------------------------------
# Directory helpers
# --------------------------------------------------------------------------------------


def _make_private_parents(directory: Path) -> list[Path]:
    """Create missing ancestors of `directory` (inclusive) with mode 0700; return them."""
    missing: list[Path] = []
    probe = directory
    while not probe.exists() and not probe.is_symlink():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    created: list[Path] = []
    for path in reversed(missing):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        created.append(path)
    return created


def _remove_created(created: list[Path]) -> None:
    for path in reversed(created):
        with contextlib.suppress(OSError):
            path.rmdir()


def _fix_permissions(root: Path) -> None:
    """Set 0700 on directories and 0600 on files, never following or touching symlinks."""
    root.chmod(0o700)
    stack = [root]
    while stack:
        with os.scandir(stack.pop()) as it:
            for entry in it:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    os.chmod(entry.path, 0o700)  # noqa: PTH101
                    stack.append(Path(entry.path))
                else:
                    os.chmod(entry.path, 0o600)  # noqa: PTH101


# --------------------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------------------


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with _open_regular_nofollow(path) as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _collect(root: Path, include_credentials: bool) -> tuple[list[str], list[str]]:
    included: list[str] = []
    skipped: list[str] = []
    registry = _PathRegistry()

    def consider(rel: str) -> None:
        if _path_problem(rel) is not None:
            skipped.append(rel)
            return
        try:
            registry.add_file(rel)
        except BundleVerificationError:
            skipped.append(rel)
            return
        included.append(rel)

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
                consider(rel)
            else:
                skipped.append(rel)

    walk(root, "")
    return included, skipped


def _choose_store(
    os_name: OsName,
    prefixes: tuple[str, ...] | None,
    override: PasswordStoreKind | None,
    warnings: list[str],
) -> PasswordStoreKind | None:
    inferred = infer_password_store(os_name, prefixes)
    if override is None or override == inferred:
        return inferred
    if inferred is not None:
        warnings.append(
            f"--password-store {override} contradicts the cookie database, which uses "
            f"{inferred}; recording {inferred}"
        )
        return inferred
    if override == "basic" and os_name != "linux":
        warnings.append("--password-store basic only exists on Linux; ignoring it")
        return None
    return override


def export_profile(  # noqa: PLR0913
    profile_dir: Path | str,
    bundle: Path | str,
    *,
    include_credentials: bool = False,
    password_store: PasswordStoreKind | None = None,
    overwrite: bool = False,
    ignore_lock: bool = False,
) -> ExportResult:
    """Write a portable session bundle (`.tar.gz`, mode 0600) from a Chrome user-data-dir.

    `profile_dir` is the directory given to Chrome as `--user-data-dir` (the one holding
    `Local State` and `Default/`). Chrome must have exited; close the waybound session and
    let it finish first. `ignore_lock` accepts a lock left by Chrome on *another* host (a
    finished container); it never overrides a lock from a live local Chrome. Saved
    passwords and autofill (`Login Data`, `Web Data`) are left out unless
    `include_credentials` is set. `password_store` is recorded only when it agrees with the
    cookie database (or nothing can be detected).
    """
    root = Path(profile_dir)
    out = Path(os.path.abspath(bundle))  # noqa: PTH100 - normalizes '..' like Chrome
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
    if out.parent.resolve().is_relative_to(root.resolve()):
        msg = f"refusing to write the bundle inside the profile directory: {out}"
        raise ProfileError(msg)

    warnings = _check_lock(root, ignore_lock=ignore_lock)

    if out.is_symlink():
        msg = f"refusing to write the bundle through a symlink: {out}"
        raise ProfileError(msg)
    if out.is_dir():
        msg = f"bundle output path is a directory: {out}"
        raise ProfileError(msg)
    if out.exists() and not overwrite:
        msg = f"bundle already exists: {out} (pass overwrite=True / --force to replace it)"
        raise ProfileError(msg)

    created = _make_private_parents(out.parent)
    try:
        manifest, manifest_bytes, skipped = _build_manifest(
            root, out, include_credentials, password_store, warnings
        )
        _write_bundle(root, out, manifest, manifest_bytes)
    except BaseException:
        _remove_created(created)
        raise
    return ExportResult(out, manifest, tuple(skipped), tuple(warnings))


def _build_manifest(
    root: Path,
    out: Path,
    include_credentials: bool,
    password_store: PasswordStoreKind | None,
    warnings: list[str],
) -> tuple[Manifest, bytes, list[str]]:
    rel_paths, skipped = _collect(root, include_credentials)
    if len(rel_paths) > MAX_FILES:
        msg = f"profile has {len(rel_paths)} files to export; the limit is {MAX_FILES}"
        raise ProfileError(msg)
    if not any(
        (split := _profile_and_rest(p)) is not None and split[1] in COOKIE_DATABASES
        for p in rel_paths
    ):
        warnings.append("no Cookies database found; the bundle will not carry a logged-in session")

    files = []
    for rel in rel_paths:
        digest, size = _sha256_file(root / rel)
        files.append(ManifestFile(rel, size, digest))

    os_name = current_os()
    # The cookie database copy lives next to the bundle, not in a shared system temp dir.
    prefixes = detect_cookie_encryption(root, scratch_dir=out.parent)
    manifest = Manifest(
        format_version=FORMAT_VERSION,
        waybound_version=_waybound_version(),
        created_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        source_os=os_name,
        source_arch=platform.machine() or "unknown",
        chrome_version=read_chrome_version(root),
        password_store=_choose_store(os_name, prefixes, password_store, warnings),
        cookie_encryption_prefixes=prefixes,
        include_credentials=include_credentials,
        files=tuple(files),
    )
    manifest_bytes = manifest.to_json().encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        msg = f"manifest would exceed {MAX_MANIFEST_BYTES} bytes; the profile has too many files"
        raise ProfileError(msg)
    return manifest, manifest_bytes, skipped


def _write_bundle(root: Path, out: Path, manifest: Manifest, manifest_bytes: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=".waybound-bundle-", suffix=".tmp", dir=out.parent)
    tmp = Path(tmp_name)
    try:
        with (
            os.fdopen(fd, "wb") as raw,
            tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as tar,
        ):
            tar.addfile(_tarinfo(MANIFEST_NAME, len(manifest_bytes)), io.BytesIO(manifest_bytes))
            for entry in manifest.files:
                info = _tarinfo(PAYLOAD_PREFIX + entry.path, entry.size)
                with _open_regular_nofollow(root / entry.path) as fh:
                    tar.addfile(info, fh)
        tmp.chmod(0o600)
        # Re-read what was written: catches a file that changed between hashing and archiving.
        verify_bundle(
            tmp,
            max_bytes=max(DEFAULT_MAX_BYTES, manifest.total_bytes, tmp.stat().st_size),
        )
        tmp.replace(out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _tarinfo(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.type = tarfile.REGTYPE
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


# --------------------------------------------------------------------------------------
# Manifest parsing and validation
# --------------------------------------------------------------------------------------

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PREFIX_LEN = 16
_MAX_PREFIX_COUNT = 32
_MAX_FIELD_LEN = 256
_ASCII_PRINTABLE_MIN = 0x20
_ASCII_DEL = 0x7F


def _str_field(doc: dict[object, object], key: str) -> str:
    value = doc.get(key)
    if (
        not isinstance(value, str)
        or len(value) > _MAX_FIELD_LEN
        or any(ord(ch) < _ASCII_PRINTABLE_MIN or ord(ch) == _ASCII_DEL for ch in value)
    ):
        msg = f"manifest field {key!r} must be a short printable string"
        raise BundleVerificationError(msg)
    return value


def _parse_files(
    raw_files: object, include_credentials: bool, max_bytes: int
) -> tuple[ManifestFile, ...]:
    if not isinstance(raw_files, list) or len(raw_files) > MAX_FILES:
        raise _fail(f"manifest 'files' must be a list of at most {MAX_FILES} entries")
    files: list[ManifestFile] = []
    registry = _PathRegistry()
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
        registry.add_file(path)
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


def _parse_prefixes(doc: dict[object, object]) -> tuple[str, ...] | None:
    raw = doc.get("cookie_encryption_prefixes")
    if raw is None:
        return None
    if (
        not isinstance(raw, list)
        or len(raw) > _MAX_PREFIX_COUNT
        or not all(isinstance(p, str) and len(p) <= _MAX_PREFIX_LEN for p in raw)
    ):
        raise _fail("manifest field 'cookie_encryption_prefixes' is malformed")
    return tuple(str(p) for p in raw)


def parse_manifest(data: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Manifest:
    """Parse and strictly validate manifest JSON."""
    try:
        doc: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
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
# Strict streaming tar reader
# --------------------------------------------------------------------------------------


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...

    def close(self) -> None: ...


class _GzipMember:
    """Decompresses exactly one gzip member and rejects anything after it.

    :class:`gzip.GzipFile` silently concatenates members; here the stream ends with the
    first member, zlib verifies its CRC-32 and length trailer, and trailing bytes (another
    member or garbage) are an error.
    """

    def __init__(self, path: Path) -> None:
        self._fh = path.open("rb")
        self._inflate = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        self._buf = bytearray()

    def read(self, size: int = -1, /) -> bytes:
        if size < 0:
            msg = "unbounded reads are not supported"
            raise ValueError(msg)
        while len(self._buf) < size and not self._inflate.eof:
            data = self._inflate.unconsumed_tail or self._fh.read(64 * 1024)
            if not data:
                msg = "bundle is truncated (the gzip stream ends early)"
                raise BundleVerificationError(msg)
            self._buf.extend(self._inflate.decompress(data, size - len(self._buf)))
            self._reject_trailing_data()
        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out

    def _reject_trailing_data(self) -> None:
        if self._inflate.eof and (self._inflate.unused_data or self._fh.read(1)):
            msg = "unexpected data after the gzip stream (concatenated member or garbage)"
            raise BundleVerificationError(msg)

    def close(self) -> None:
        self._fh.close()


def _open_gzip(bundle: Path) -> _Readable:
    """Open the decompressed stream of a bundle (a seam for tests that count bytes)."""
    return _GzipMember(bundle)


class _BoundedStream:
    """Reads decompressed bytes while enforcing a hard budget, checked *before* reading."""

    def __init__(self, raw: _Readable, limit: int) -> None:
        self._raw = raw
        self.limit = limit
        self.consumed = 0
        self.pax_bytes = 0

    def _reserve(self, n: int) -> None:
        if n < 0 or self.consumed + n > self.limit:
            msg = "bundle expands beyond its size budget (oversized or malicious archive)"
            raise BundleVerificationError(msg)
        self.consumed += n

    def chunks(self, n: int) -> Iterator[bytes]:
        self._reserve(n)
        remaining = n
        while remaining > 0:
            chunk = self._raw.read(min(remaining, _CHUNK))
            if not chunk:
                msg = "bundle is truncated"
                raise BundleVerificationError(msg)
            remaining -= len(chunk)
            yield chunk

    def read_exact(self, n: int) -> bytes:
        return b"".join(self.chunks(n))

    def expect_end(self) -> None:
        """After the first end-of-archive block: only zero padding may follow, then EOF."""
        trailing = 0
        while chunk := self._raw.read(_BLOCK):
            trailing += len(chunk)
            self._reserve(len(chunk))
            if trailing > _MAX_TRAILER_BYTES or any(chunk):
                msg = "unexpected data after the end of the archive"
                raise BundleVerificationError(msg)


@dataclass(frozen=True, slots=True)
class _TarHeader:
    name: str
    size: int
    regular: bool


_REGULAR_TYPES = frozenset({b"0", b"\x00"})
_OCTAL_RE = re.compile(rb"[0-7]{1,22}")
_DECIMAL_RE = re.compile(rb"[0-9]{1,20}")
_MAX_TRAILER_BYTES = 2 * 20 * _BLOCK
"""Zero padding accepted after the end marker (tar pads archives to 10 KiB records)."""

_PAX_USED_KEYS = frozenset({"path", "size"})
_PAX_IGNORED_KEYS = frozenset(
    {"mtime", "atime", "ctime", "uid", "gid", "uname", "gname"}
    | {"SCHILY.dev", "SCHILY.ino", "SCHILY.nlink", "SCHILY.fflags", "LIBARCHIVE.creationtime"}
)
_PAX_IGNORED_PREFIXES = ("SCHILY.xattr.", "LIBARCHIVE.xattr.")
"""Metadata other tools write that does not change a regular file's name or content."""


def _padded(n: int) -> int:
    return (n + _BLOCK - 1) // _BLOCK * _BLOCK


def _octal(field: bytes, what: str) -> int:
    text = field.split(b"\x00", 1)[0].strip(b" ")
    if not text:
        return 0
    if not _OCTAL_RE.fullmatch(text):
        raise _fail(f"tar header {what} is not an octal number")
    return int(text, 8)


def _parse_pax(data: bytes) -> dict[str, str]:
    records: dict[str, str] = {}
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos)
        length_text = data[pos:space] if space > pos else b""
        if not _DECIMAL_RE.fullmatch(length_text):
            raise _fail("malformed PAX extended header")
        length = int(length_text)
        record = data[pos : pos + length]
        if length <= len(length_text) + 1 or len(record) != length or not record.endswith(b"\n"):
            raise _fail("malformed PAX extended header")
        key_bytes, eq, value_bytes = record[space - pos + 1 : -1].partition(b"=")
        if not eq:
            raise _fail("malformed PAX extended header")
        try:
            key, value = key_bytes.decode("utf-8"), value_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _fail("PAX extended header is not UTF-8") from exc
        if key in _PAX_USED_KEYS:
            records[key] = value
        elif key not in _PAX_IGNORED_KEYS and not key.startswith(_PAX_IGNORED_PREFIXES):
            raise _fail(f"unsupported PAX extended header key {key!r}")
        pos += length
    return records


def _read_header(stream: _BoundedStream) -> _TarHeader | None:
    pax: dict[str, str] | None = None
    while True:
        block = stream.read_exact(_BLOCK)
        if not any(block):
            if pax is not None:
                raise _fail("PAX extended header without a following entry")
            return None
        checksum = sum(block[:148]) + 8 * 0x20 + sum(block[156:])
        if _octal(block[148:156], "checksum") != checksum:
            raise _fail("tar header checksum mismatch")
        typeflag = block[156:157]
        size = _octal(block[124:136], "size")
        if typeflag == b"x":
            if pax is not None:
                raise _fail("consecutive PAX extended headers")
            if size > MAX_PAX_HEADER_BYTES:
                raise _fail(f"PAX extended header of {size} bytes exceeds the limit")
            pax = _parse_pax(stream.read_exact(_padded(size))[:size])
            continue
        if typeflag in {b"g", b"L", b"K"}:
            raise _fail(f"unsupported tar extended header type {typeflag!r}")
        name, size = _apply_pax(_ustar_name(block), size, pax)
        return _TarHeader(name, size, typeflag in _REGULAR_TYPES)


def _ustar_name(block: bytes) -> str:
    name_bytes = block[0:100].split(b"\x00", 1)[0]
    if block[257:263] == b"ustar\x00":
        prefix = block[345:500].split(b"\x00", 1)[0]
        if prefix:
            name_bytes = prefix + b"/" + name_bytes
    try:
        return name_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail("tar member name is not UTF-8") from exc


def _apply_pax(name: str, size: int, pax: dict[str, str] | None) -> tuple[str, int]:
    if pax is None:
        return name, size
    if "size" in pax:
        raw = pax["size"].encode("ascii", errors="replace")
        if not _DECIMAL_RE.fullmatch(raw):
            raise _fail("malformed PAX size")
        size = int(raw)
    return pax.get("path", name), size


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
                raise _fail(f"symlink in staging path: {target}")
            if not target.exists():
                target.mkdir(mode=0o700)
        target = target / parts[-1]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        return os.fdopen(os.open(target, flags, 0o600), "wb")


def _copy_verified(stream: _BoundedStream, spec: ManifestFile, sink: _Sink | None) -> None:
    digest = hashlib.sha256()
    dst = sink.open(spec.path) if sink is not None else None
    try:
        for chunk in stream.chunks(spec.size):
            digest.update(chunk)
            if dst is not None:
                dst.write(chunk)
    finally:
        if dst is not None:
            dst.close()
    stream.read_exact(_padded(spec.size) - spec.size)
    if digest.hexdigest() != spec.sha256:
        msg = f"hash mismatch for {spec.path!r}; the bundle is corrupt or was modified"
        raise BundleVerificationError(msg)


def _payload_budget(manifest: Manifest) -> int:
    per_member = 2 * _BLOCK + MAX_PAX_HEADER_BYTES
    body = sum(_padded(f.size) for f in manifest.files)
    return body + len(manifest.files) * per_member + _BLOCK + _MAX_TRAILER_BYTES


def _scan_stream(
    stream: _BoundedStream, max_bytes: int, sink: _Sink | None, *, manifest_only: bool
) -> Manifest:
    header = _read_header(stream)
    if header is None or header.name != MANIFEST_NAME or not header.regular:
        raise _fail(f"bundle must start with a regular {MANIFEST_NAME} entry")
    if header.size > MAX_MANIFEST_BYTES:
        raise _fail("manifest is too large")
    manifest = parse_manifest(
        stream.read_exact(_padded(header.size))[: header.size], max_bytes=max_bytes
    )
    if manifest_only:
        return manifest
    stream.limit = stream.consumed + _payload_budget(manifest)
    expected = {f.path: f for f in manifest.files}
    seen: set[str] = set()
    while (member := _read_header(stream)) is not None:
        if not member.name.startswith(PAYLOAD_PREFIX):
            raise _fail(f"unexpected entry outside {PAYLOAD_PREFIX!r}: {member.name!r}")
        rel = validate_member_path(member.name[len(PAYLOAD_PREFIX) :])
        if not member.regular:
            raise _fail(f"refusing non-regular entry (link, device, fifo or dir): {member.name!r}")
        spec = expected.get(rel)
        if spec is None or rel in seen:
            raise _fail(f"entry not listed in the manifest (or repeated): {member.name!r}")
        if member.size != spec.size:
            raise _fail(f"size mismatch for {rel!r}")
        seen.add(rel)
        _copy_verified(stream, spec, sink)
    missing = sorted(set(expected) - seen)
    if missing:
        raise _fail(
            f"bundle is missing {len(missing)} file(s) listed in the manifest, e.g. {missing[0]!r}"
        )
    stream.expect_end()
    return manifest


def _scan_bundle(
    bundle: Path, max_bytes: int, sink: _Sink | None, *, manifest_only: bool = False
) -> Manifest:
    if max_bytes <= 0:
        msg = "max_bytes must be positive"
        raise ProfileError(msg)
    try:
        if not bundle.is_file():
            msg = f"bundle not found: {bundle}"
            raise ProfileError(msg)
        if bundle.stat().st_size > max_bytes:
            raise _fail(f"bundle file is larger than {max_bytes} bytes")
        raw = _open_gzip(bundle)
    except PermissionError as exc:
        msg = f"cannot read bundle {bundle}: {exc}"
        raise ProfileError(msg) from exc
    with contextlib.closing(raw):
        stream = _BoundedStream(raw, MAX_MANIFEST_BYTES + MAX_PAX_HEADER_BYTES + 4 * _BLOCK)
        try:
            return _scan_stream(stream, max_bytes, sink, manifest_only=manifest_only)
        except (EOFError, zlib.error, ValueError, OverflowError) as exc:
            msg = f"corrupt bundle: {exc}"
            raise BundleVerificationError(msg) from exc


def read_manifest(bundle: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Manifest:
    """Read and validate a bundle's manifest without extracting anything."""
    return _scan_bundle(Path(bundle), max_bytes, None, manifest_only=True)


def verify_bundle(bundle: Path | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Manifest:
    """Fully verify a bundle (structure, paths, sizes, SHA-256) without writing anything."""
    return _scan_bundle(Path(bundle), max_bytes, None)


# --------------------------------------------------------------------------------------
# Import
# --------------------------------------------------------------------------------------

TargetState = Literal["absent", "empty", "empty_mount", "replace"]


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _looks_like_profile(target: Path) -> bool:
    default = target / "Default"
    return (
        _is_regular_file(target / "Local State")
        or (not default.is_symlink() and _is_regular_file(default / "Preferences"))
        or _is_regular_file(target / IMPORT_MARKER)
    )


def _target_state(
    target: Path, *, force: bool, ignore_lock: bool, staging: Path | None = None
) -> TargetState:
    """Classify the destination, refusing unsafe ones (`staging` is ignored if inside)."""
    if target.is_symlink():
        msg = f"refusing to import into a symlink: {target}"
        raise ProfileError(msg)
    if not target.exists():
        return "absent"
    if not target.is_dir():
        msg = f"target exists and is not a directory: {target}"
        raise ProfileError(msg)
    resolved = target.resolve()
    if resolved == Path(resolved.anchor) or Path.home().resolve().is_relative_to(resolved):
        msg = (
            f"refusing to import into {resolved}: it is a filesystem root or contains your "
            "home directory"
        )
        raise ProfileError(msg)
    is_mount = os.path.ismount(resolved)
    entries = [e for e in target.iterdir() if staging is None or e.name != staging.name]
    if not entries:
        return "empty_mount" if is_mount else "empty"
    if is_mount:
        msg = (
            f"refusing to replace the contents of mount point {resolved}; import into an empty "
            "mount point or a directory inside it"
        )
        raise ProfileError(msg)
    if not force:
        msg = f"target directory is not empty: {target} (pass force=True / --force to replace it)"
        raise ProfileError(msg)
    if not _looks_like_profile(target):
        msg = (
            "--force only replaces a Chrome user-data-dir (a 'Local State' file or "
            f"'Default/Preferences') or a previous waybound import; {target} is neither"
        )
        raise ProfileError(msg)
    _check_lock(target, ignore_lock=ignore_lock)
    return "replace"


def _leftover_warnings(target: Path) -> list[str]:
    """Report copies left by interrupted imports (they may hold live session cookies)."""
    name = glob.escape(target.name)
    found: list[Path] = []
    with contextlib.suppress(OSError):
        found += sorted(target.parent.glob(f".{name}.waybound-import-*"))
        found += sorted(target.parent.glob(f".{name}.waybound-backup-*"))
        if target.is_dir() and not target.is_symlink():
            found += sorted(target.glob(".waybound-import-*"))
    return [
        f"found {path}, left by an interrupted import; it may hold live session cookies. "
        + (
            f"It is the previous profile: rename it to {target} to restore it, or delete it."
            if ".waybound-backup-" in path.name
            else "It is an unfinished or verified-but-unplaced import: delete it, or rename it "
            "into place yourself."
        )
        for path in found
    ]


def _write_marker(staging: Path, manifest: Manifest) -> None:
    marker = {
        "bundle_created_at": manifest.created_at,
        "imported_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "waybound_version": _waybound_version(),
    }
    (staging / IMPORT_MARKER).write_text(json.dumps(marker), encoding="utf-8")


def _kept(staging: Path) -> str:
    return f"the verified import (it holds live session cookies) is kept at {staging}"


def _recheck(
    staging: Path, target: Path, state: TargetState, *, force: bool, ignore_lock: bool
) -> TargetState:
    """Re-run every target check right before anything is moved."""
    inner = staging if state == "empty_mount" else None
    try:
        now = _target_state(target, force=force, ignore_lock=ignore_lock, staging=inner)
    except ProfileError as exc:
        raise type(exc)(f"{exc}; nothing was replaced and {_kept(staging)}") from exc
    if now != state and not (state == "absent" and now == "empty"):
        msg = (
            f"the target changed while the bundle was extracted ({state} -> {now}); nothing "
            f"was replaced and {_kept(staging)}"
        )
        raise ProfileError(msg)
    return now


def _move_into_empty(staging: Path, target: Path, *, empty: bool) -> None:
    try:
        if empty and os.name == "nt":
            target.rmdir()
        # POSIX rename() replaces an empty directory atomically and fails (ENOTEMPTY or
        # ENOTDIR) if anything appeared at the target in the meantime.
        staging.rename(target)
    except OSError as exc:
        msg = f"could not move the verified profile into place ({exc}); {_kept(staging)}"
        raise ProfileError(msg) from exc
    except BaseException as exc:
        exc.add_note(_kept(staging))
        raise


def _replace_existing(staging: Path, target: Path) -> list[str]:
    backup = target.with_name(f".{target.name}.waybound-backup-{secrets.token_hex(6)}")
    try:
        target.rename(backup)
    except OSError as exc:
        msg = (
            f"could not move the existing profile aside ({exc}); nothing was changed and "
            f"{_kept(staging)}"
        )
        raise ProfileError(msg) from exc
    except BaseException as exc:
        exc.add_note(f"{_kept(staging)}; the existing profile may have been moved to {backup}")
        raise
    try:
        staging.rename(target)
    except BaseException as exc:
        try:
            backup.rename(target)
        except BaseException as rollback_exc:
            msg = (
                f"could not move the verified profile into place ({exc}) nor restore the old "
                f"one ({rollback_exc}): old profile at {backup}, {_kept(staging)}"
            )
            raise ProfileError(msg) from exc
        if isinstance(exc, OSError):
            msg = (
                f"could not move the verified profile into place ({exc}); the original was "
                f"restored and {_kept(staging)}"
            )
            raise ProfileError(msg) from exc
        exc.add_note(f"the original profile was restored; {_kept(staging)}")
        raise
    try:
        shutil.rmtree(backup)
    except OSError as exc:
        return [f"the previous profile could not be fully removed ({exc}); it remains at {backup}"]
    except BaseException as exc:
        exc.add_note(f"the import finished, but the previous profile is partly left at {backup}")
        raise
    return []


def _fill_mount(staging: Path, target: Path) -> None:
    """Move verified entries from `staging` (inside the mount) into `target`. Not atomic."""
    moved: list[Path] = []
    try:
        for entry in sorted(staging.iterdir()):
            dest = target / entry.name
            if os.path.lexists(dest):
                msg = f"{dest} appeared while the bundle was being imported"
                raise ProfileError(msg)
            entry.rename(dest)
            moved.append(dest)
        staging.rmdir()
    except BaseException:
        for path in reversed(moved):
            with contextlib.suppress(OSError):
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _place(
    staging: Path, target: Path, state: TargetState, *, force: bool, ignore_lock: bool
) -> list[str]:
    now = _recheck(staging, target, state, force=force, ignore_lock=ignore_lock)
    if now == "empty_mount":
        _fill_mount(staging, target)
        return []
    if now == "replace":
        return _replace_existing(staging, target)
    _move_into_empty(staging, target, empty=now == "empty")
    return []


def _assess(manifest: Manifest, allow_incompatible: bool) -> tuple[Compatibility, list[str]]:
    compat = assess_compatibility(
        manifest.source_os,
        manifest.password_store,
        current_os(),
        prefixes=manifest.cookie_encryption_prefixes,
    )
    if compat.level == "incompatible":
        if not allow_incompatible:
            msg = f"{compat.message} (pass allow_incompatible=True to import anyway)"
            raise IncompatibleBundleError(msg)
        return compat, [f"importing anyway: {compat.message}"]
    return compat, [] if compat.level == "portable" else [compat.message]


def import_profile(  # noqa: PLR0913
    bundle: Path | str,
    profile_dir: Path | str,
    *,
    force: bool = False,
    allow_incompatible: bool = False,
    ignore_lock: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ImportResult:
    """Verify a bundle and restore it as a Chrome user-data-dir.

    Everything is extracted into a private sibling staging directory
    (`.<name>.waybound-import-*`) and hash-checked before the target is touched. All target
    checks are then repeated, and the verified directory is put in place with renames: an
    absent or empty target is replaced in one `rename`; a non-empty one (only with `force`,
    and only if it looks like a Chrome user-data-dir or a previous import) is moved aside,
    the new one moved in, and the old one deleted only after that succeeded (rolled back if
    not). An empty mount point is filled in place instead (staging inside the mount; not
    atomic). Bundles whose cookies cannot decrypt on this OS are refused unless
    `allow_incompatible`. Restored directories are 0700, files 0600.
    """
    src = Path(bundle)
    target = Path(os.path.abspath(profile_dir))  # noqa: PTH100 - normalizes '..'
    manifest = read_manifest(src, max_bytes=max_bytes)
    compat, warnings = _assess(manifest, allow_incompatible)
    warnings.extend(_leftover_warnings(target))

    state = _target_state(target, force=force, ignore_lock=ignore_lock)
    in_mount = state == "empty_mount"
    try:
        created = _make_private_parents(target.parent)
        staging = Path(
            tempfile.mkdtemp(
                prefix=".waybound-import-" if in_mount else f".{target.name}.waybound-import-",
                dir=target if in_mount else target.parent,
            )
        )
    except OSError as exc:
        msg = f"cannot create a staging directory for {target}: {exc}"
        raise ProfileError(msg) from exc
    try:
        staged = _scan_bundle(src, max_bytes, _Sink(staging))
        if staged != manifest:
            raise _fail("bundle changed while it was being imported")
        _write_marker(staging, manifest)
        _fix_permissions(staging)
    except BaseException as exc:
        shutil.rmtree(staging, ignore_errors=True)
        _remove_created(created)
        if isinstance(exc, OSError):
            msg = f"could not extract the bundle: {exc}"
            raise ProfileError(msg) from exc
        raise
    warnings.extend(_place(staging, target, state, force=force, ignore_lock=ignore_lock))
    if in_mount:
        target.chmod(0o700)
    return ImportResult(target, manifest, compat, tuple(warnings))
