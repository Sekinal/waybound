"""Fast copy-on-write Chrome profile store and snapshot archiving (`ProfileStore`)."""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

DEFAULT_MAX_SNAPSHOT_BYTES: int = 512 * 1024 * 1024
_COPY_CHUNK_BYTES: int = 64 * 1024
_MAX_PROFILE_NAME_LEN: int = 255
_SAFE_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")

EXCLUDED_PROFILE_NAMES: frozenset[str] = frozenset(
    {
        "SingletonLock",
        "SingletonCookie",
        "SingletonSocket",
        "LOCK",
        "lockfile",
        "Crashpad",
        "BrowserMetrics",
        "ShaderCache",
        "GrShaderCache",
        "GraphiteDawnCache",
        "Code Cache",
        "GPUCache",
        "DawnCache",
        "Cache",
        "Cache_Data",
    }
)


def validate_profile_name(name: str) -> str:
    """Validate that `name` is a safe single-segment profile identifier."""
    if (
        not name
        or len(name) > _MAX_PROFILE_NAME_LEN
        or name.startswith(".")
        or ".." in name
        or not _SAFE_PROFILE_NAME_RE.fullmatch(name)
    ):
        msg = f"invalid profile name: {name!r}"
        raise ValueError(msg)
    return name


def _is_excluded_name(name: str) -> bool:
    return name in EXCLUDED_PROFILE_NAMES


def _lstat_kind(path: Path) -> int | None:
    try:
        return path.lstat().st_mode
    except OSError:
        return None


def _is_regular_or_dir(path: Path) -> tuple[bool, bool]:
    """Return `(is_regular, is_dir)` using `lstat` (never follows symlinks)."""
    mode = _lstat_kind(path)
    if mode is None:
        return (False, False)
    return (stat.S_ISREG(mode), stat.S_ISDIR(mode))


def _strip_excluded_entries(root: Path) -> None:
    """Remove any excluded files, directories, symlinks, or special files under `root`."""
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in dirnames:
            entry = current_path / dirname
            if _is_excluded_name(dirname) or entry.is_symlink():
                if entry.is_symlink():
                    entry.unlink(missing_ok=True)
                else:
                    shutil.rmtree(entry, ignore_errors=True)
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            entry = current_path / filename
            is_reg, _ = _is_regular_or_dir(entry)
            if _is_excluded_name(filename) or not is_reg:
                entry.unlink(missing_ok=True)


def _run_cow_cp(cp_bin: str, sources: list[Path], dest_dir: Path) -> bool:
    """Copy `sources` into `dest_dir` using OS copy-on-write flags. Returns True on success."""
    if not sources:
        return True
    if sys.platform == "darwin":
        args = [cp_bin, "-c", "-R", "--", *[str(s) for s in sources], str(dest_dir)]
    elif sys.platform.startswith("linux"):
        args = [cp_bin, "-a", "--reflink=auto", "--", *[str(s) for s in sources], str(dest_dir)]
    else:
        return False

    result = subprocess.run(  # noqa: S603
        args,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _copy_dir_cow(src: Path, dst: Path, cp_bin: str, depth: int = 0) -> bool:
    """Selectively CoW-copy `src` into `dst`, skipping excluded names before invoking `cp`."""
    dst.mkdir(parents=True, exist_ok=True)
    batch: list[Path] = []
    subdirs_to_recurse: list[tuple[Path, Path]] = []

    for entry in src.iterdir():
        if _is_excluded_name(entry.name):
            continue
        is_reg, is_dir = _is_regular_or_dir(entry)
        if not is_reg and not is_dir:
            continue
        if is_dir and depth == 0:
            # Recurse into top-level profile subdirs (e.g. `Default/`, `Profile 1/`) so large
            # nested caches like `Default/Cache` are skipped before invoking `cp`.
            subdirs_to_recurse.append((entry, dst / entry.name))
        else:
            batch.append(entry)

    if batch and not _run_cow_cp(cp_bin, batch, dst):
        return False

    for child_src, child_dst in subdirs_to_recurse:
        if not _copy_dir_cow(child_src, child_dst, cp_bin, depth=depth + 1):
            return False

    return True


def _copy_dir_fallback(src: Path, dst: Path) -> None:
    """Portable recursive copy that excludes ephemeral Chrome files and non-regular entries."""

    def _ignore(directory: str, names: list[str]) -> set[str]:
        base = Path(directory)
        ignored: set[str] = set()
        for name in names:
            if _is_excluded_name(name):
                ignored.add(name)
                continue
            is_reg, is_dir = _is_regular_or_dir(base / name)
            if not is_reg and not is_dir:
                ignored.add(name)
        return ignored

    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=_ignore, symlinks=False)


def _clear_directory(directory: Path) -> None:
    """Remove all children of `directory` without removing `directory` itself."""
    for child in directory.iterdir():
        if child.is_symlink() or not child.is_dir():
            child.unlink(missing_ok=True)
        else:
            shutil.rmtree(child, ignore_errors=True)


def _validate_archive_member_path(raw_name: str) -> PurePosixPath | None:
    """Validate and normalize a tar member path; return None for root `.` entries."""
    if "\x00" in raw_name:
        msg = f"archive member contains NUL byte: {raw_name!r}"
        raise ValueError(msg)
    if raw_name.startswith(("/", "\\")) or _WINDOWS_DRIVE_RE.match(raw_name):
        msg = f"archive member uses absolute path: {raw_name!r}"
        raise ValueError(msg)

    normalized = raw_name.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.rstrip("/")
    if normalized in ("", "."):
        return None

    parts = PurePosixPath(normalized).parts
    for part in parts:
        if part in ("..", "", "/"):
            msg = f"archive member contains path traversal: {raw_name!r}"
            raise ValueError(msg)

    return PurePosixPath(*parts)


def _extract_member_to_staging(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    staging_resolved: Path,
    *,
    total_bytes: int,
    max_bytes: int,
) -> int:
    """Validate and extract a single tar member into `staging_resolved`; return updated bytes."""
    if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
        msg = f"archive member has disallowed type ({member.type!r}): {member.name!r}"
        raise ValueError(msg)

    if member.size < 0:
        msg = f"archive member has negative size: {member.name!r}"
        raise ValueError(msg)
    if member.isdir() and member.size > 0:
        msg = f"archive directory member has non-zero size: {member.name!r}"
        raise ValueError(msg)
    if total_bytes + member.size > max_bytes:
        msg = f"snapshot exceeds max_bytes limit ({max_bytes} bytes)"
        raise ValueError(msg)

    rel = _validate_archive_member_path(member.name)
    if rel is None or any(_is_excluded_name(part) for part in rel.parts):
        return total_bytes + member.size

    dest_path = staging_resolved / Path(*rel.parts)
    if not dest_path.resolve().is_relative_to(staging_resolved):
        msg = f"archive member escapes staging directory: {member.name!r}"
        raise ValueError(msg)

    if member.isdir():
        dest_path.mkdir(parents=True, exist_ok=True)
        return total_bytes

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    extracted = archive.extractfile(member)
    if extracted is None:
        msg = f"could not read archive member: {member.name!r}"
        raise ValueError(msg)

    with extracted, dest_path.open("wb") as out_fh:
        while True:
            chunk = extracted.read(_COPY_CHUNK_BYTES)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                msg = f"snapshot exceeds max_bytes limit ({max_bytes} bytes)"
                raise ValueError(msg)
            out_fh.write(chunk)

    dest_path.chmod((member.mode & 0o755) | 0o600)
    return total_bytes


class ProfileStore:
    """Manage named Chrome `--user-data-dir` profiles with fast CoW cloning and snapshots."""

    def __init__(self, root_dir: str | Path) -> None:
        self._root_dir = Path(root_dir)

    @property
    def root_dir(self) -> Path:
        """Directory storing named profiles."""
        return self._root_dir

    def profile_path(self, name: str) -> Path:
        """Return the validated filesystem path for a named profile."""
        valid = validate_profile_name(name)
        return self._root_dir / valid

    def list_profiles(self) -> list[str]:
        """Return sorted names of stored profiles."""
        if not self._root_dir.is_dir():
            return []
        names: list[str] = []
        for entry in self._root_dir.iterdir():
            if entry.name.startswith("."):
                continue
            _, is_dir = _is_regular_or_dir(entry)
            if not is_dir:
                continue
            try:
                validate_profile_name(entry.name)
            except ValueError:
                continue
            names.append(entry.name)
        return sorted(names)

    def exists(self, name: str) -> bool:
        """Return True if a stored profile with `name` exists as a real directory."""
        target = self.profile_path(name)
        _, is_dir = _is_regular_or_dir(target)
        return is_dir

    def delete(self, name: str) -> None:
        """Delete a stored profile if it exists (idempotent; validates `name`)."""
        target = self.profile_path(name)
        if target.is_symlink():
            target.unlink()
        elif target.exists():
            shutil.rmtree(target)

    def _resolve_source(self, source: str | Path) -> Path:
        if isinstance(source, Path):
            src = source
        elif (
            os.sep in source
            or (os.altsep is not None and os.altsep in source)
            or Path(source).is_absolute()
        ):
            src = Path(source)
        else:
            src = self.profile_path(source)

        if not src.is_dir():
            msg = f"profile source directory not found: {src}"
            raise FileNotFoundError(msg)
        return src

    def clone(
        self,
        source: str | Path,
        dest_dir: str | Path | None = None,
        *,
        prefer_cow: bool = True,
    ) -> Path:
        """Clone a profile directory, excluding ephemeral Chrome locks, sockets, and caches."""
        src = self._resolve_source(source)
        created_temp = dest_dir is None
        dest = (
            Path(tempfile.mkdtemp(prefix="waybound-profile-"))
            if dest_dir is None
            else Path(dest_dir)
        )
        try:
            dest.mkdir(parents=True, exist_ok=True)
            src_resolved = src.resolve()
            dest_resolved = dest.resolve()
            if dest_resolved == src_resolved or dest_resolved.is_relative_to(src_resolved):
                msg = f"cannot clone profile into itself or a subdirectory: {dest}"
                raise ValueError(msg)

            copied_with_cow = False
            if prefer_cow and sys.platform != "win32":
                cp_bin = shutil.which("cp")
                if cp_bin is not None:
                    copied_with_cow = _copy_dir_cow(src, dest, cp_bin)
                    if copied_with_cow:
                        _strip_excluded_entries(dest)
                    else:
                        _clear_directory(dest)

            if not copied_with_cow:
                _copy_dir_fallback(src, dest)
        except BaseException:
            if created_temp:
                shutil.rmtree(dest, ignore_errors=True)
            raise

        return dest

    @contextlib.contextmanager
    def ephemeral_clone(
        self,
        source: str | Path,
        *,
        prefer_cow: bool = True,
    ) -> Iterator[Path]:
        """Context manager that clones `source` to a temporary directory and deletes it on exit."""
        cloned = self.clone(source, dest_dir=None, prefer_cow=prefer_cow)
        try:
            yield cloned
        finally:
            shutil.rmtree(cloned, ignore_errors=True)

    def export_snapshot(self, source: str | Path, archive_path: str | Path) -> Path:
        """Atomically export a profile directory to a `.tar.gz` snapshot archive."""
        src = self._resolve_source(source)
        dest = Path(archive_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=dest.parent,
            prefix=".waybound-snapshot-",
            suffix=".tar.gz.tmp",
        )
        tmp_path = Path(tmp_name)
        try:
            with (
                os.fdopen(tmp_fd, "wb") as raw_file,
                tarfile.open(
                    fileobj=raw_file,
                    mode="w:gz",
                    format=tarfile.PAX_FORMAT,
                ) as archive,
            ):
                for current, dirnames, filenames in os.walk(src, topdown=True, followlinks=False):
                    current_path = Path(current)
                    dirnames[:] = sorted(
                        d
                        for d in dirnames
                        if not _is_excluded_name(d) and _is_regular_or_dir(current_path / d)[1]
                    )
                    rel_dir = current_path.relative_to(src)
                    if rel_dir != Path():
                        dir_info = archive.gettarinfo(str(current_path), arcname=rel_dir.as_posix())
                        archive.addfile(dir_info)

                    for filename in sorted(filenames):
                        if _is_excluded_name(filename):
                            continue
                        file_path = current_path / filename
                        is_reg, _ = _is_regular_or_dir(file_path)
                        if not is_reg:
                            continue
                        rel_file = file_path.relative_to(src)
                        file_info = archive.gettarinfo(str(file_path), arcname=rel_file.as_posix())
                        with file_path.open("rb") as fh:
                            archive.addfile(file_info, fh)

            tmp_path.replace(dest)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

        return dest

    def import_snapshot(
        self,
        archive_path: str | Path,
        name: str,
        *,
        overwrite: bool = False,
        max_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
    ) -> Path:
        """Safely extract a `.tar.gz` snapshot archive into a named profile."""
        valid_name = validate_profile_name(name)
        if max_bytes <= 0:
            msg = f"max_bytes must be positive, got {max_bytes}"
            raise ValueError(msg)

        archive_file = Path(archive_path)
        if not archive_file.is_file():
            msg = f"snapshot archive not found: {archive_file}"
            raise FileNotFoundError(msg)

        target = self._root_dir / valid_name
        if (target.exists() or target.is_symlink()) and not overwrite:
            msg = f"profile already exists: {valid_name}"
            raise FileExistsError(msg)

        self._root_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(dir=self._root_dir, prefix=f".{valid_name}-staging-"))
        staging_resolved = staging.resolve()
        total_bytes = 0

        try:
            with tarfile.open(archive_file, mode="r:gz") as archive:
                for member in archive:
                    total_bytes = _extract_member_to_staging(
                        archive,
                        member,
                        staging_resolved,
                        total_bytes=total_bytes,
                        max_bytes=max_bytes,
                    )

            self._commit_staged_profile(staging, target, valid_name, overwrite=overwrite)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise

        return target

    def _commit_staged_profile(
        self,
        staging: Path,
        target: Path,
        valid_name: str,
        *,
        overwrite: bool,
    ) -> None:
        if target.exists() or target.is_symlink():
            if not overwrite:
                msg = f"profile already exists: {valid_name}"
                raise FileExistsError(msg)
            backup = self._root_dir / f".{valid_name}-old-{uuid.uuid4().hex}"
            target.rename(backup)
            try:
                staging.rename(target)
            except BaseException:
                backup.rename(target)
                raise
            if backup.is_symlink():
                backup.unlink(missing_ok=True)
            else:
                shutil.rmtree(backup, ignore_errors=True)
        else:
            staging.rename(target)
