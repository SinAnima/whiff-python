"""Opt-in local staging for path extraction.

``stage="local"`` copies a regular file into a private directory before the
native call opens it, then rewrites the report so it still describes the
original path. Times are second precision. Fields this module does not read
(birth time, allocated size, sparse flag, owner names, ACLs, extended
attributes) are omitted and named in ``diagnostics.warnings``.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from whiff.errors import (
    AccessError,
    InvalidOptionError,
    NativeError,
    NotFoundError,
    UnsupportedInputError,
    WhiffError,
)

_DEFAULT_MAX_BYTES = 1_073_741_824
_DIR_MODE = 0o700
_FILE_MODE = 0o600

_OMITTED = (
    'stage="local": filesystem fields taken from the original at second precision; '
    "created, allocated_bytes, sparse, owner names, acl, and xattrs omitted"
)
_UNREAD = 'stage="local": original file could not be re-read; filesystem fields describe the copy'


@dataclass(frozen=True)
class Staged:
    original: str
    staged: str


def scratch_dir() -> str:
    return os.environ.get("WHIFF_SCRATCH_DIR") or str(Path(tempfile.gettempdir()) / "whiff-scratch")


def scratch_max_bytes() -> int:
    raw = os.environ.get("WHIFF_SCRATCH_MAX_BYTES")
    if raw is None:
        return _configured_max
    try:
        value = int(raw)
    except ValueError:
        return _configured_max
    return value if value > 0 else _configured_max


_configured_max = _DEFAULT_MAX_BYTES


def configure(*, directory: str | None = None, max_bytes: int | None = None) -> None:
    global _configured_max
    if directory is not None:
        os.environ["WHIFF_SCRATCH_DIR"] = directory
    if max_bytes is not None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise InvalidOptionError("scratch_max_bytes must be a positive integer")
        _configured_max = max_bytes
        os.environ["WHIFF_SCRATCH_MAX_BYTES"] = str(max_bytes)


def stage(path: str, mode: str) -> Staged | None:
    """Copy ``path`` when ``mode`` is ``local``. Return None when staging is off."""
    if mode == "never":
        return None
    if mode != "local":
        raise InvalidOptionError(f"invalid stage: {mode!r}")
    return _stage_local(path)


def cleanup(tag: Staged | None) -> None:
    if tag is None:
        return
    shutil.rmtree(os.path.dirname(tag.staged), ignore_errors=True)


def restore_report(report: dict[str, Any], tag: Staged | None) -> dict[str, Any]:
    if tag is None:
        return report
    try:
        info = os.stat(tag.original)
    except OSError:
        return _warn(_put(report, ("source", "path"), tag.original), _UNREAD)
    updated = _put(report, ("source", "path"), tag.original)
    updated = _restore_temporal(updated, info)
    updated = _restore_system(updated, info)
    updated = _restore_security(updated, info)
    return _warn(updated, _OMITTED)


def restore_error(err: WhiffError, tag: Staged | None) -> WhiffError:
    if tag is None:
        return err
    message = err.message.replace(tag.staged, tag.original)
    err.message = message
    err.path = tag.original
    err.args = (err._format(),)
    return err


def _stage_local(path: str) -> Staged:
    try:
        info = os.stat(path)
    except FileNotFoundError as err:
        raise NotFoundError(f"stat: no such file: {err.strerror}", path=path) from err
    except PermissionError as err:
        raise AccessError(f"stat: permission denied: {err.strerror}", path=path) from err
    except OSError as err:
        raise NativeError(f"stat: {err.strerror or err}", path=path) from err
    if not stat.S_ISREG(info.st_mode):
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "non-regular file"
        raise UnsupportedInputError(
            f"scratch staging requires a regular file, got {kind}", path=path
        )
    limit = scratch_max_bytes()
    if info.st_size > limit:
        raise InvalidOptionError(
            f"file size {info.st_size} exceeds scratch_max_bytes {limit}",
            path=path,
            details={"size": info.st_size, "scratch_max_bytes": limit},
        )
    root = _ensure_root(scratch_dir())
    job = _job_dir(root)
    try:
        _verify_root(root, job)
        staged = os.path.join(job, os.path.basename(path) or "input")
        _copy(path, staged, info)
    except Exception:
        shutil.rmtree(job, ignore_errors=True)
        raise
    return Staged(original=path, staged=staged)


def _ensure_root(root: str) -> str:
    if os.path.islink(root):
        raise NativeError("scratch_dir is a symlink, not a directory", path=root)
    if os.path.exists(root):
        if not os.path.isdir(root):
            raise NativeError("scratch_dir is not a directory", path=root)
        return root
    os.makedirs(root, mode=_DIR_MODE, exist_ok=False)
    os.chmod(root, _DIR_MODE)
    return root


def _job_dir(root: str) -> str:
    last_error: Exception | None = None
    for _ in range(3):
        path = os.path.join(root, "whiff-" + secrets.token_urlsafe(12))
        try:
            os.mkdir(path, _DIR_MODE)
        except FileExistsError:
            continue
        except OSError as err:
            last_error = err
            break
        os.chmod(path, _DIR_MODE)
        return path
    raise NativeError(
        f"could not create a unique scratch job directory: {last_error}",
        path=root,
    )


def _verify_root(root: str, job: str) -> None:
    if os.name != "posix":
        return
    root_stat = os.lstat(root)
    job_stat = os.lstat(job)
    if root_stat.st_uid != job_stat.st_uid:
        raise AccessError("scratch_dir is owned by another user", path=root)
    if (root_stat.st_mode & 0o022) != 0 and (root_stat.st_mode & 0o1000) == 0:
        raise AccessError("scratch_dir is writable by group or other users", path=root)


def _copy(source: str, dest: str, info: os.stat_result) -> None:
    shutil.copyfile(source, dest)
    os.chmod(dest, _FILE_MODE)
    os.utime(dest, (info.st_atime, info.st_mtime))


def _restore_temporal(report: dict[str, Any], info: os.stat_result) -> dict[str, Any]:
    def update(section: dict[str, Any]) -> dict[str, Any]:
        section = dict(section)
        section["modified"] = _rfc3339(info.st_mtime)
        section["accessed"] = _rfc3339(info.st_atime)
        section.pop("created", None)
        if os.name == "posix":
            section["changed"] = _rfc3339(info.st_ctime)
        else:
            section.pop("changed", None)
        return section

    return _update(report, ("temporal", "filesystem"), update)


def _restore_system(report: dict[str, Any], info: os.stat_result) -> dict[str, Any]:
    def update(section: dict[str, Any]) -> dict[str, Any]:
        section = dict(section)
        section["device"] = info.st_dev
        section["inode"] = info.st_ino
        section["links"] = info.st_nlink
        section.pop("allocated_bytes", None)
        section.pop("sparse", None)
        return section

    return _update(report, ("system",), update)


def _restore_security(report: dict[str, Any], info: os.stat_result) -> dict[str, Any]:
    def update(section: dict[str, Any]) -> dict[str, Any]:
        section = dict(section)
        mode = info.st_mode & 0o7777
        _put_if(section, "mode", "0" + format(mode, "o"))
        _put_if(section, "permissions", _permissions(mode))
        _put_if(section, "setuid", (mode & 0o4000) != 0)
        _put_if(section, "setgid", (mode & 0o2000) != 0)
        _put_if(section, "sticky", (mode & 0o1000) != 0)
        if "owner" in section:
            section["owner"] = {"uid": info.st_uid, "gid": info.st_gid}
        section.pop("acl", None)
        section.pop("xattrs", None)
        return section

    return _update(report, ("security",), update)


def _put_if(section: dict[str, Any], key: str, value: object) -> None:
    if key in section:
        section[key] = value


def _permissions(mode: int) -> str:
    bits = (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)
    chars = "rwxrwxrwx"
    return "".join(char if mode & bit else "-" for bit, char in zip(bits, chars, strict=True))


def _rfc3339(timestamp: float) -> str:
    return datetime.fromtimestamp(int(timestamp), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _update(report: dict[str, Any], path: tuple[str, ...], fn) -> dict[str, Any]:
    current = _get(report, path)
    if not isinstance(current, dict):
        return report
    return _put(report, path, fn(current))


def _warn(report: dict[str, Any], warning: str) -> dict[str, Any]:
    diagnostics = report.get("diagnostics")
    diagnostics = dict(diagnostics) if isinstance(diagnostics, dict) else {}
    warnings = list(diagnostics.get("warnings") or [])
    warnings.append(warning)
    diagnostics["warnings"] = warnings
    updated = dict(report)
    updated["diagnostics"] = diagnostics
    return updated


def _get(report: dict[str, Any], path: tuple[str, ...]) -> object:
    current: object = report
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _put(report: dict[str, Any], path: tuple[str, ...], value: object) -> dict[str, Any]:
    if len(path) == 1:
        updated = dict(report)
        updated[path[0]] = value
        return updated
    child = report.get(path[0])
    child = dict(child) if isinstance(child, dict) else {}
    updated = dict(report)
    updated[path[0]] = _put(child, path[1:], value)
    return updated
