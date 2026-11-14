"""Public extraction entry points."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Any

from whiff import input as input_mod
from whiff import plugins, scratch
from whiff.errors import (
    NativeError,
    UnsupportedInputError,
    WhiffError,
    WhiffTimeoutError,
    error_for,
)
from whiff.limiter import LIMITER
from whiff.options import native_payload, validate
from whiff.report import SCHEMA, decode

__version__ = "0.1.0"

_NATIVE_KEYS = {
    "profile",
    "hashes",
    "privacy",
    "only",
    "skip",
    "format",
    "provenance",
    "limits",
}
_BATCH_TIMEOUT_MS = 300_000
_schema_cache: dict[str, Any] | None = None
_default_engine: Engine | None = None


def _extension():
    try:
        from whiff import _native
    except ImportError as err:
        raise NativeError(
            "whiff native extension is not built; run `maturin develop` from the repository root"
        ) from err
    return _native


def _from_native(exc: BaseException, path: str | None) -> WhiffError:
    args = getattr(exc, "args", ())
    if len(args) == 1 and isinstance(args[0], tuple) and len(args[0]) == 2:
        args = args[0]
    if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], str):
        err = error_for(args[0], args[1], path=path)
    else:
        err = NativeError(str(exc), path=path)
    if path is not None and err.path is None:
        err.path = path
        err.args = (err._format(),)
    return err


class Engine:
    """Reusable extractor. Safe to share across threads.

    Keyword arguments are the native options (``profile``, ``hashes``,
    ``privacy``, ``only``, ``skip``, ``format``, ``provenance``, ``limits``).
    Per-call keywords override them.
    """

    def __init__(self, **kwargs: Any) -> None:
        unknown = sorted(key for key in kwargs if key not in _NATIVE_KEYS)
        if unknown:
            from whiff.errors import InvalidOptionError

            raise InvalidOptionError(f"unknown option(s): {unknown}", details={"unknown": unknown})
        normalized = validate(kwargs, "path")
        self._native_kwargs = {key: normalized[key] for key in kwargs}
        self._cache_key: str | None = None
        self._rust: Any = None

    def extract(self, source: Any, **kwargs: Any) -> dict[str, Any]:
        combined = {**self._native_kwargs, **kwargs}
        if _is_bytes(source) or _is_file(source):
            opts = validate(combined, "bytes")
            return _extract_bytes(source, opts, self)
        if _is_path(source):
            opts = validate(combined, "path")
            return _extract_path(source, opts, self)
        raise UnsupportedInputError("path must be a path, bytes, or a binary file object")

    def llm(self, source: Any, **kwargs: Any) -> dict[str, Any]:
        combined = {**self._native_kwargs, **kwargs}
        if _is_bytes(source) or _is_file(source):
            opts = validate(combined, "llm_bytes")
            return _llm_bytes(source, opts, self)
        if _is_path(source):
            opts = validate(combined, "llm_path")
            return _llm_path(source, opts, self)
        raise UnsupportedInputError("path must be a path, bytes, or a binary file object")

    def extract_many(self, paths: Sequence[Any], **kwargs: Any) -> list[tuple[str, Any]]:
        combined = {**self._native_kwargs, **kwargs}
        return _extract_many(paths, combined, self)

    def _rust_engine(self, opts: dict[str, Any]) -> Any:
        payload = json.dumps(
            native_payload(opts, include_tokens=False),
            sort_keys=True,
            separators=(",", ":"),
        )
        if payload != self._cache_key:
            self._rust = _extension().Engine(payload)
            self._cache_key = payload
        return self._rust


def extract(source: Any, **kwargs: Any) -> dict[str, Any]:
    """Extract a ``whiff/1`` report from a path, ``bytes``, or a binary file.

    Problems inside a readable file are recorded in ``diagnostics`` and still
    return a report. The call raises :class:`~whiff.errors.WhiffError` when
    the path cannot be inspected or an option is invalid.
    """
    return _engine_for(kwargs).extract(source, **_without_native(kwargs))


def llm(source: Any, **kwargs: Any) -> dict[str, Any]:
    """Compact ``Report::llm_view`` projection. Python plugins do not run."""
    return _engine_for(kwargs).llm(source, **_without_native(kwargs))


def extract_many(paths: Sequence[Any], **kwargs: Any) -> list[tuple[str, Any]]:
    """Extract each path, in input order.

    ``on_error="collect"`` (default) returns ``(path, report)`` or
    ``(path, error)``. ``on_error="halt"`` raises the first error and sets
    ``details["partial"]`` to the pairs completed before it. ``timeout`` is
    per path, in milliseconds (default 300000). Native work already running
    is not cancelled when a path times out.
    """
    native = {key: value for key, value in kwargs.items() if key in _NATIVE_KEYS}
    rest = {key: value for key, value in kwargs.items() if key not in _NATIVE_KEYS}
    engine = Engine(**native) if native else _default()
    return engine.extract_many(paths, **rest)


def schema() -> dict[str, Any]:
    """Vendored ``whiff/1`` JSON Schema."""
    global _schema_cache
    if _schema_cache is None:
        from whiff.merge import _SCHEMA_PATH

        _schema_cache = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _schema_cache


def version() -> dict[str, Any]:
    """Binding version, upstream crate, schema id, features, and limit caps."""
    info = json.loads(bytes(_extension().version()))
    info["version"] = __version__
    info["schema"] = info.get("schema") or SCHEMA
    return info


def configure(
    *,
    native_max_concurrency: int | None = None,
    native_wait_ms: int | None = None,
    scratch_dir: str | None = None,
    scratch_max_bytes: int | None = None,
) -> None:
    """Set process-wide native concurrency and scratch-staging limits."""
    if native_max_concurrency is not None or native_wait_ms is not None:
        LIMITER.configure(max_concurrency=native_max_concurrency, wait_ms=native_wait_ms)
    if scratch_dir is not None or scratch_max_bytes is not None:
        scratch.configure(directory=scratch_dir, max_bytes=scratch_max_bytes)


def _default() -> Engine:
    global _default_engine
    if _default_engine is None:
        _default_engine = Engine()
    return _default_engine


def _engine_for(kwargs: dict[str, Any]) -> Engine:
    native = {key: value for key, value in kwargs.items() if key in _NATIVE_KEYS}
    if native:
        return Engine(**native)
    return _default()


def _without_native(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in kwargs.items() if key not in _NATIVE_KEYS}


def _extract_path(source: Any, opts: dict[str, Any], engine: Engine) -> dict[str, Any]:
    path = _display_path(source)
    tag = scratch.stage(path, opts.get("stage", "never"))
    try:
        staged = tag.staged if tag is not None else path
        try:
            with LIMITER.slot():
                raw = engine._rust_engine(opts).extract_path(os.fsencode(staged))
        except WhiffError as err:
            raise scratch.restore_error(err, tag) from None
        except Exception as err:
            if _is_native_fault(err):
                raise scratch.restore_error(_from_native(err, path), tag) from None
            raise
        report = scratch.restore_report(decode(bytes(raw)), tag)
    finally:
        scratch.cleanup(tag)
    return plugins.run(input_mod.from_path(path), report, opts)


def _extract_bytes(source: Any, opts: dict[str, Any], engine: Engine) -> dict[str, Any]:
    data, name = _bytes_of(source, opts)
    mime = opts.get("mime")
    try:
        with LIMITER.slot():
            raw = engine._rust_engine(opts).extract_bytes(data, name)
    except WhiffError:
        raise
    except Exception as err:
        if _is_native_fault(err):
            raise _from_native(err, name) from None
        raise
    report = decode(bytes(raw))
    return plugins.run(input_mod.from_binary(data, name=name, mime=mime), report, opts)


def _llm_path(source: Any, opts: dict[str, Any], engine: Engine) -> dict[str, Any]:
    path = _display_path(source)
    tag = scratch.stage(path, opts.get("stage", "never"))
    try:
        staged = tag.staged if tag is not None else path
        try:
            with LIMITER.slot():
                raw = engine._rust_engine(opts).llm_path(
                    os.fsencode(staged), opts.get("tokens", 800)
                )
        except WhiffError as err:
            raise scratch.restore_error(err, tag) from None
        except Exception as err:
            if _is_native_fault(err):
                raise scratch.restore_error(_from_native(err, path), tag) from None
            raise
        return scratch.restore_report(decode(bytes(raw)), tag)
    finally:
        scratch.cleanup(tag)


def _llm_bytes(source: Any, opts: dict[str, Any], engine: Engine) -> dict[str, Any]:
    data, name = _bytes_of(source, opts)
    try:
        with LIMITER.slot():
            raw = engine._rust_engine(opts).llm_bytes(data, name, opts.get("tokens", 800))
    except WhiffError:
        raise
    except Exception as err:
        if _is_native_fault(err):
            raise _from_native(err, name) from None
        raise
    return decode(bytes(raw))


def _extract_many(
    paths: Sequence[Any], opts_in: dict[str, Any], engine: Engine
) -> list[tuple[str, Any]]:
    if isinstance(paths, (str, bytes)) or not isinstance(paths, Sequence):
        raise UnsupportedInputError("paths must be a list")
    opts = validate(dict(opts_in), "extract_many")
    timeout_ms = opts.get("timeout", _BATCH_TIMEOUT_MS)
    timeout_s = None if timeout_ms is None else timeout_ms / 1000
    workers = opts.get("max_concurrency", 4)
    on_error = opts.get("on_error", "collect")
    results: list[tuple[str, Any]] = []

    def one(path: Any) -> Any:
        try:
            if not _is_path(path):
                raise UnsupportedInputError("path must be a path")
            single = {
                key: value
                for key, value in opts.items()
                if key not in {"max_concurrency", "on_error", "timeout"}
            }
            return _extract_path(path, single, engine)
        except WhiffError as err:
            return err

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="whiff") as pool:
        futures = [pool.submit(one, path) for path in paths]
        for path, future in zip(paths, futures, strict=True):
            label = _display_path(path) if _is_path(path) else str(path)
            try:
                item = future.result(timeout=timeout_s)
            except FuturesTimeout:
                item = WhiffTimeoutError(
                    f"extraction exceeded {timeout_ms}ms",
                    path=label if _is_path(path) else None,
                )
            if isinstance(item, WhiffError):
                if on_error == "halt":
                    item.details = {**item.details, "partial": list(results)}
                    if item.path is None and _is_path(path):
                        item.path = label
                    item.args = (item._format(),)
                    raise item
            results.append((label, item))
    return results


def _bytes_of(source: Any, opts: dict[str, Any]) -> tuple[bytes, str | None]:
    name = opts.get("name") or opts.get("filename")
    if _is_file(source):
        if name is None:
            raw_name = getattr(source, "name", None)
            if isinstance(raw_name, str) and raw_name not in {"<stdin>", "<stdout>"}:
                name = os.path.basename(raw_name) or None
        cap = _read_cap(opts)
        return _read_file(source, cap), name
    data = _as_bytes(source)
    if data is None:
        raise UnsupportedInputError("expected bytes or a binary file object")
    return data, name


def _read_cap(opts: dict[str, Any]) -> int:
    limits = opts.get("limits") or {}
    if "max_read_bytes" in limits:
        return int(limits["max_read_bytes"])
    raw = _extension().default_limits(opts.get("profile"))
    return int(json.loads(bytes(raw))["max_read_bytes"])


def _read_file(source: Any, cap: int) -> bytes:
    chunks: list[bytes] = []
    remaining = cap
    while remaining > 0:
        chunk = source.read(remaining)
        if not chunk:
            break
        if isinstance(chunk, str):
            raise UnsupportedInputError("file object must be opened in binary mode")
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise UnsupportedInputError("file object must be opened in binary mode")
        piece = bytes(chunk)
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


def _is_native_fault(err: BaseException) -> bool:
    return type(err).__name__ == "NativeFault"


def _is_path(source: Any) -> bool:
    return isinstance(source, (str, os.PathLike)) and not isinstance(source, bytes)


def _is_bytes(source: Any) -> bool:
    return isinstance(source, (bytes, bytearray, memoryview))


def _is_file(source: Any) -> bool:
    return not _is_bytes(source) and not _is_path(source) and hasattr(source, "read")


def _display_path(source: Any) -> str:
    text = os.fspath(source)
    if isinstance(text, bytes):
        return os.fsdecode(text)
    return text


def _as_bytes(source: Any) -> bytes | None:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    return None
