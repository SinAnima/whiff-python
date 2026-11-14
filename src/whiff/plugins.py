"""Run Python extractors, then analyzers, after native extraction.

Plugins run on a worker thread with ``plugin_timeout_ms``. A failure is
recorded in ``diagnostics.extractors`` unless ``strict`` is set, in which
case it is raised. Plugins are not a security boundary: a native crash inside
a plugin still takes down the process. Error text stored in the report is
privacy-scrubbed and truncated, and does not include arbitrary exception
messages.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Any

from whiff.errors import (
    AnalyzerError,
    ExtractorError,
    WhiffError,
    WhiffTimeoutError,
    error_for,
)
from whiff.input import Input
from whiff.merge import merge_tracked, validate_patch
from whiff.privacy import scrub_patch, scrub_string
from whiff.report import append_extractor, extractor_ids, native_covered, unreadable


class Extractor:
    """Base class for a plugin that adds fields after native extraction.

    ``supports`` is called with the :class:`~whiff.input.Input` and the report
    so far. ``extract`` returns a patch dict. With ``mode="fallback"`` (the
    default) ``extract`` runs only when native extraction did not cover a
    readable file.
    """

    id: str = ""
    version: int = 1

    def supports(self, source: Input, report: dict[str, Any]) -> bool:
        return False

    def extract(self, source: Input, report: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class Analyzer:
    """Base class for a plugin that runs after extractors.

    ``analyze`` returns a patch merged in ``augment`` mode: it can add fields
    and append keywords, risks, and warnings, and it does not replace values
    already set.
    """

    id: str = ""
    version: int = 1

    def analyze(self, report: dict[str, Any], source: Input) -> dict[str, Any]:
        raise NotImplementedError


_MAX_ID_BYTES = 128
_MAX_VERSION = 4_294_967_295
_MAX_ERROR_BYTES = 256
_META_TIMEOUT_MS = 1_000


def run(source: Input, report: dict[str, Any], opts: dict[str, Any]) -> dict[str, Any]:
    ctx = _Ctx(
        mode=opts.get("mode", "fallback"),
        strict=bool(opts.get("strict", False)),
        timeout_ms=int(opts.get("plugin_timeout_ms", 5_000)),
        privacy=opts.get("privacy", "strict"),
        provenance=bool(opts.get("provenance", False)),
        override_fields=list(opts.get("override_fields") or []),
        native_ids=set(extractor_ids(report)),
        covered=native_covered(report),
        unreadable=unreadable(report),
    )
    report, owned = _reduce(
        opts.get("extractors") or [], report, set(), source, ctx, kind="extractor"
    )
    report, _owned = _reduce(
        opts.get("analyzers") or [], report, owned, source, ctx, kind="analyzer"
    )
    return report


class _Ctx:
    def __init__(
        self,
        *,
        mode: str,
        strict: bool,
        timeout_ms: int,
        privacy: str,
        provenance: bool,
        override_fields: list[str],
        native_ids: set[str],
        covered: bool,
        unreadable: bool,
    ) -> None:
        self.mode = mode
        self.strict = strict
        self.timeout_ms = timeout_ms
        self.privacy = privacy
        self.provenance = provenance
        self.override_fields = override_fields
        self.native_ids = native_ids
        self.covered = covered
        self.unreadable = unreadable


def _reduce(plugins, report, owned, source, ctx, *, kind: str):
    for plugin in plugins:
        report, owned = _one(plugin, source, report, owned, ctx, kind)
    return report, owned


def _one(plugin, source, report, owned, ctx: _Ctx, kind: str):
    obj = plugin() if isinstance(plugin, type) else plugin
    meta, err = _metadata(obj, kind, ctx)
    if err is not None:
        return _failure(report, owned, err, meta, ctx)
    if kind == "extractor":
        supported, err = _call(
            lambda: obj.supports(source, report) is True,
            timeout_ms=ctx.timeout_ms,
            kind=kind,
            plugin_id=meta["id"],
        )
        if err is not None:
            return _failure(report, owned, err, meta, ctx)
        if not supported:
            return report, owned
        if ctx.mode == "fallback" and (ctx.covered or ctx.unreadable):
            return report, owned
        started = time.perf_counter()
        result, err = _call(
            lambda: obj.extract(source, report),
            timeout_ms=ctx.timeout_ms,
            kind=kind,
            plugin_id=meta["id"],
        )
        meta = {**meta, "ms": (time.perf_counter() - started) * 1000}
        mode = ctx.mode
    else:
        started = time.perf_counter()
        result, err = _call(
            lambda: obj.analyze(report, source),
            timeout_ms=ctx.timeout_ms,
            kind=kind,
            plugin_id=meta["id"],
        )
        meta = {**meta, "ms": (time.perf_counter() - started) * 1000}
        mode = "augment"
    if err is not None:
        return _failure(report, owned, err, meta, ctx)
    if not isinstance(result, dict):
        reason = "analyzer_error" if kind == "analyzer" else "extractor_error"
        err = error_for(reason, f"{kind} returned {_shape(result)}; expected a dict")
        return _failure(report, owned, err, meta, ctx)
    return _apply(report, owned, result, mode, meta, ctx)


def _metadata(obj, kind: str, ctx: _Ctx) -> tuple[dict[str, Any], WhiffError | None]:
    fallback = {"id": type(obj).__name__, "version": 0, "ms": 0.0, "kind": kind}

    def read():
        plugin_id = obj.id() if callable(obj.id) else obj.id
        version = (
            obj.version() if callable(getattr(obj, "version", None)) else getattr(obj, "version", 0)
        )
        return plugin_id, version

    try:
        plugin_id, version = _invoke(read, min(ctx.timeout_ms, _META_TIMEOUT_MS))
    except WhiffTimeoutError as err:
        return fallback, err
    except WhiffError as err:
        return fallback, err
    except Exception as err:
        reason = "analyzer_error" if kind == "analyzer" else "extractor_error"
        return fallback, error_for(
            reason, f"plugin raised {type(err).__name__}", details={"plugin": fallback["id"]}
        )

    reason = "analyzer_error" if kind == "analyzer" else "extractor_error"
    if not _valid_id(plugin_id):
        return fallback, error_for(
            reason,
            f"id must be a non-empty string (max {_MAX_ID_BYTES} bytes)",
        )
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not 0 <= version <= _MAX_VERSION
    ):
        return fallback, error_for(reason, f"version must be an integer in 0..{_MAX_VERSION}")
    if plugin_id in ctx.native_ids:
        return fallback, error_for(
            "conflict", f"plugin id `{plugin_id}` collides with a native extractor id"
        )
    return {**fallback, "id": plugin_id, "version": version}, None


def _valid_id(plugin_id: object) -> bool:
    return (
        isinstance(plugin_id, str)
        and plugin_id != ""
        and len(plugin_id.encode("utf-8")) <= _MAX_ID_BYTES
    )


def _call(fn, *, timeout_ms: int, kind: str, plugin_id: str):
    try:
        return _invoke(fn, timeout_ms), None
    except WhiffError as err:
        err.details = {**err.details, "plugin": plugin_id}
        return None, err
    except FuturesTimeout:
        return None, WhiffTimeoutError(
            f"plugin timed out after {timeout_ms}ms",
            details={"plugin": plugin_id},
        )
    except Exception as err:
        reason_cls = AnalyzerError if kind == "analyzer" else ExtractorError
        return None, reason_cls(
            f"plugin raised {type(err).__name__}",
            details={"plugin": plugin_id, "class": type(err).__name__},
        )


def _invoke(fn, timeout_ms: int):
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whiff-plugin")
    try:
        future = pool.submit(fn)
        try:
            return future.result(timeout=timeout_ms / 1000)
        except FuturesTimeout:
            raise WhiffTimeoutError(f"plugin timed out after {timeout_ms}ms") from None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _apply(report, owned: set[str], patch: dict, mode: str, meta: dict, ctx: _Ctx):
    try:
        validate_patch(patch)
        patch = scrub_patch(patch, ctx.privacy)
        merged, written = merge_tracked(
            report,
            patch,
            mode=mode,
            override_fields=ctx.override_fields,
            plugin_id=meta["id"],
            provenance=ctx.provenance,
            owned=owned,
        )
    except WhiffError as err:
        return _failure(report, owned, err, meta, ctx)
    entry = {"id": meta["id"], "version": meta["version"], "ms": meta["ms"], "status": "ok"}
    return append_extractor(merged, entry), owned | set(written)


def _failure(report, owned, err: WhiffError, meta: dict, ctx: _Ctx):
    err = _sanitize(err, ctx)
    err.details = {**err.details, "plugin": meta["id"]}
    if ctx.strict:
        raise err
    entry = {
        "id": meta["id"],
        "version": meta["version"],
        "ms": meta["ms"],
        "status": "error",
        "error_kind": err.reason,
        "error": err.message,
    }
    return append_extractor(report, entry), owned


def _sanitize(err: WhiffError, ctx: _Ctx) -> WhiffError:
    message = scrub_string(err.message, ctx.privacy) if isinstance(err.message, str) else ""
    err.message = _truncate(message)
    err.args = (err._format(),)
    return err


def _truncate(message: str) -> str:
    raw = message.encode("utf-8")
    if len(raw) <= _MAX_ERROR_BYTES:
        return message
    cut = raw[:_MAX_ERROR_BYTES]
    while cut:
        try:
            return cut.decode("utf-8") + "..."
        except UnicodeDecodeError:
            cut = cut[:-1]
    return "..."


def _shape(value: object) -> str:
    if isinstance(value, tuple):
        return f"a tuple of size {len(value)}"
    if isinstance(value, dict):
        return "a dict"
    if isinstance(value, list):
        return "a list"
    if isinstance(value, str):
        return "a str"
    if value is None:
        return "None"
    return type(value).__name__
