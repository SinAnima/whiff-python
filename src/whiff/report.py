"""Decode and inspect ``whiff/1`` reports."""

from __future__ import annotations

import json
from typing import Any

from whiff.errors import InvalidReportError

SCHEMA = "whiff/1"

TOP_LEVEL = (
    "whiff",
    "source",
    "identification",
    "system",
    "temporal",
    "security",
    "rights",
    "physical",
    "integrity",
    "content",
    "metadata",
    "format",
    "embedded",
    "diagnostics",
)


def decode(raw: bytes | str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as err:
        raise InvalidReportError(f"failed to decode report JSON: {err}") from err
    if not isinstance(value, dict):
        raise InvalidReportError("report JSON root must be an object")
    return value


def native_covered(report: dict[str, Any]) -> bool:
    """Whether native extraction covered the identified format.

    Coverage requires a non-empty ``identification.extractor``, an extension
    that was not reported as a mismatch, a detection that is not a bare
    heuristic, and an ``ok`` diagnostics entry for that extractor.
    """
    ident = report.get("identification") or {}
    if not isinstance(ident, dict):
        return False
    extractor = ident.get("extractor")
    if not isinstance(extractor, str) or not extractor:
        return False
    if ident.get("extension_matches") is False:
        return False
    if ident.get("detected_by") == "heuristic" and ident.get("extension_matches") is not True:
        return False
    return _diag_ok(report, extractor)


def unreadable(report: dict[str, Any]) -> bool:
    ident = report.get("identification")
    return isinstance(ident, dict) and ident.get("format") == "unreadable"


def extractor_ids(report: dict[str, Any]) -> list[str]:
    runs = _runs(report)
    return [run["id"] for run in runs if isinstance(run, dict) and isinstance(run.get("id"), str)]


def append_extractor(report: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    else:
        diagnostics = dict(diagnostics)
    runs = list(diagnostics.get("extractors") or [])
    runs.append(entry)
    diagnostics["extractors"] = runs
    updated = dict(report)
    updated["diagnostics"] = diagnostics
    return updated


def _diag_ok(report: dict[str, Any], extractor: str) -> bool:
    return any(
        isinstance(run, dict) and run.get("id") == extractor and run.get("status") == "ok"
        for run in _runs(report)
    )


def _runs(report: dict[str, Any]) -> list[Any]:
    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return []
    runs = diagnostics.get("extractors") or []
    return runs if isinstance(runs, list) else []
