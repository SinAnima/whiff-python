"""Merge a plugin patch into a ``whiff/1`` report.

Section rules match the Elixir binding:

* ``whiff`` and ``integrity`` cannot be patched.
* ``embedded`` cannot be patched.
* ``diagnostics`` accepts only ``warnings``, prefixed with ``python:<id>:``.
* ``security.risks`` are appended with ``source`` set to ``python:<id>``.
  ``secrets`` and ``personal_data`` cannot be patched. Other security keys
  may be added and never replace a native value.
* ``metadata`` and ``format`` keys are namespaces.
* ``content.keywords`` are appended and de-duplicated.
* An identical value is never a conflict. ``fallback`` replaces native
  ``content`` leaves. ``override`` replaces a leaf only when its dotted path
  is listed in ``override_fields``. A value written by an earlier plugin in
  the same call is a conflict unless declared.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from whiff.errors import ConflictError, InvalidReportError

_MAX_DEPTH = 8
_MAX_STRING = 64 * 1024
_MAX_MAP_KEYS = 256
_MAX_NODES = 10_000
_MAX_TOTAL_BYTES = 1024 * 1024

_TREE = {"source", "identification", "system", "temporal", "rights", "physical"}
_NAMESPACED = {"metadata", "format"}
_RISK_KEYS = {"kind", "category", "severity", "detail", "source"}

_SCHEMA_PATH = Path(__file__).with_name("schemas") / "whiff-1.schema.json"


def _consts(name: str) -> frozenset[str]:
    document = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return frozenset(item["const"] for item in document["$defs"][name]["oneOf"])


_RISK_CATEGORIES = _consts("RiskCategory")
_SEVERITIES = _consts("Severity")


def merge(
    report: dict[str, Any],
    patch: dict[str, Any],
    *,
    mode: str = "augment",
    override_fields: list[str] | tuple[str, ...] = (),
    plugin_id: str = "plugin",
    provenance: bool = False,
    owned: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    merged, _written = merge_tracked(
        report,
        patch,
        mode=mode,
        override_fields=override_fields,
        plugin_id=plugin_id,
        provenance=provenance,
        owned=owned,
    )
    return merged


def merge_tracked(
    report: dict[str, Any],
    patch: dict[str, Any],
    *,
    mode: str = "augment",
    override_fields: list[str] | tuple[str, ...] = (),
    plugin_id: str = "plugin",
    provenance: bool = False,
    owned: set[str] | frozenset[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(report, dict) or not isinstance(patch, dict):
        raise InvalidReportError("merge requires dict report and patch")
    validate_patch(patch)
    ctx = _Ctx(
        mode=mode,
        fields=set(override_fields),
        plugin_id=plugin_id,
        owned=set(owned or ()),
    )
    merged, written = _apply(report, patch, ctx)
    if provenance:
        merged = _provenance(merged, written, plugin_id)
    return merged, written


def validate_patch(patch: object) -> None:
    _walk_size(patch, 0, 0, 0)


class _Ctx:
    def __init__(self, mode: str, fields: set[str], plugin_id: str, owned: set[str]) -> None:
        self.mode = mode
        self.fields = fields
        self.plugin_id = plugin_id
        self.owned = owned


def _walk_size(value: object, depth: int, nodes: int, byte_count: int) -> tuple[int, int]:
    if depth > _MAX_DEPTH:
        raise InvalidReportError(f"plugin patch exceeds max depth {_MAX_DEPTH}")
    if nodes >= _MAX_NODES:
        raise InvalidReportError(f"plugin patch exceeds {_MAX_NODES} values")
    if isinstance(value, dict):
        if len(value) > _MAX_MAP_KEYS:
            raise InvalidReportError(f"plugin patch map exceeds {_MAX_MAP_KEYS} keys")
        if any(not isinstance(key, str) for key in value):
            raise InvalidReportError("plugin patch keys must be strings")
        key_bytes = sum(len(key.encode("utf-8")) for key in value)
        nodes += 1
        byte_count += key_bytes
        for item in value.values():
            nodes, byte_count = _walk_size(item, depth + 1, nodes, byte_count)
        return nodes, byte_count
    if isinstance(value, list):
        nodes += 1
        for item in value:
            nodes, byte_count = _walk_size(item, depth + 1, nodes, byte_count)
        return nodes, byte_count
    if isinstance(value, str):
        size = len(value.encode("utf-8"))
        if size > _MAX_STRING:
            raise InvalidReportError(f"plugin patch string exceeds {_MAX_STRING} bytes")
        byte_count += size
        if byte_count > _MAX_TOTAL_BYTES:
            raise InvalidReportError(f"plugin patch exceeds {_MAX_TOTAL_BYTES} string bytes")
        return nodes + 1, byte_count
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return nodes + 1, byte_count
    raise InvalidReportError("plugin patch contains an unsupported value")


def _apply(
    report: dict[str, Any], patch: dict[str, Any], ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    written: list[str] = []
    for section in sorted(patch):
        report, new = _section(report, section, patch[section], ctx)
        written.extend(new)
    return report, written


def _section(
    report: dict[str, Any], name: str, value: object, ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    if name == "embedded":
        raise InvalidReportError("embedded patches are not allowed")
    if name in {"whiff", "integrity"}:
        raise ConflictError(f"cannot patch protected section `{name}`")
    if not isinstance(value, dict):
        raise InvalidReportError(f"patch section `{name}` must be a dict")
    if name == "diagnostics":
        return _diagnostics(report, value, ctx)
    if name == "security":
        return _security(report, value, ctx)
    if name == "content":
        return _tree(report, ["content"], value, ctx)
    if name in _NAMESPACED:
        return _namespaced(report, name, value, ctx)
    if name in _TREE:
        return _tree(report, [name], value, ctx)
    raise InvalidReportError(f"unsupported patch section `{name}`")


def _diagnostics(
    report: dict[str, Any], value: dict[str, Any], ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    extra = [key for key in value if key != "warnings"]
    if extra:
        raise ConflictError(f"plugins may only add diagnostics.warnings (got {extra!r})")
    warnings = value.get("warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        raise InvalidReportError("diagnostics.warnings must be a list of strings")
    prefixed = [f"python:{ctx.plugin_id}: {item}" for item in warnings]
    existing = _get(report, ["diagnostics", "warnings"])
    current = (
        list(existing) if isinstance(existing, list) else ([] if existing is None else [existing])
    )
    return _put(report, ["diagnostics", "warnings"], current + prefixed), []


def _security(
    report: dict[str, Any], value: dict[str, Any], ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    blocked = [key for key in value if key in {"secrets", "personal_data"}]
    if blocked:
        raise ConflictError(f"cannot patch native security fields: {blocked!r}")
    risks = value.get("risks", None) if "risks" in value else None
    rest = {key: item for key, item in value.items() if key != "risks"}
    report, written = _append_risks(report, risks, ctx)
    report, more = _security_fields(report, rest)
    return report, written + more


def _append_risks(
    report: dict[str, Any], risks: object, ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    if risks is None:
        return report, []
    if not isinstance(risks, list):
        raise InvalidReportError("security.risks must be a list")
    stamped: list[dict[str, Any]] = []
    for risk in risks:
        _validate_risk(risk)
        assert isinstance(risk, dict)
        stamped.append({**risk, "source": f"python:{ctx.plugin_id}"})
    if not stamped:
        return report, []
    existing = _get(report, ["security", "risks"])
    current = (
        list(existing) if isinstance(existing, list) else ([] if existing is None else [existing])
    )
    return _put(report, ["security", "risks"], current + stamped), ["security.risks"]


def _validate_risk(risk: object) -> None:
    if not isinstance(risk, dict):
        raise InvalidReportError("each security.risks entry must be a dict")
    unknown = [key for key in risk if key not in _RISK_KEYS]
    if unknown:
        raise InvalidReportError(f"risk has unknown keys: {unknown!r}")
    kind = risk.get("kind")
    if not isinstance(kind, str) or not kind:
        raise InvalidReportError("risk.kind must be a non-empty string")
    if risk.get("category") not in _RISK_CATEGORIES:
        raise InvalidReportError(f"risk.category must be one of {sorted(_RISK_CATEGORIES)}")
    if risk.get("severity") not in _SEVERITIES:
        raise InvalidReportError(f"risk.severity must be one of {sorted(_SEVERITIES)}")
    detail = risk.get("detail")
    if detail is not None and not isinstance(detail, str):
        raise InvalidReportError("risk.detail must be a string")


def _security_fields(
    report: dict[str, Any], fields: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    written: list[str] = []
    for key in sorted(fields):
        path = ["security", key]
        dotted = ".".join(path)
        if not _has(report, path):
            report = _put(report, path, fields[key])
            written.append(dotted)
        elif _get(report, path) != fields[key]:
            raise ConflictError(f"cannot replace native `{dotted}`")
    return report, written


def _namespaced(
    report: dict[str, Any], section: str, value: dict[str, Any], ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    written: list[str] = []
    for key in sorted(value):
        path = [section, key]
        dotted = ".".join(path)
        if not _has(report, path):
            report = _put(report, path, value[key])
            written.extend(_leaf_paths(value[key], dotted))
        elif _get(report, path) == value[key]:
            continue
        elif ctx.mode == "override" and dotted in ctx.fields:
            report = _put(report, path, value[key])
            written.extend(_leaf_paths(value[key], dotted))
        else:
            raise ConflictError(f"namespace collision on `{dotted}`")
    return report, written


def _tree(
    report: dict[str, Any], prefix: list[str], value: dict[str, Any], ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    written: list[str] = []
    for key in sorted(value):
        report, new = _tree_key(report, prefix + [key], value[key], ctx)
        written.extend(new)
    return report, written


def _tree_key(
    report: dict[str, Any], path: list[str], value: object, ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    if path == ["content", "keywords"] and isinstance(value, list):
        existing = _get(report, path)
        current = (
            list(existing)
            if isinstance(existing, list)
            else ([] if existing is None else [existing])
        )
        merged = list(current)
        for item in value:
            if item not in merged:
                merged.append(item)
        if merged == current:
            return report, []
        return _put(report, path, merged), ["content.keywords"]

    if not _has(report, path):
        dotted = ".".join(path)
        return _put(report, path, value), _leaf_paths(value, dotted)

    existing = _get(report, path)
    if isinstance(existing, dict) and isinstance(value, dict):
        return _tree(report, path, value, ctx)
    if existing == value:
        return report, []
    return _replace_leaf(report, path, value, ctx)


def _replace_leaf(
    report: dict[str, Any], path: list[str], value: object, ctx: _Ctx
) -> tuple[dict[str, Any], list[str]]:
    dotted = ".".join(path)
    declared = ctx.mode == "override" and dotted in ctx.fields
    owned = any(item == dotted or item.startswith(dotted + ".") for item in ctx.owned)
    if declared:
        return _put(report, path, value), _leaf_paths(value, dotted)
    if owned:
        raise ConflictError(f"`{dotted}` was already set by another plugin")
    if ctx.mode == "override":
        raise ConflictError(f"override of `{dotted}` not declared in override_fields")
    if ctx.mode == "fallback" and path[0] == "content":
        return _put(report, path, value), _leaf_paths(value, dotted)
    return report, []


def _provenance(report: dict[str, Any], written: list[str], plugin_id: str) -> dict[str, Any]:
    if not written:
        return report
    existing = _get(report, ["diagnostics", "provenance"])
    current = dict(existing) if isinstance(existing, dict) else {}
    new = {path: f"python:{plugin_id}" for path in written}
    new.update(current)
    return _put(report, ["diagnostics", "provenance"], new)


def _leaf_paths(value: object, prefix: str) -> list[str]:
    if isinstance(value, dict) and value:
        out: list[str] = []
        for key in sorted(value):
            out.extend(_leaf_paths(value[key], f"{prefix}.{key}"))
        return out
    return [prefix]


def _has(report: dict[str, Any], path: list[str]) -> bool:
    current: object = report
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    return True


def _get(report: dict[str, Any], path: list[str]) -> object:
    current: object = report
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _put(report: dict[str, Any], path: list[str], value: object) -> dict[str, Any]:
    if len(path) == 1:
        updated = dict(report)
        updated[path[0]] = value
        return updated
    child = report.get(path[0])
    child_dict = dict(child) if isinstance(child, dict) else {}
    updated = dict(report)
    updated[path[0]] = _put(child_dict, path[1:], value)
    return updated
