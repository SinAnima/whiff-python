"""Validate public options before any native call.

Each entry point has its own allow-list, so an option that a function would
ignore is rejected instead of being dropped.
"""

from __future__ import annotations

from typing import Any

from whiff.errors import InvalidOptionError

# Mirrors LIMIT_CAPS in native/src/lib.rs. A test compares both.
LIMIT_CAPS: dict[str, int] = {
    "max_read_bytes": 4 * 1024 * 1024 * 1024,
    "max_decompressed_bytes": 4 * 1024 * 1024 * 1024,
    "max_depth": 8,
    "max_children": 500,
    "file_timeout_ms": 600_000,
    "extractor_timeout_ms": 600_000,
    "max_text_bytes": 64 * 1024 * 1024,
    "hash_max_bytes": 4 * 1024 * 1024 * 1024,
    "max_parse_bytes": 256 * 1024 * 1024,
}

_NONZERO = {
    "max_read_bytes",
    "max_decompressed_bytes",
    "file_timeout_ms",
    "extractor_timeout_ms",
}

_NATIVE = {
    "profile",
    "hashes",
    "privacy",
    "only",
    "skip",
    "format",
    "provenance",
    "limits",
}
_PIPELINE = {
    "extractors",
    "analyzers",
    "mode",
    "strict",
    "plugin_timeout_ms",
    "override_fields",
}

_ALLOWED = {
    "path": _NATIVE | _PIPELINE | {"stage"},
    "bytes": _NATIVE | _PIPELINE | {"name", "filename", "mime"},
    "llm_path": _NATIVE | {"tokens", "stage"},
    "llm_bytes": _NATIVE | {"tokens", "name", "filename"},
    "extract_many": _NATIVE | _PIPELINE | {"stage", "max_concurrency", "on_error", "timeout"},
}

_PROFILES = ("minimal", "standard", "full", "llm")
_PRIVACY = ("strict", "off")
_MODES = ("fallback", "augment", "override")
_STAGES = ("never", "local")
_HASHES = ("sha256", "blake3")

_DEFAULTS = {
    "profile": "standard",
    "privacy": "strict",
    "mode": "fallback",
    "strict": False,
    "plugin_timeout_ms": 5_000,
    "provenance": False,
    "tokens": 800,
    "stage": "never",
}


def validate(opts: dict[str, Any], entry: str) -> dict[str, Any]:
    """Return normalized options for ``entry`` or raise :class:`InvalidOptionError`."""
    allowed = _ALLOWED[entry]
    unknown = sorted(key for key in opts if key not in allowed)
    if unknown:
        raise InvalidOptionError(
            f"unknown option(s): {unknown}",
            details={"unknown": unknown},
        )
    if "name" in opts and "filename" in opts:
        raise InvalidOptionError("pass either name or filename, not both")

    normalized = dict(_DEFAULTS)
    for key, value in opts.items():
        normalized[key] = _one(key, value)
    return normalized


def native_payload(opts: dict[str, Any], *, include_tokens: bool) -> dict[str, Any]:
    """JSON-ready native options. Defaults that match upstream are omitted."""
    payload: dict[str, Any] = {}
    if opts.get("profile") not in (None, "standard"):
        payload["profile"] = opts["profile"]
    if "hashes" in opts and opts["hashes"] is not None:
        payload["hashes"] = opts["hashes"]
    if opts.get("privacy") not in (None, "strict"):
        payload["privacy"] = opts["privacy"]
    for key in ("only", "skip", "format"):
        if key in opts and opts[key] is not None:
            payload[key] = opts[key]
    if opts.get("provenance"):
        payload["provenance"] = True
    if opts.get("limits"):
        payload["limits"] = opts["limits"]
    if include_tokens and "tokens" in opts:
        payload["tokens"] = opts["tokens"]
    return payload


def _one(key: str, value: Any) -> Any:
    if key == "profile":
        return _choice(key, value, _PROFILES)
    if key == "privacy":
        return _choice(key, value, _PRIVACY)
    if key == "mode":
        return _choice(key, value, _MODES)
    if key == "stage":
        return _choice(key, value, _STAGES)
    if key == "on_error":
        return _choice(key, value, ("collect", "halt"))
    if key == "hashes":
        return _hashes(value)
    if key in {"only", "skip"}:
        return _strings(key, value, "be a list of extractor id strings")
    if key == "override_fields":
        return _paths(value)
    if key in {"format", "name", "filename", "mime"}:
        if isinstance(value, str) and value:
            return value
        raise InvalidOptionError(f"{key} must be a non-empty string, got: {value!r}")
    if key in {"provenance", "strict"}:
        if isinstance(value, bool):
            return value
        raise InvalidOptionError(f"{key} must be a boolean, got: {value!r}")
    if key == "tokens":
        return _int_range(key, value, 1, 100_000)
    if key == "plugin_timeout_ms":
        return _int_range(key, value, 1, 600_000)
    if key == "max_concurrency":
        return _int_range(key, value, 1, 128)
    if key == "timeout":
        if value is None:
            return None
        return _int_range(key, value, 1, 3_600_000, extra=" or None")
    if key == "limits":
        return _limits(value)
    if key in {"extractors", "analyzers"}:
        return _plugins(key, value)
    raise InvalidOptionError(f"unknown option(s): [{key!r}]")


def _choice(key: str, value: Any, allowed: tuple[str, ...]) -> str:
    if isinstance(value, str) and value in allowed:
        return value
    raise InvalidOptionError(f"{key} must be one of {list(allowed)}, got: {value!r}")


def _hashes(value: Any) -> str | list[str]:
    if isinstance(value, str) and value in {"all", "none"}:
        return value
    if isinstance(value, (list, tuple)) and value and all(item in _HASHES for item in value):
        seen: list[str] = []
        for item in value:
            if item not in seen:
                seen.append(item)
        return seen
    raise InvalidOptionError(
        f"hashes must be 'all', 'none', or a non-empty list of 'sha256' / 'blake3', got: {value!r}"
    )


def _strings(key: str, value: Any, expectation: str) -> list[str]:
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) and item for item in value):
        return list(value)
    raise InvalidOptionError(f"{key} must {expectation}, got: {value!r}")


def _paths(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)) and all(_dotted(item) for item in value):
        return list(value)
    raise InvalidOptionError(
        f'override_fields must be a list of dotted paths such as "content.title", got: {value!r}'
    )


def _dotted(value: object) -> bool:
    if not isinstance(value, str) or "." not in value:
        return False
    parts = value.split(".")
    return len(parts) >= 2 and all(parts)


def _int_range(key: str, value: Any, low: int, high: int, extra: str = "") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise InvalidOptionError(
            f"{key} must be an integer in {low}..{high}{extra}, got: {value!r}"
        )
    return value


def _limits(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise InvalidOptionError(f"limits must be a dict, got: {value!r}")
    unknown = sorted(key for key in value if key not in LIMIT_CAPS)
    if unknown:
        raise InvalidOptionError(f"unknown limit key(s): {unknown}")
    out: dict[str, int] = {}
    for key, item in value.items():
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise InvalidOptionError(f"{key} must be a non-negative integer, got: {item!r}")
        if item == 0 and key in _NONZERO:
            raise InvalidOptionError(f"{key} must be greater than 0")
        cap = LIMIT_CAPS[key]
        if item > cap:
            raise InvalidOptionError(f"{key} exceeds cap {cap}")
        out[key] = item
    return out


def _plugins(key: str, value: Any) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise InvalidOptionError(f"{key} must be a list")
    needed = ("id", "supports", "extract") if key == "extractors" else ("id", "analyze")
    bad = [item for item in value if any(not hasattr(item, attr) for attr in needed)]
    if bad:
        names = ", ".join(needed)
        raise InvalidOptionError(
            f"{key} must provide {names}: {bad!r}",
            details={"invalid": [repr(item) for item in bad]},
        )
    return list(value)
