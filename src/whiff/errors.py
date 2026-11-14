"""Public exceptions.

IO failures subclass both :class:`WhiffError` and the matching builtin
(``FileNotFoundError`` or ``PermissionError``) so either handler catches them.
Messages for IO errors include the full path. Log the base name when paths
are sensitive.
"""

from __future__ import annotations

_SENSITIVE = {"bytes", "content", "binary"}


def _scrub(value: object) -> object:
    if isinstance(value, dict):
        return {key: _scrub(item) for key, item in value.items() if key not in _SENSITIVE}
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


class WhiffError(Exception):
    """Failure of a whole call. Problems inside a readable file are not errors.

    ``reason`` is a stable string (``enoent``, ``invalid_option``, …).
    ``details`` drops keys named ``bytes``, ``content``, or ``binary``.
    """

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        path: str | None = None,
        details: dict | None = None,
    ) -> None:
        self.reason = reason
        self.message = message
        self.path = path
        scrubbed = _scrub(details or {})
        self.details: dict = scrubbed if isinstance(scrubbed, dict) else {}
        super().__init__(self._format())

    def _format(self) -> str:
        base = f"{self.reason}: {self.message}"
        if self.path:
            return f"{base} (path: {self.path})"
        return base


class NotFoundError(WhiffError, FileNotFoundError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("enoent", message, path=path, details=details)


class AccessError(WhiffError, PermissionError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("eacces", message, path=path, details=details)


class InvalidOptionError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("invalid_option", message, path=path, details=details)


class UnsupportedInputError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("unsupported_input", message, path=path, details=details)


class NativeError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("native_error", message, path=path, details=details)


class OverloadedError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("overloaded", message, path=path, details=details)


class InvalidReportError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("invalid_report", message, path=path, details=details)


class ExtractorError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("extractor_error", message, path=path, details=details)


class AnalyzerError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("analyzer_error", message, path=path, details=details)


class WhiffTimeoutError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("timeout", message, path=path, details=details)


class ConflictError(WhiffError):
    def __init__(
        self, message: str, *, path: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__("conflict", message, path=path, details=details)


_BY_REASON: dict[str, type[WhiffError]] = {
    "enoent": NotFoundError,
    "eacces": AccessError,
    "invalid_option": InvalidOptionError,
    "unsupported_input": UnsupportedInputError,
    "native_error": NativeError,
    "overloaded": OverloadedError,
    "invalid_report": InvalidReportError,
    "extractor_error": ExtractorError,
    "analyzer_error": AnalyzerError,
    "timeout": WhiffTimeoutError,
    "conflict": ConflictError,
}


def error_for(
    reason: str,
    message: str,
    *,
    path: str | None = None,
    details: dict | None = None,
) -> WhiffError:
    cls = _BY_REASON.get(reason, NativeError)
    if cls is NativeError and reason != "native_error":
        return WhiffError(reason, message, path=path, details=details)
    return cls(message, path=path, details=details)
