"""Redaction for Python plugin patches.

Upstream whiff does not re-scan data added by plugins. With ``privacy="strict"``
(the default), each patch is scrubbed before it is merged. Patterns and
``[redacted:]`` markers follow whiff 0.8.0 ``src/text/sensitive.rs``. A private
key is redacted from its BEGIN line through its END line.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from whiff.errors import InvalidOptionError, InvalidReportError

_Check = Callable[[str], bool]

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY"
            r"(?: BLOCK)?-----(?:.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?"
            r"PRIVATE KEY(?: BLOCK)?-----)?",
            re.DOTALL,
        ),
        "always",
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "always"),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
        "always",
    ),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "always"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "always"),
    ("stripe_secret_key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}"), "always"),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "always"),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}"), "always"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "always",
    ),
    (
        "url_credentials",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^\s/]+"),
        "always",
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b[\w.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|"
            r"access[_-]?token|auth[_-]?token|client[_-]?secret)"
            r"[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{6,}"
        ),
        "not_placeholder",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        "always",
    ),
    (
        "phone",
        re.compile(
            r"(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)|\d{1,4})|\(\d{2,4}\))"
            r"[ .-]?\d{3,4}[ .-]?\d{3,4}\b"
        ),
        "always",
    ),
    (
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b"),
        "iban",
    ),
    ("payment_card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), "luhn"),
]

_PLACEHOLDERS = ("changeme", "xxxxxx", "password", "secret", "example", "redacted", "******")


def scrub_patch(patch: dict, mode: str) -> dict:
    if mode == "off":
        return patch
    if mode != "strict":
        raise InvalidOptionError("privacy must be 'strict' or 'off'")
    if _sensitive_key(patch):
        raise InvalidReportError("plugin patch key matches a sensitive pattern")
    walked = _walk(patch)
    if not isinstance(walked, dict):
        raise InvalidReportError("plugin patch must be an object")
    return walked


def scrub_string(text: str, mode: str) -> str:
    if mode == "off":
        return text
    if mode != "strict":
        raise InvalidOptionError("privacy must be 'strict' or 'off'")
    for kind, pattern, check in _PATTERNS:
        text = pattern.sub(lambda match, kind=kind, check=check: _replace(kind, check, match), text)
    return text


def _replace(kind: str, check: str, match: re.Match[str]) -> str:
    value = match.group(0)
    if _valid(check, value):
        return f"[redacted:{kind}]"
    return value


def _walk(value: object) -> object:
    if isinstance(value, dict):
        return {key: _walk(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_walk(item) for item in value]
    if isinstance(value, str):
        return scrub_string(value, "strict")
    return value


def _sensitive_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            (isinstance(key, str) and scrub_string(key, "strict") != key) or _sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_sensitive_key(item) for item in value)
    return False


def _valid(check: str, match: str) -> bool:
    if check == "always":
        return True
    if check == "luhn":
        return _luhn(match)
    if check == "iban":
        return _iban(match)
    if check == "not_placeholder":
        return not _placeholder(match)
    return False


def _placeholder(match: str) -> bool:
    value = match.split("=")[-1].split(":")[-1].strip("\"' ").lower()
    if value.startswith(("${", "<", "{{", "$", "%(")):
        return True
    return any(word in value for word in _PLACEHOLDERS)


def _luhn(match: str) -> bool:
    digits = [ord(char) - 48 for char in match if "0" <= char <= "9"]
    if len(digits) not in range(13, 20):
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


def _iban(match: str) -> bool:
    compact = re.sub(r"\s", "", match)
    if not 15 <= len(compact) <= 34:
        return False
    moved = compact[4:] + compact[:4]
    digits: list[int] = []
    for char in moved:
        if "A" <= char <= "Z":
            digits.extend(divmod(ord(char) - ord("A") + 10, 10))
        elif "0" <= char <= "9":
            digits.append(ord(char) - 48)
        else:
            return False
    remainder = 0
    for digit in digits:
        remainder = (remainder * 10 + digit) % 97
    return remainder == 1
