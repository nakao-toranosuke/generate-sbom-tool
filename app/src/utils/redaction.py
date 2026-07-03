from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SENSITIVE_KEYWORDS = (
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
    "credential",
    "apikey",
    "api_key",
)

_REDACTION_PATTERNS = [
    re.compile(r"(?i)(token|secret|password|passwd|authorization|api[_-]?key)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)(bearer)\s+([A-Za-z0-9._~+/\-]+=*)"),
    re.compile(r"(?i)(basic)\s+([A-Za-z0-9._~+/\-]+=*)"),
]


def redact_text(value: str) -> str:
    result = value
    for pattern in _REDACTION_PATTERNS:
        result = pattern.sub(lambda m: f"{m.group(1)}=<REDACTED>", result)
    return result


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_obj(v) for v in value)
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if any(word in key_str.lower() for word in SENSITIVE_KEYWORDS):
                redacted[key_str] = "<REDACTED>"
            else:
                redacted[key_str] = redact_obj(item)
        return redacted
    return value
