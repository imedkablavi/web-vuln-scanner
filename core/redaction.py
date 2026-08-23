from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

SENSITIVE_KEY_RE = re.compile(
    r"(^|[-_])(authorization|cookie|set-cookie|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|session|csrf)([-_]|$)",
    re.IGNORECASE,
)

_TEXT_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)(\b[A-Za-z0-9_]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token)\s*[:=]\s*[\"']?)[^\"'\s&;,]{3,}"
    ),
    re.compile(r"(?i)([?&](?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token)=)[^&#\s]+"),
    re.compile(r"(?i)(\b(?:session|sessionid|csrf)=)[^;\s,]+"),
]


def redact_text(value: str) -> str:
    text = str(value)
    text = _TEXT_PATTERNS[0].sub("Bearer ***redacted***", text)
    for pattern in _TEXT_PATTERNS[1:]:
        text = pattern.sub(lambda match: f"{match.group(1)}***redacted***", text)
    return text


def redact_value(value: Any) -> Any:
    """Recursively redact secret-bearing keys and common inline secret formats."""
    value = deepcopy(value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if SENSITIVE_KEY_RE.search(str(key)):
                result[key] = "***redacted***"
            else:
                result[key] = redact_value(item)
        return result
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value
