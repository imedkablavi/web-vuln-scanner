from __future__ import annotations

import hashlib
import re
from typing import Any


REDACTED = "***redacted***"

# Keys that normally contain credential/session material. Metadata keys such as
# cookie_names, *_count and *_status are intentionally preserved.
_SENSITIVE_KEY = re.compile(
    r"(?:^|[-_])(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|"
    r"password|passwd|secret|api[-_]?key|access[-_]?token|refresh[-_]?token|"
    r"client[-_]?secret|session[-_]?token)(?:$|[-_])",
    re.IGNORECASE,
)
_SAFE_METADATA_KEY = re.compile(
    r"(?:_names?|_keys?|_count|_status|_state|_path|_id|_ids|_enabled)$",
    re.IGNORECASE,
)

# Match common credential assignments, including prefixed environment-style
# names such as DB_PASSWORD, PROD_API_KEY and APP_REFRESH_TOKEN. The prefix is
# retained for diagnostic value while the assigned value is never persisted.
_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"([A-Za-z0-9_]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|session[_-]?token|token))"
    r"(\s*[:=]\s*)([\"']?)([^\s,;\"'<>{}]+)(\3)"
)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})")
_BASIC = re.compile(r"(?i)\b(Basic\s+)([A-Za-z0-9+/=]{8,})")
_URL_USERINFO = re.compile(r"(://[^:/\s]+:)([^@/\s]+)(@)")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:token|access_token|refresh_token|api_key|apikey|secret|password)=)"
    r"([^&#\s]+)"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----",
    re.IGNORECASE | re.DOTALL,
)


def fingerprint_secret(value: str) -> str:
    """Return a non-reversible evidence fingerprint for a sensitive value."""
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()


def redact_text(value: str, *, max_length: int | None = None) -> str:
    """Redact common secret forms from arbitrary text before persistence."""
    text = str(value or "")
    text = _PRIVATE_KEY.sub(
        lambda match: f"-----BEGIN {match.group(1)}-----\n{REDACTED}\n-----END {match.group(1)}-----",
        text,
    )
    text = _ASSIGNMENT.sub(
        lambda match: (
            f"{match.group(1)}{match.group(2)}{match.group(3)}"
            f"{REDACTED}{match.group(5)}"
        ),
        text,
    )
    text = _BEARER.sub(lambda match: f"{match.group(1)}{REDACTED}", text)
    text = _BASIC.sub(lambda match: f"{match.group(1)}{REDACTED}", text)
    text = _URL_USERINFO.sub(
        lambda match: f"{match.group(1)}{REDACTED}{match.group(3)}", text
    )
    text = _QUERY_SECRET.sub(lambda match: f"{match.group(1)}{REDACTED}", text)
    if max_length is not None:
        return text[: max(0, int(max_length))]
    return text


def redact_structure(value: Any, *, key_hint: str = "") -> Any:
    """Recursively remove credential material from report/event structures."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            if _SENSITIVE_KEY.search(key_text) and not _SAFE_METADATA_KEY.search(
                key_text
            ):
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_structure(item, key_hint=key_text)
        return redacted
    if isinstance(value, list):
        return [redact_structure(item, key_hint=key_hint) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item, key_hint=key_hint) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value
