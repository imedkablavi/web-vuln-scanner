from __future__ import annotations

import re
from typing import Any, Dict, List

from core.models import Finding


_SENSITIVE_PATH_RE = re.compile(
    r"/(?:login|signin|account|profile|dashboard|admin|settings|billing|checkout|session)(?:/|$)",
    re.IGNORECASE,
)
_MAX_AGE_RE = re.compile(r"(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*(\d+)", re.IGNORECASE)


def check_cache_policy(snapshot: Dict[str, Any]) -> List[Finding]:
    """Report explicit caching of responses that are likely user-specific.

    The check intentionally avoids treating a missing Cache-Control header alone
    as a vulnerability. A finding requires an explicit shared/public cache
    directive or a positive cache lifetime on a response that also looks
    session-specific.
    """

    if int(snapshot.get("status", 0) or 0) != 200:
        return []
    headers = {str(k).lower(): str(v) for k, v in (snapshot.get("headers") or {}).items()}
    cache_control = headers.get("cache-control", "")
    if not cache_control:
        return []

    lowered = cache_control.lower()
    explicitly_public = "public" in {part.strip() for part in lowered.split(",")}
    shared_cache = "s-maxage=" in lowered
    positive_lifetime = any(int(match) > 0 for match in _MAX_AGE_RE.findall(lowered))
    protected = "no-store" in lowered or "private" in lowered
    if protected or not (explicitly_public or shared_cache or positive_lifetime):
        return []

    path = str(snapshot.get("path") or "/")
    set_cookies = list(snapshot.get("set_cookies") or [])
    has_session_cookie = bool(set_cookies)
    sensitive_path = bool(_SENSITIVE_PATH_RE.search(path))
    if not (has_session_cookie or sensitive_path):
        return []

    reasons = []
    if has_session_cookie:
        reasons.append("response sets a cookie")
    if sensitive_path:
        reasons.append("URL matches an account/session-oriented path")

    url = str(snapshot.get("url") or "")
    return [
        Finding(
            plugin="cache_posture",
            type="Sensitive Response Cache Policy",
            title="User-Specific Response Is Explicitly Cacheable",
            category="misconfiguration",
            severity="MEDIUM",
            confidence="MEDIUM",
            surface_id=f"cache:{url}",
            url=url,
            evidence={
                "cache_control": cache_control,
                "reasons": reasons,
                "set_cookie_names_present": has_session_cookie,
                "path": path,
            },
            remediation=(
                "Review whether this response can contain user-specific data. For sensitive authenticated "
                "responses, prefer Cache-Control: no-store or a deliberately private cache policy and ensure "
                "shared caches cannot reuse one user's representation for another user."
            ),
            reproduction={"method": "GET", "url": url},
            verification_status="suspected",
            scanner_mode="passive-web",
            reproducible=True,
            target={"source": "passive-web", "path": path},
            notes=[
                "This check requires an explicit cache lifetime/public directive; a missing Cache-Control header alone is not reported."
            ],
        )
    ]
