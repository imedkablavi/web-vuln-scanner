from __future__ import annotations

from copy import deepcopy
from typing import Dict

from core.request_manager import RequestManager


def requester_with_ephemeral_auth(requester, headers: Dict[str, str] | None = None, cookies: Dict[str, str] | None = None):
    """Clone RequestManager policy while replacing ambient auth material.

    This avoids requests.Session header/cookie merging from contaminating
    cross-actor and anonymous verification probes. Scope, timeout, retry,
    concurrency and request policy remain inherited from the original config.
    """
    config = deepcopy(requester.config)
    config["auth"] = {
        "headers": dict(headers or {}),
        "cookies": dict(cookies or {}),
    }
    if "auth_verification" in config:
        auth_verification = dict(config.get("auth_verification", {}) or {})
        auth_verification["enabled"] = False
        config["auth_verification"] = auth_verification

    clone = RequestManager(config)
    if getattr(requester, "event_bus", None) is not None:
        clone.attach_event_bus(requester.event_bus)
    return clone
