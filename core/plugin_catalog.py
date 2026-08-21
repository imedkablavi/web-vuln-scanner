from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


PLUGIN_CATALOG: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "maturity": "stable",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-89"],
        "owasp": ["A05:2025-Injection"],
        "notes": (
            "Bounded SQL injection checks. Active testing is opt-in through an "
            "authorized scan profile; time-based probes remain disabled by default."
        ),
    },
    "business_logic": {
        "maturity": "stable",
        "activity": "active-auth-aware",
        "default_enabled": False,
        "cwe": ["CWE-639", "CWE-862"],
        "owasp": ["A01:2025-Broken Access Control"],
        "notes": (
            "Actor-aware IDOR and access-control verification where configured. "
            "Active testing is opt-in."
        ),
    },
    "xss_reflected": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-79"],
        "owasp": ["A05:2025-Injection"],
        "notes": (
            "Experimental reflected-input detector; disabled until browser/context "
            "verification quality is hardened."
        ),
    },
    "lfi": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-22", "CWE-98"],
        "owasp": ["A01:2025-Broken Access Control"],
        "notes": (
            "Experimental local-file/path traversal checks; disabled by the registry."
        ),
    },
    "cmd_injection": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-78"],
        "owasp": ["A05:2025-Injection"],
        "notes": (
            "Experimental command-injection marker checks; disabled by the registry."
        ),
    },
    "open_redirect": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-601"],
        "owasp": [],
        "notes": "Experimental redirect verification; disabled by the registry.",
    },
}


def get_plugin_catalog() -> Dict[str, Dict[str, Any]]:
    return deepcopy(PLUGIN_CATALOG)


def get_plugin_metadata(name: str) -> Dict[str, Any]:
    return deepcopy(
        PLUGIN_CATALOG.get(
            name,
            {"maturity": "unknown", "default_enabled": False},
        )
    )
