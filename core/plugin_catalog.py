from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


PLUGIN_CATALOG: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "maturity": "stable",
        "activity": "active",
        "default_enabled": True,
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Bounded SQL injection checks with time-based probes disabled by default.",
    },
    "business_logic": {
        "maturity": "stable",
        "activity": "active-auth-aware",
        "default_enabled": True,
        "cwe": ["CWE-639", "CWE-862"],
        "owasp": ["A01:2021-Broken Access Control"],
        "notes": "Actor-aware IDOR and access-control verification where configured.",
    },
    "xss_reflected": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Experimental reflected-input detector; disabled by the registry until verification quality is hardened.",
    },
    "lfi": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-22", "CWE-98"],
        "owasp": ["A01:2021-Broken Access Control"],
        "notes": "Experimental local-file/path traversal checks; disabled by the registry.",
    },
    "cmd_injection": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Experimental command-injection marker checks; disabled by the registry.",
    },
    "open_redirect": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-601"],
        "owasp": [],
        "notes": "Experimental redirect verification; disabled by the registry.",
    },
    "ssti": {
        "maturity": "experimental",
        "activity": "active-bounded",
        "default_enabled": False,
        "cwe": ["CWE-1336"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Marker-only arithmetic template-expression verification; no command execution, file reads, or sandbox escape probes.",
    },
    "crlf_injection": {
        "maturity": "experimental",
        "activity": "active-bounded",
        "default_enabled": False,
        "cwe": ["CWE-113"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Inert response-header canary verification only; no cookie, redirect, script, or cache-control injection.",
    },
}


def get_plugin_catalog() -> Dict[str, Dict[str, Any]]:
    return deepcopy(PLUGIN_CATALOG)


def get_plugin_metadata(name: str) -> Dict[str, Any]:
    return deepcopy(PLUGIN_CATALOG.get(name, {"maturity": "unknown", "default_enabled": False}))
