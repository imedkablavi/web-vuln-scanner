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
        "notes": "Bounded error/differential SQL injection checks; time-based probes remain disabled by default.",
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
        "activity": "active-opt-in",
        "default_enabled": False,
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Context-aware reflected HTML/XSS sink detector using a non-executable custom element; requires explicit experimental opt-in and scope.",
    },
    "lfi": {
        "maturity": "experimental",
        "activity": "active-opt-in",
        "default_enabled": False,
        "cwe": ["CWE-22", "CWE-98"],
        "owasp": ["A01:2021-Broken Access Control"],
        "notes": "Signature-gated path traversal/LFI checks; requires explicit experimental opt-in and scope.",
    },
    "cmd_injection": {
        "maturity": "experimental",
        "activity": "active-double-opt-in",
        "default_enabled": False,
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021-Injection"],
        "notes": "Bounded non-destructive echo-marker probe; requires experimental opt-in, explicit scope, and allow_command_probe=true.",
    },
    "open_redirect": {
        "maturity": "experimental",
        "activity": "active-opt-in",
        "default_enabled": False,
        "cwe": ["CWE-601"],
        "owasp": [],
        "notes": "Exact external Location-header verification against a .invalid marker without following the redirect; requires explicit opt-in and scope.",
    },
}


def get_plugin_catalog() -> Dict[str, Dict[str, Any]]:
    return deepcopy(PLUGIN_CATALOG)


def get_plugin_metadata(name: str) -> Dict[str, Any]:
    return deepcopy(PLUGIN_CATALOG.get(name, {"maturity": "unknown", "default_enabled": False}))
