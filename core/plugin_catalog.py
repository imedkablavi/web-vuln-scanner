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
        "wstg": ["WSTG-INPV-05"],
        "notes": "Bounded SQL injection checks using error and differential response evidence. Timing probes stay disabled in release profiles.",
    },
    "business_logic": {
        "maturity": "stable",
        "activity": "active-auth-aware",
        "default_enabled": False,
        "cwe": ["CWE-639", "CWE-862"],
        "owasp": ["A01:2025-Broken Access Control"],
        "wstg": ["WSTG-ATHZ-04"],
        "notes": "Actor-aware object access and RBAC verification when test identities and policy data are configured.",
    },
    "xss_reflected": {
        "maturity": "stable",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-79"],
        "owasp": ["A05:2025-Injection"],
        "wstg": ["WSTG-INPV-01"],
        "notes": "Injects an inert custom HTML element and reports only when the response parser reconstructs that element. It does not claim JavaScript execution.",
    },
    "lfi": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-22", "CWE-98"],
        "owasp": ["A01:2025-Broken Access Control"],
        "wstg": ["WSTG-ATHZ-01", "WSTG-INPV-11"],
        "notes": "Path traversal/file inclusion verifier still needs stronger platform-specific fixtures before release use.",
    },
    "cmd_injection": {
        "maturity": "experimental",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-78"],
        "owasp": ["A05:2025-Injection"],
        "wstg": ["WSTG-INPV-12"],
        "notes": "Command injection remains experimental until execution proof can be separated reliably from ordinary reflection.",
    },
    "open_redirect": {
        "maturity": "stable",
        "activity": "active",
        "default_enabled": False,
        "cwe": ["CWE-601"],
        "owasp": [],
        "wstg": [],
        "notes": "Tests common redirect parameters with a reserved .invalid destination and requires an exact redirect Location match.",
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
