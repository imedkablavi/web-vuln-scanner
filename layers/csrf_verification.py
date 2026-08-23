from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding


class CSRFVerifier:
    """Explicit opt-in CSRF workflow verifier for a configured safe action.

    The verifier performs exactly two POST requests: one same-origin request with the
    configured CSRF token and one cross-site request with that token removed. It only
    reports when both requests satisfy the configured success marker.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("csrf", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.endpoint_url = str(layer.get("endpoint_url", "") or "")
        self.token_field = str(layer.get("token_field", "csrf_token") or "csrf_token")
        self.token_value = str(layer.get("token_value", "") or "")
        self.form_data = dict(layer.get("form_data", {}) or {})
        self.success_marker = str(layer.get("success_marker", "") or "")
        self.hostile_origin = str(layer.get("hostile_origin", "https://csrf-audit.invalid") or "")
        self.trusted_origin = str(layer.get("trusted_origin", "") or "")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 2)), 5.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self, endpoint_url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        endpoint = endpoint_url or self.endpoint_url
        if not self.enabled:
            return [], self._meta("CSRF verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("CSRF verification requires explicit_opt_in=true for a safe configured action.")
        if not endpoint or not self.token_value or not self.success_marker:
            return [], self._meta("CSRF verification requires endpoint_url, token_value, and success_marker.")

        trusted_origin = self.trusted_origin or self._origin(endpoint)
        baseline_data = dict(self.form_data)
        baseline_data[self.token_field] = self.token_value
        probe_data = dict(self.form_data)
        auth_cookies = dict(getattr(self.requester, "cookies", {}) or {})

        try:
            baseline = self.requester.send(
                "POST",
                endpoint,
                data=baseline_data,
                headers={
                    "Origin": trusted_origin,
                    "Referer": trusted_origin.rstrip("/") + "/",
                    "Sec-Fetch-Site": "same-origin",
                    "X-Scanner-Probe": "csrf-baseline",
                },
                cookies=auth_cookies,
                timeout=self.timeout,
                source="csrf_verification",
            )
            probe = self.requester.send(
                "POST",
                endpoint,
                data=probe_data,
                headers={
                    "Origin": self.hostile_origin,
                    "Referer": self.hostile_origin.rstrip("/") + "/",
                    "Sec-Fetch-Site": "cross-site",
                    "X-Scanner-Probe": "csrf-cross-site-without-token",
                },
                cookies=auth_cookies,
                timeout=self.timeout,
                source="csrf_verification",
            )
        except Exception as exc:
            self.errors.append({"url": endpoint, "error": str(exc)})
            return [], self._meta()

        baseline_ok = baseline.status_code < 400 and self.success_marker in (baseline.text or "")
        probe_ok = probe.status_code < 400 and self.success_marker in (probe.text or "")
        if not (baseline_ok and probe_ok):
            return [], self._meta()

        finding = Finding(
            plugin="csrf_verification",
            type="Cross-Site Request Forgery",
            title="State-Changing Workflow Accepts Cross-Site Request Without CSRF Token",
            category="access-control",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"csrf:{endpoint}",
            url=endpoint,
            evidence={
                "baseline_status": baseline.status_code,
                "cross_site_status": probe.status_code,
                "baseline_success_marker": True,
                "cross_site_success_marker": True,
                "csrf_token_omitted_in_probe": True,
                "cross_site_origin_used": True,
                "auth_cookies_reused": bool(auth_cookies),
                "auth_cookie_values_recorded": False,
            },
            remediation=(
                "Require a cryptographically strong per-session/per-request CSRF token for cookie-authenticated "
                "state changes and validate Origin/Referer as a defense-in-depth control. Use SameSite cookies appropriately."
            ),
            reproduction={
                "method": "POST",
                "request_count": 2,
                "baseline": "same-origin-with-token",
                "probe": "cross-site-without-token",
                "auth_cookie_values_recorded": False,
            },
            verification_status="verified",
            scanner_mode="workflow-bounded",
            reproducible=True,
            target={"source": "explicit-safe-csrf-workflow"},
        )
        return [finding], self._meta()

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "endpoint_configured": bool(self.endpoint_url),
            "max_requests": 2,
            "auth_cookie_values_recorded": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
