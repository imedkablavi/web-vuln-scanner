from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding
from core.utils import normalize_url


class CORSVerifier:
    """Verify arbitrary credentialed Origin reflection using two distinct origins.

    A single reflected Origin is insufficient evidence. The verifier requires two
    unrelated synthetic origins to be reflected exactly with credentials enabled.
    Wildcard ACAO with credentials is recorded as invalid posture but is not
    reported as verified credentialed cross-origin access because browsers reject
    that combination for credentialed reads.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        self.config = config
        layer = config.get("active_verification", {}).get("cors", {})
        self.enabled = bool(layer.get("enabled", True))
        self.max_urls = max(0, min(int(layer.get("max_urls", 10)), 25))
        origins = list(layer.get("origins", []))
        self.origins = origins[:2] if len(origins) >= 2 else [
            "https://cors-a.audit.invalid",
            "https://cors-b.audit.invalid",
        ]
        self.errors: List[Dict[str, Any]] = []
        self.observations: List[Dict[str, Any]] = []

    def scan(self, urls: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta(skipped="CORS verification disabled by configuration.")
        findings: List[Finding] = []
        seen = set()
        for raw_url in urls:
            if len(seen) >= self.max_urls:
                break
            url = normalize_url(raw_url)
            if not url.startswith(("http://", "https://")) or url in seen:
                continue
            seen.add(url)
            finding = self._verify_url(url)
            if finding is not None:
                findings.append(finding)
        return findings, self._meta()

    def _verify_url(self, url: str) -> Finding | None:
        results = []
        for origin in self.origins:
            try:
                response = self.requester.send("GET", url, headers={"Origin": origin})
            except Exception as exc:
                self.errors.append({"url": url, "origin": origin, "error": str(exc)})
                return None
            if response is None:
                return None
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
            results.append(
                {
                    "origin": origin,
                    "acao": acao,
                    "credentials": acac,
                    "status": response.status_code,
                    "exact_reflection": acao == origin,
                    "wildcard": acao == "*",
                }
            )
        self.observations.append({"url": url, "results": results})
        if len(results) != 2 or self.origins[0] == self.origins[1]:
            return None
        verified = all(item["exact_reflection"] and item["credentials"] for item in results)
        if not verified:
            return None
        host = urlparse(url).netloc
        return Finding(
            plugin="cors_verification",
            type="Credentialed Arbitrary-Origin CORS",
            title="CORS Reflects Arbitrary Origins with Credentials",
            category="misconfiguration",
            severity="MEDIUM",
            confidence="HIGH",
            surface_id=f"cors-verified:{url}",
            url=url,
            evidence={
                "origins_tested": list(self.origins),
                "responses": results,
                "proof": "two distinct untrusted origins were reflected exactly with Access-Control-Allow-Credentials: true",
            },
            remediation="Allow only explicitly trusted origins and avoid reflecting arbitrary Origin values when credentials are permitted.",
            reproduction={
                "method": "GET",
                "headers": {"Origin": "<two distinct synthetic origins>"},
                "request_count": 2,
            },
            verification_status="verified",
            scanner_mode="active-bounded",
            reproducible=True,
            target={"source": "cors-verification", "host": host},
        )

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "origins": list(self.origins),
            "observations": self.observations[:20],
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
