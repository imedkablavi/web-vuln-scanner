from __future__ import annotations

import re
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding
from core.utils import logger, normalize_url
from layers.active_web_probes import ActiveWebProbeScanner


SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

VERBOSE_ERROR_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"exception in thread",
    r"stack trace",
    r"line \d+, in ",
    r"sqlstate",
    r"syntax error at or near",
]


class WebPostureScanner:
    def __init__(self, requester, config):
        self.requester = requester
        self.config = config
        self.layer_config = config.get("passive_checks", {}).get("web", {})
        self.enabled = bool(self.layer_config.get("enabled", True))
        self.max_urls = int(self.layer_config.get("max_urls", 25))
        self.origin_probe = self.layer_config.get("origin_probe", "https://audit.invalid")
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []
        self.snapshots: List[Dict[str, Any]] = []
        self.active_probe_meta: Dict[str, Any] = {}

    def scan(self, urls: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            self.skipped.append("Web posture checks are disabled in this configuration.")
            return [], self._meta()

        findings: List[Finding] = []
        inspected = 0
        for url in self._unique_urls(urls):
            if inspected >= self.max_urls:
                self.skipped.append(f"Stopped after {self.max_urls} URLs; raise passive_checks.web.max_urls to inspect more.")
                break
            inspected += 1
            snapshot = self._fetch_snapshot(url)
            if not snapshot:
                continue
            self.snapshots.append(snapshot)
            findings.extend(self._check_security_headers(snapshot))
            findings.extend(self._check_cookies(snapshot))
            findings.extend(self._check_redirects(snapshot))
            findings.extend(self._check_verbose_errors(snapshot))
            cors_finding = self._check_cors(url)
            if cors_finding:
                findings.append(cors_finding)

        active_probe_scanner = ActiveWebProbeScanner(self.requester, self.config)
        active_findings, self.active_probe_meta = active_probe_scanner.scan(self.snapshots)
        findings.extend(active_findings)
        if self.active_probe_meta.get("errors"):
            self.errors.extend(self.active_probe_meta["errors"])
        self.skipped.extend(self.active_probe_meta.get("skipped", []))
        return findings, self._meta()

    def _meta(self) -> Dict[str, Any]:
        return {
            "checked_urls": len(self.snapshots),
            "errors": self.errors,
            "skipped": self.skipped,
            "sampled_urls": [snapshot["url"] for snapshot in self.snapshots[:10]],
            "active_probes": self.active_probe_meta,
        }

    def _unique_urls(self, urls: List[str]) -> List[str]:
        seen = set()
        normalized_urls = []
        for raw_url in urls:
            if not raw_url:
                continue
            url = normalize_url(raw_url)
            if not url.startswith(("http://", "https://")):
                continue
            if url not in seen:
                seen.add(url)
                normalized_urls.append(url)
        return normalized_urls

    def _fetch_snapshot(self, url: str) -> Dict[str, Any] | None:
        try:
            response = self.requester.send("GET", url)
        except Exception as exc:
            logger.error(f"Web posture request failed for {url}: {exc}")
            self.errors.append({"url": url, "error": str(exc)})
            return None
        if response is None:
            self.errors.append({"url": url, "error": "empty_response"})
            return None
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        text = response.text or ""
        parsed = urlparse(url)
        return {
            "url": url,
            "status": response.status_code,
            "headers": headers,
            "text": text,
            "content_type": headers.get("content-type", ""),
            "location": headers.get("location", ""),
            "set_cookies": self._extract_set_cookie_values(response),
            "host": parsed.netloc,
            "path": parsed.path or "/",
        }

    def _extract_set_cookie_values(self, response) -> List[str]:
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            values = raw_headers.get_all("Set-Cookie")
            if values:
                return list(values)
        header = response.headers.get("Set-Cookie")
        return [header] if header else []

    def _check_security_headers(self, snapshot: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        headers = snapshot["headers"]
        missing = []
        for header_key, header_name in SECURITY_HEADERS.items():
            if header_key == "content-security-policy" and not snapshot["content_type"].startswith("text/html"):
                continue
            if header_key not in headers:
                missing.append(header_name)
        if snapshot["url"].startswith("https://") and "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")
        if not missing:
            return findings
        severity = "MEDIUM" if len(missing) >= 3 else "LOW"
        findings.append(
            Finding(
                plugin="web_posture",
                type="Missing Security Headers",
                title="Browser Security Headers Are Incomplete",
                category="misconfiguration",
                severity=severity,
                confidence="HIGH",
                surface_id=f"passive:{snapshot['url']}",
                url=snapshot["url"],
                evidence={
                    "missing_headers": missing,
                    "observed_headers": headers,
                    "status": snapshot["status"],
                },
                remediation="Set the missing headers at the application or edge layer, then verify the final response seen by clients.",
                reproduction={"method": "GET", "url": snapshot["url"]},
                verification_status="detected",
                scanner_mode="passive-web",
                reproducible=True,
                target={"source": "passive-web", "host": snapshot["host"], "path": snapshot["path"]},
            )
        )
        return findings

    def _check_cookies(self, snapshot: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for raw_cookie in snapshot["set_cookies"]:
            cookie = SimpleCookie()
            try:
                cookie.load(raw_cookie)
            except Exception:
                continue
            for morsel in cookie.values():
                missing_flags = []
                if not morsel["httponly"]:
                    missing_flags.append("HttpOnly")
                if not morsel["secure"]:
                    missing_flags.append("Secure")
                same_site = morsel["samesite"] or "unspecified"
                if same_site.lower() == "unspecified":
                    missing_flags.append("SameSite")
                if not missing_flags:
                    continue
                findings.append(
                    Finding(
                        plugin="web_posture",
                        type="Cookie Security Attributes Missing",
                        title="Cookie Is Missing Recommended Security Attributes",
                        category="misconfiguration",
                        severity="LOW" if snapshot["url"].startswith("http://") else "MEDIUM",
                        confidence="HIGH",
                        surface_id=f"cookie:{snapshot['url']}:{morsel.key}",
                        url=snapshot["url"],
                        evidence={
                            "cookie_name": morsel.key,
                            "missing_flags": missing_flags,
                            "same_site": same_site,
                            "set_cookie": raw_cookie,
                        },
                        remediation="Set HttpOnly, Secure, and an appropriate SameSite policy on session or sensitive cookies.",
                        reproduction={"method": "GET", "url": snapshot["url"]},
                        verification_status="detected",
                        scanner_mode="passive-web",
                        reproducible=True,
                        target={"source": "passive-web", "host": snapshot["host"], "path": snapshot["path"]},
                    )
                )
        return findings

    def _check_cors(self, url: str) -> Finding | None:
        try:
            response = self.requester.send("GET", url, headers={"Origin": self.origin_probe})
        except Exception as exc:
            self.errors.append({"url": url, "kind": "cors", "error": str(exc)})
            return None
        if response is None:
            return None
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"
        reflects_origin = acao == self.origin_probe
        wildcard_with_credentials = acao == "*" and acac
        if not (wildcard_with_credentials or (reflects_origin and acac)):
            return None
        return Finding(
            plugin="web_posture",
            type="Permissive CORS Policy",
            title="Credentialed CORS Accepts an Untrusted Origin",
            category="misconfiguration",
            severity="MEDIUM",
            confidence="HIGH",
            surface_id=f"cors:{normalize_url(url)}",
            url=normalize_url(url),
            evidence={
                "origin_probe": self.origin_probe,
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": headers.get("access-control-allow-credentials"),
                "status": response.status_code,
            },
            remediation="Allow only trusted origins when credentials are permitted, and avoid reflecting arbitrary Origin values.",
            reproduction={"method": "GET", "url": normalize_url(url), "headers": {"Origin": self.origin_probe}},
            verification_status="detected",
            scanner_mode="passive-web",
            reproducible=True,
            target={"source": "passive-web"},
        )

    def _check_redirects(self, snapshot: Dict[str, Any]) -> List[Finding]:
        if snapshot["status"] not in {301, 302, 303, 307, 308} or not snapshot["location"]:
            return []
        parsed_current = urlparse(snapshot["url"])
        parsed_target = urlparse(snapshot["location"])
        if not parsed_target.scheme:
            return []
        if parsed_current.scheme == "https" and parsed_target.scheme == "http":
            title = "HTTPS Request Redirects to HTTP"
            severity = "MEDIUM"
        elif parsed_target.netloc and parsed_target.netloc != parsed_current.netloc:
            title = "Response Redirects to an External Host"
            severity = "LOW"
        else:
            return []
        return [
            Finding(
                plugin="web_posture",
                type="Redirect Posture Observation",
                title=title,
                category="misconfiguration",
                severity=severity,
                confidence="HIGH",
                surface_id=f"redirect:{snapshot['url']}",
                url=snapshot["url"],
                evidence={
                    "status": snapshot["status"],
                    "location": snapshot["location"],
                },
                remediation="Confirm that the redirect is intentional. Remove downgrade redirects and restrict external destinations where users can influence the target.",
                reproduction={"method": "GET", "url": snapshot["url"]},
                verification_status="detected",
                scanner_mode="passive-web",
                reproducible=True,
                target={"source": "passive-web", "host": snapshot["host"], "path": snapshot["path"]},
            )
        ]

    def _check_verbose_errors(self, snapshot: Dict[str, Any]) -> List[Finding]:
        body = snapshot["text"] or ""
        if snapshot["status"] < 500:
            return []
        matched = []
        lowered_body = body.lower()
        for pattern in VERBOSE_ERROR_PATTERNS:
            if re.search(pattern, lowered_body, re.IGNORECASE):
                matched.append(pattern)
        if not matched:
            return []
        return [
            Finding(
                plugin="web_posture",
                type="Verbose Error Disclosure",
                title="Server Error Reveals Internal Details",
                category="misconfiguration",
                severity="MEDIUM",
                confidence="HIGH",
                surface_id=f"verbose:{snapshot['url']}",
                url=snapshot["url"],
                evidence={
                    "status": snapshot["status"],
                    "matched_patterns": matched,
                    "response_excerpt": re.sub(r"\s+", " ", body).strip()[:240],
                },
                remediation="Return a generic error to the client and keep stack traces, SQL errors, and framework diagnostics in server-side logs.",
                reproduction={"method": "GET", "url": snapshot["url"]},
                verification_status="detected",
                scanner_mode="passive-web",
                reproducible=True,
                target={"source": "passive-web", "host": snapshot["host"], "path": snapshot["path"]},
            )
        ]
