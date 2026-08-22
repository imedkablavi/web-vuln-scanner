from __future__ import annotations

import hashlib
from difflib import SequenceMatcher
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from core.models import Finding
from core.redaction import redact_text


_URL_PARAM_HINTS = {
    "url",
    "uri",
    "link",
    "target",
    "destination",
    "dest",
    "callback",
    "webhook",
    "endpoint",
    "proxy",
    "fetch",
    "remote",
    "source",
    "src",
    "image",
    "avatar",
    "feed",
    "load",
}


class ActiveWebProbeScanner:
    """Low-impact checks used by the safe-active and full-authorized profiles.

    The layer has explicit URL, parameter, and request caps. It never follows
    redirects and does not use external callbacks, command execution, file
    reads, private-network targets, or timing payloads.
    """

    def __init__(self, requester, config):
        self.requester = requester
        self.config = config
        self.layer_config = config.get("active_checks", {}).get("web", {})
        self.enabled = bool(self.layer_config.get("enabled", False))
        self.max_urls = max(0, int(self.layer_config.get("max_urls", 10)))
        self.max_params_per_url = max(
            0, int(self.layer_config.get("max_params_per_url", 3))
        )
        self.max_requests = max(0, int(self.layer_config.get("max_requests", 50)))
        self.enable_ssti = bool(self.layer_config.get("ssti", True))
        self.enable_crlf = bool(self.layer_config.get("crlf", True))
        self.enable_trace = bool(self.layer_config.get("trace", True))
        self.enable_ssrf = bool(self.layer_config.get("ssrf_same_origin", True))
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []
        self.checked_urls = 0
        self.checked_parameters = 0
        self.requests_sent = 0
        self._trace_origins: set[str] = set()
        self._reference_pages: Dict[str, str] = {}
        self._budget_notice_written = False

    def scan(self, snapshots: List[Dict[str, Any]]) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            return [], self._meta()

        findings: List[Finding] = []
        for snapshot in snapshots[: self.max_urls]:
            if not self._budget_available():
                break
            url = str(snapshot.get("url") or "")
            if not url:
                continue
            self.checked_urls += 1

            origin = self._origin(url)
            if self.enable_trace and origin and origin not in self._trace_origins:
                self._trace_origins.add(origin)
                finding = self._check_trace(origin)
                if finding:
                    findings.append(finding)

            parameters = self._query_params(url)[: self.max_params_per_url]
            for param, value in parameters:
                if not self._budget_available():
                    break
                self.checked_parameters += 1
                if self.enable_ssrf and self._looks_like_url_input(param, value):
                    finding = self._check_same_origin_ssrf(
                        url,
                        param,
                        str(snapshot.get("text") or ""),
                    )
                    if finding:
                        findings.append(finding)
                if self.enable_crlf and self._budget_available():
                    finding = self._check_crlf(url, param)
                    if finding:
                        findings.append(finding)
                if self.enable_ssti and self._remaining_requests() >= 2:
                    finding = self._check_ssti(
                        url,
                        param,
                        str(snapshot.get("text") or ""),
                    )
                    if finding:
                        findings.append(finding)
        return findings, self._meta()

    def _meta(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "checked_urls": self.checked_urls,
            "checked_parameters": self.checked_parameters,
            "max_params_per_url": self.max_params_per_url,
            "requests_sent": self.requests_sent,
            "max_requests": self.max_requests,
            "trace_origins_checked": len(self._trace_origins),
            "same_origin_references": len(self._reference_pages),
            "checks": {
                "ssti": self.enable_ssti,
                "crlf": self.enable_crlf,
                "trace": self.enable_trace,
                "ssrf_same_origin": self.enable_ssrf,
            },
            "errors": self.errors,
            "skipped": self.skipped,
        }

    def _remaining_requests(self) -> int:
        return max(0, self.max_requests - self.requests_sent)

    def _budget_available(self) -> bool:
        if self.requests_sent < self.max_requests:
            return True
        if not self._budget_notice_written:
            self.skipped.append(
                f"Active web request budget reached ({self.max_requests})."
            )
            self._budget_notice_written = True
        return False

    def _reserve_request(self) -> bool:
        if not self._budget_available():
            return False
        self.requests_sent += 1
        return True

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}/"

    @staticmethod
    def _token(*parts: str) -> str:
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
        return f"wvs-{digest}"

    @staticmethod
    def _query_params(url: str) -> list[tuple[str, str]]:
        seen: set[str] = set()
        result: list[tuple[str, str]] = []
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if name in seen:
                continue
            seen.add(name)
            result.append((name, value))
        return result

    @staticmethod
    def _looks_like_url_input(name: str, value: str) -> bool:
        lowered = str(name or "").strip().lower().replace("-", "_")
        pieces = {piece for piece in lowered.split("_") if piece}
        if lowered in _URL_PARAM_HINTS or pieces.intersection(_URL_PARAM_HINTS):
            return True
        return str(value or "").strip().lower().startswith(("http://", "https://"))

    @staticmethod
    def _replace_query_value(
        url: str,
        name: str,
        value: str,
    ) -> tuple[str, list[tuple[str, str]]]:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        updated: list[tuple[str, str]] = []
        for key, current in pairs:
            if key == name and not replaced:
                updated.append((key, value))
                replaced = True
            else:
                updated.append((key, current))
        if not replaced:
            updated.append((name, value))
        base_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.fragment)
        )
        return base_url, updated

    def _send_query_probe(self, url: str, param: str, payload: str):
        if not self._reserve_request():
            return None
        base_url, params = self._replace_query_value(url, param, payload)
        return self.requester.send(
            "GET",
            base_url,
            params=params,
            allow_redirects=False,
            source="safe-active-web",
        )

    def _same_origin_reference(self, origin: str) -> str:
        if origin in self._reference_pages:
            return self._reference_pages[origin]
        if not self._reserve_request():
            return ""
        try:
            response = self.requester.send(
                "GET",
                origin,
                allow_redirects=False,
                source="safe-active-ssrf-reference",
            )
        except Exception as exc:
            self.errors.append(
                {"url": origin, "check": "ssrf_same_origin_reference", "error": str(exc)}
            )
            self._reference_pages[origin] = ""
            return ""
        body = str(getattr(response, "text", "") or "") if response is not None else ""
        self._reference_pages[origin] = body
        return body

    @staticmethod
    def _similarity(left: str, right: str) -> float:
        left = " ".join(str(left or "").split())[:8000]
        right = " ".join(str(right or "").split())[:8000]
        if len(left) < 80 or len(right) < 80:
            return 0.0
        return SequenceMatcher(None, left, right).ratio()

    def _check_same_origin_ssrf(
        self,
        url: str,
        param: str,
        baseline_text: str,
    ) -> Finding | None:
        origin = self._origin(url)
        if not origin or self._remaining_requests() < 2:
            return None
        reference = self._same_origin_reference(origin)
        if len(" ".join(reference.split())) < 80 or not self._budget_available():
            return None
        try:
            response = self._send_query_probe(url, param, origin)
        except Exception as exc:
            self.errors.append(
                {"url": url, "parameter": param, "check": "ssrf_same_origin", "error": str(exc)}
            )
            return None
        if response is None:
            return None
        injected_body = str(response.text or "")
        reference_similarity = self._similarity(injected_body, reference)
        baseline_similarity = self._similarity(baseline_text, reference)
        if reference_similarity < 0.86 or baseline_similarity >= 0.72:
            return None
        if injected_body.strip() == origin.strip():
            return None
        return Finding(
            plugin="active_web_probe",
            type="Server-Side URL Fetch Behavior",
            title="Same-Origin URL Fetch Behavior Detected",
            category="ssrf",
            severity="MEDIUM",
            confidence="MEDIUM",
            surface_id=f"ssrf-same-origin:{url}:{param}",
            url=url,
            evidence={
                "parameter": param,
                "probe_target": "same-origin-root",
                "reference_similarity": round(reference_similarity, 3),
                "baseline_similarity": round(baseline_similarity, 3),
                "status": response.status_code,
                "response_excerpt": redact_text(injected_body, max_length=220),
            },
            remediation=(
                "Treat user-controlled URLs as untrusted. Resolve and validate the final destination, "
                "allow only required schemes and hosts, and block loopback, private, link-local, and "
                "metadata address ranges after every redirect and DNS resolution."
            ),
            reproduction={
                "method": "GET",
                "url": url,
                "param": param,
                "probe": "same-origin-root",
            },
            verification_status="detected",
            scanner_mode="safe-active-web",
            reproducible=True,
            target={"source": "safe-active-web", "parameter": param},
            notes=[
                "The response became strongly similar to a page fetched directly from the same authorized origin. "
                "No private IP, cloud metadata address, external callback, or redirect chain was used. This proves "
                "URL-fetch-like behavior, not reachability of internal networks."
            ],
        )

    def _check_crlf(self, url: str, param: str) -> Finding | None:
        token = self._token("crlf", url, param)
        header_name = "X-WVS-Canary"
        payload = f"probe\r\n{header_name}: {token}"
        try:
            response = self._send_query_probe(url, param, payload)
        except Exception as exc:
            self.errors.append(
                {"url": url, "parameter": param, "check": "crlf", "error": str(exc)}
            )
            return None
        if response is None:
            return None
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        if headers.get(header_name.lower()) != token:
            return None
        return Finding(
            plugin="active_web_probe",
            type="HTTP Response Header Injection",
            title="Response Header Injection Confirmed",
            category="injection",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"crlf:{url}:{param}",
            url=url,
            evidence={
                "parameter": param,
                "injected_header": header_name,
                "observed_header_value": token,
                "status": response.status_code,
            },
            remediation="Reject CR/LF characters in values that can reach response headers and build headers through framework-safe APIs.",
            reproduction={
                "method": "GET",
                "url": url,
                "param": param,
                "payload": payload,
            },
            verification_status="verified",
            scanner_mode="safe-active-web",
            reproducible=True,
            target={"source": "safe-active-web", "parameter": param},
            notes=[
                "The canary appeared as a separate response header; no cache or second-response payload was sent."
            ],
        )

    def _check_ssti(
        self,
        url: str,
        param: str,
        baseline_text: str,
    ) -> Finding | None:
        token = self._token("ssti", url, param)
        families = [
            ("double-curly", "{{13*17}}", "{{19*23}}", "221", "437"),
            ("dollar-expression", "${13*17}", "${19*23}", "221", "437"),
        ]
        for family, expression_a, expression_b, result_a, result_b in families:
            if self._remaining_requests() < 2:
                break
            payload_a = f"{token}-a-{expression_a}-end"
            payload_b = f"{token}-b-{expression_b}-end"
            expected_a = f"{token}-a-{result_a}-end"
            expected_b = f"{token}-b-{result_b}-end"
            try:
                response_a = self._send_query_probe(url, param, payload_a)
                response_b = self._send_query_probe(url, param, payload_b)
            except Exception as exc:
                self.errors.append(
                    {"url": url, "parameter": param, "check": "ssti", "error": str(exc)}
                )
                continue
            if response_a is None or response_b is None:
                continue
            body_a = response_a.text or ""
            body_b = response_b.text or ""
            verified = (
                expected_a in body_a
                and expected_b in body_b
                and payload_a not in body_a
                and payload_b not in body_b
                and expected_a not in baseline_text
                and expected_b not in baseline_text
            )
            if not verified:
                continue
            return Finding(
                plugin="active_web_probe",
                type="Server-Side Template Injection",
                title="Template Expression Evaluation Confirmed",
                category="injection",
                severity="HIGH",
                confidence="HIGH",
                surface_id=f"ssti:{url}:{param}",
                url=url,
                evidence={
                    "parameter": param,
                    "expression_family": family,
                    "expected_outputs": [expected_a, expected_b],
                    "statuses": [response_a.status_code, response_b.status_code],
                    "response_excerpt": redact_text(body_b, max_length=220),
                },
                remediation="Keep user-controlled values out of template expressions. Pass them as data through the template engine's normal escaping and sandboxing controls.",
                reproduction={
                    "method": "GET",
                    "url": url,
                    "param": param,
                    "payloads": [payload_a, payload_b],
                },
                verification_status="verified",
                scanner_mode="safe-active-web",
                reproducible=True,
                target={"source": "safe-active-web", "parameter": param},
                notes=[
                    "Two arithmetic canaries produced two distinct evaluated results; no file, process, network, or timing primitive was used."
                ],
            )
        return None

    def _check_trace(self, url: str) -> Finding | None:
        token = self._token("trace", url)
        header_name = "X-WVS-Trace-Canary"
        if not self._reserve_request():
            return None
        try:
            response = self.requester.send(
                "TRACE",
                url,
                headers={header_name: token},
                allow_redirects=False,
                source="safe-active-web",
            )
        except Exception as exc:
            self.errors.append({"url": url, "check": "trace", "error": str(exc)})
            return None
        if response is None or not 200 <= response.status_code < 300:
            return None
        body = response.text or ""
        if header_name.lower() not in body.lower() or token not in body:
            return None
        return Finding(
            plugin="active_web_probe",
            type="HTTP TRACE Enabled",
            title="TRACE Method Reflects Request Headers",
            category="misconfiguration",
            severity="LOW",
            confidence="HIGH",
            surface_id=f"trace:{url}",
            url=url,
            evidence={
                "status": response.status_code,
                "reflected_header": header_name,
                "canary": token,
            },
            remediation="Disable TRACE unless it is explicitly required and covered by a documented operational need.",
            reproduction={
                "method": "TRACE",
                "url": url,
                "headers": {header_name: token},
            },
            verification_status="detected",
            scanner_mode="safe-active-web",
            reproducible=True,
            target={"source": "safe-active-web"},
        )
