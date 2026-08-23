from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

from core.models import Finding


_XML_TYPES = {"application/xml", "text/xml", "application/soap+xml"}
_MUTATING_METHODS = {"POST", "PUT", "PATCH"}


class XMLParserProbeScanner:
    """Opt-in XML parser posture probe using an internal entity only.

    No external entity URL, local file URI, parameter entity fetch, or recursive
    expansion is used. The probe is disabled by default because XML endpoints
    commonly use state-changing HTTP methods.
    """

    def __init__(self, requester, config):
        self.requester = requester
        layer = config.get("active_checks", {}).get("xml", {})
        self.enabled = bool(layer.get("enabled", False))
        self.max_requests = max(0, int(layer.get("max_requests", 3)))
        self.requests_sent = 0
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []

    @staticmethod
    def _token(url: str, method: str) -> str:
        digest = hashlib.sha256(f"{method}:{url}".encode("utf-8")).hexdigest()[:12]
        return f"wvs-xml-{digest}"

    @staticmethod
    def _declares_xml(surface) -> bool:
        content_types = {
            str(item).split(";", 1)[0].strip().lower()
            for item in (surface.meta.get("request_content_types", []) or [])
        }
        current = str(surface.meta.get("content_type", "")).split(";", 1)[0].strip().lower()
        if current:
            content_types.add(current)
        return bool(content_types.intersection(_XML_TYPES))

    def scan(self, api_engine) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            self.skipped.append(
                "Internal XML entity probe is disabled; enable active_checks.xml.enabled only for an explicitly approved XML endpoint."
            )
            return [], self._meta()
        if self.requester is None:
            self.skipped.append("No RequestManager was available for the XML probe.")
            return [], self._meta()

        findings: List[Finding] = []
        for surface in api_engine.get_endpoints():
            if self.requests_sent >= self.max_requests:
                self.skipped.append(
                    f"XML probe request budget reached ({self.max_requests})."
                )
                break
            method = str(surface.method or "").upper()
            if method not in _MUTATING_METHODS or not self._declares_xml(surface):
                continue
            token = self._token(surface.url, method)
            payload = (
                '<?xml version="1.0"?>\n'
                f'<!DOCTYPE wvs [<!ENTITY wvs_probe "{token}">]>\n'
                '<wvs><probe>&wvs_probe;</probe></wvs>'
            )
            try:
                self.requests_sent += 1
                response = self.requester.send(
                    method,
                    surface.url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    allow_redirects=False,
                    source="xml-internal-entity-probe",
                )
            except Exception as exc:
                self.errors.append(
                    {
                        "url": surface.url,
                        "method": method,
                        "error": str(exc),
                    }
                )
                continue
            if response is None:
                continue
            body = str(response.text or "")
            expanded = (
                token in body
                and "&wvs_probe;" not in body
                and "<!ENTITY" not in body
            )
            if not expanded:
                continue
            findings.append(
                Finding(
                    plugin="xml_parser_probe",
                    type="XML DTD Entity Processing",
                    title="XML Parser Expands an Internal DTD Entity",
                    category="xml-security",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    surface_id=f"xml-entity:{method}:{surface.url}",
                    url=surface.url,
                    evidence={
                        "method": method,
                        "status": response.status_code,
                        "content_type": "application/xml",
                        "internal_entity_expanded": True,
                    },
                    remediation=(
                        "Disable DTD and entity processing unless the application explicitly requires it. "
                        "Use parser settings that reject external entities, external DTDs, and recursive expansion."
                    ),
                    reproduction={
                        "method": method,
                        "url": surface.url,
                        "probe": "internal-entity-only",
                    },
                    verification_status="detected",
                    scanner_mode="full-authorized-opt-in",
                    reproducible=True,
                    target={"source": surface.source, "method": method},
                    notes=[
                        "Only an internal entity was used. The scanner did not request a local file, private address, metadata service, or external callback. This indicates risky DTD/entity processing, not confirmed external-entity data exfiltration."
                    ],
                )
            )
        return findings, self._meta()

    def _meta(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "requests_sent": self.requests_sent,
            "max_requests": self.max_requests,
            "errors": self.errors,
            "skipped": self.skipped,
        }
