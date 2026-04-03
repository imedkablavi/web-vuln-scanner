from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from core.models import Finding


class DNSTLSScanner:
    def __init__(self, config):
        self.config = config
        self.layer_config = config.get("passive_checks", {}).get("dns_tls", {})
        self.enabled = bool(self.layer_config.get("enabled", True))
        self.timeout = float(self.layer_config.get("timeout", 3.0))
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []

    def scan(self, target: str) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            self.skipped.append("DNS/TLS checks are disabled by configuration.")
            return [], self._meta({}, {})
        parsed = urlparse(target)
        host = parsed.hostname or ""
        if not host:
            self.skipped.append("Target host could not be parsed for DNS/TLS checks.")
            return [], self._meta({}, {})

        dns_inventory = self._dns_inventory(host)
        tls_inventory = self._tls_inventory(parsed.scheme, host, parsed.port)
        findings: List[Finding] = []
        findings.extend(self._build_dns_findings(parsed, dns_inventory))
        findings.extend(self._build_tls_findings(parsed, tls_inventory))
        return findings, self._meta(dns_inventory, tls_inventory)

    def _dns_inventory(self, host: str) -> Dict[str, Any]:
        inventory: Dict[str, Any] = {"host": host, "addresses": [], "mode": "hostname"}
        try:
            ipaddress.ip_address(host)
            inventory["mode"] = "literal_ip"
            inventory["addresses"] = [host]
            return inventory
        except ValueError:
            pass
        if host in {"localhost"}:
            inventory["mode"] = "local_hostname"
        try:
            records = socket.getaddrinfo(host, None)
            addresses = sorted({entry[4][0] for entry in records if entry and entry[4]})
            inventory["addresses"] = addresses
        except Exception as exc:
            self.errors.append({"kind": "dns", "host": host, "error": str(exc)})
        return inventory

    def _tls_inventory(self, scheme: str, host: str, port: int | None) -> Dict[str, Any]:
        if scheme.lower() != "https":
            return {"enabled": False, "reason": "plaintext_http"}
        tls_inventory: Dict[str, Any] = {"enabled": True, "host": host, "port": port or 443}
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port or 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert()
                    tls_inventory["version"] = wrapped.version()
                    tls_inventory["cipher"] = wrapped.cipher()
                    tls_inventory["subject"] = cert.get("subject", [])
                    tls_inventory["issuer"] = cert.get("issuer", [])
                    tls_inventory["not_after"] = cert.get("notAfter")
        except Exception as exc:
            self.errors.append({"kind": "tls", "host": host, "error": str(exc)})
        return tls_inventory

    def _build_dns_findings(self, parsed, inventory: Dict[str, Any]) -> List[Finding]:
        if not inventory:
            return []
        if inventory.get("mode") == "literal_ip":
            title = "Literal IP Target"
            finding_type = "Literal IP Scope"
        else:
            title = "DNS Inventory"
            finding_type = "DNS Inventory"
        return [
            Finding(
                plugin="dns_tls",
                type=finding_type,
                title=title,
                category="dns",
                severity="INFO",
                confidence="HIGH",
                surface_id=f"dns:{parsed.netloc}",
                url=f"{parsed.scheme}://{parsed.netloc}",
                evidence=inventory,
                remediation="Track exposed DNS and IP inventory as part of attack-surface management.",
                reproduction={"kind": "dns_inventory", "host": inventory.get("host")},
                verification_status="informational",
                scanner_mode="external-passive",
                reproducible=True,
                target={"source": "dns-tls", "host": parsed.netloc},
            )
        ]

    def _build_tls_findings(self, parsed, inventory: Dict[str, Any]) -> List[Finding]:
        if not inventory:
            return []
        if not inventory.get("enabled"):
            return [
                Finding(
                    plugin="dns_tls",
                    type="HTTPS Not Enabled",
                    title="Target Served Over Plain HTTP",
                    category="tls-posture",
                    severity="LOW",
                    confidence="HIGH",
                    surface_id=f"tls:{parsed.netloc}",
                    url=f"{parsed.scheme}://{parsed.netloc}",
                    evidence=inventory,
                    remediation="Serve the target over HTTPS and redirect plaintext HTTP where appropriate.",
                    reproduction={"method": "GET", "url": f"{parsed.scheme}://{parsed.netloc}"},
                    verification_status="detected",
                    scanner_mode="external-passive",
                    reproducible=True,
                    target={"source": "dns-tls", "host": parsed.netloc},
                )
            ]

        findings = [
            Finding(
                plugin="dns_tls",
                type="TLS Inventory",
                title="TLS Posture Inventory",
                category="tls-posture",
                severity="INFO",
                confidence="HIGH",
                surface_id=f"tls:{parsed.netloc}",
                url=f"{parsed.scheme}://{parsed.netloc}",
                evidence=inventory,
                remediation="Review TLS versions, ciphers, and certificate metadata regularly.",
                reproduction={"kind": "tls_handshake", "host": inventory.get("host"), "port": inventory.get("port")},
                verification_status="informational",
                scanner_mode="external-passive",
                reproducible=True,
                target={"source": "dns-tls", "host": parsed.netloc},
            )
        ]
        not_after = inventory.get("not_after")
        if not_after:
            try:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expires - datetime.utcnow()).days
                if days_remaining < 14:
                    findings.append(
                        Finding(
                            plugin="dns_tls",
                            type="TLS Certificate Expiry Window",
                            title="TLS Certificate Expires Soon",
                            category="tls-posture",
                            severity="MEDIUM" if days_remaining < 7 else "LOW",
                            confidence="HIGH",
                            surface_id=f"tls:expiry:{parsed.netloc}",
                            url=f"{parsed.scheme}://{parsed.netloc}",
                            evidence={"not_after": not_after, "days_remaining": days_remaining},
                            remediation="Rotate or renew the TLS certificate before it expires.",
                            reproduction={"kind": "tls_handshake", "host": inventory.get("host"), "port": inventory.get("port")},
                            verification_status="detected",
                            scanner_mode="external-passive",
                            reproducible=True,
                            target={"source": "dns-tls", "host": parsed.netloc},
                        )
                    )
            except ValueError:
                self.errors.append({"kind": "tls", "host": inventory.get("host"), "error": f"unable_to_parse_not_after:{not_after}"})
        return findings

    def _meta(self, dns_inventory: Dict[str, Any], tls_inventory: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "dns_inventory": dns_inventory,
            "tls_inventory": tls_inventory,
            "errors": self.errors,
            "skipped": self.skipped,
        }
