from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from core.models import Finding
from core.redaction import fingerprint_secret, redact_text
from core.utils import logger, normalize_url


DEFAULT_PROBE_PATHS = [
    "/.env",
    "/.env.bak",
    "/.git/HEAD",
    "/backup.zip",
    "/debug/config.json",
]

SENSITIVE_PATTERNS = [
    (
        re.compile(
            r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*"
            r"[\"']?[^\"'\s]{4,}"
        ),
        "credential_assignment",
    ),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private_key_block"),
]


class DataExposureScanner:
    def __init__(self, requester, config):
        self.requester = requester
        self.config = config
        self.layer_config = config.get("passive_checks", {}).get("data_exposure", {})
        self.enabled = bool(self.layer_config.get("enabled", True))
        self.max_probe_paths = int(self.layer_config.get("max_probe_paths", 6))
        self.probe_paths = list(self.layer_config.get("probe_paths", DEFAULT_PROBE_PATHS))
        self.inspect_observed_urls = bool(
            self.layer_config.get("inspect_observed_urls", True)
        )
        self.errors: List[Dict[str, Any]] = []
        self.skipped: List[str] = []
        self.probed_urls: List[str] = []

    def scan(
        self, target: str, observed_urls: List[str]
    ) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.enabled:
            self.skipped.append("Data exposure checks are disabled by configuration.")
            return [], self._meta()

        findings: List[Finding] = []
        base_url = self._origin(target)
        probe_urls = [
            urljoin(base_url + "/", path.lstrip("/"))
            for path in self.probe_paths[: self.max_probe_paths]
        ]
        inventory = list(dict.fromkeys(probe_urls))
        if self.inspect_observed_urls:
            inventory.extend(
                url
                for url in dict.fromkeys(normalize_url(url) for url in observed_urls)
                if url.startswith(("http://", "https://"))
            )

        checked = set()
        for url in inventory:
            if url in checked:
                continue
            checked.add(url)
            snapshot = self._fetch(url)
            if not snapshot:
                continue
            findings.extend(self._check_exposed_files(snapshot))
            findings.extend(self._check_sensitive_indicators(snapshot))
        return findings, self._meta()

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _fetch(self, url: str) -> Dict[str, Any] | None:
        self.probed_urls.append(url)
        try:
            response = self.requester.send("GET", url)
        except Exception as exc:
            logger.error(f"Data exposure probe failed for {url}: {exc}")
            self.errors.append({"url": url, "error": str(exc)})
            return None
        if response is None:
            return None
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        return {
            "url": normalize_url(url),
            "status": response.status_code,
            "headers": headers,
            "content_type": headers.get("content-type", ""),
            # Raw response text is kept in memory only long enough to classify
            # the response. Persistence paths below always redact first.
            "text": response.text or "",
            "path": urlparse(url).path or "/",
        }

    def _check_exposed_files(self, snapshot: Dict[str, Any]) -> List[Finding]:
        path = snapshot["path"].lower()
        body = snapshot["text"]
        if snapshot["status"] != 200:
            return []
        matched_kind = None
        if path.endswith("/.git/head") and body.strip().startswith("ref:"):
            matched_kind = "git_head"
        elif path.endswith((".env", ".env.bak")) and "=" in body:
            matched_kind = "env_file"
        elif path.endswith((".zip", ".tar", ".bak", ".old")):
            matched_kind = "backup_file"
        elif path.endswith("config.json") and (
            "debug" in body.lower() or "password" in body.lower()
        ):
            matched_kind = "debug_config"
        if not matched_kind:
            return []
        return [
            Finding(
                plugin="data_exposure",
                type="Exposed File or Backup",
                title="Exposed Backup or Configuration Resource",
                category="data-exposure",
                severity="HIGH"
                if matched_kind in {"git_head", "env_file"}
                else "MEDIUM",
                confidence="HIGH",
                surface_id=f"data:{snapshot['url']}",
                url=snapshot["url"],
                evidence={
                    "matched_kind": matched_kind,
                    "path": snapshot["path"],
                    "content_type": snapshot["content_type"],
                    "response_excerpt": redact_text(
                        re.sub(r"\s+", " ", body).strip(), max_length=240
                    ),
                },
                remediation=(
                    "Remove backup/debug artifacts from the web root and block "
                    "direct access to configuration material."
                ),
                reproduction={"method": "GET", "url": snapshot["url"]},
                verification_status="detected",
                scanner_mode="data-exposure",
                reproducible=True,
                target={"source": "data-exposure"},
            )
        ]

    def _check_sensitive_indicators(self, snapshot: Dict[str, Any]) -> List[Finding]:
        body = snapshot["text"]
        if snapshot["status"] != 200 or not body:
            return []
        hits = []
        for pattern, signal in SENSITIVE_PATTERNS:
            match = pattern.search(body)
            if match:
                raw_match = match.group(0)
                hits.append(
                    {
                        "signal": signal,
                        "match_sha256": fingerprint_secret(raw_match),
                        "redacted_excerpt": redact_text(raw_match, max_length=120),
                    }
                )
        if not hits:
            return []
        return [
            Finding(
                plugin="data_exposure",
                type="Sensitive Data Indicator",
                title="Sensitive Data Indicator Exposed",
                category="data-exposure",
                severity="MEDIUM",
                confidence="HIGH",
                surface_id=f"sensitive:{snapshot['url']}",
                url=snapshot["url"],
                evidence={"path": snapshot["path"], "hits": hits},
                remediation=(
                    "Avoid returning secrets or credential-like values in HTTP "
                    "responses and debug endpoints."
                ),
                reproduction={"method": "GET", "url": snapshot["url"]},
                verification_status="detected",
                scanner_mode="data-exposure",
                reproducible=True,
                target={"source": "data-exposure"},
            )
        ]

    def _meta(self) -> Dict[str, Any]:
        return {
            "probed_urls": self.probed_urls[:20],
            "errors": self.errors,
            "skipped": self.skipped,
        }
