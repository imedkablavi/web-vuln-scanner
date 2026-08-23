from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from core.models import Finding


def _json_path(value: Any, path: str):
    current = value
    for part in [item for item in str(path).split(".") if item]:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class FileUploadVerifier:
    """Explicit opt-in upload/content-type verifier using a harmless HTML marker.

    The uploaded body contains no JavaScript. A finding requires the server to accept
    the upload, return a same-origin retrieval URL, and serve the marker back as
    `text/html`. The verifier does not attempt executable payloads or polyglots.
    """

    def __init__(self, requester, config: Dict[str, Any]):
        self.requester = requester
        layer = config.get("active_verification", {}).get("file_upload", {})
        self.layer = layer
        self.enabled = bool(layer.get("enabled", False))
        self.explicit_opt_in = bool(layer.get("explicit_opt_in", False))
        self.upload_url = str(layer.get("upload_url", "") or "")
        self.field_name = str(layer.get("field_name", "file") or "file")
        self.filename = str(layer.get("filename", "scanner-audit.html") or "scanner-audit.html")
        self.marker = str(layer.get("marker", "scanner-upload-canary") or "scanner-upload-canary")
        self.response_url_json_path = str(layer.get("response_url_json_path", "url") or "url")
        self.timeout = max(0.1, min(float(layer.get("timeout_seconds", 3)), 8.0))
        self.errors: List[Dict[str, Any]] = []

    def scan(self, upload_url: str = "") -> Tuple[List[Finding], Dict[str, Any]]:
        endpoint = upload_url or self.upload_url
        if not self.enabled:
            return [], self._meta("File-upload verification disabled.")
        if not self.explicit_opt_in:
            return [], self._meta("File-upload verification requires explicit_opt_in=true on a disposable/safe upload endpoint.")
        if not endpoint:
            return [], self._meta("File-upload verification requires an explicit upload_url.")

        boundary = "----WebVulnScannerAuditBoundary"
        html_body = f"<!doctype html><title>scanner upload canary</title><p>{self.marker}</p>"
        multipart = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{self.field_name}"; filename="{self.filename}"\r\n'
            "Content-Type: text/html\r\n\r\n"
            f"{html_body}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")

        try:
            upload_response = self.requester.send(
                "POST",
                endpoint,
                data=multipart,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "X-Scanner-Probe": "harmless-html-upload",
                },
                timeout=self.timeout,
                source="file_upload_verification",
            )
        except Exception as exc:
            self.errors.append({"url": endpoint, "phase": "upload", "error": str(exc)})
            return [], self._meta()

        if upload_response.status_code >= 400:
            return [], self._meta()

        try:
            payload = upload_response.json()
        except Exception:
            try:
                payload = json.loads(upload_response.text or "{}")
            except Exception:
                payload = {}

        returned = _json_path(payload, self.response_url_json_path)
        if not isinstance(returned, str) or not returned:
            return [], self._meta()

        retrieval_url = urljoin(endpoint, returned)
        if not self._same_origin(endpoint, retrieval_url):
            return [], self._meta("Upload retrieval URL was cross-origin; verifier refused to follow it.")

        try:
            retrieval = self.requester.send(
                "GET",
                retrieval_url,
                headers={"X-Scanner-Probe": "upload-retrieval"},
                timeout=self.timeout,
                source="file_upload_verification",
            )
        except Exception as exc:
            self.errors.append({"url": retrieval_url, "phase": "retrieval", "error": str(exc)})
            return [], self._meta()

        content_type = str(retrieval.headers.get("Content-Type", "") or "").lower()
        marker_present = self.marker in (retrieval.text or "")
        served_as_html = content_type.startswith("text/html")
        if not (retrieval.status_code < 400 and marker_present and served_as_html):
            return [], self._meta()

        finding = Finding(
            plugin="file_upload_verification",
            type="Active Content Upload Served Inline",
            title="Uploaded HTML Content Is Served Inline from the Application Origin",
            category="file-upload",
            severity="HIGH",
            confidence="HIGH",
            surface_id=f"upload-html:{endpoint}",
            url=endpoint,
            evidence={
                "upload_status": upload_response.status_code,
                "retrieval_status": retrieval.status_code,
                "same_origin_retrieval": True,
                "content_type": content_type.split(";", 1)[0],
                "marker_present": True,
                "javascript_payload_used": False,
            },
            remediation=(
                "Reject active-content extensions when unnecessary, store uploads outside the application origin, "
                "serve user files with safe download headers/content types, and apply allowlisted MIME/extension validation."
            ),
            reproduction={
                "upload_method": "POST",
                "retrieval_method": "GET",
                "request_count": 2,
                "payload_class": "harmless-static-html-marker",
            },
            verification_status="verified",
            scanner_mode="active-explicit-opt-in",
            reproducible=True,
            target={"source": "explicit-disposable-upload-endpoint"},
        )
        return [finding], self._meta()

    @staticmethod
    def _same_origin(left: str, right: str) -> bool:
        a = urlparse(left)
        b = urlparse(right)
        return a.scheme == b.scheme and a.netloc == b.netloc

    def _meta(self, skipped: str = "") -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "explicit_opt_in": self.explicit_opt_in,
            "upload_url_configured": bool(self.upload_url),
            "max_requests": 2,
            "payload_contains_javascript": False,
            "errors": self.errors,
            "skipped": [skipped] if skipped else [],
        }
