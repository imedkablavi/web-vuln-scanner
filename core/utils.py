import hashlib
import logging
import re
from copy import deepcopy
from typing import Any, Dict
from urllib.parse import urlparse


SENSITIVE_KEY = re.compile(r"(password|passwd|token|authorization|cookie|set-cookie|api[-_]?key|secret|csrf)", re.IGNORECASE)
BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|authorization|cookie|set-cookie|api[-_]?key|secret|csrf)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
JWT_VALUE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def redact_text(value: Any) -> str:
    """Best-effort redaction for log strings and free-form diagnostic text."""

    text = str(value)
    text = BEARER_VALUE.sub("Bearer ***redacted***", text)
    text = JWT_VALUE.sub("***redacted-jwt***", text)
    text = SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}***redacted***", text)
    return text


def redact_sensitive_data(value: Any):
    """Recursively redact values whose keys are likely to contain authentication material."""

    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if SENSITIVE_KEY.search(str(key)):
                redacted[key] = "***redacted***"
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(record.getMessage())
            record.args = ()
        except Exception:
            return True
        return True


# --- Logging Setup ---
def setup_logger(level="INFO", log_file="scanner.log"):
    """Configure redacted logging without making a writable CWD mandatory."""

    stream_handler = logging.StreamHandler()
    handlers = [stream_handler]
    try:
        handlers.insert(0, logging.FileHandler(log_file))
    except OSError:
        # Containers, packaged CLIs, or read-only working directories may not
        # permit file creation. Logging must fail open to stderr, not crash the
        # scanner before scope/auth safeguards are initialized.
        pass

    redaction_filter = SecretRedactionFilter()
    for handler in handlers:
        handler.addFilter(redaction_filter)
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("WebVulnScanner")


logger = setup_logger()


# --- Content Hashing for Stability Checks ---
def get_content_hash(content):
    """Generate a normalized content hash for response comparison."""

    content = re.sub(r"\d{4}-\d{2}-\d{2}", "", content)
    content = re.sub(r"\d{2}:\d{2}:\d{2}", "", content)
    content = re.sub(r"[a-fA-F0-9]{32,}", "", content)
    return hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()


def normalize_url(url):
    """Normalize URL by dropping fragments/query values for deduplication."""

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep-copied, recursively redacted configuration."""

    clean = deepcopy(config)
    return redact_sensitive_data(clean)
