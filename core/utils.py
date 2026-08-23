import hashlib
import logging
import re
from typing import Any, Dict
from urllib.parse import urlparse

from core.redaction import redact_text, redact_value


class SecretRedactionFilter(logging.Filter):
    """Last-line defense against credentials reaching console or log files."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        redacted = redact_text(rendered)
        record.msg = redacted
        record.args = ()
        return True


# --- Logging Setup ---
def setup_logger(level="INFO", log_file="scanner.log"):
    handlers = [logging.FileHandler(log_file), logging.StreamHandler()]
    redaction_filter = SecretRedactionFilter()
    for handler in handlers:
        handler.addFilter(redaction_filter)
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    named_logger = logging.getLogger("WebVulnScanner")
    named_logger.addFilter(redaction_filter)
    return named_logger


logger = setup_logger()


# --- Content Hashing for Stability Checks ---
def get_content_hash(content):
    """Generate a stable content hash while ignoring common dynamic values."""
    content = re.sub(r"\d{4}-\d{2}-\d{2}", "", content)
    content = re.sub(r"\d{2}:\d{2}:\d{2}", "", content)
    content = re.sub(r"[a-fA-F0-9]{32,}", "", content)
    return hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()


def normalize_url(url):
    """Normalize URL by removing fragments and query parameters."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact credentials before logging or reporting."""
    return redact_value(config)
