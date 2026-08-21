import hashlib
import logging
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse


_LOGGER_NAME = "WebVulnScanner"
_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logger = logging.getLogger(_LOGGER_NAME)
logger.addHandler(logging.NullHandler())


def setup_logger(level="INFO", log_file="scanner.log"):
    """Configure the scanner logger explicitly and idempotently.

    Importing ``core.utils`` never creates files. File logging is best-effort:
    an unwritable configured path must not prevent the scanner from starting,
    because console logging remains available.
    """
    configured = logging.getLogger(_LOGGER_NAME)
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    configured.setLevel(numeric_level)
    configured.propagate = False

    for handler in list(configured.handlers):
        configured.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    formatter = logging.Formatter(_LOG_FORMAT)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(numeric_level)
    stream_handler.setFormatter(formatter)
    configured.addHandler(stream_handler)

    if log_file:
        path = Path(log_file).expanduser()
        try:
            if path.parent != Path("."):
                path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(path, encoding="utf-8")
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            configured.addHandler(file_handler)
        except OSError as exc:
            configured.warning(
                "File logging disabled because %s is not writable: %s",
                path,
                exc,
            )

    return configured


def get_content_hash(content):
    """Generate a comparison hash after removing common dynamic values."""
    content = re.sub(r"\d{4}-\d{2}-\d{2}", "", content)
    content = re.sub(r"\d{2}:\d{2}:\d{2}", "", content)
    content = re.sub(r"[a-fA-F0-9]{32,}", "", content)
    # MD5 is used only as a non-security content fingerprint.
    return hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()


def normalize_url(url):
    """Normalize a URL for discovery deduplication by dropping query/fragment."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive values before config data is logged or reported."""
    clean = deepcopy(config)
    auth = clean.get("auth") or clean.get("scanner", {}).get("auth")
    if auth:
        for key in ("cookies", "headers", "password", "token", "api_key"):
            if isinstance(auth, dict) and key in auth:
                auth[key] = "***redacted***"
    return clean
