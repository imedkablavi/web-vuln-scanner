import logging
import hashlib
import re
from copy import deepcopy
from typing import Dict, Any
from urllib.parse import urlparse

# --- Logging Setup ---
def setup_logger(level="INFO", log_file="scanner.log"):
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("WebVulnScanner")

logger = setup_logger()

# --- Content Hashing for Stability Checks ---
def get_content_hash(content):
    """
    Generates a hash of the content, ignoring dynamic elements like timestamps or CSRF tokens.
    This is a simplified normalization.
    """
    # Remove potential dynamic content using regex
    # 1. Remove timestamps (simple heuristic)
    content = re.sub(r'\d{4}-\d{2}-\d{2}', '', content)
    content = re.sub(r'\d{2}:\d{2}:\d{2}', '', content)
    # 2. Remove potential CSRF tokens (hex strings of 32+ chars)
    content = re.sub(r'[a-fA-F0-9]{32,}', '', content)
    
    return hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()

def normalize_url(url):
    """Normalizes URL by removing fragments and sorting query params."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove sensitive information (tokens/passwords/cookies) before logging or reporting.
    """
    clean = deepcopy(config)
    auth = clean.get("auth") or clean.get("scanner", {}).get("auth")
    if auth:
        for key in ("cookies", "headers", "password", "token", "api_key"):
            if isinstance(auth, dict) and key in auth:
                auth[key] = "***redacted***"
    return clean
