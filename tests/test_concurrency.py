from __future__ import annotations

import concurrent.futures
import threading
import time
from types import SimpleNamespace

from core.request_manager import RequestManager


def _config():
    return {
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 1,
            "threads": 8,
            "per_host_concurrency": 2,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": 0,
            "follow_redirects": False,
        },
        "scope": {"include_domains": ["example.com"], "allow_private": False},
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def test_per_host_concurrency_never_exceeds_configured_limit(monkeypatch):
    manager = RequestManager(_config())
    lock = threading.Lock()
    active = 0
    max_active = 0

    def fake_request(**kwargs):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=kwargs["url"])

    monkeypatch.setattr(manager.session, "request", fake_request)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(manager.send, "GET", "https://example.com/test") for _ in range(12)]
        for future in futures:
            assert future.result().status_code == 200

    assert max_active <= 2
