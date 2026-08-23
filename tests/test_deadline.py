import os
import time

import pytest

from core.deadline import DEADLINE_ENV, ScanDeadline
from core.scope import ScopePolicy


def config():
    return {
        "target": "https://example.com",
        "scope": {
            "include_domains": ["example.com"],
            "allow_private": False,
            "resolve_dns": False,
            "exclude_paths": [],
        },
        "crawler": {"max_url_length": 2048},
        "concurrency": {"global_timeout_seconds": 60},
    }


def test_expired_deadline_blocks_new_outbound_work(monkeypatch):
    monkeypatch.setenv(DEADLINE_ENV, str(time.monotonic() - 1))
    policy = ScopePolicy(config())
    decision = policy.evaluate("https://example.com/")
    assert decision.allowed is False
    assert "deadline" in decision.reason
    with pytest.raises(TimeoutError, match="deadline"):
        policy.require("https://example.com/")


def test_deadline_from_config_is_future_when_no_env(monkeypatch):
    monkeypatch.delenv(DEADLINE_ENV, raising=False)
    deadline = ScanDeadline.from_config(config())
    assert deadline.remaining() > 0
    assert deadline.expired() is False
