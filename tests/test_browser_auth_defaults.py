import os

from core.browser_auth_engine import BrowserAuthEngine


def test_browser_auth_sensitive_artifacts_are_opt_in(tmp_path):
    config = {
        "output": {"directory": str(tmp_path / "reports")},
        "browser": {},
        "scope": {"include_domains": [], "allow_private": True, "resolve_dns": False},
        "crawler": {"max_url_length": 2048},
    }
    engine = BrowserAuthEngine(config)
    ephemeral = engine._ephemeral_dir
    try:
        assert engine.capture_auth_trace is False
        assert engine.capture_auth_screenshots is False
        assert engine.retain_storage_state is False
        assert os.path.isdir(ephemeral)
    finally:
        engine.cleanup()
    assert not os.path.exists(ephemeral)
