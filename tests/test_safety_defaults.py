import logging
import stat
from pathlib import Path

import yaml

from core.artifact_store import ArtifactStore
from core.browser_engine import BrowserEngine
from core.scan_profiles import apply_profile
from core.utils import setup_logger


ROOT = Path(__file__).resolve().parent.parent


def test_default_config_and_passive_profile_disable_active_behavior():
    config = yaml.safe_load(
        (ROOT / "config" / "default_config.yaml").read_text(encoding="utf-8")
    )
    scanner = config["scanner"]
    assert scanner["browser_enabled"] is False
    assert scanner["plugins"]["sqli"]["enabled"] is False
    assert scanner["plugins"]["business_logic"]["enabled"] is False
    assert scanner["browser"]["interactions"]["enabled"] is False
    assert scanner["browser"]["interactions"]["submit_forms"] is False

    passive = apply_profile(config, "passive")["scanner"]
    assert passive["plugins"]["sqli"]["enabled"] is False
    assert passive["plugins"]["business_logic"]["enabled"] is False
    assert passive["passive_checks"]["data_exposure"]["max_probe_paths"] == 0


def test_full_authorized_still_requires_explicit_generic_browser_interactions():
    config = yaml.safe_load(
        (ROOT / "config" / "default_config.yaml").read_text(encoding="utf-8")
    )
    scanner = apply_profile(config, "full-authorized")["scanner"]
    interactions = scanner["browser"]["interactions"]
    assert scanner["browser_enabled"] is True
    assert interactions["enabled"] is False
    assert interactions["submit_forms"] is False
    assert interactions["click_selectors"] == []

    browser = BrowserEngine(scanner)
    assert browser.interactions_enabled is False
    assert browser.submit_forms is False


def test_setup_logger_creates_file_only_when_explicitly_configured(tmp_path):
    log_path = tmp_path / "logs" / "scanner.log"
    configured = setup_logger("DEBUG", str(log_path))
    configured.debug("qa-log-check")
    for handler in configured.handlers:
        handler.flush()
    assert log_path.exists()
    assert "qa-log-check" in log_path.read_text(encoding="utf-8")

    # Avoid leaking handlers into unrelated tests.
    for handler in list(configured.handlers):
        configured.removeHandler(handler)
        handler.close()
    configured.addHandler(logging.NullHandler())


def test_artifact_store_uses_restrictive_permissions(tmp_path):
    store = ArtifactStore(str(tmp_path / "artifacts"))
    reference = store.write_json("session", "actor-state", {"token": "redacted"})

    directory_mode = stat.S_IMODE((tmp_path / "artifacts").stat().st_mode)
    kind_mode = stat.S_IMODE((tmp_path / "artifacts" / "session").stat().st_mode)
    file_mode = stat.S_IMODE(Path(reference.path).stat().st_mode)

    assert directory_mode & 0o077 == 0
    assert kind_mode & 0o077 == 0
    assert file_mode & 0o077 == 0
