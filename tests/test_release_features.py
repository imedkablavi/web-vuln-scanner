from __future__ import annotations

import json

import pytest
import yaml

from core.plugin_catalog import PLUGIN_CATALOG, get_plugin_metadata
from core.sarif import convert_report, report_to_sarif
from core.scan_profiles import PROFILES, apply_profile, materialize_profile
from core.scanner import PluginRegistry


def test_plugin_catalog_covers_registry():
    assert set(PluginRegistry.available) <= set(PLUGIN_CATALOG)
    assert get_plugin_metadata("sqli")["maturity"] == "stable"
    assert get_plugin_metadata("cmd_injection")["maturity"] == "experimental"


def test_profiles_keep_experimental_plugins_disabled():
    config = {"scanner": {"plugins": {}}}
    for profile in PROFILES:
        rendered = apply_profile(config, profile)
        plugins = rendered["scanner"]["plugins"]
        for name in ("xss_reflected", "lfi", "cmd_injection", "open_redirect"):
            assert plugins[name]["enabled"] is False


def test_passive_profile_disables_active_plugins():
    rendered = apply_profile({"scanner": {}}, "passive")
    assert rendered["scanner"]["profile"] == "passive"
    assert rendered["scanner"]["plugins"]["sqli"]["enabled"] is False
    assert rendered["scanner"]["plugins"]["business_logic"]["enabled"] is False


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        apply_profile({"scanner": {}}, "anything-goes")


def test_materialize_profile_preserves_unrelated_config(tmp_path):
    source = tmp_path / "config.yaml"
    destination = tmp_path / "generated.yaml"
    source.write_text(
        yaml.safe_dump({"scanner": {"scope": {"include_domains": ["example.test"]}}, "logging": {"level": "INFO"}}),
        encoding="utf-8",
    )
    materialize_profile(source, "safe-active", destination)
    rendered = yaml.safe_load(destination.read_text(encoding="utf-8"))
    assert rendered["scanner"]["scope"]["include_domains"] == ["example.test"]
    assert rendered["logging"]["level"] == "INFO"
    assert rendered["scanner"]["plugins"]["sqli"]["enabled"] is True


def _sample_report():
    return {
        "scan_info": {
            "target": "https://example.test",
            "status": "completed",
            "target_classification": "remote",
        },
        "findings": [
            {
                "plugin": "web_posture",
                "type": "Missing Security Headers",
                "title": "Security Headers Missing",
                "category": "misconfiguration",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "verification_status": "detected",
                "scanner_mode": "passive-web",
                "url": "https://example.test/",
                "remediation": "Set baseline security headers.",
            }
        ],
    }


def test_sarif_conversion_shape():
    sarif = report_to_sarif(_sample_report())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Web Vulnerability Scanner"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["results"][0]["level"] == "warning"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.test/"


def test_sarif_file_conversion(tmp_path):
    source = tmp_path / "scan_report.json"
    source.write_text(json.dumps(_sample_report()), encoding="utf-8")
    output = convert_report(source)
    assert output.name == "scan_report.sarif"
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["runs"][0]["results"][0]["ruleId"].startswith("web-vuln-scanner/")
