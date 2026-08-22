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
    assert get_plugin_metadata("xss_reflected")["maturity"] == "stable"
    assert get_plugin_metadata("open_redirect")["maturity"] == "stable"
    assert get_plugin_metadata("cmd_injection")["maturity"] == "experimental"


def test_profiles_keep_experimental_plugins_disabled():
    config = {"scanner": {"plugins": {}}}
    for profile in PROFILES:
        rendered = apply_profile(config, profile)
        plugins = rendered["scanner"]["plugins"]
        for name in ("lfi", "cmd_injection"):
            assert plugins[name]["enabled"] is False


def test_passive_profile_disables_all_active_checks():
    rendered = apply_profile({"scanner": {}}, "passive")
    scanner = rendered["scanner"]
    assert scanner["profile"] == "passive"
    assert scanner["active_checks"]["web"]["enabled"] is False
    for name in ("sqli", "business_logic", "xss_reflected", "open_redirect", "lfi", "cmd_injection"):
        assert scanner["plugins"][name]["enabled"] is False


def test_safe_active_enables_bounded_hardened_checks():
    rendered = apply_profile({"scanner": {}}, "safe-active")
    scanner = rendered["scanner"]
    assert scanner["active_checks"]["web"]["enabled"] is True
    assert scanner["active_checks"]["web"]["ssti"] is True
    assert scanner["active_checks"]["web"]["crlf"] is True
    assert scanner["active_checks"]["web"]["trace"] is True
    assert scanner["plugins"]["sqli"]["enabled"] is True
    assert scanner["plugins"]["xss_reflected"]["enabled"] is True
    assert scanner["plugins"]["open_redirect"]["enabled"] is True
    assert scanner["request"]["follow_redirects"] is False


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        apply_profile({"scanner": {}}, "anything-goes")


def test_materialize_profile_preserves_unrelated_config(tmp_path):
    source = tmp_path / "config.yaml"
    destination = tmp_path / "generated.yaml"
    source.write_text(
        yaml.safe_dump(
            {
                "scanner": {"scope": {"include_domains": ["example.test"]}},
                "logging": {"level": "INFO"},
            }
        ),
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
    result = run["results"][0]
    assert result["level"] == "warning"
    location = result["locations"][0]["logicalLocations"][0]
    assert location["kind"] == "web-target"
    assert location["fullyQualifiedName"] == "https://example.test/"
    assert "physicalLocation" not in result["locations"][0]
    assert result["properties"]["targetUrl"] == "https://example.test/"


def test_sarif_file_conversion(tmp_path):
    source = tmp_path / "scan_report.json"
    source.write_text(json.dumps(_sample_report()), encoding="utf-8")
    output = convert_report(source)
    assert output.name == "scan_report.sarif"
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["runs"][0]["results"][0]["ruleId"].startswith(
        "web-vuln-scanner/"
    )


def test_sarif_does_not_copy_raw_evidence_secrets():
    secret = "SARIF-SUPERSECRET-123456789"
    report = _sample_report()
    report["findings"][0]["evidence"] = {"DB_PASSWORD": secret}
    report["findings"][0]["remediation"] = f"Rotate token={secret}"
    serialized = json.dumps(report_to_sarif(report))
    assert secret not in serialized
    assert "***redacted***" in serialized
