from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

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


def test_wheel_contents(tmp_path):
    """Verify the wheel ships correct packages and excludes dev artifacts."""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()

    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "-w", str(wheel_dir)],
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"wheel build failed:\n{result.stderr}"

    whl_files = list(wheel_dir.glob("*.whl"))
    assert len(whl_files) == 1, f"expected 1 wheel, found {whl_files}"

    with zipfile.ZipFile(whl_files[0]) as zf:
        names = zf.namelist()

        # Required packages and modules
        for prefix in ("core/", "layers/", "plugins/", "workflows/", "main_v2.py"):
            assert any(n.startswith(prefix) for n in names), f"{prefix} missing from wheel"

        # CLI entry points
        ep_files = [n for n in names if n.endswith("/entry_points.txt")]
        assert len(ep_files) == 1, "entry_points.txt not found in dist-info"
        ep_content = zf.read(ep_files[0]).decode()
        for entry in ("web-vuln-scanner", "web-vuln-sarif", "web-vuln-profile"):
            assert entry in ep_content, f"{entry} missing from entry_points.txt"

        # Dev-only outputs must not ship
        for prefix in ("reports/", "smoke_out/", "benchmark_out/", "tests/"):
            assert not any(n.startswith(prefix) for n in names), f"{prefix} should not be in wheel"
