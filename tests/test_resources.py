import ast
from pathlib import Path

import yaml

from core.resources import materialize_runtime_config


ROOT = Path(__file__).resolve().parent.parent


def test_bundled_runtime_config_does_not_inject_fixture_policy():
    path = materialize_runtime_config()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    scanner = data["scanner"]

    assert scanner["rbac_matrix_file"] == ""
    assert scanner["workflows"]["directory"] == ""
    assert scanner["workflows"]["files"] == []
    assert scanner["workflows"]["enabled"] is False


def test_default_runtime_config_has_no_target_specific_fixture_data():
    config = yaml.safe_load(
        (ROOT / "config" / "default_config.yaml").read_text(encoding="utf-8")
    )
    scanner = config["scanner"]

    assert scanner["rbac_matrix_file"] == ""
    assert scanner["workflows"]["enabled"] is False
    assert scanner["workflows"]["directory"] == ""
    assert scanner["workflows"]["files"] == []

    for actor in scanner["auth_verification"]["actors"]:
        assert actor["enabled"] is False
        auth = actor.get("auth", {})
        for key in (
            "login_url",
            "browser_login_url",
            "token_url",
            "refresh_url",
            "verify_url",
        ):
            if key in auth:
                assert auth[key] == ""

    serialized = yaml.safe_dump(config, sort_keys=True).lower()
    assert "target.local" not in serialized
    assert "/auth_bypass" not in serialized
    assert "/workflow/documents" not in serialized


def test_production_runtime_does_not_import_test_or_smoke_modules():
    production_paths = [
        ROOT / "main_v2.py",
        ROOT / "core",
        ROOT / "layers",
        ROOT / "plugins",
        ROOT / "policies",
        ROOT / "workflows",
    ]
    violations = []
    for base in production_paths:
        files = [base] if base.is_file() else list(base.rglob("*.py"))
        for path in files:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    if name.split(".", 1)[0] in {"tests", "smoke"}:
                        violations.append(f"{path.relative_to(ROOT)} imports {name}")
    assert violations == []


def test_user_relative_policy_paths_are_resolved(tmp_path):
    policy = tmp_path / "rbac.yaml"
    workflow_dir = tmp_path / "workflows"
    workflow_dir.mkdir()
    policy.write_text("rbac_matrix: []\n", encoding="utf-8")

    config = {
        "scanner": {
            "profile": "passive",
            "scope": {"include_domains": [], "allow_private": False, "resolve_dns": True},
            "crawler": {"har_seed": {"enabled": False, "files": [], "max_entries": 10}},
            "concurrency": {"threads": 1, "per_host_concurrency": 1, "timeout": 5, "global_timeout_seconds": 30},
            "browser": {},
            "request": {},
            "active_checks": {"web": {}, "templates": {"files": []}, "xml": {}},
            "attack_policy": {"skip_parameters": [], "skip_parameter_patterns": []},
            "rbac_matrix_file": "rbac.yaml",
            "workflows": {"enabled": False, "directory": "workflows", "files": []},
        }
    }
    source = tmp_path / "scanner.yaml"
    source.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    path = materialize_runtime_config(str(source))
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    scanner = data["scanner"]

    assert scanner["rbac_matrix_file"] == str(policy.resolve())
    assert scanner["workflows"]["directory"] == str(workflow_dir.resolve())
