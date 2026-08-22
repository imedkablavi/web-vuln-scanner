from pathlib import Path

import yaml

from core.resources import materialize_runtime_config


def test_bundled_runtime_config_does_not_inject_fixture_policy():
    path = materialize_runtime_config()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    scanner = data["scanner"]

    assert scanner["rbac_matrix_file"] == ""
    assert scanner["workflows"]["directory"] == ""
    assert scanner["workflows"]["files"] == []
    assert scanner["workflows"]["enabled"] is False


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
