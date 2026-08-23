from pathlib import Path

import pytest
import yaml

from core.cli import (
    _apply_checkpoint_override,
    _apply_har_seed_override,
    _print_scan_help,
)
from core.config_validation import validate_config


def write_runtime(path: Path):
    path.write_text(
        yaml.safe_dump(
            {
                "scanner": {
                    "target": "https://example.test/",
                    "profile": "safe-active",
                    "checkpoint": {
                        "enabled": False,
                        "path": "",
                        "resume": False,
                        "flush_every": 10,
                        "keep_completed": False,
                    },
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_checkpoint_override_only_mutates_materialized_runtime_config(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime.yaml"
    write_runtime(runtime)
    monkeypatch.chdir(tmp_path)

    _apply_checkpoint_override(runtime, checkpoint_path="state/resume.json")
    config = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    checkpoint = config["scanner"]["checkpoint"]
    assert checkpoint["enabled"] is True
    assert checkpoint["resume"] is False
    assert checkpoint["path"] == str((tmp_path / "state/resume.json").resolve())
    assert checkpoint["flush_every"] == 10


def test_resume_override_sets_resume_mode(tmp_path):
    runtime = tmp_path / "runtime.yaml"
    write_runtime(runtime)
    state = tmp_path / "resume.json"

    _apply_checkpoint_override(runtime, resume_path=str(state))
    config = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    checkpoint = config["scanner"]["checkpoint"]
    assert checkpoint["enabled"] is True
    assert checkpoint["resume"] is True
    assert checkpoint["path"] == str(state)


def test_checkpoint_and_resume_are_mutually_exclusive(tmp_path):
    runtime = tmp_path / "runtime.yaml"
    write_runtime(runtime)
    with pytest.raises(SystemExit, match="mutually exclusive"):
        _apply_checkpoint_override(
            runtime,
            checkpoint_path=str(tmp_path / "a.json"),
            resume_path=str(tmp_path / "b.json"),
        )


def test_checkpoint_validation_rejects_invalid_resume_configuration():
    with pytest.raises(ValueError, match="resume requires"):
        validate_config(
            {
                "scanner": {
                    "checkpoint": {
                        "enabled": False,
                        "path": "resume.json",
                        "resume": True,
                    }
                }
            }
        )


def test_har_seed_override_adds_absolute_existing_file_without_enabling_active_tests(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime.yaml"
    write_runtime(runtime)
    har_path = tmp_path / "traffic.har"
    har_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    _apply_har_seed_override(runtime, "traffic.har")
    config = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    har_seed = config["scanner"]["crawler"]["har_seed"]
    assert har_seed["enabled"] is True
    assert har_seed["files"] == [str(har_path.resolve())]
    assert har_seed["active_tests"] is False
    assert har_seed["max_entries"] == 5000


def test_har_seed_override_preserves_explicit_active_tests_config(tmp_path):
    runtime = tmp_path / "runtime.yaml"
    write_runtime(runtime)
    config = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    config["scanner"]["crawler"] = {
        "har_seed": {
            "enabled": False,
            "files": [],
            "max_entries": 25,
            "active_tests": True,
        }
    }
    runtime.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    har_path = tmp_path / "traffic.har"
    har_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")

    _apply_har_seed_override(runtime, str(har_path))
    updated = yaml.safe_load(runtime.read_text(encoding="utf-8"))
    har_seed = updated["scanner"]["crawler"]["har_seed"]
    assert har_seed["active_tests"] is True
    assert har_seed["max_entries"] == 25


def test_har_seed_override_rejects_missing_file(tmp_path):
    runtime = tmp_path / "runtime.yaml"
    write_runtime(runtime)
    with pytest.raises(SystemExit) as exc:
        _apply_har_seed_override(runtime, str(tmp_path / "missing.har"))
    assert exc.value.code == 2


def test_scan_help_documents_checkpoint_and_har_controls(capsys):
    _print_scan_help()
    output = capsys.readouterr().out
    assert "--checkpoint PATH" in output
    assert "--resume PATH" in output
    assert "--har-seed PATH" in output