from pathlib import Path

import yaml

from core.resources import materialize_runtime_config


def test_bundled_runtime_config_has_absolute_resource_paths():
    path = materialize_runtime_config()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    scanner = data["scanner"]
    rbac = Path(scanner["rbac_matrix_file"])
    workflows = Path(scanner["workflows"]["directory"])
    assert rbac.is_absolute() and rbac.is_file()
    assert workflows.is_absolute() and workflows.is_dir()
    assert list(workflows.glob("*.yaml")) or list(workflows.glob("*.yml"))
