from __future__ import annotations

import os
from typing import Any, Dict

import yaml

from .expectation_models import RBACMatrix, RBACResourcePolicy


def load_rbac_matrix(config: Dict[str, Any]) -> RBACMatrix:
    scanner_cfg = config.get("scanner", config)
    raw_matrix = scanner_cfg.get("rbac_matrix")
    matrix_file = scanner_cfg.get("rbac_matrix_file", "")
    if raw_matrix is None and matrix_file:
        path = os.path.abspath(matrix_file)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                raw_matrix = yaml.safe_load(handle) or {}
    raw_resources = []
    if isinstance(raw_matrix, dict):
        raw_resources = raw_matrix.get("rbac_matrix", raw_matrix.get("resources", [])) or []
    elif isinstance(raw_matrix, list):
        raw_resources = raw_matrix
    resources = []
    for item in raw_resources:
        if not isinstance(item, dict):
            continue
        resources.append(
            RBACResourcePolicy(
                resource_id=item.get("resource_id", ""),
                route=item.get("route", ""),
                method=item.get("method", "GET"),
                params=item.get("params", {}) or {},
                expectations=item.get("expectations", {}) or {},
                ownership=item.get("ownership", {}) or {},
                masked_markers=list(item.get("masked_markers", []) or []),
                policy_source=path if matrix_file else "inline",
            )
        )
    return RBACMatrix(resources=resources)
