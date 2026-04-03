from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlparse, parse_qs


@dataclass
class RBACResourcePolicy:
    resource_id: str
    route: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    expectations: Dict[str, str] = field(default_factory=dict)
    ownership: Dict[str, str] = field(default_factory=dict)
    masked_markers: List[str] = field(default_factory=list)
    policy_source: str = ""

    def matches(self, url: str, method: str, scenario_param: str = "", scenario_payload: str = "") -> bool:
        parsed = urlparse(url)
        if parsed.path != self.route:
            return False
        if self.method.upper() != (method or "GET").upper():
            return False
        combined_params = {key: values[0] if isinstance(values, list) else values for key, values in parse_qs(parsed.query).items()}
        if scenario_param and scenario_payload:
            combined_params[scenario_param] = scenario_payload
        for key, value in self.params.items():
            if str(combined_params.get(key, "")) != str(value):
                return False
        return True


@dataclass
class RBACMatrix:
    resources: List[RBACResourcePolicy] = field(default_factory=list)

    def find_policy(self, url: str, method: str, scenario_param: str = "", scenario_payload: str = "") -> RBACResourcePolicy | None:
        for policy in self.resources:
            if policy.matches(url, method, scenario_param=scenario_param, scenario_payload=scenario_payload):
                return policy
        return None
