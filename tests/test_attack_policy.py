import pytest

from core.scanner import ScannerEngine
from plugins.base import TestCase


class Requester:
    pass


def config(policy):
    return {
        "scanner": {
            "concurrency": {
                "threads": 1,
                "per_host_concurrency": 1,
                "timeout": 1,
                "global_timeout_seconds": 5,
            },
            "plugins": {},
            "attack_policy": policy,
            "max_findings_per_plugin": 10,
        }
    }


def case(param):
    return TestCase(
        plugin="fixture",
        surface_id="surface",
        param=param,
        kind="query",
        payload="x",
    )


def test_exact_parameter_names_are_suppressed_case_insensitively():
    engine = ScannerEngine(
        Requester(),
        config({"skip_parameters": ["csrf_token", "password"]}),
    )
    assert engine._testcase_allowed(case("CSRF_TOKEN")) is False
    assert engine._testcase_allowed(case("password")) is False
    assert engine._testcase_allowed(case("search")) is True


def test_parameter_regex_can_suppress_project_specific_names():
    engine = ScannerEngine(
        Requester(),
        config({"skip_parameter_patterns": [r"^danger_", r"_secret$"]}),
    )
    assert engine._testcase_allowed(case("danger_action")) is False
    assert engine._testcase_allowed(case("api_secret")) is False
    assert engine._testcase_allowed(case("safe_value")) is True


def test_invalid_parameter_policy_regex_fails_fast():
    with pytest.raises(ValueError, match="Invalid attack_policy"):
        ScannerEngine(
            Requester(),
            config({"skip_parameter_patterns": ["["]}),
        )
