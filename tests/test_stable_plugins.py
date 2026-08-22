from dataclasses import dataclass

from core.models import AttackSurface
from core.utils import get_content_hash
from plugins.base import TestCase
from plugins.business_logic import BusinessLogicPlugin
from plugins.sqli import SQLiPlugin


class Response:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


def baseline(text="baseline account page", status=200):
    return {
        "text": text,
        "length": len(text),
        "hash": get_content_hash(text),
        "status": status,
    }


def surface():
    return AttackSurface(
        url="https://example.test/item",
        method="GET",
        params={"id": "10"},
        source="fixture",
    )


def test_sqli_error_pattern_is_detected_not_overclaimed_verified():
    plugin = SQLiPlugin(None, {"enabled": True, "min_length_delta_ratio": 0.05})
    testcase = TestCase("sqli", surface().id, "id", "query", "'")
    result = plugin.verify(
        testcase,
        baseline(),
        Response("SQLSTATE syntax error at or near quote", 500),
        {},
    )
    assert result.is_verified is True
    assert result.verification_status == "detected"
    assert result.severity == "HIGH"


def test_sqli_identical_safe_response_is_not_reportable():
    plugin = SQLiPlugin(None, {"enabled": True, "min_length_delta_ratio": 0.05})
    testcase = TestCase("sqli", surface().id, "id", "query", "'")
    base = baseline("same response")
    result = plugin.verify(testcase, base, Response("same response"), {})
    assert result.is_verified is False
    assert result.verification_status == "not_reproducible"


def test_sqli_boolean_pair_requires_false_then_material_true_difference():
    plugin = SQLiPlugin(None, {"enabled": True, "min_length_delta_ratio": 0.05})
    key = f"{surface().id}:id"
    context = {}
    base = baseline("BASELINE " * 20)
    false_case = TestCase(
        "sqli", surface().id, "id", "query", "' AND '1'='2", baseline_key=key
    )
    true_case = TestCase(
        "sqli", surface().id, "id", "query", "' OR '1'='1", baseline_key=key
    )
    false_result = plugin.verify(
        false_case, base, Response("FALSE RESULT " * 5), context
    )
    true_result = plugin.verify(
        true_case, base, Response("TRUE ROW DATA " * 30), context
    )
    assert false_result.is_verified is False
    assert true_result.is_verified is True
    assert true_result.verification_status == "verified"


def test_sqli_test_generation_is_bounded():
    plugin = SQLiPlugin(None, {"enabled": True, "max_tests_per_surface": 3})
    tests = plugin.generate_tests(surface(), {})
    assert len(tests) == 3


def test_business_logic_denied_candidate_is_not_a_finding():
    plugin = BusinessLogicPlugin(
        None,
        {
            "enabled": True,
            "idor": {"require_status_200": True, "min_length_delta_ratio": 0.05},
        },
    )
    testcase = TestCase("business_logic", surface().id, "id", "query", "11")
    result = plugin.verify(
        testcase, baseline("owner resource"), Response("Forbidden", 403), {}
    )
    assert result.is_verified is False
    assert result.verification_status == "not_reproducible"


def test_business_logic_template_only_variation_is_rejected():
    plugin = BusinessLogicPlugin(
        None,
        {
            "enabled": True,
            "idor": {"require_status_200": True, "min_length_delta_ratio": 0.01},
        },
    )
    testcase = TestCase("business_logic", surface().id, "id", "query", "11")
    base = baseline("Document 100 belongs to user 200")
    result = plugin.verify(
        testcase,
        base,
        Response("Document 999999 belongs to user 888888"),
        {},
    )
    assert result.is_verified is False
    assert result.evidence["reason"] == "template_variation_only"


@dataclass
class RBACResult:
    decision: str
    confidence: str = "HIGH"
    evidence: dict = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {"policy": {"source": "fixture"}}


class RBACVerifier:
    def __init__(self, decision):
        self.decision = decision

    def verify_access(self, _surface, _scenario):
        return RBACResult(self.decision)


def test_business_logic_policy_verified_bypass_is_verified():
    plugin = BusinessLogicPlugin(None, {"enabled": True, "idor": {}})
    testcase = TestCase("business_logic", surface().id, "id", "query", "11")
    result = plugin.verify(
        testcase,
        baseline(),
        Response("candidate"),
        {"surface": surface(), "rbac_verifier": RBACVerifier("violates_policy_verified")},
    )
    assert result.is_verified is True
    assert result.verification_status == "verified"
    finding = plugin.build_finding(testcase, result, surface())
    assert finding.severity == "HIGH"
    assert finding.reproducible is True


def test_business_logic_policy_match_is_not_reported():
    plugin = BusinessLogicPlugin(None, {"enabled": True, "idor": {}})
    testcase = TestCase("business_logic", surface().id, "id", "query", "11")
    result = plugin.verify(
        testcase,
        baseline(),
        Response("candidate"),
        {"surface": surface(), "rbac_verifier": RBACVerifier("matches_policy")},
    )
    assert result.is_verified is False
    assert result.verification_status == "not_reproducible"
