from __future__ import annotations

from core.models import AttackSurface
from plugins.base import BasePlugin, TestCase, VerificationResult


class BudgetPlugin(BasePlugin):
    name = "budget-test"
    supported_input_kinds = ["query"]

    def applicable(self, surface):
        return True

    def generate_tests(self, surface, context):
        return [
            TestCase(plugin=self.name, surface_id=surface.id, param="q", kind="query", payload=str(index))
            for index in range(3)
        ]

    def verify(self, testcase, baseline, response, context):
        return VerificationResult(False, "LOW", {"reason": "synthetic"}, {}, verification_status="not_reproducible")

    def build_finding(self, testcase, vres, surface):  # pragma: no cover
        raise AssertionError("not expected")


class AlwaysFailRequester:
    def __init__(self):
        self.calls = 0

    def send_surface(self, surface, param_to_inject=None, payload=None, actor=None, replay_of=""):
        self.calls += 1
        raise RuntimeError("synthetic dispatch failure")


def test_legacy_adapter_counts_failed_dispatch_against_request_budget():
    requester = AlwaysFailRequester()
    plugin = BudgetPlugin(
        requester,
        {"enabled": True, "max_tests_per_surface": 3, "request_budget": 1, "timeout_seconds": 2},
    )
    surface = AttackSurface(url="http://local.invalid/safe", method="GET", params={"q": "x"})
    context = {"baseline": None, "errors": []}

    findings = plugin.run(surface, context)

    assert findings == []
    assert requester.calls == 1
    assert any("request budget exhausted" in error for error in context["errors"])
