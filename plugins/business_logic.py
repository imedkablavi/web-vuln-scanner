import re
from typing import List, Dict
from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding, VerificationScenario
from core.utils import get_content_hash


class BusinessLogicPlugin(BasePlugin):
    name = "business_logic"
    supported_input_kinds = ["query", "body"]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface: AttackSurface) -> bool:
        return bool(surface.params or surface.inputs)

    def max_tests_per_surface(self, config: Dict) -> int:
        return int(config.get("max_tests_per_surface", 3))

    def _shape(self, text: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"\d+", "", text or "")).strip().lower()

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        cfg = self.config.get("idor", {})
        regex = re.compile(cfg.get("id_param_regex", "(^id$|_id$|Id$|doc)"))
        deltas = cfg.get("numeric_delta", [-1, 1, 10])
        tests: List[TestCase] = []
        max_tests = self.max_tests_per_surface(cfg)
        for name, val in surface.params.items():
            if str(val).isdigit() and regex.search(name):
                tests.append(TestCase(plugin=self.name, surface_id=surface.id, param=name, kind="query", payload=str(val), baseline_key=f"{surface.id}:{name}", notes="current_value"))
                if len(tests) >= max_tests:
                    return tests
                for d in deltas:
                    tests.append(TestCase(plugin=self.name, surface_id=surface.id, param=name, kind="query", payload=str(int(val) + d), baseline_key=f"{surface.id}:{name}"))
                    if len(tests) >= max_tests:
                        return tests
        for inp in surface.inputs:
            if inp.value and str(inp.value).isdigit() and regex.search(inp.name):
                tests.append(TestCase(plugin=self.name, surface_id=surface.id, param=inp.name, kind=inp.kind, payload=str(inp.value), baseline_key=f"{surface.id}:{inp.name}", notes="current_value"))
                if len(tests) >= max_tests:
                    return tests
                for d in deltas:
                    tests.append(TestCase(plugin=self.name, surface_id=surface.id, param=inp.name, kind=inp.kind, payload=str(int(inp.value) + d), baseline_key=f"{surface.id}:{inp.name}"))
                    if len(tests) >= max_tests:
                        return tests
        return tests

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        surface = context.get("surface")
        rbac_verifier = context.get("rbac_verifier")
        if rbac_verifier and surface is not None:
            scenario = VerificationScenario(
                scenario_id=f"rbac:{surface.id}:{testcase.param}:{testcase.payload}",
                url=surface.url,
                method=surface.method,
                source=self.name,
                param_name=testcase.param,
                payload=testcase.payload,
            )
            rbac_result = rbac_verifier.verify_access(surface, scenario)
            if rbac_result.decision == "violates_policy_verified":
                return VerificationResult(
                    True,
                    rbac_result.confidence,
                    rbac_result.evidence,
                    {"param": testcase.param, "payload": testcase.payload},
                    severity="HIGH",
                    verification_status="verified",
                    rationale="Deterministic RBAC policy verification proved an authorization bypass.",
                )
            if rbac_result.decision == "matches_policy":
                return VerificationResult(
                    False,
                    "LOW",
                    rbac_result.evidence,
                    {},
                    severity="LOW",
                    verification_status="not_reproducible",
                    rationale="Observed access matched the configured RBAC expectations.",
                )
            if rbac_result.decision in {"insufficient_setup", "indeterminate"}:
                return VerificationResult(
                    False,
                    "LOW",
                    rbac_result.evidence,
                    {},
                    severity="LOW",
                    verification_status="informational",
                    rationale="RBAC policy existed, but deterministic verification could not complete truthfully.",
                )

        auth_harness = context.get("auth_harness")
        if auth_harness and getattr(auth_harness, "is_ready", lambda: False)() and surface is not None:
            scenario = VerificationScenario(
                scenario_id=f"{surface.id}:{testcase.param}:{testcase.payload}",
                url=surface.url,
                method=surface.method,
                source=self.name,
                param_name=testcase.param,
                payload=testcase.payload,
                comparison_mode=getattr(auth_harness.context, "default_comparison_mode", "semantic"),
                baseline_actor_id=getattr(auth_harness.context, "baseline_actor_id", ""),
            )
            auth_result = auth_harness.verify_access(surface, scenario)
            if auth_result.decision == "verified":
                return VerificationResult(
                    True,
                    auth_result.confidence,
                    auth_result.evidence,
                    {"param": testcase.param, "payload": testcase.payload},
                    severity="HIGH",
                    verification_status="verified",
                    rationale="Cross-actor verification proved access to the same protected resource.",
                )
            if auth_result.decision == "suspected":
                return VerificationResult(
                    True,
                    auth_result.confidence,
                    auth_result.evidence,
                    {"param": testcase.param, "payload": testcase.payload},
                    severity="MEDIUM",
                    verification_status="suspected",
                    rationale="Cross-actor comparison was suspicious but not strong enough to prove unauthorized access.",
                )
            if auth_result.decision == "no_issue":
                return VerificationResult(
                    False,
                    "LOW",
                    {"reason": "auth_harness_no_issue"},
                    {},
                    severity="LOW",
                    verification_status="not_reproducible",
                )
            if auth_result.decision == "insufficient_evidence":
                context.setdefault("errors", []).append("Auth verification was inconclusive for business_logic scenario.")
        cfg = self.config.get("idor", {})
        require_200 = cfg.get("require_status_200", True)
        min_delta_ratio = cfg.get("min_length_delta_ratio", 0.1)
        if baseline is None or response is None:
            return VerificationResult(
                False,
                "LOW",
                {"reason": "missing_baseline_or_response"},
                {},
                severity="LOW",
                verification_status="not_reproducible",
            )
        if response.status_code in (401, 403):
            return VerificationResult(
                False,
                "LOW",
                {"reason": "candidate_request_denied"},
                {},
                severity="LOW",
                verification_status="not_reproducible",
            )
        if require_200 and (baseline["status"] != 200 or response.status_code != 200):
            return VerificationResult(
                False,
                "LOW",
                {"reason": "status_requirements_not_met"},
                {},
                severity="LOW",
                verification_status="not_reproducible",
            )
        base_hash = baseline["hash"]
        cand_hash = get_content_hash(response.text or "")
        if cand_hash == base_hash:
            return VerificationResult(
                False,
                "LOW",
                {"reason": "identical_hash"},
                {},
                severity="LOW",
                verification_status="not_reproducible",
            )
        delta_ratio = abs(len(response.text) - baseline["length"]) / max(1, baseline["length"])
        if delta_ratio < min_delta_ratio:
            return VerificationResult(
                False,
                "LOW",
                {"reason": "delta_below_threshold"},
                {},
                severity="LOW",
                verification_status="not_reproducible",
            )
        if self._shape(response.text or "") == self._shape(baseline["text"]):
            return VerificationResult(
                False,
                "LOW",
                {"reason": "template_variation_only"},
                {},
                severity="LOW",
                verification_status="not_reproducible",
            )
        evidence = {
            "param": testcase.param,
            "baseline_status": baseline["status"],
            "candidate_status": response.status_code,
            "delta_ratio": delta_ratio,
            "baseline_hash": base_hash,
            "candidate_hash": cand_hash,
            "baseline_length": baseline["length"],
            "candidate_length": len(response.text or ""),
            "baseline_excerpt": (baseline["text"] or "")[:160],
            "candidate_excerpt": (response.text or "")[:160],
        }
        reproduction = {"param": testcase.param, "payload": testcase.payload}
        return VerificationResult(
            True,
            "LOW",
            evidence,
            reproduction,
            severity="LOW",
            verification_status="suspected",
            rationale="Content variance was observed for an object-like identifier, but authorization bypass was not proven.",
        )

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        auth_evidence = (vres.evidence or {}).get("auth", {})
        policy_evidence = (vres.evidence or {}).get("policy", {})
        authorization_signal = auth_evidence.get("authorization_signal", "")
        baseline_actor_id = auth_evidence.get("baseline_actor_id", "")
        comparison_actor_id = auth_evidence.get("comparison_actor_id", "")
        deterministic_verification = bool(policy_evidence) and (vres.evidence or {}).get("policy", {}).get("source", "")
        session_origin = (vres.evidence or {}).get("session_origin", "") or ",".join(
            sorted(
                {
                    value.get("session_origin", "")
                    for value in ((vres.evidence or {}).get("auth_state", {}).get("actors", {}) or {}).values()
                    if isinstance(value, dict) and value.get("session_origin")
                }
            )
        )
        browser_login_used = bool((vres.evidence or {}).get("browser_login_used")) or "browser_login" in session_origin
        if vres.verification_status == "verified" and policy_evidence:
            title = "RBAC Policy Violation Verified"
            finding_type = "Unauthorized Resource Access"
            severity = "HIGH"
            confidence = "HIGH"
        elif vres.verification_status == "verified":
            title = "Authorization Bypass Verified"
            finding_type = "Cross-Actor Resource Exposure"
            severity = "HIGH"
            confidence = "HIGH"
        elif authorization_signal:
            title = "Unauthorized Object Access Signal"
            finding_type = "Authorization Inconsistency Signal"
            severity = vres.severity
            confidence = vres.confidence
        else:
            title = "Authorization Inconsistency Signal"
            finding_type = "Object Reference Variance"
            severity = vres.severity
            confidence = vres.confidence
        return Finding(
            plugin=self.name,
            type=finding_type,
            title=title,
            category="access-control",
            severity=severity,
            confidence=confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Implement access control checks and object ownership validation.",
            reproduction=vres.reproduction,
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=vres.verification_status == "verified",
            actor_comparison=auth_evidence.get("actor_comparison", {}),
            baseline_actor_id=baseline_actor_id,
            comparison_actor_id=comparison_actor_id,
            authorization_signal=authorization_signal,
            auth_state=vres.evidence.get("auth_state", {}),
            login_performed=bool(vres.evidence.get("login_performed", False)),
            refresh_performed=bool(vres.evidence.get("refresh_performed", False)),
            refresh_count=int(vres.evidence.get("refresh_count", 0) or 0),
            actor_ready=bool(vres.evidence.get("actor_ready", False)),
            auth_evidence=auth_evidence,
            session_expiry_state=vres.evidence.get("session_expiry_state", ""),
            policy_source=policy_evidence.get("source", ""),
            expected_access=policy_evidence.get("expectations", {}),
            observed_access=(vres.evidence or {}).get("observed_access", {}),
            policy_verdict="violates_policy_verified" if policy_evidence and vres.verification_status == "verified" else (policy_evidence.get("verdict", "") or ""),
            ownership_context=policy_evidence.get("ownership", {}),
            deterministic_verification=bool(policy_evidence),
            actor_scope=list((vres.evidence or {}).get("actor_scope", []) or ((vres.evidence or {}).get("auth_state", {}).get("actors", {}) or {}).keys()),
            browser_login_used=browser_login_used,
            session_origin=session_origin,
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
