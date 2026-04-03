from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from core.auth_harness import ResponseComparator
from core.models import AccessControlEvidence, AttackSurface, AuthActor, VerificationScenario
from policies.expectation_models import RBACResourcePolicy
from policies.rbac_matrix_loader import load_rbac_matrix


@dataclass
class RBACVerificationResult:
    decision: str  # matches_policy / violates_policy_verified / insufficient_setup / indeterminate / policy_missing
    verification_status: str = "informational"
    confidence: str = "LOW"
    policy_verdict: str = ""
    policy_source: str = ""
    expected_access: Dict[str, Any] = field(default_factory=dict)
    observed_access: Dict[str, Any] = field(default_factory=dict)
    ownership_context: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    authorization_signal: str = ""
    reproducible: bool = False
    deterministic_verification: bool = False
    actor_scope: List[str] = field(default_factory=list)
    browser_login_used: bool = False
    session_origin: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def reportable(self) -> bool:
        return self.decision == "violates_policy_verified"


class RBACVerifier:
    def __init__(self, requester, session_manager, config, event_bus=None, artifact_store=None):
        self.requester = requester
        self.session_manager = session_manager
        self.config = config
        self.matrix = load_rbac_matrix(config)
        self.comparator = ResponseComparator()
        self.event_bus = event_bus
        self.artifact_store = artifact_store
        self.stats = {
            "enabled": bool(self.matrix.resources),
            "resources_loaded": len(self.matrix.resources),
            "attempted": 0,
            "violates_policy_verified": 0,
            "matches_policy": 0,
            "insufficient_setup": 0,
            "indeterminate": 0,
            "policy_missing": 0,
        }

    def _anonymous_actor(self) -> AuthActor:
        return AuthActor(actor_id="anonymous", display_name="Anonymous", auth_type="none", role="anonymous")

    def find_policy(self, surface: AttackSurface, scenario: VerificationScenario) -> RBACResourcePolicy | None:
        return self.matrix.find_policy(surface.url, scenario.method or surface.method, scenario_param=scenario.param_name, scenario_payload=scenario.payload)

    def _observed_outcome(self, response, owner_response, policy: RBACResourcePolicy) -> tuple[str, Dict[str, Any]]:
        deny = self.comparator.detect_denial(response)
        if deny["denied"]:
            return "deny", {"status_code": response.status_code, "reason": "deny_pattern"}
        if owner_response is None:
            return "allow", {"status_code": response.status_code}
        diff = self.comparator.compare(owner_response, response)
        masked_markers = [marker for marker in policy.masked_markers if marker.lower() in (response.text or "").lower()]
        if masked_markers or (diff["normalized_similarity"] < 0.97 and diff["json_structural_overlap"] >= 0.7):
            return "masked", {"status_code": response.status_code, "response_diff": diff, "masked_markers": masked_markers}
        return "allow", {"status_code": response.status_code, "response_diff": diff}

    def verify_access(self, surface: AttackSurface, scenario: VerificationScenario) -> RBACVerificationResult:
        self.stats["attempted"] += 1
        policy = self.find_policy(surface, scenario)
        if policy is None:
            self.stats["policy_missing"] += 1
            return RBACVerificationResult(decision="policy_missing", policy_verdict="policy_missing")

        actor_ids = list(policy.expectations.keys())
        actor_scope = list(actor_ids)
        owner_actor_id = policy.ownership.get("owner_actor_id", "")
        owner_actor = self.session_manager.get_actor(owner_actor_id) if owner_actor_id else None
        owner_response = None
        ownership_context = dict(policy.ownership or {})
        actor_states = {}
        browser_login_used = False
        session_origins = []

        if owner_actor_id:
            owner_state = self.session_manager.get_state(owner_actor)
            if owner_actor and not self.session_manager.is_actor_ready(owner_actor):
                self.stats["insufficient_setup"] += 1
                return RBACVerificationResult(
                    decision="insufficient_setup",
                    verification_status="informational",
                    policy_verdict="insufficient_setup",
                    policy_source=policy.policy_source,
                    expected_access=dict(policy.expectations),
                    ownership_context=ownership_context,
                    actor_scope=actor_scope,
                    notes=[f"Owner actor {owner_actor_id} was not ready for deterministic policy evaluation."],
                )
            if owner_actor is not None:
                owner_response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload, actor=owner_actor)
                if owner_state:
                    actor_states[owner_actor.actor_id] = owner_state.to_summary()
                    browser_login_used = browser_login_used or owner_state.session_origin == "browser_login"
                    if owner_state.session_origin:
                        session_origins.append(owner_state.session_origin)

        observed_access: Dict[str, Any] = {}
        policy_violations = []
        auth_notes = []
        request_fingerprints = {}
        has_conditional_expectation = False
        for actor_id, expected in policy.expectations.items():
            expected_value = str(expected or "").strip().lower()
            if expected_value == "conditional":
                has_conditional_expectation = True
            actor = self._anonymous_actor() if actor_id == "anonymous" else self.session_manager.get_actor(actor_id)
            if actor is None:
                self.stats["insufficient_setup"] += 1
                return RBACVerificationResult(
                    decision="insufficient_setup",
                    verification_status="informational",
                    policy_verdict="insufficient_setup",
                    policy_source=policy.policy_source,
                    expected_access=dict(policy.expectations),
                    ownership_context=ownership_context,
                    actor_scope=actor_scope,
                    notes=[f"Policy referenced actor {actor_id}, but no such actor was configured."],
                )
            if actor_id != "anonymous" and not self.session_manager.is_actor_ready(actor):
                self.stats["insufficient_setup"] += 1
                return RBACVerificationResult(
                    decision="insufficient_setup",
                    verification_status="informational",
                    policy_verdict="insufficient_setup",
                    policy_source=policy.policy_source,
                    expected_access=dict(policy.expectations),
                    ownership_context=ownership_context,
                    actor_scope=actor_scope,
                    notes=[f"Actor {actor_id} was not ready for deterministic policy verification."],
                )
            if actor_id != "anonymous":
                state = self.session_manager.get_state(actor)
                if state:
                    actor_states[actor.actor_id] = state.to_summary()
                    browser_login_used = browser_login_used or state.session_origin == "browser_login"
                    if state.session_origin:
                        session_origins.append(state.session_origin)

            response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload, actor=actor if actor_id != "anonymous" else actor)
            observed, evidence = self._observed_outcome(response, owner_response, policy)
            observed_access[actor_id] = {"expected": expected_value, "observed": observed, **evidence}
            request_fingerprints[actor_id] = f"{actor_id}:{scenario.method.upper()}:{surface.url}:{scenario.param_name}={scenario.payload}"

            if expected_value == "deny" and observed != "deny":
                policy_violations.append(actor_id)
                auth_notes.append(f"Policy expected deny for {actor_id}, but observed {observed}.")
            elif expected_value == "masked" and observed == "allow":
                policy_violations.append(actor_id)
                auth_notes.append(f"Policy expected masked content for {actor_id}, but materially full access was observed.")
            elif expected_value in {"allow", "allow_owned"} and observed == "deny":
                auth_notes.append(f"Policy expected allow for {actor_id}, but the actor was denied. This may indicate setup drift rather than a bypass.")
            elif expected_value == "partial" and observed == "deny":
                auth_notes.append(f"Policy expected partial visibility for {actor_id}, but the actor was denied.")
            elif expected_value == "conditional":
                auth_notes.append(f"Policy for {actor_id} was conditional and cannot be verified deterministically without extra setup.")

        session_origin = ",".join(sorted(set(session_origins))) if session_origins else ""
        auth_evidence = AccessControlEvidence(
            decision="verified" if policy_violations else "no_issue",
            baseline_actor_id=owner_actor_id or scenario.baseline_actor_id,
            comparison_actor_id=policy_violations[0] if policy_violations else "",
            authorization_signal="policy_violation_verified" if policy_violations else "matches_policy",
            actor_comparison={"policy_expectations": dict(policy.expectations), "actor_states": actor_states},
            response_diff={actor_id: value.get("response_diff", {}) for actor_id, value in observed_access.items() if value.get("response_diff")},
            sensitive_fields=[],
            request_fingerprints=request_fingerprints,
            reproducible=bool(policy_violations),
            notes=auth_notes,
        )
        payload = {
            "auth": asdict(auth_evidence),
            "auth_state": {"actors": actor_states},
            "browser_login_used": browser_login_used,
            "session_origin": session_origin,
            "actor_scope": actor_scope,
            "policy": {
                "resource_id": policy.resource_id,
                "route": policy.route,
                "method": policy.method,
                "source": policy.policy_source,
                "verdict": "violates_policy_verified" if policy_violations else ("indeterminate" if has_conditional_expectation else "matches_policy"),
                "expectations": dict(policy.expectations),
                "ownership": ownership_context,
            },
            "request_fingerprints": request_fingerprints,
            "observed_access": observed_access,
        }
        if self.event_bus is not None:
            self.event_bus.emit(
                "policy_decision",
                {
                    "scenario_id": scenario.scenario_id,
                    "policy_id": policy.resource_id,
                    "verdict": "violates_policy_verified" if policy_violations else "matches_policy",
                    "expected_access": dict(policy.expectations),
                    "observed_access": observed_access,
                    "actor_scope": actor_scope,
                },
            )

        if policy_violations:
            self.stats["violates_policy_verified"] += 1
            return RBACVerificationResult(
                decision="violates_policy_verified",
                verification_status="verified",
                confidence="HIGH",
                policy_verdict="violates_policy_verified",
                policy_source=policy.policy_source,
                expected_access=dict(policy.expectations),
                observed_access=observed_access,
                ownership_context=ownership_context,
                evidence=payload,
                authorization_signal="policy_violation_verified",
                reproducible=True,
                deterministic_verification=True,
                actor_scope=actor_scope,
                browser_login_used=browser_login_used,
                session_origin=session_origin,
                notes=auth_notes,
            )

        if has_conditional_expectation:
            self.stats["indeterminate"] += 1
            return RBACVerificationResult(
                decision="indeterminate",
                verification_status="informational",
                confidence="LOW",
                policy_verdict="indeterminate",
                policy_source=policy.policy_source,
                expected_access=dict(policy.expectations),
                observed_access=observed_access,
                ownership_context=ownership_context,
                evidence=payload,
                authorization_signal="policy_conditional",
                reproducible=False,
                deterministic_verification=False,
                actor_scope=actor_scope,
                browser_login_used=browser_login_used,
                session_origin=session_origin,
                notes=auth_notes,
            )

        self.stats["matches_policy"] += 1
        return RBACVerificationResult(
            decision="matches_policy",
            verification_status="informational",
            confidence="LOW",
            policy_verdict="matches_policy",
            policy_source=policy.policy_source,
            expected_access=dict(policy.expectations),
            observed_access=observed_access,
            ownership_context=ownership_context,
            evidence=payload,
            authorization_signal="matches_policy",
            reproducible=False,
            deterministic_verification=True,
            actor_scope=actor_scope,
            browser_login_used=browser_login_used,
            session_origin=session_origin,
            notes=auth_notes or ["Observed access matched the configured RBAC policy."],
        )

    def get_summary(self) -> Dict[str, Any]:
        return dict(self.stats)
