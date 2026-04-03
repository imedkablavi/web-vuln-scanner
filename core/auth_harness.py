from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List

from core.models import (
    AccessControlEvidence,
    AttackSurface,
    AuthActor,
    AuthContext,
    VerificationScenario,
    infer_privilege_rank,
)
from core.utils import normalize_url


DENIAL_PATTERNS = [
    re.compile(r"\b(forbidden|unauthorized|access denied|not permitted)\b", re.IGNORECASE),
    re.compile(r"\blogin\b", re.IGNORECASE),
]

DYNAMIC_PATTERNS = [
    (re.compile(r"[a-f0-9]{32,}", re.IGNORECASE), "<token>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE), "<uuid>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[t\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?\b", re.IGNORECASE), "<timestamp>"),
    (re.compile(r"csrf[_-]?token[\"'=: ]+[A-Za-z0-9._-]+", re.IGNORECASE), "csrf_token=<token>"),
    (re.compile(r"\b\d{6,}\b"), "<number>"),
]

SENSITIVE_FIELD_NAMES = {
    "id",
    "doc",
    "document",
    "owner",
    "email",
    "name",
    "title",
    "account",
    "address",
    "phone",
}
STRONG_VALUE_FIELDS = {"owner", "email", "account", "address", "phone", "name"}


@dataclass
class AuthVerificationResult:
    decision: str  # no_issue / insufficient_evidence / suspected / verified
    verification_status: str = "informational"
    confidence: str = "LOW"
    authorization_signal: str = ""
    reproducible: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def reportable(self) -> bool:
        return self.decision in {"suspected", "verified"}


class ResponseComparator:
    def normalize_text(self, text: str) -> str:
        normalized = text or ""
        for pattern, replacement in DYNAMIC_PATTERNS:
            normalized = pattern.sub(replacement, normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip().lower()
        return normalized

    def parse_json(self, text: str):
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None

    def flatten_json(self, value: Any, prefix: str = "") -> Dict[str, Any]:
        flat: Dict[str, Any] = {}
        if isinstance(value, dict):
            for key, inner in value.items():
                child_prefix = f"{prefix}.{key}" if prefix else str(key)
                flat.update(self.flatten_json(inner, child_prefix))
        elif isinstance(value, list):
            for index, inner in enumerate(value[:10]):
                child_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
                flat.update(self.flatten_json(inner, child_prefix))
        else:
            flat[prefix or "$"] = value
        return flat

    def detect_denial(self, response) -> Dict[str, Any]:
        text = response.text or ""
        location = response.headers.get("Location") if hasattr(response, "headers") else None
        denied = response.status_code in {401, 403}
        login_redirect = bool(location and "login" in location.lower())
        pattern_hits = [pattern.pattern for pattern in DENIAL_PATTERNS if pattern.search(text)]
        return {
            "denied": denied or login_redirect or bool(pattern_hits),
            "status": response.status_code,
            "location": location,
            "pattern_hits": pattern_hits,
            "login_redirect": login_redirect,
        }

    def extract_sensitive_fields(self, response) -> List[str]:
        body = response.text or ""
        parsed = self.parse_json(body)
        if parsed is not None:
            flat = self.flatten_json(parsed)
            return sorted({key for key in flat if key.split(".")[-1].lower().strip("[]$") in SENSITIVE_FIELD_NAMES})
        hits = set()
        for field_name in SENSITIVE_FIELD_NAMES:
            if re.search(rf"\b{re.escape(field_name)}\b", body, re.IGNORECASE):
                hits.add(field_name)
        return sorted(hits)

    def compare(self, baseline_response, comparison_response) -> Dict[str, Any]:
        baseline_text = baseline_response.text or ""
        comparison_text = comparison_response.text or ""
        baseline_normalized = self.normalize_text(baseline_text)
        comparison_normalized = self.normalize_text(comparison_text)
        similarity = SequenceMatcher(None, baseline_text, comparison_text).ratio()
        normalized_similarity = SequenceMatcher(None, baseline_normalized, comparison_normalized).ratio()

        baseline_json = self.parse_json(baseline_text)
        comparison_json = self.parse_json(comparison_text)
        shared_sensitive_values = []
        json_structural_overlap = 0.0
        if baseline_json is not None and comparison_json is not None:
            baseline_flat = self.flatten_json(baseline_json)
            comparison_flat = self.flatten_json(comparison_json)
            baseline_keys = set(baseline_flat.keys())
            comparison_keys = set(comparison_flat.keys())
            union = baseline_keys | comparison_keys
            intersection = baseline_keys & comparison_keys
            json_structural_overlap = len(intersection) / max(1, len(union))
            for key in sorted(intersection):
                if baseline_flat.get(key) == comparison_flat.get(key):
                    leaf = key.split(".")[-1].lower().strip("[]$")
                    if leaf in STRONG_VALUE_FIELDS:
                        shared_sensitive_values.append(key)
        denial_baseline = self.detect_denial(baseline_response)
        denial_comparison = self.detect_denial(comparison_response)
        return {
            "status_codes": {
                "baseline": baseline_response.status_code,
                "comparison": comparison_response.status_code,
            },
            "redirects": {
                "baseline": denial_baseline.get("location"),
                "comparison": denial_comparison.get("location"),
            },
            "denial_patterns": {
                "baseline": denial_baseline,
                "comparison": denial_comparison,
            },
            "similarity": round(similarity, 4),
            "normalized_similarity": round(normalized_similarity, 4),
            "json_structural_overlap": round(json_structural_overlap, 4),
            "shared_sensitive_values": shared_sensitive_values,
            "sensitive_fields": {
                "baseline": self.extract_sensitive_fields(baseline_response),
                "comparison": self.extract_sensitive_fields(comparison_response),
            },
            "response_excerpt": {
                "baseline": re.sub(r"\s+", " ", baseline_text).strip()[:220],
                "comparison": re.sub(r"\s+", " ", comparison_text).strip()[:220],
            },
        }


class AuthVerificationHarness:
    def __init__(self, requester, config):
        self.requester = requester
        self.config = config
        self.session_manager = getattr(requester, "auth_session_manager", None)
        if self.session_manager is not None:
            self.context = self.session_manager.context
        else:
            self.context = self._parse_context(config.get("auth_verification", {}))
        self.compare_unauthenticated = bool(config.get("auth_verification", {}).get("compare_unauthenticated", True))
        self.comparator = ResponseComparator()
        self.stats = {
            "enabled": self.context.enabled,
            "actors": [actor.actor_id for actor in self.context.enabled_actors()],
            "scenarios_total": 0,
            "verified": 0,
            "suspected": 0,
            "skipped": [],
        }

    def _parse_context(self, raw_config: Dict[str, Any]) -> AuthContext:
        actors = []
        for raw_actor in raw_config.get("actors", []) or []:
            actor = AuthActor(
                actor_id=raw_actor.get("actor_id", ""),
                display_name=raw_actor.get("display_name", ""),
                auth_type=raw_actor.get("auth_type", "cookie"),
                headers=raw_actor.get("headers", {}) or {},
                cookies=raw_actor.get("cookies", {}) or {},
                bearer_token=raw_actor.get("bearer_token", ""),
                storage_state_path=raw_actor.get("storage_state_path", raw_actor.get("storage_state", "")),
                role=raw_actor.get("role", "unknown"),
                privilege_label=raw_actor.get("privilege_label", raw_actor.get("role", "unknown")),
                notes=list(raw_actor.get("notes", []) or []),
                enabled=bool(raw_actor.get("enabled", True)),
                privilege_rank=raw_actor.get("privilege_rank"),
            )
            actors.append(actor)
        context = AuthContext(
            enabled=bool(raw_config.get("enabled", False)),
            default_comparison_mode=(raw_config.get("default_comparison_mode", "semantic") or "semantic").strip().lower(),
            baseline_actor_id=(raw_config.get("baseline_actor_id", "") or "").strip(),
            actors=actors,
            notes=[],
        )
        if context.enabled and len(context.enabled_actors()) < 2:
            context.notes.append("Auth verification disabled at runtime because fewer than two valid actors were configured.")
        return context

    def is_ready(self) -> bool:
        if self.session_manager is not None:
            return len(self.session_manager.ready_actors()) >= 2
        return self.context.is_ready()

    def _request_fingerprint(self, actor: AuthActor, scenario: VerificationScenario) -> str:
        return f"{actor.actor_id}:{scenario.method.upper()}:{normalize_url(scenario.url)}:{scenario.param_name}={scenario.payload}"

    def _candidate_pairs(self) -> List[tuple[AuthActor, AuthActor]]:
        if self.session_manager is not None:
            actors = self.session_manager.ready_actors()
        else:
            actors = self.context.enabled_actors()
        if len(actors) < 2:
            return []
        actor_map = {actor.actor_id: actor for actor in actors}
        if self.context.baseline_actor_id and self.context.baseline_actor_id in actor_map:
            baseline_actor = actor_map[self.context.baseline_actor_id]
            return [(baseline_actor, actor) for actor in actors if actor.actor_id != baseline_actor.actor_id]
        pairs = []
        for index, baseline_actor in enumerate(actors):
            for comparison_actor in actors[index + 1 :]:
                pairs.append((baseline_actor, comparison_actor))
        return pairs

    def _actor_state_summary(self, actor: AuthActor) -> Dict[str, Any]:
        if self.session_manager is None:
            return {
                "actor_id": actor.actor_id,
                "session_status": "static",
                "actor_ready": True,
                "login_performed": False,
                "refresh_performed": False,
                "refresh_count": 0,
                "auth_method_used": actor.auth_type,
            }
        state = self.session_manager.ensure_authenticated(actor)
        return state.to_summary() if state is not None else {"actor_id": actor.actor_id, "session_status": "not_started", "actor_ready": False}

    def verify_access(self, surface: AttackSurface, scenario: VerificationScenario) -> AuthVerificationResult:
        if not self.context.enabled:
            return AuthVerificationResult(decision="insufficient_evidence", verification_status="informational", notes=["Auth verification is disabled in configuration."])
        if not self.context.is_ready():
            return AuthVerificationResult(decision="insufficient_evidence", verification_status="informational", notes=self.context.notes or ["Not enough valid actors to compare."])

        if self.compare_unauthenticated:
            public_result = self._detect_public_resource(surface, scenario)
            if public_result is not None:
                return public_result

        best_result = AuthVerificationResult(decision="no_issue", verification_status="informational")
        for baseline_actor, comparison_actor in self._candidate_pairs():
            result = self._verify_pair(surface, scenario, baseline_actor, comparison_actor)
            self.stats["scenarios_total"] += 1
            if result.decision == "verified":
                self.stats["verified"] += 1
                return result
            if result.decision == "suspected":
                self.stats["suspected"] += 1
                best_result = result
            elif best_result.decision == "no_issue" and result.decision == "insufficient_evidence":
                best_result = result
        return best_result

    def _detect_public_resource(self, surface: AttackSurface, scenario: VerificationScenario) -> AuthVerificationResult | None:
        actors = self.context.enabled_actors()
        if not actors:
            return None
        baseline_actor = next((actor for actor in actors if actor.actor_id == self.context.baseline_actor_id), actors[0])
        anonymous_actor = AuthActor(actor_id="anonymous", display_name="Unauthenticated", auth_type="none", role="anonymous")
        try:
            baseline_response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload, actor=baseline_actor)
            anonymous_response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload, actor=anonymous_actor)
        except Exception:
            return None
        diff = self.comparator.compare(baseline_response, anonymous_response)
        anonymous_denied = diff["denial_patterns"]["comparison"]["denied"]
        strong_similarity = bool(diff["shared_sensitive_values"]) or (
            diff["normalized_similarity"] >= 0.97 and diff["json_structural_overlap"] >= 0.9
        )
        if baseline_response.status_code < 400 and not anonymous_denied and strong_similarity:
            return AuthVerificationResult(
                decision="no_issue",
                verification_status="informational",
                evidence={
                    "auth": {
                        "decision": "no_issue",
                        "baseline_actor_id": baseline_actor.actor_id,
                        "comparison_actor_id": "anonymous",
                        "authorization_signal": "public_resource_visible_without_auth",
                        "response_diff": diff,
                    }
                },
                notes=["Resource content was materially similar for an authenticated actor and an unauthenticated request."],
            )
        return None

    def _verify_pair(self, surface: AttackSurface, scenario: VerificationScenario, baseline_actor: AuthActor, comparison_actor: AuthActor) -> AuthVerificationResult:
        baseline_state = self._actor_state_summary(baseline_actor)
        comparison_state = self._actor_state_summary(comparison_actor)
        if not baseline_state.get("actor_ready") or not comparison_state.get("actor_ready"):
            notes = ["Auth comparison skipped because one or more actors were not authenticated and ready."]
            return AuthVerificationResult(
                decision="insufficient_evidence",
                verification_status="informational",
                confidence="LOW",
                evidence={
                    "auth": {
                        "decision": "insufficient_evidence",
                        "baseline_actor_id": baseline_actor.actor_id,
                        "comparison_actor_id": comparison_actor.actor_id,
                        "auth_state": {
                            "actors": {
                                baseline_actor.actor_id: baseline_state,
                                comparison_actor.actor_id: comparison_state,
                            }
                        },
                    }
                },
                notes=notes,
            )
        baseline_response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload, actor=baseline_actor)
        comparison_response = self.requester.send_surface(surface, scenario.param_name or None, scenario.payload, actor=comparison_actor)
        diff = self.comparator.compare(baseline_response, comparison_response)

        baseline_denied = diff["denial_patterns"]["baseline"]["denied"]
        comparison_denied = diff["denial_patterns"]["comparison"]["denied"]
        baseline_rank = baseline_actor.privilege_rank if baseline_actor.privilege_rank is not None else infer_privilege_rank(baseline_actor.role)
        comparison_rank = comparison_actor.privilege_rank if comparison_actor.privilege_rank is not None else infer_privilege_rank(comparison_actor.role)
        same_role = baseline_actor.role == comparison_actor.role
        lower_or_equal_privilege = comparison_rank <= baseline_rank
        strong_similarity = bool(diff["shared_sensitive_values"]) or (
            diff["normalized_similarity"] >= 0.97 and diff["json_structural_overlap"] >= 0.9
        )
        medium_similarity = diff["normalized_similarity"] >= 0.75 or diff["json_structural_overlap"] >= 0.9

        auth_evidence = AccessControlEvidence(
            decision="no_issue",
            baseline_actor_id=baseline_actor.actor_id,
            comparison_actor_id=comparison_actor.actor_id,
            actor_comparison={
                "baseline_actor": asdict(baseline_actor),
                "comparison_actor": asdict(comparison_actor),
                "comparison_mode": scenario.comparison_mode,
            },
            response_diff=diff,
            sensitive_fields=sorted(set(diff["sensitive_fields"]["baseline"]) | set(diff["sensitive_fields"]["comparison"])),
            request_fingerprints={
                "baseline": self._request_fingerprint(baseline_actor, scenario),
                "comparison": self._request_fingerprint(comparison_actor, scenario),
            },
            reproducible=False,
            notes=[],
        )
        auth_state = {
            "actors": {
                baseline_actor.actor_id: baseline_state,
                comparison_actor.actor_id: comparison_state,
            }
        }
        refresh_performed = bool(baseline_state.get("refresh_performed") or comparison_state.get("refresh_performed"))
        refresh_count = int(baseline_state.get("refresh_count", 0)) + int(comparison_state.get("refresh_count", 0))
        login_performed = bool(baseline_state.get("login_performed") or comparison_state.get("login_performed"))
        session_expiry_state = "expired" if any(state.get("session_status") == "expired" for state in auth_state["actors"].values()) else "valid"

        if baseline_denied and comparison_denied:
            auth_evidence.notes.append("Both actors were denied for the same resource.")
            return AuthVerificationResult(decision="no_issue", verification_status="informational", evidence={"auth": asdict(auth_evidence), "auth_state": auth_state, "login_performed": login_performed, "refresh_performed": refresh_performed, "refresh_count": refresh_count, "actor_ready": False, "session_expiry_state": session_expiry_state}, notes=auth_evidence.notes)

        if not baseline_denied and comparison_denied:
            auth_evidence.authorization_signal = "enforcement_observed"
            auth_evidence.notes.append("Comparison actor was denied while the baseline actor was allowed.")
            return AuthVerificationResult(decision="no_issue", verification_status="informational", evidence={"auth": asdict(auth_evidence), "auth_state": auth_state, "login_performed": login_performed, "refresh_performed": refresh_performed, "refresh_count": refresh_count, "actor_ready": True, "session_expiry_state": session_expiry_state}, notes=auth_evidence.notes)

        if baseline_denied and not comparison_denied:
            auth_evidence.authorization_signal = "baseline_denied_comparison_allowed"
            auth_evidence.notes.append("Comparison actor was allowed while the baseline actor was denied; the ownership relationship is ambiguous.")
            return AuthVerificationResult(
                decision="insufficient_evidence",
                verification_status="informational",
                confidence="LOW",
                evidence={"auth": asdict(auth_evidence), "auth_state": auth_state, "login_performed": login_performed, "refresh_performed": refresh_performed, "refresh_count": refresh_count, "actor_ready": False, "session_expiry_state": session_expiry_state},
                notes=auth_evidence.notes,
            )

        if strong_similarity and (same_role or lower_or_equal_privilege):
            if comparison_actor.auth_type == "none":
                signal = "unauthenticated_resource_exposure"
            elif same_role and baseline_actor.actor_id != comparison_actor.actor_id:
                signal = "peer_cross_actor_resource_exposure"
            else:
                signal = "lower_privilege_cross_actor_access"
            auth_evidence.decision = "verified"
            auth_evidence.authorization_signal = signal
            auth_evidence.reproducible = True
            auth_evidence.notes.append("Cross-actor access returned materially similar sensitive content.")
            return AuthVerificationResult(
                decision="verified",
                verification_status="verified",
                confidence="HIGH",
                authorization_signal=signal,
                reproducible=True,
                evidence={"auth": asdict(auth_evidence), "response_diff": diff, "sensitive_fields": auth_evidence.sensitive_fields, "request_fingerprints": auth_evidence.request_fingerprints, "auth_state": auth_state, "login_performed": login_performed, "refresh_performed": refresh_performed, "refresh_count": refresh_count, "actor_ready": True, "session_expiry_state": session_expiry_state},
                notes=auth_evidence.notes,
            )

        if medium_similarity and (same_role or lower_or_equal_privilege):
            auth_evidence.decision = "suspected"
            auth_evidence.authorization_signal = "ambiguous_cross_actor_similarity"
            auth_evidence.notes.append("Cross-actor access returned similar content, but not enough to prove unauthorized disclosure.")
            return AuthVerificationResult(
                decision="suspected",
                verification_status="suspected",
                confidence="LOW",
                authorization_signal=auth_evidence.authorization_signal,
                reproducible=False,
                evidence={"auth": asdict(auth_evidence), "response_diff": diff, "sensitive_fields": auth_evidence.sensitive_fields, "request_fingerprints": auth_evidence.request_fingerprints, "auth_state": auth_state, "login_performed": login_performed, "refresh_performed": refresh_performed, "refresh_count": refresh_count, "actor_ready": True, "session_expiry_state": session_expiry_state},
                notes=auth_evidence.notes,
            )

        auth_evidence.decision = "no_issue"
        auth_evidence.notes.append("Cross-actor responses diverged enough to avoid an authorization bypass conclusion.")
        return AuthVerificationResult(decision="no_issue", verification_status="informational", evidence={"auth": asdict(auth_evidence), "auth_state": auth_state, "login_performed": login_performed, "refresh_performed": refresh_performed, "refresh_count": refresh_count, "actor_ready": True, "session_expiry_state": session_expiry_state}, notes=auth_evidence.notes)

    async def capture_browser_artifacts(self, findings, browser_engine):
        if browser_engine is None:
            return findings
        actor_map = self.context.actor_map()
        for finding in findings:
            if finding.category != "access-control":
                continue
            if not (finding.baseline_actor_id and finding.comparison_actor_id):
                continue
            baseline_actor = actor_map.get(finding.baseline_actor_id)
            comparison_actor = actor_map.get(finding.comparison_actor_id)
            if baseline_actor is None or comparison_actor is None:
                continue
            auth_bucket = finding.evidence.setdefault("auth", {})
            browser_bucket = auth_bucket.setdefault("browser_artifacts", [])
            if not hasattr(browser_engine, "capture_actor_snapshot"):
                continue
            for label, actor in (("baseline", baseline_actor), ("comparison", comparison_actor)):
                try:
                    artifact = await browser_engine.capture_actor_snapshot(finding.url, actor, label=f"{finding.id[:8]}-{label}")
                except Exception as exc:
                    artifact = {"actor_id": actor.actor_id, "error": str(exc)}
                browser_bucket.append(artifact)
                if artifact.get("screenshot"):
                    finding.artifact_refs.append(
                        {
                            "kind": "screenshot",
                            "path": artifact.get("screenshot"),
                            "actor_id": actor.actor_id,
                            "description": f"Browser auth snapshot ({label})",
                        }
                    )
        return findings

    def get_summary(self) -> Dict[str, Any]:
        session_summary = self.session_manager.get_summary() if self.session_manager is not None else {}
        return {
            "enabled": self.context.enabled,
            "ready": self.is_ready(),
            "default_comparison_mode": self.context.default_comparison_mode,
            "compare_unauthenticated": self.compare_unauthenticated,
            "baseline_actor_id": self.context.baseline_actor_id,
            "actors": [
                {
                    "actor_id": actor.actor_id,
                    "display_name": actor.display_name,
                    "role": actor.role,
                    "auth_type": actor.auth_type,
                    "enabled": actor.enabled,
                }
                for actor in self.context.actors
            ],
            "stats": self.stats,
            "auth_sessions": session_summary,
            "notes": self.context.notes,
        }
