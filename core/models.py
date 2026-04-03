from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import hashlib
from urllib.parse import urlparse


VERIFICATION_STATUS_ORDER = {
    "not_reproducible": 0,
    "informational": 1,
    "suspected": 2,
    "detected": 3,
    "verified": 4,
}

CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SESSION_STATUS_ORDER = {
    "not_started": 0,
    "authenticated": 1,
    "expired": 2,
    "refresh_failed": 3,
    "login_failed": 4,
    "degraded": 5,
}


def normalize_verification_status(value: str | None) -> str:
    status = (value or "informational").strip().lower()
    if status not in VERIFICATION_STATUS_ORDER:
        return "informational"
    return status


def normalize_session_status(value: str | None) -> str:
    status = (value or "not_started").strip().lower()
    if status not in SESSION_STATUS_ORDER:
        return "not_started"
    return status


@dataclass
class ActorCredentials:
    username_env: str = ""
    password_env: str = ""
    username_value: str = ""
    password_value: str = ""
    secret_refs: Dict[str, str] = field(default_factory=dict)

    def has_any(self) -> bool:
        return bool(self.username_env or self.password_env or self.username_value or self.password_value)


@dataclass
class RefreshPolicy:
    enabled: bool = False
    strategy: str = "none"  # none / refresh_token / relogin / cookie_renewal
    pre_expiry_seconds: int = 30
    retry_on_401: bool = True
    max_attempts: int = 1
    relogin_on_failure: bool = True

    def __post_init__(self):
        self.strategy = (self.strategy or "none").strip().lower()
        if self.strategy not in {"none", "refresh_token", "relogin", "cookie_renewal"}:
            self.strategy = "none"
        self.pre_expiry_seconds = max(0, int(self.pre_expiry_seconds or 0))
        self.max_attempts = max(1, int(self.max_attempts or 1))


@dataclass
class LoginFlow:
    auth_scheme: str = "cookie"  # form_login / json_login / bearer_with_refresh / static_cookie / static_bearer / browser_state / none
    login_method: str = ""
    login_url: str = ""
    token_url: str = ""
    refresh_url: str = ""
    verify_url: str = ""
    browser_login_url: str = ""
    use_browser: bool = False
    browser_required: bool = False
    username_field: str = "username"
    password_field: str = "password"
    username_selector: str = ""
    password_selector: str = ""
    submit_selector: str = ""
    success_selector: str = ""
    wait_for_url_contains: str = ""
    pre_submit_click_selectors: List[str] = field(default_factory=list)
    post_login_click_selectors: List[str] = field(default_factory=list)
    browser_storage_keys: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    access_token_json_path: str = "access_token"
    refresh_token_json_path: str = "refresh_token"
    expires_in_json_path: str = "expires_in"
    cookie_names: List[str] = field(default_factory=list)
    csrf_cookie_names: List[str] = field(default_factory=list)
    csrf_field_names: List[str] = field(default_factory=lambda: ["csrf", "csrf_token", "_csrf", "authenticity_token"])
    auth_headers_template: Dict[str, str] = field(default_factory=dict)
    refresh: RefreshPolicy = field(default_factory=RefreshPolicy)
    notes: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.auth_scheme = (self.auth_scheme or "cookie").strip().lower()
        self.login_method = (self.login_method or self.auth_scheme).strip().lower()
        self.login_url = (self.login_url or "").strip()
        self.token_url = (self.token_url or "").strip()
        self.refresh_url = (self.refresh_url or "").strip()
        self.verify_url = (self.verify_url or "").strip()
        self.browser_login_url = (self.browser_login_url or self.login_url or "").strip()
        self.username_selector = (self.username_selector or "").strip()
        self.password_selector = (self.password_selector or "").strip()
        self.submit_selector = (self.submit_selector or "").strip()
        self.success_selector = (self.success_selector or "").strip()
        self.wait_for_url_contains = (self.wait_for_url_contains or "").strip()
        self.pre_submit_click_selectors = [str(item) for item in (self.pre_submit_click_selectors or []) if str(item).strip()]
        self.post_login_click_selectors = [str(item) for item in (self.post_login_click_selectors or []) if str(item).strip()]
        self.browser_storage_keys = [str(item) for item in (self.browser_storage_keys or []) if str(item).strip()]
        self.success_indicators = [str(item) for item in (self.success_indicators or []) if str(item).strip()]
        self.failure_indicators = [str(item) for item in (self.failure_indicators or []) if str(item).strip()]
        self.cookie_names = [str(item) for item in (self.cookie_names or []) if str(item).strip()]
        self.csrf_cookie_names = [str(item) for item in (self.csrf_cookie_names or []) if str(item).strip()]
        self.csrf_field_names = [str(item) for item in (self.csrf_field_names or []) if str(item).strip()]
        self.auth_headers_template = {str(k): str(v) for k, v in (self.auth_headers_template or {}).items()}
        if not isinstance(self.refresh, RefreshPolicy):
            self.refresh = RefreshPolicy(**(self.refresh or {}))

    def supports_login(self) -> bool:
        return self.auth_scheme in {"form_login", "json_login", "bearer_with_refresh", "browser_form_login", "browser_spa_login"}

    def supports_refresh(self) -> bool:
        return bool(self.refresh.enabled and self.refresh.strategy != "none")

    def requires_browser(self) -> bool:
        return bool(self.use_browser or self.browser_required or self.auth_scheme in {"browser_form_login", "browser_spa_login"})


@dataclass
class SessionMaterial:
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    access_token: str = ""
    refresh_token: str = ""
    csrf_token: str = ""
    storage_state_path: str = ""

    def is_present(self) -> bool:
        return bool(self.headers or self.cookies or self.access_token or self.refresh_token or self.storage_state_path)


@dataclass
class AuthenticatedActorState:
    actor_id: str
    auth_scheme: str
    session_status: str = "not_started"
    session_material: SessionMaterial = field(default_factory=SessionMaterial)
    acquired_at: str = ""
    expires_at: str = ""
    last_refresh_at: str = ""
    refresh_count: int = 0
    login_performed: bool = False
    refresh_performed: bool = False
    login_evidence: Dict[str, Any] = field(default_factory=dict)
    refresh_evidence: List[Dict[str, Any]] = field(default_factory=list)
    auth_method_used: str = ""
    session_origin: str = ""
    actor_ready: bool = False
    limitations: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.session_status = normalize_session_status(self.session_status)
        self.auth_method_used = (self.auth_method_used or self.auth_scheme or "").strip().lower()
        self.session_origin = (self.session_origin or "").strip().lower()
        if not isinstance(self.session_material, SessionMaterial):
            self.session_material = SessionMaterial(**(self.session_material or {}))

    def expiry_state(self, pre_expiry_seconds: int = 30) -> str:
        if not self.expires_at:
            return "unknown"
        try:
            expires_at = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return "unknown"
        now = datetime.now(timezone.utc)
        if expires_at <= now:
            return "expired"
        if expires_at <= now + timedelta(seconds=max(0, int(pre_expiry_seconds or 0))):
            return "nearing_expiry"
        return "valid"

    def to_summary(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "auth_scheme": self.auth_scheme,
            "session_status": self.session_status,
            "actor_ready": self.actor_ready,
            "login_performed": self.login_performed,
            "refresh_performed": self.refresh_performed,
            "refresh_count": self.refresh_count,
            "acquired_at": self.acquired_at,
            "expires_at": self.expires_at,
            "last_refresh_at": self.last_refresh_at,
            "auth_method_used": self.auth_method_used,
            "session_origin": self.session_origin,
            "login_evidence": self.login_evidence,
            "refresh_evidence": self.refresh_evidence,
            "limitations": list(self.limitations),
        }


@dataclass
class InputField:
    name: str
    value: Optional[str] = None
    kind: str = "query"  # query/body/path/header/cookie


@dataclass
class AttackSurface:
    url: str
    method: str
    params: Dict[str, str] = field(default_factory=dict)
    inputs: List[InputField] = field(default_factory=list)
    source: str = "unknown"
    meta: Dict = field(default_factory=dict)
    id: str = field(init=False)

    def __post_init__(self):
        param_keys = sorted(self.params.keys())
        input_names = sorted([inp.name for inp in self.inputs])
        fingerprint = f"{self.method}:{self.url}:{param_keys}:{input_names}"
        self.id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


@dataclass
class AuthActor:
    actor_id: str
    display_name: str
    auth_type: str = "cookie"  # cookie / bearer / header / browser-state / none
    login_flow: LoginFlow = field(default_factory=LoginFlow)
    credentials: ActorCredentials = field(default_factory=ActorCredentials)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    storage_state_path: str = ""
    role: str = "unknown"
    privilege_label: str = ""
    notes: List[str] = field(default_factory=list)
    enabled: bool = True
    privilege_rank: Optional[int] = None

    def __post_init__(self):
        self.actor_id = (self.actor_id or "").strip()
        self.display_name = (self.display_name or self.actor_id or "Actor").strip()
        self.auth_type = (self.auth_type or "cookie").strip().lower()
        if not isinstance(self.login_flow, LoginFlow):
            self.login_flow = LoginFlow(**(self.login_flow or {}))
        if not isinstance(self.credentials, ActorCredentials):
            self.credentials = ActorCredentials(**(self.credentials or {}))
        if self.auth_type in {"cookie", "bearer", "header", "browser-state", "none"} and self.login_flow.auth_scheme == "cookie":
            self.login_flow.auth_scheme = {
                "cookie": "static_cookie",
                "bearer": "static_bearer",
                "header": "header",
                "browser-state": "browser_state",
                "none": "none",
            }.get(self.auth_type, self.login_flow.auth_scheme)
        self.role = (self.role or "unknown").strip().lower()
        self.privilege_label = (self.privilege_label or self.role or "unknown").strip().lower()
        self.headers = {str(k): str(v) for k, v in (self.headers or {}).items()}
        self.cookies = {str(k): str(v) for k, v in (self.cookies or {}).items()}
        self.storage_state_path = (self.storage_state_path or "").strip()
        self.bearer_token = (self.bearer_token or "").strip()
        if self.privilege_rank is None:
            self.privilege_rank = infer_privilege_rank(self.role or self.privilege_label)

    def has_static_material(self) -> bool:
        return bool(self.cookies or self.headers or self.bearer_token or self.storage_state_path)

    def has_dynamic_auth_config(self) -> bool:
        flow = self.login_flow
        if flow.auth_scheme in {"form_login", "browser_form_login", "browser_spa_login"}:
            return bool(flow.login_url and self.credentials.has_any())
        if flow.auth_scheme in {"json_login", "bearer_with_refresh"}:
            return bool((flow.token_url or flow.login_url) and self.credentials.has_any())
        if flow.auth_scheme in {"static_cookie", "static_bearer", "header", "browser_state"}:
            return self.has_static_material()
        if flow.auth_scheme == "none":
            return True
        return False

    def is_valid(self) -> bool:
        if not self.enabled or not self.actor_id:
            return False
        if self.auth_type == "none":
            return True
        return self.has_static_material() or self.has_dynamic_auth_config()


@dataclass
class ActorSession:
    actor_id: str
    auth_type: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    storage_state_path: str = ""
    access_token: str = ""
    refresh_token: str = ""
    csrf_token: str = ""
    session_status: str = "not_started"
    auth_method_used: str = ""
    session_origin: str = ""


@dataclass
class AuthContext:
    enabled: bool = False
    default_comparison_mode: str = "semantic"
    baseline_actor_id: str = ""
    actors: List[AuthActor] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def enabled_actors(self) -> List[AuthActor]:
        return [actor for actor in self.actors if actor.is_valid()]

    def actor_map(self) -> Dict[str, AuthActor]:
        return {actor.actor_id: actor for actor in self.enabled_actors()}

    def is_ready(self) -> bool:
        return self.enabled and len(self.enabled_actors()) >= 2


@dataclass
class VerificationScenario:
    scenario_id: str
    url: str
    method: str
    source: str
    param_name: str = ""
    payload: str = ""
    comparison_mode: str = "semantic"
    baseline_actor_id: str = ""
    comparison_actor_ids: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class AccessControlEvidence:
    decision: str  # no_issue / insufficient_evidence / suspected / verified
    baseline_actor_id: str = ""
    comparison_actor_id: str = ""
    authorization_signal: str = ""
    actor_comparison: Dict[str, Any] = field(default_factory=dict)
    response_diff: Dict[str, Any] = field(default_factory=dict)
    sensitive_fields: List[str] = field(default_factory=list)
    request_fingerprints: Dict[str, str] = field(default_factory=dict)
    reproducible: bool = False
    notes: List[str] = field(default_factory=list)


def infer_privilege_rank(value: str | None) -> int:
    role = (value or "").strip().lower()
    if role in {"none", "anon", "anonymous", "guest", "public"}:
        return 0
    if role in {"low", "user", "member", "customer", "basic"}:
        return 1
    if role in {"moderator", "support", "staff", "editor", "operator"}:
        return 2
    if role in {"admin", "superuser", "root", "owner", "high"}:
        return 3
    return 1


@dataclass
class Finding:
    plugin: str
    type: str
    severity: str  # LOW/MEDIUM/HIGH/CRITICAL
    confidence: str  # LOW/MEDIUM/HIGH
    surface_id: str
    url: str
    evidence: Dict[str, Any]
    remediation: str
    reproduction: Dict[str, Any]
    verification_status: str = "suspected"
    title: str = ""
    category: str = "web"
    target: Dict[str, Any] = field(default_factory=dict)
    scanner_mode: str = "active"
    reproducible: bool = False
    timestamps: Dict[str, str] = field(default_factory=dict)
    actor_comparison: Dict[str, Any] = field(default_factory=dict)
    baseline_actor_id: str = ""
    comparison_actor_id: str = ""
    authorization_signal: str = ""
    auth_state: Dict[str, Any] = field(default_factory=dict)
    login_performed: bool = False
    refresh_performed: bool = False
    refresh_count: int = 0
    actor_ready: bool = False
    auth_evidence: Dict[str, Any] = field(default_factory=dict)
    session_expiry_state: str = ""
    policy_source: str = ""
    expected_access: Dict[str, Any] = field(default_factory=dict)
    observed_access: Dict[str, Any] = field(default_factory=dict)
    policy_verdict: str = ""
    ownership_context: Dict[str, Any] = field(default_factory=dict)
    deterministic_verification: bool = False
    actor_scope: List[str] = field(default_factory=list)
    browser_login_used: bool = False
    session_origin: str = ""
    workflow_id: str = ""
    workflow_execution_id: str = ""
    workflow_step_ids: List[str] = field(default_factory=list)
    workflow_checkpoint_results: List[Dict[str, Any]] = field(default_factory=list)
    workflow_status: str = ""
    workflow_replay_status: str = ""
    verification_basis: str = ""
    artifact_refs: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    fingerprint: str = field(init=False)
    id: str = field(init=False)

    def __post_init__(self):
        self.severity = (self.severity or "LOW").upper()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "LOW"
        self.confidence = (self.confidence or "LOW").upper()
        if self.confidence not in CONFIDENCE_ORDER:
            self.confidence = "LOW"
        self.verification_status = normalize_verification_status(self.verification_status)
        self.evidence = self.evidence or {}
        self.reproduction = self.reproduction or {}
        self.title = (self.title or self.type or self.plugin or "Finding").strip()
        self.category = (self.category or "web").strip().lower()
        self.scanner_mode = (self.scanner_mode or "active").strip().lower()
        self.reproducible = bool(self.reproducible)
        self.target = self._normalize_target(self.target)
        self.timestamps = self._normalize_timestamps(self.timestamps)
        self.actor_comparison = dict(self.actor_comparison or {})
        self.baseline_actor_id = (self.baseline_actor_id or "").strip()
        self.comparison_actor_id = (self.comparison_actor_id or "").strip()
        self.authorization_signal = (self.authorization_signal or "").strip().lower()
        self.auth_state = dict(self.auth_state or {})
        self.actor_ready = bool(self.actor_ready)
        self.login_performed = bool(self.login_performed)
        self.refresh_performed = bool(self.refresh_performed)
        self.refresh_count = max(0, int(self.refresh_count or 0))
        self.auth_evidence = dict(self.auth_evidence or {})
        self.session_expiry_state = (self.session_expiry_state or "").strip().lower()
        self.policy_source = (self.policy_source or "").strip()
        self.expected_access = dict(self.expected_access or {})
        self.observed_access = dict(self.observed_access or {})
        self.policy_verdict = (self.policy_verdict or "").strip().lower()
        self.ownership_context = dict(self.ownership_context or {})
        self.deterministic_verification = bool(self.deterministic_verification)
        self.actor_scope = [str(item) for item in (self.actor_scope or []) if str(item).strip()]
        self.browser_login_used = bool(self.browser_login_used)
        self.session_origin = (self.session_origin or "").strip().lower()
        self.workflow_id = (self.workflow_id or "").strip()
        self.workflow_execution_id = (self.workflow_execution_id or "").strip()
        self.workflow_step_ids = [str(item) for item in (self.workflow_step_ids or []) if str(item).strip()]
        self.workflow_checkpoint_results = [dict(item) for item in (self.workflow_checkpoint_results or []) if item]
        self.workflow_status = (self.workflow_status or "").strip().lower()
        self.workflow_replay_status = (self.workflow_replay_status or "").strip().lower()
        self.verification_basis = (self.verification_basis or "").strip().lower()
        self.artifact_refs = [dict(item) for item in (self.artifact_refs or []) if item]

        if self.verification_status in {"verified", "detected", "suspected"} and not self.evidence:
            self.verification_status = "informational"
            self.confidence = "LOW"
            self.notes.append("Downgraded because no evidence was captured.")
        if self.verification_status == "verified" and not self.reproducible:
            self.verification_status = "detected"
            self.confidence = "MEDIUM" if self.confidence == "HIGH" else self.confidence
            self.notes.append("Downgraded because the condition was not marked reproducible.")
        if self.category == "access-control" and self.verification_status == "verified":
            has_actor_pair = bool(self.baseline_actor_id and self.comparison_actor_id)
            has_actor_evidence = bool(self.actor_comparison or self.evidence.get("auth"))
            actor_states = self.auth_state.get("actors", {}) if isinstance(self.auth_state, dict) else {}
            degraded_auth = any(
                str((state or {}).get("session_status", "")).strip().lower() in {"expired", "refresh_failed", "login_failed", "degraded"}
                or not bool((state or {}).get("actor_ready", False))
                for state in actor_states.values()
            ) if actor_states else not self.actor_ready
            if not has_actor_pair or not has_actor_evidence or degraded_auth:
                self.verification_status = "suspected"
                self.confidence = "LOW"
                self.reproducible = False
                self.notes.append("Downgraded because verified access-control findings require cross-actor evidence and ready authenticated actors.")
        if self.policy_verdict == "violates_policy_verified" and not self.deterministic_verification:
            self.policy_verdict = "indeterminate"
            self.verification_status = "suspected"
            self.confidence = "LOW"
            self.notes.append("Downgraded because policy-backed verified findings require deterministic verification.")
        if self.scanner_mode == "workflow" and self.verification_status == "verified":
            workflow_ready = bool(self.workflow_id and self.workflow_execution_id and self.workflow_step_ids and self.workflow_checkpoint_results)
            workflow_complete = self.workflow_status not in {"partial", "failed", "indeterminate", "blocked_auth"}
            workflow_basis_ok = self.verification_basis in {"policy-backed", "proof-backed"}
            if not workflow_ready or not workflow_complete or not workflow_basis_ok:
                self.verification_status = "suspected"
                self.confidence = "LOW"
                self.reproducible = False
                self.notes.append("Downgraded because verified workflow findings require step-level checkpoint evidence, a completed workflow state, and a non-heuristic verification basis.")

        param_name = self.reproduction.get("param") or self.evidence.get("param") or ""
        fingerprint = f"{self.plugin}:{self.type}:{self.url}:{self.surface_id}:{param_name}:{self.workflow_id}:{','.join(self.workflow_step_ids)}"
        self.fingerprint = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        self.id = self.fingerprint

    def _normalize_target(self, value: Dict[str, Any]) -> Dict[str, Any]:
        target = dict(value or {})
        parsed = urlparse(self.url or "")
        target.setdefault("url", self.url)
        target.setdefault("host", parsed.netloc or parsed.hostname or "")
        target.setdefault("path", parsed.path or "/")
        if self.surface_id:
            target.setdefault("surface_id", self.surface_id)
        param_name = self.reproduction.get("param") or self.evidence.get("param")
        if param_name:
            target.setdefault("parameter", param_name)
        return target

    def _normalize_timestamps(self, value: Dict[str, str]) -> Dict[str, str]:
        timestamps = dict(value or {})
        now = datetime.now(timezone.utc).isoformat()
        timestamps.setdefault("first_seen", now)
        timestamps.setdefault("last_seen", timestamps["first_seen"])
        return timestamps


@dataclass
class ArtifactReference:
    artifact_id: str
    kind: str
    path: str
    actor_id: str = ""
    finding_id: str = ""
    workflow_id: str = ""
    execution_id: str = ""
    step_id: str = ""
    checkpoint_id: str = ""
    replay_id: str = ""
    artifact_role: str = ""
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScanEvent:
    event_id: str
    kind: str
    timestamp: str
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestRecord:
    fingerprint: str
    method: str
    url: str
    actor_id: str = ""
    source: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    replay_of: str = ""


@dataclass
class ResponseRecord:
    fingerprint: str
    status_code: int
    actor_id: str = ""
    url: str = ""
    content_length: int = 0
    headers: Dict[str, Any] = field(default_factory=dict)
    excerpt: str = ""


@dataclass
class BrowserActionRecord:
    action: str
    url: str
    actor_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationRecord:
    scenario_id: str
    verifier: str
    decision: str
    actor_scope: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyDecisionRecord:
    scenario_id: str
    policy_id: str
    verdict: str
    expected_access: Dict[str, Any] = field(default_factory=dict)
    observed_access: Dict[str, Any] = field(default_factory=dict)
    actor_scope: List[str] = field(default_factory=list)
