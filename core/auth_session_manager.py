from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .models import (
    ActorCredentials,
    ActorSession,
    AuthActor,
    AuthContext,
    AuthenticatedActorState,
    LoginFlow,
    RefreshPolicy,
    SessionMaterial,
)


AUTH_FAILURE_STATUS_CODES = {401, 419}


class AuthSessionManager:
    def __init__(self, config: Dict[str, Any], requester=None):
        self.config = config
        self.requester = requester
        self.browser_auth_engine = None
        self.event_bus = None
        self.artifact_store = None
        raw_auth = config.get("auth_verification", {}) or {}
        self.context = self._parse_context(raw_auth)
        self._lock = threading.RLock()
        self.states: Dict[str, AuthenticatedActorState] = {
            actor.actor_id: AuthenticatedActorState(
                actor_id=actor.actor_id,
                auth_scheme=actor.login_flow.auth_scheme or actor.auth_type,
                auth_method_used=actor.login_flow.login_method or actor.login_flow.auth_scheme or actor.auth_type,
            )
            for actor in self.context.actors
        }
        self.summary = {
            "enabled": self.context.enabled,
            "attempted": [],
            "authenticated": [],
            "failed_login": [],
            "refresh_successes": [],
            "refresh_failures": [],
            "degraded": [],
            "skipped": [],
            "notes": list(self.context.notes),
        }

    def _parse_context(self, raw_config: Dict[str, Any]) -> AuthContext:
        actors: List[AuthActor] = []
        for raw_actor in raw_config.get("actors", []) or []:
            auth_cfg = raw_actor.get("auth", {}) or {}
            flow = LoginFlow(
                auth_scheme=auth_cfg.get("auth_scheme", raw_actor.get("auth_type", "cookie")),
                login_method=auth_cfg.get("login_method", auth_cfg.get("auth_scheme", raw_actor.get("auth_type", "cookie"))),
                login_url=auth_cfg.get("login_url", ""),
                token_url=auth_cfg.get("token_url", auth_cfg.get("login_url", "")),
                refresh_url=auth_cfg.get("refresh_url", ""),
                verify_url=auth_cfg.get("verify_url", ""),
                browser_login_url=auth_cfg.get("browser_login_url", auth_cfg.get("login_url", "")),
                use_browser=bool(auth_cfg.get("use_browser", False)),
                browser_required=bool(auth_cfg.get("browser_required", False)),
                username_field=auth_cfg.get("username_field", "username"),
                password_field=auth_cfg.get("password_field", "password"),
                username_selector=auth_cfg.get("username_selector", ""),
                password_selector=auth_cfg.get("password_selector", ""),
                submit_selector=auth_cfg.get("submit_selector", ""),
                success_selector=auth_cfg.get("success_selector", ""),
                wait_for_url_contains=auth_cfg.get("wait_for_url_contains", ""),
                pre_submit_click_selectors=auth_cfg.get("pre_submit_click_selectors", []) or [],
                post_login_click_selectors=auth_cfg.get("post_login_click_selectors", []) or [],
                browser_storage_keys=auth_cfg.get("browser_storage_keys", []) or [],
                success_indicators=auth_cfg.get("success_indicators", []) or [],
                failure_indicators=auth_cfg.get("failure_indicators", []) or [],
                access_token_json_path=auth_cfg.get("access_token_json_path", "access_token"),
                refresh_token_json_path=auth_cfg.get("refresh_token_json_path", "refresh_token"),
                expires_in_json_path=auth_cfg.get("expires_in_json_path", "expires_in"),
                cookie_names=auth_cfg.get("session", {}).get("cookie_names", auth_cfg.get("cookie_names", []) or []),
                csrf_cookie_names=auth_cfg.get("session", {}).get("csrf_cookie_names", auth_cfg.get("csrf_cookie_names", []) or []),
                csrf_field_names=auth_cfg.get("session", {}).get("csrf_field_names", auth_cfg.get("csrf_field_names", ["csrf", "csrf_token", "_csrf", "authenticity_token"])),
                auth_headers_template=auth_cfg.get("auth_headers_template", {}),
                refresh=RefreshPolicy(**(auth_cfg.get("session", {}).get("refresh", auth_cfg.get("refresh", {})) or {})),
                notes=list(auth_cfg.get("notes", []) or []),
            )
            credentials = ActorCredentials(
                username_env=auth_cfg.get("username_env", ""),
                password_env=auth_cfg.get("password_env", ""),
                username_value=auth_cfg.get("username", ""),
                password_value=auth_cfg.get("password", ""),
                secret_refs=auth_cfg.get("secret_refs", {}) or {},
            )
            static_token = auth_cfg.get("static_token", "")
            static_token_env = auth_cfg.get("static_token_env", "")
            if static_token_env and os.getenv(static_token_env):
                static_token = os.getenv(static_token_env, "")
            actor = AuthActor(
                actor_id=raw_actor.get("actor_id", ""),
                display_name=raw_actor.get("display_name", ""),
                auth_type=raw_actor.get("auth_type", flow.auth_scheme),
                login_flow=flow,
                credentials=credentials,
                headers=raw_actor.get("headers", auth_cfg.get("headers", {}) or {}),
                cookies=raw_actor.get("cookies", auth_cfg.get("cookies", {}) or {}),
                bearer_token=raw_actor.get("bearer_token", static_token),
                storage_state_path=raw_actor.get("storage_state_path", raw_actor.get("storage_state", auth_cfg.get("storage_state_path", auth_cfg.get("storage_state", "")))),
                role=raw_actor.get("role", "unknown"),
                privilege_label=raw_actor.get("privilege_label", raw_actor.get("role", "unknown")),
                notes=list(raw_actor.get("notes", []) or []) + list(flow.notes),
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
            context.notes.append("Auth verification was configured but fewer than two actor definitions were usable.")
        return context

    def actor_map(self) -> Dict[str, AuthActor]:
        return {actor.actor_id: actor for actor in self.context.actors}

    def attach_browser_auth_engine(self, browser_auth_engine):
        self.browser_auth_engine = browser_auth_engine

    def attach_event_bus(self, event_bus):
        self.event_bus = event_bus

    def attach_artifact_store(self, artifact_store):
        self.artifact_store = artifact_store

    def get_actor(self, actor_or_id: str | AuthActor | None) -> AuthActor | None:
        if actor_or_id is None:
            return None
        if isinstance(actor_or_id, AuthActor):
            return actor_or_id
        return self.actor_map().get(str(actor_or_id))

    def get_state(self, actor_or_id: str | AuthActor | None) -> AuthenticatedActorState | None:
        actor = self.get_actor(actor_or_id)
        if actor is None:
            return None
        return self.states.get(actor.actor_id)

    def bootstrap_enabled_actors(self) -> Dict[str, Any]:
        if not self.context.enabled:
            self.summary["skipped"].append("Auth session bootstrap was skipped because auth verification is disabled.")
            return self.get_summary()
        for actor in self.context.enabled_actors():
            if actor.actor_id == "anonymous" or actor.auth_type == "none":
                continue
            self.ensure_authenticated(actor)
        return self.get_summary()

    def _utc_now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _iso_now(self) -> str:
        return self._utc_now().isoformat()

    def _record_summary(self, bucket: str, actor_id: str):
        values = self.summary.setdefault(bucket, [])
        if actor_id not in values:
            values.append(actor_id)

    def _resolve_credentials(self, actor: AuthActor) -> Dict[str, str]:
        username = actor.credentials.username_value or os.getenv(actor.credentials.username_env or "", "")
        password = actor.credentials.password_value or os.getenv(actor.credentials.password_env or "", "")
        return {"username": username, "password": password}

    def _timeout_tuple(self):
        req_cfg = self.config.get("request", {}) or {}
        timeouts = req_cfg.get("timeouts", {}) or {}
        connect = float(timeouts.get("connect", self.config.get("concurrency", {}).get("timeout", 10)))
        read = float(timeouts.get("read", self.config.get("concurrency", {}).get("timeout", 10)))
        return (connect, read)

    def _url_allowed(self, url: str) -> bool:
        if self.requester and hasattr(self.requester, "_host_allowed"):
            parsed = urlparse(url)
            return bool(self.requester._host_allowed(parsed.hostname or "", parsed.netloc or parsed.hostname or ""))  # noqa: SLF001
        return True

    def _raw_request(
        self,
        method: str,
        url: str,
        *,
        headers: Dict[str, str] | None = None,
        cookies: Dict[str, str] | None = None,
        data: Dict[str, Any] | None = None,
        json_body: Dict[str, Any] | None = None,
        allow_redirects: bool = False,
    ):
        if not self._url_allowed(url):
            raise RuntimeError(f"Auth request URL {url} is outside allowed scope")
        session = requests.Session()
        if headers:
            session.headers.update(headers)
        if cookies:
            session.cookies.update(cookies)
        response = session.request(
            method=method,
            url=url,
            data=data,
            json=json_body,
            timeout=self._timeout_tuple(),
            allow_redirects=allow_redirects,
        )
        cookie_jar = session.cookies.get_dict()
        session.close()
        return response, cookie_jar

    def _cookie_presence(self, expected_names: List[str], cookies: Dict[str, str]) -> List[str]:
        return [name for name in expected_names if cookies.get(name)]

    def _contains_indicator(self, indicators: List[str], response) -> str:
        body = response.text or ""
        haystack = f"{response.url}\n{body}"
        for indicator in indicators:
            if indicator and indicator.lower() in haystack.lower():
                return indicator
        return ""

    def _detect_login_redirect(self, response) -> bool:
        final_url = getattr(response, "url", "") or ""
        location = response.headers.get("Location", "") if hasattr(response, "headers") else ""
        return "login" in final_url.lower() or "login" in location.lower()

    def _extract_hidden_fields(self, html_text: str, csrf_field_names: List[str]) -> Dict[str, str]:
        soup = BeautifulSoup(html_text or "", "html.parser")
        payload: Dict[str, str] = {}
        for form in soup.find_all("form")[:1]:
            for field in form.find_all("input"):
                name = field.get("name")
                if not name:
                    continue
                field_type = (field.get("type") or "text").strip().lower()
                value = field.get("value", "")
                if field_type == "hidden" or name in csrf_field_names:
                    payload[name] = value
        return payload

    def _extract_form_action(self, login_url: str, html_text: str) -> str:
        soup = BeautifulSoup(html_text or "", "html.parser")
        form = soup.find("form")
        if not form:
            return login_url
        return urljoin(login_url, form.get("action") or login_url)

    def _extract_json_path(self, payload: Dict[str, Any], path: str):
        current: Any = payload
        for chunk in [part for part in (path or "").split(".") if part]:
            if not isinstance(current, dict):
                return None
            current = current.get(chunk)
        return current

    def _parse_set_cookie_header(self, header_value: str) -> Dict[str, str]:
        jar = {}
        if not header_value:
            return jar
        cookie = SimpleCookie()
        try:
            cookie.load(header_value)
        except Exception:
            return jar
        for key, morsel in cookie.items():
            jar[key] = morsel.value
        return jar

    def _extract_cookie_expiry(self, header_value: str, cookie_name: str) -> str:
        if not header_value or not cookie_name:
            return ""
        chunks = [chunk.strip() for chunk in header_value.split(";") if chunk.strip()]
        for idx, chunk in enumerate(chunks):
            if not chunk.lower().startswith(f"{cookie_name.lower()}="):
                continue
            for attr in chunks[idx + 1 :]:
                if attr.lower().startswith("max-age="):
                    try:
                        return (self._utc_now() + timedelta(seconds=int(attr.split("=", 1)[1]))).isoformat()
                    except (TypeError, ValueError):
                        return ""
        return ""

    def _build_headers_from_template(self, flow: LoginFlow, material: SessionMaterial) -> Dict[str, str]:
        headers = dict(flow.auth_headers_template or {})
        access_token = material.access_token
        for key, value in list(headers.items()):
            value = value.replace("{access_token}", access_token or "")
            value = value.replace("{refresh_token}", material.refresh_token or "")
            headers[key] = value
        if access_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {access_token}"
        return headers

    def _probe_material(self, actor: AuthActor, material: SessionMaterial) -> Dict[str, Any]:
        flow = actor.login_flow
        verify_url = flow.verify_url
        if not verify_url:
            return {
                "success": False,
                "reason": "missing_verify_url",
                "limitations": ["No verify_url was configured to prove the provided auth material is valid."],
            }
        headers = dict(actor.headers or {})
        headers.update(self._build_headers_from_template(flow, material))
        cookies = dict(actor.cookies or {})
        cookies.update(material.cookies)
        response, returned_cookies = self._raw_request("GET", verify_url, headers=headers, cookies=cookies, allow_redirects=True)
        success_indicator = self._contains_indicator(flow.success_indicators, response)
        failure_indicator = self._contains_indicator(flow.failure_indicators, response)
        expected_cookies = self._cookie_presence(flow.cookie_names, {**cookies, **returned_cookies})
        success = response.status_code < 400 and not self._detect_login_redirect(response) and not failure_indicator
        if flow.success_indicators:
            success = success and bool(success_indicator)
        evidence = {
            "verify_url": verify_url,
            "status_code": response.status_code,
            "final_url": response.url,
            "matched_success_indicator": success_indicator,
            "matched_failure_indicator": failure_indicator,
            "expected_cookies_present": expected_cookies,
        }
        return {"success": success, "evidence": evidence}

    def _mark_state(
        self,
        actor: AuthActor,
        *,
        status: str,
        actor_ready: bool,
        material: SessionMaterial | None = None,
        login_performed: bool | None = None,
        refresh_performed: bool | None = None,
        login_evidence: Dict[str, Any] | None = None,
        refresh_evidence: Dict[str, Any] | None = None,
        expires_at: str | None = None,
        limitations: List[str] | None = None,
        auth_method_used: str | None = None,
        session_origin: str | None = None,
    ) -> AuthenticatedActorState:
        state = self.states[actor.actor_id]
        state.session_status = status
        state.actor_ready = actor_ready
        if material is not None:
            state.session_material = material
        if login_performed is not None:
            state.login_performed = login_performed
        if refresh_performed is not None:
            state.refresh_performed = refresh_performed
        if login_evidence is not None:
            state.login_evidence = login_evidence
        if refresh_evidence is not None:
            state.refresh_evidence.append(refresh_evidence)
            if refresh_performed:
                state.refresh_count += 1
                state.last_refresh_at = self._iso_now()
        if expires_at is not None:
            state.expires_at = expires_at
        if material is not None and not state.acquired_at:
            state.acquired_at = self._iso_now()
        if limitations:
            for limitation in limitations:
                if limitation not in state.limitations:
                    state.limitations.append(limitation)
        if auth_method_used is not None:
            state.auth_method_used = auth_method_used
        if session_origin is not None:
            state.session_origin = session_origin
        if self.event_bus is not None:
            self.event_bus.emit(
                "auth_state",
                {
                    "actor_id": actor.actor_id,
                    "session_status": state.session_status,
                    "actor_ready": state.actor_ready,
                    "auth_method_used": state.auth_method_used,
                    "session_origin": state.session_origin,
                },
            )
        return state

    def _expiry_from_seconds(self, seconds_value: Any) -> str:
        try:
            seconds = int(seconds_value)
        except (TypeError, ValueError):
            return ""
        return (self._utc_now() + timedelta(seconds=max(0, seconds))).isoformat()

    def _perform_form_login(self, actor: AuthActor) -> AuthenticatedActorState:
        flow = actor.login_flow
        creds = self._resolve_credentials(actor)
        if not creds["username"] or not creds["password"]:
            self._record_summary("failed_login", actor.actor_id)
            return self._mark_state(
                actor,
                status="login_failed",
                actor_ready=False,
                login_performed=True,
                login_evidence={"reason": "missing_credentials", "login_url": flow.login_url},
                limitations=["Form login credentials were not available from env or config placeholders."],
                auth_method_used=flow.auth_scheme,
                session_origin="http_login",
            )

        login_page, page_cookies = self._raw_request("GET", flow.login_url, allow_redirects=True)
        action_url = self._extract_form_action(flow.login_url, login_page.text or "")
        payload = self._extract_hidden_fields(login_page.text or "", flow.csrf_field_names)
        payload[flow.username_field] = creds["username"]
        payload[flow.password_field] = creds["password"]
        login_response, returned_cookies = self._raw_request(
            "POST",
            action_url,
            data=payload,
            cookies=page_cookies,
            allow_redirects=True,
        )
        all_cookies = dict(page_cookies)
        all_cookies.update(returned_cookies)
        all_cookies.update(self._parse_set_cookie_header(login_response.headers.get("Set-Cookie", "")))
        matched_success = self._contains_indicator(flow.success_indicators, login_response)
        matched_failure = self._contains_indicator(flow.failure_indicators, login_response)
        cookie_hits = self._cookie_presence(flow.cookie_names, all_cookies)
        success = login_response.status_code < 400 and not matched_failure and not self._detect_login_redirect(login_response)
        if flow.success_indicators:
            success = success and bool(matched_success)
        elif flow.cookie_names:
            success = success and bool(cookie_hits)

        evidence = {
            "login_url": flow.login_url,
            "submit_url": action_url,
            "status_code": login_response.status_code,
            "redirect_chain": [resp.status_code for resp in list(login_response.history)] + [login_response.status_code],
            "final_url": login_response.url,
            "matched_success_indicator": matched_success,
            "matched_failure_indicator": matched_failure,
            "cookie_presence": cookie_hits,
        }
        if not success:
            self._record_summary("failed_login", actor.actor_id)
            return self._mark_state(
                actor,
                status="login_failed",
                actor_ready=False,
                login_performed=True,
                login_evidence=evidence,
                limitations=["Form login did not produce a verifiable authenticated session."],
                auth_method_used=flow.auth_scheme,
                session_origin="http_login",
            )

        material = SessionMaterial(cookies=all_cookies)
        expires_at = ""
        set_cookie_headers = [resp.headers.get("Set-Cookie", "") for resp in list(login_response.history)] + [login_response.headers.get("Set-Cookie", "")]
        for cookie_name in flow.cookie_names:
            for header_value in set_cookie_headers:
                expires_at = self._extract_cookie_expiry(header_value, cookie_name)
                if expires_at:
                    break
            if expires_at:
                break
        self._record_summary("authenticated", actor.actor_id)
        return self._mark_state(
            actor,
            status="authenticated",
            actor_ready=True,
            material=material,
            login_performed=True,
            login_evidence=evidence,
            expires_at=expires_at,
            auth_method_used=flow.auth_scheme,
            session_origin="http_login",
        )

    def _perform_json_login(self, actor: AuthActor) -> AuthenticatedActorState:
        flow = actor.login_flow
        creds = self._resolve_credentials(actor)
        if not creds["username"] or not creds["password"]:
            self._record_summary("failed_login", actor.actor_id)
            return self._mark_state(
                actor,
                status="login_failed",
                actor_ready=False,
                login_performed=True,
                login_evidence={"reason": "missing_credentials", "token_url": flow.token_url or flow.login_url},
                limitations=["JSON login credentials were not available from env or config placeholders."],
                auth_method_used=flow.auth_scheme,
                session_origin="http_login",
            )

        token_url = flow.token_url or flow.login_url
        response, _ = self._raw_request(
            "POST",
            token_url,
            json_body={flow.username_field: creds["username"], flow.password_field: creds["password"]},
            allow_redirects=True,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        access_token = self._extract_json_path(payload, flow.access_token_json_path)
        refresh_token = self._extract_json_path(payload, flow.refresh_token_json_path)
        expires_in = self._extract_json_path(payload, flow.expires_in_json_path)
        matched_success = self._contains_indicator(flow.success_indicators, response)
        matched_failure = self._contains_indicator(flow.failure_indicators, response)
        success = response.status_code < 400 and bool(access_token) and not matched_failure
        if flow.success_indicators:
            success = success and bool(matched_success)
        evidence = {
            "token_url": token_url,
            "status_code": response.status_code,
            "final_url": response.url,
            "matched_success_indicator": matched_success,
            "matched_failure_indicator": matched_failure,
            "access_token_present": bool(access_token),
            "refresh_token_present": bool(refresh_token),
            "expires_in": expires_in,
        }
        if not success:
            self._record_summary("failed_login", actor.actor_id)
            return self._mark_state(
                actor,
                status="login_failed",
                actor_ready=False,
                login_performed=True,
                login_evidence=evidence,
                limitations=["JSON login did not produce a verifiable bearer token."],
                auth_method_used=flow.auth_scheme,
                session_origin="http_login",
            )

        material = SessionMaterial(
            access_token=str(access_token or ""),
            refresh_token=str(refresh_token or ""),
            headers=self._build_headers_from_template(flow, SessionMaterial(access_token=str(access_token or ""), refresh_token=str(refresh_token or ""))),
        )
        self._record_summary("authenticated", actor.actor_id)
        return self._mark_state(
            actor,
            status="authenticated",
            actor_ready=True,
            material=material,
            login_performed=True,
            login_evidence=evidence,
            expires_at=self._expiry_from_seconds(expires_in),
            auth_method_used=flow.auth_scheme,
            session_origin="http_login",
        )

    def _perform_browser_login(self, actor: AuthActor) -> AuthenticatedActorState:
        flow = actor.login_flow
        if self.browser_auth_engine is None:
            self._record_summary("failed_login", actor.actor_id)
            return self._mark_state(
                actor,
                status="degraded",
                actor_ready=False,
                login_performed=True,
                login_evidence={"reason": "browser_auth_engine_unavailable", "login_url": flow.browser_login_url or flow.login_url},
                limitations=["Browser-driven login was required for this actor, but no browser auth engine was attached."],
                auth_method_used=flow.auth_scheme,
                session_origin="browser_authenticated_only",
            )
        try:
            result = self.browser_auth_engine.authenticate_actor(actor)
        except Exception as exc:
            self._record_summary("failed_login", actor.actor_id)
            return self._mark_state(
                actor,
                status="login_failed",
                actor_ready=False,
                login_performed=True,
                login_evidence={"reason": "browser_login_exception", "error": str(exc)},
                limitations=["Browser-driven login raised an exception before a usable session could be proven."],
                auth_method_used=flow.auth_scheme,
                session_origin="browser_authenticated_only",
            )

        material = result.get("material") if isinstance(result.get("material"), SessionMaterial) else SessionMaterial(**(result.get("material") or {}))
        evidence = dict(result.get("evidence") or {})
        session_origin = str(result.get("session_origin") or "browser_login")
        limitations = list(result.get("limitations") or [])
        expires_at = str(result.get("expires_at") or "")
        success = bool(result.get("success", False))
        http_handoff_usable = bool(result.get("http_handoff_usable", False))

        if success and http_handoff_usable:
            self._record_summary("authenticated", actor.actor_id)
            return self._mark_state(
                actor,
                status="authenticated",
                actor_ready=True,
                material=material,
                login_performed=True,
                login_evidence=evidence,
                expires_at=expires_at,
                limitations=limitations,
                auth_method_used=flow.auth_scheme,
                session_origin=session_origin,
            )

        bucket = "degraded" if success else "failed_login"
        self._record_summary(bucket, actor.actor_id)
        return self._mark_state(
            actor,
            status="degraded" if success else "login_failed",
            actor_ready=False,
            material=material,
            login_performed=True,
            login_evidence=evidence,
            expires_at=expires_at,
            limitations=limitations or ["Browser login did not produce a reusable verified session."],
            auth_method_used=flow.auth_scheme,
            session_origin=session_origin or "browser_authenticated_only",
        )

    def _bootstrap_static_actor(self, actor: AuthActor) -> AuthenticatedActorState:
        material = SessionMaterial(
            headers=dict(actor.headers or {}),
            cookies=dict(actor.cookies or {}),
            access_token=actor.bearer_token or "",
            storage_state_path=actor.storage_state_path or "",
        )
        if material.access_token:
            headers = self._build_headers_from_template(actor.login_flow, material)
            if not headers.get("Authorization"):
                headers["Authorization"] = f"Bearer {material.access_token}"
            material.headers.update(headers)
        probe = self._probe_material(actor, material)
        if probe.get("success"):
            self._record_summary("authenticated", actor.actor_id)
            return self._mark_state(
                actor,
                status="authenticated",
                actor_ready=True,
                material=material,
                login_performed=False,
                login_evidence=probe.get("evidence", {}),
                auth_method_used=actor.login_flow.auth_scheme,
                session_origin="reused_state",
            )
        self._record_summary("degraded", actor.actor_id)
        return self._mark_state(
            actor,
            status="degraded",
            actor_ready=False,
            material=material,
            login_performed=False,
            login_evidence=probe.get("evidence", {"reason": probe.get("reason", "unproven_static_material")}),
            limitations=probe.get("limitations", ["Static auth material could not be proven valid."]),
            auth_method_used=actor.login_flow.auth_scheme,
            session_origin="reused_state",
        )

    def ensure_authenticated(self, actor_or_id: str | AuthActor | None) -> AuthenticatedActorState | None:
        actor = self.get_actor(actor_or_id)
        if actor is None and isinstance(actor_or_id, AuthActor) and actor_or_id.auth_type == "none":
            actor = actor_or_id
        if actor is None:
            return None
        with self._lock:
            self._record_summary("attempted", actor.actor_id)
            if actor.auth_type == "none" or actor.login_flow.auth_scheme == "none":
                return AuthenticatedActorState(
                    actor_id=actor.actor_id,
                    auth_scheme="none",
                    session_status="authenticated",
                    session_material=SessionMaterial(),
                    login_performed=False,
                    login_evidence={"reason": "unauthenticated_comparison_actor"},
                    auth_method_used="none",
                    session_origin="none",
                    actor_ready=True,
                )
            state = self.states[actor.actor_id]
            if state.actor_ready:
                return self.refresh_if_needed(actor)
            if state.session_status in {"expired", "refresh_failed"} and not actor.login_flow.supports_refresh():
                return state
            if actor.login_flow.requires_browser():
                return self._perform_browser_login(actor)
            if actor.login_flow.auth_scheme == "form_login":
                return self._perform_form_login(actor)
            if actor.login_flow.auth_scheme in {"json_login", "bearer_with_refresh"}:
                return self._perform_json_login(actor)
            return self._bootstrap_static_actor(actor)

    def refresh_if_needed(self, actor_or_id: str | AuthActor | None, *, force: bool = False, reason: str = "") -> AuthenticatedActorState | None:
        actor = self.get_actor(actor_or_id)
        if actor is None:
            return None
        with self._lock:
            state = self.states[actor.actor_id]
            flow = actor.login_flow
            if state.session_status == "not_started":
                return self.ensure_authenticated(actor)
            expiry_state = state.expiry_state(flow.refresh.pre_expiry_seconds)
            needs_refresh = force or expiry_state in {"expired", "nearing_expiry"}
            if expiry_state == "expired" and not flow.supports_refresh():
                return self._mark_state(
                    actor,
                    status="expired",
                    actor_ready=False,
                    material=state.session_material,
                    limitations=["The actor session expired and no refresh or re-login policy was available."],
                    auth_method_used=flow.auth_scheme,
                )
            if not needs_refresh or not flow.supports_refresh():
                return state
            if state.refresh_count >= flow.refresh.max_attempts and not force:
                return state

            refresh_evidence = {"reason": reason or expiry_state, "strategy": flow.refresh.strategy}
            if flow.refresh.strategy == "refresh_token" and state.session_material.refresh_token and flow.refresh_url:
                response, _ = self._raw_request(
                    "POST",
                    flow.refresh_url,
                    json_body={"refresh_token": state.session_material.refresh_token},
                    allow_redirects=True,
                )
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                access_token = self._extract_json_path(payload, flow.access_token_json_path)
                refresh_token = self._extract_json_path(payload, flow.refresh_token_json_path) or state.session_material.refresh_token
                expires_in = self._extract_json_path(payload, flow.expires_in_json_path)
                refresh_evidence.update(
                    {
                        "refresh_url": flow.refresh_url,
                        "status_code": response.status_code,
                        "access_token_present": bool(access_token),
                        "refresh_token_present": bool(refresh_token),
                        "expires_in": expires_in,
                    }
                )
                if response.status_code < 400 and access_token:
                    material = SessionMaterial(
                        headers=self._build_headers_from_template(flow, SessionMaterial(access_token=str(access_token), refresh_token=str(refresh_token))),
                        cookies=dict(state.session_material.cookies),
                        access_token=str(access_token),
                        refresh_token=str(refresh_token),
                        csrf_token=state.session_material.csrf_token,
                        storage_state_path=state.session_material.storage_state_path,
                    )
                    self._record_summary("refresh_successes", actor.actor_id)
                    return self._mark_state(
                        actor,
                        status="authenticated",
                        actor_ready=True,
                        material=material,
                        refresh_performed=True,
                        refresh_evidence=refresh_evidence,
                        expires_at=self._expiry_from_seconds(expires_in),
                        auth_method_used=flow.auth_scheme,
                        session_origin=state.session_origin or "http_login",
                    )

            if flow.refresh.relogin_on_failure:
                relogin_state = None
                if flow.requires_browser():
                    relogin_state = self._perform_browser_login(actor)
                elif flow.auth_scheme == "form_login":
                    relogin_state = self._perform_form_login(actor)
                elif flow.auth_scheme in {"json_login", "bearer_with_refresh"}:
                    relogin_state = self._perform_json_login(actor)
                if relogin_state and relogin_state.actor_ready:
                    refresh_evidence["fallback"] = "relogin"
                    relogin_state.refresh_performed = True
                    relogin_state.refresh_count += 1
                    relogin_state.last_refresh_at = self._iso_now()
                    relogin_state.refresh_evidence.append(refresh_evidence)
                    self._record_summary("refresh_successes", actor.actor_id)
                    return relogin_state

            self._record_summary("refresh_failures", actor.actor_id)
            return self._mark_state(
                actor,
                status="refresh_failed",
                actor_ready=False,
                refresh_performed=True,
                refresh_evidence=refresh_evidence,
                limitations=["Session refresh failed and the actor can no longer be treated as ready."],
                auth_method_used=flow.auth_scheme,
                session_origin=state.session_origin or "http_login",
            )

    def invalidate(self, actor_or_id: str | AuthActor | None) -> AuthenticatedActorState | None:
        actor = self.get_actor(actor_or_id)
        if actor is None:
            return None
        with self._lock:
            state = self.states[actor.actor_id]
            state.session_status = "expired"
            state.actor_ready = False
            return state

    def is_actor_ready(self, actor_or_id: str | AuthActor | None) -> bool:
        state = self.ensure_authenticated(actor_or_id)
        return bool(state and state.actor_ready and state.session_status == "authenticated")

    def get_http_context(self, actor_or_id: str | AuthActor | None) -> ActorSession | None:
        actor = self.get_actor(actor_or_id)
        if actor is None and isinstance(actor_or_id, AuthActor) and actor_or_id.auth_type == "none":
            actor = actor_or_id
        if actor is None:
            return None
        if actor.auth_type == "none" or actor.login_flow.auth_scheme == "none":
            return ActorSession(
                actor_id=actor.actor_id,
                auth_type="none",
                headers={},
                cookies={},
                session_status="authenticated",
                auth_method_used="none",
                session_origin="none",
            )
        state = self.ensure_authenticated(actor)
        if state is None:
            return None
        material = state.session_material
        headers = dict(actor.headers or {})
        headers.update(material.headers or {})
        cookies = dict(actor.cookies or {})
        cookies.update(material.cookies or {})
        if material.access_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {material.access_token}"
        return ActorSession(
            actor_id=actor.actor_id,
            auth_type=actor.auth_type,
            headers=headers,
            cookies=cookies,
            storage_state_path=material.storage_state_path or actor.storage_state_path,
            access_token=material.access_token,
            refresh_token=material.refresh_token,
            csrf_token=material.csrf_token,
            session_status=state.session_status,
            auth_method_used=state.auth_method_used,
            session_origin=state.session_origin,
        )

    def get_browser_context(self, actor_or_id: str | AuthActor | None, url: str = "") -> Dict[str, Any]:
        actor = self.get_actor(actor_or_id)
        if actor is None:
            return {}
        session = self.get_http_context(actor)
        if session is None:
            return {}
        cookies = []
        parsed = urlparse(url or self.config.get("target", ""))
        cookie_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        for name, value in session.cookies.items():
            item = {"name": name, "value": value}
            if cookie_url:
                item["url"] = cookie_url
            cookies.append(item)
        return {
            "headers": dict(session.headers or {}),
            "cookies": cookies,
            "storage_state_path": session.storage_state_path,
            "session_status": session.session_status,
        }

    def response_requires_reauth(self, response) -> bool:
        if response is None:
            return False
        if getattr(response, "status_code", 0) in AUTH_FAILURE_STATUS_CODES:
            return True
        return self._detect_login_redirect(response)

    def handle_auth_failure(self, actor_or_id: str | AuthActor | None, response=None) -> AuthenticatedActorState | None:
        actor = self.get_actor(actor_or_id)
        if actor is None:
            return None
        if response is not None and not self.response_requires_reauth(response):
            return self.get_state(actor)
        return self.refresh_if_needed(actor, force=True, reason=f"http_{getattr(response, 'status_code', 'unknown')}")

    def ready_actors(self) -> List[AuthActor]:
        ready = []
        for actor in self.context.enabled_actors():
            if self.is_actor_ready(actor):
                ready.append(actor)
        return ready

    def get_actor_state_summary(self, actor_or_id: str | AuthActor | None) -> Dict[str, Any]:
        state = self.get_state(actor_or_id)
        return state.to_summary() if state else {}

    def get_summary(self) -> Dict[str, Any]:
        actor_summaries = {actor.actor_id: self.get_actor_state_summary(actor) for actor in self.context.actors}
        ready_ids = {actor_id for actor_id, state in actor_summaries.items() if state.get("actor_ready")} if self.context.enabled else set()
        return {
            "enabled": self.context.enabled,
            "ready": len(ready_ids) >= 2,
            "baseline_actor_id": self.context.baseline_actor_id,
            "actors": [
                {
                    "actor_id": actor.actor_id,
                    "display_name": actor.display_name,
                    "role": actor.role,
                    "auth_type": actor.auth_type,
                    "auth_scheme": actor.login_flow.auth_scheme,
                    "enabled": actor.enabled,
                }
                for actor in self.context.actors
            ],
            "actor_states": actor_summaries,
            "stats": self.summary,
            "notes": self.context.notes,
        }
