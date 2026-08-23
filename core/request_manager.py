import hashlib
import json
import os
import random
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import requests

from .models import AttackSurface, AuthActor, ActorSession, RequestRecord, ResponseRecord
from .redaction import redact_structure, redact_text
from .request_materializer import materialize_surface_request
from .scope import ScopePolicy
from .utils import logger


class RequestManager:
    def __init__(self, config):
        self.config = config
        self.cookies = dict(config.get("auth", {}).get("cookies", {}) or {})
        self._base_headers = dict(config.get("auth", {}).get("headers", {}) or {})
        # Each worker thread owns a map of sessions keyed by actor identity. This
        # prevents Set-Cookie state from one RBAC actor contaminating another.
        self._session_local = threading.local()
        self.delay = config["concurrency"]["delay"]
        self.max_retries = config["concurrency"]["max_retries"]
        self.timeout = config["concurrency"]["timeout"]
        req_cfg = config.get("request", {})
        timeouts_cfg = req_cfg.get("timeouts", {})
        self.connect_timeout = timeouts_cfg.get("connect", self.timeout)
        self.read_timeout = timeouts_cfg.get("read", self.timeout)
        self.max_retries = req_cfg.get("max_retries", self.max_retries)
        self.follow_redirects = bool(req_cfg.get("follow_redirects", False))
        self.max_redirects = max(0, int(req_cfg.get("max_redirects", 5)))
        self.scope_policy = ScopePolicy(config)
        self.include_domains = list(self.scope_policy.include_domains)
        self.allow_private = self.scope_policy.allow_private
        self.circuit_breaker = defaultdict(int)
        self.circuit_window = 60
        self.last_reset = time.time()
        self._lock = threading.Lock()
        self.per_host_limit = int(
            config.get("concurrency", {}).get(
                "per_host_concurrency",
                max(1, config["concurrency"].get("threads", 1)),
            )
        )
        self._host_semaphores = defaultdict(
            lambda: threading.Semaphore(self.per_host_limit)
        )
        self.auth_session_manager = None
        self.event_bus = None
        if config.get("auth_verification", {}).get("enabled"):
            try:
                from .auth_session_manager import AuthSessionManager

                self.auth_session_manager = AuthSessionManager(config, requester=self)
                try:
                    from .browser_auth_engine import BrowserAuthEngine

                    self.auth_session_manager.attach_browser_auth_engine(
                        BrowserAuthEngine(config)
                    )
                except Exception as exc:  # pragma: no cover - defensive path
                    logger.warning(f"Browser auth engine bootstrap failed: {exc}")
            except Exception as exc:  # pragma: no cover - defensive path
                logger.warning(f"Auth session manager bootstrap failed: {exc}")
                self.auth_session_manager = None

    def _new_session(self):
        session = requests.Session()
        # Scanner targets are untrusted by definition. Do not implicitly ingest
        # proxy or .netrc credentials from the process environment.
        session.trust_env = False
        session.headers.update(self._base_headers)
        session.cookies.update(self.cookies)
        return session

    def _session_for(self, actor_id: str = ""):
        sessions = getattr(self._session_local, "sessions", None)
        if sessions is None:
            sessions = {}
            self._session_local.sessions = sessions
        key = str(actor_id or "__anonymous__")
        session = sessions.get(key)
        if session is None:
            session = self._new_session()
            sessions[key] = session
        return session

    @property
    def session(self):
        """Compatibility accessor for the anonymous session in this thread."""
        return self._session_for("")

    def attach_auth_session_manager(self, session_manager):
        self.auth_session_manager = session_manager

    def attach_event_bus(self, event_bus):
        self.event_bus = event_bus

    def _request_fingerprint(
        self, method, url, actor_id="", params=None, data=None, json_body=None
    ):
        basis = json.dumps(
            {
                "method": str(method).upper(),
                "url": url,
                "actor_id": actor_id,
                "params": params or {},
                "data": data or {},
                "json": json_body or {},
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def _reset_circuit(self):
        now = time.time()
        with self._lock:
            if now - self.last_reset > self.circuit_window:
                self.circuit_breaker.clear()
                self.last_reset = now

    def _host_allowed(self, host: str, host_with_port: str = "") -> bool:
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        authority = host_with_port or host
        if ":" in host and not authority.startswith("["):
            authority = f"[{host}]"
        return self.scope_policy.is_allowed(
            f"https://{authority}/", resolve_dns=False
        )

    @staticmethod
    def _retry_after_seconds(value, fallback):
        if not value:
            return fallback
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            pass
        try:
            when = parsedate_to_datetime(str(value))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(
                0, int((when - datetime.now(timezone.utc)).total_seconds())
            )
        except (TypeError, ValueError, OverflowError):
            return fallback

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int | None]:
        parsed = urlparse(url)
        return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port

    @staticmethod
    def _redirect_method(method: str, status_code: int) -> str:
        method = str(method).upper()
        if status_code == 303 and method != "HEAD":
            return "GET"
        if status_code in {301, 302} and method == "POST":
            return "GET"
        return method

    def _follow_scoped_redirects(
        self,
        response,
        *,
        session,
        method,
        headers,
        cookies,
        timeout,
        params,
        data,
        json_body,
    ):
        redirects = 0
        current_response = response
        current_method = str(method).upper()
        current_headers = dict(headers or {})
        current_cookies = dict(cookies or {})
        current_params = params
        current_data = data
        current_json = json_body

        while current_response.is_redirect or current_response.is_permanent_redirect:
            if redirects >= self.max_redirects:
                raise RuntimeError(f"Redirect limit exceeded ({self.max_redirects})")
            location = current_response.headers.get("Location")
            if not location:
                break
            next_url = urljoin(current_response.url, location)
            self.scope_policy.require(next_url, resolve_dns=True)

            previous_origin = self._origin(current_response.url)
            next_origin = self._origin(next_url)
            if previous_origin != next_origin:
                for sensitive_header in (
                    "Authorization",
                    "Cookie",
                    "Proxy-Authorization",
                ):
                    current_headers.pop(sensitive_header, None)
                current_cookies = {}

            next_method = self._redirect_method(
                current_method, current_response.status_code
            )
            if next_method == "GET" and current_method != "GET":
                current_params = None
                current_data = None
                current_json = None

            current_response = session.request(
                method=next_method,
                url=next_url,
                params=current_params,
                data=current_data,
                json=current_json,
                headers=current_headers or None,
                cookies=current_cookies,
                timeout=timeout,
                allow_redirects=False,
            )
            current_method = next_method
            redirects += 1
        return current_response

    def send(
        self,
        method,
        url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        timeout=None,
        json=None,
        allow_redirects=None,
        actor_id="",
        source="",
        replay_of="",
    ):
        """Centralized request sending with scope checks, bounded concurrency and retries."""
        self._reset_circuit()
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.scheme not in {"http", "https"}:
            raise RuntimeError(
                f"Unsupported URL scheme: {parsed.scheme or '<missing>'}"
            )
        if not host:
            raise RuntimeError(f"Invalid host parsed from URL: {url}")

        try:
            self.scope_policy.require(url, resolve_dns=True)
        except RuntimeError as exc:
            logger.warning(
                f"Request blocked by scope/SSRF guard: {url} ({exc})"
            )
            raise

        with self._lock:
            if self.circuit_breaker.get(host, 0) >= 3:
                logger.warning(
                    f"Circuit breaker open for host {host}, skipping request."
                )
                raise RuntimeError(f"Circuit open for host {host}")

        effective_timeout = (
            timeout
            if timeout is not None
            else (self.connect_timeout, self.read_timeout)
        )
        follow_redirects = (
            self.follow_redirects
            if allow_redirects is None
            else bool(allow_redirects)
        )
        request_cookies = self.cookies if cookies is None else cookies
        request_session = self._session_for(actor_id)
        sem = self._host_semaphores[host]
        sem.acquire()
        try:
            retries = 0
            backoff = 1
            while retries <= self.max_retries:
                base_delay = max(
                    0,
                    float(self.delay)
                    * (
                        0.5
                        if self.circuit_breaker.get(host, 0) == 0
                        else 1.0
                    ),
                )
                jitter_window = (
                    0
                    if self.delay <= 0
                    else min(0.1, max(0.01, float(self.delay) * 0.25))
                )
                time.sleep(base_delay + random.uniform(0, jitter_window))
                try:
                    resp = request_session.request(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json,
                        headers=headers,
                        cookies=request_cookies,
                        timeout=effective_timeout,
                        allow_redirects=False,
                    )
                    if follow_redirects and (
                        resp.is_redirect or resp.is_permanent_redirect
                    ):
                        resp = self._follow_scoped_redirects(
                            resp,
                            session=request_session,
                            method=method,
                            headers=headers,
                            cookies=request_cookies,
                            timeout=effective_timeout,
                            params=params,
                            data=data,
                            json_body=json,
                        )

                    if resp.status_code in (429, 503):
                        wait_time = self._retry_after_seconds(
                            resp.headers.get("Retry-After"), backoff
                        )
                        wait_time = min(wait_time, 30)
                        logger.warning(
                            f"Rate limited ({resp.status_code}). Waiting "
                            f"{wait_time}s before retry."
                        )
                        retries += 1
                        with self._lock:
                            self.circuit_breaker[host] += 1
                        if retries > self.max_retries:
                            break
                        time.sleep(wait_time)
                        backoff = min(backoff * 2, 30)
                        continue

                    with self._lock:
                        self.circuit_breaker[host] = 0
                    if self.event_bus is not None:
                        fingerprint = self._request_fingerprint(
                            method,
                            url,
                            actor_id=actor_id,
                            params=params,
                            data=data,
                            json_body=json,
                        )
                        self.event_bus.emit_record(
                            "request",
                            RequestRecord(
                                fingerprint=fingerprint,
                                method=str(method).upper(),
                                url=url,
                                actor_id=actor_id,
                                source=source,
                                params=redact_structure(
                                    params or data or json or {}
                                ),
                                headers=redact_structure(headers or {}),
                                replay_of=replay_of,
                            ),
                        )
                        self.event_bus.emit_record(
                            "response",
                            ResponseRecord(
                                fingerprint=fingerprint,
                                status_code=getattr(resp, "status_code", 0),
                                actor_id=actor_id,
                                url=getattr(resp, "url", url),
                                content_length=len(
                                    getattr(resp, "text", "") or ""
                                ),
                                headers=redact_structure(
                                    dict(getattr(resp, "headers", {}) or {})
                                ),
                                excerpt=redact_text(
                                    getattr(resp, "text", "") or "",
                                    max_length=220,
                                ),
                            ),
                        )
                    return resp

                except requests.RequestException as exc:
                    logger.error(f"Request failed: {exc}")
                    retries += 1
                    if retries > self.max_retries:
                        break
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 30)
            raise RuntimeError(f"Request to {url} failed after retries")
        finally:
            sem.release()

    def _load_storage_state(self, actor: AuthActor):
        if not actor.storage_state_path:
            return {}
        path = actor.storage_state_path
        if not os.path.exists(path):
            logger.warning(f"Actor storage state not found: {path}")
            return {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            logger.warning(f"Failed to load actor storage state {path}: {exc}")
            return {}

    def build_actor_session(
        self, actor: AuthActor | None
    ) -> ActorSession | None:
        if actor is None:
            return None
        if self.auth_session_manager is not None:
            dynamic_session = self.auth_session_manager.get_http_context(actor)
            if dynamic_session is not None:
                return dynamic_session
        headers = dict(actor.headers or {})
        cookies = dict(actor.cookies or {})
        if actor.auth_type == "bearer" and actor.bearer_token:
            headers["Authorization"] = f"Bearer {actor.bearer_token}"
        if actor.auth_type == "browser-state" and actor.storage_state_path:
            state = self._load_storage_state(actor)
            for cookie in state.get("cookies", []):
                name = cookie.get("name")
                value = cookie.get("value")
                if name:
                    cookies[name] = value or ""
        return ActorSession(
            actor_id=actor.actor_id,
            auth_type=actor.auth_type,
            headers=headers,
            cookies=cookies,
            storage_state_path=actor.storage_state_path,
        )

    def send_as_actor(
        self,
        method,
        url,
        *,
        actor: AuthActor | None = None,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        timeout=None,
        json=None,
        allow_redirects=None,
        source="direct",
        replay_of="",
    ):
        request_headers = dict(headers or {})
        request_cookies = dict(cookies or {})
        actor_session = self.build_actor_session(actor)
        actor_id = getattr(actor, "actor_id", "")
        if actor_session:
            request_headers.update(actor_session.headers)
            request_cookies.update(actor_session.cookies)
        response = self.send(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=request_headers or None,
            cookies=request_cookies if request_cookies else {},
            timeout=timeout,
            json=json,
            allow_redirects=allow_redirects,
            actor_id=actor_id,
            source=source,
            replay_of=replay_of,
        )
        if (
            actor is None
            or getattr(actor, "auth_type", "") == "none"
            or self.auth_session_manager is None
            or not self.auth_session_manager.response_requires_reauth(response)
        ):
            return response
        refreshed_state = self.auth_session_manager.handle_auth_failure(
            actor, response
        )
        if not refreshed_state or not getattr(
            refreshed_state, "actor_ready", False
        ):
            return response
        refreshed_session = self.build_actor_session(actor)
        retry_headers = dict(headers or {})
        retry_cookies = dict(cookies or {})
        if refreshed_session:
            retry_headers.update(refreshed_session.headers)
            retry_cookies.update(refreshed_session.cookies)
        return self.send(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=retry_headers or None,
            cookies=retry_cookies if retry_cookies else {},
            timeout=timeout,
            json=json,
            allow_redirects=allow_redirects,
            actor_id=actor_id,
            source=f"{source}:retry",
            replay_of=replay_of,
        )

    def send_surface(
        self,
        surface: AttackSurface,
        param_to_inject=None,
        payload=None,
        actor: AuthActor | None = None,
        replay_of="",
    ):
        mutation_name = str(param_to_inject or "")
        body_matches = [
            field
            for field in (surface.inputs or [])
            if str(getattr(field, "kind", "") or "").lower() == "body"
            and str(getattr(field, "name", "") or "") == mutation_name
        ]
        mutation_path = ""
        mutate_body = bool(mutation_name and payload is not None and body_matches)
        if mutate_body:
            if len(body_matches) > 1:
                paths = {
                    str(getattr(field, "path", "") or "")
                    for field in body_matches
                }
                raise ValueError(
                    f"Body input '{mutation_name}' is ambiguous across paths: {sorted(paths)}"
                )
            mutation_path = str(getattr(body_matches[0], "path", "") or "")

        materialized = materialize_surface_request(
            surface,
            auth_headers=dict(self.config.get("auth", {}).get("headers", {}) or {}),
            cookies=dict(self.cookies),
            body_mutation_name=mutation_name,
            body_mutation_path=mutation_path,
            body_mutation_payload=payload,
            mutate_body=mutate_body,
        )
        params = dict(materialized.params)
        if mutation_name and payload is not None and mutation_name in params:
            params[mutation_name] = payload

        return self.send_as_actor(
            materialized.method,
            surface.url,
            actor=actor,
            params=params or None,
            data=materialized.data,
            json=materialized.json,
            headers=materialized.headers or None,
            cookies=materialized.cookies or None,
            timeout=self.timeout,
            source=surface.source,
            replay_of=replay_of,
        )
