import requests
import time
import random
import threading
import ipaddress
import json
import os
import hashlib
from collections import defaultdict
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from urllib.parse import urlparse
from .utils import logger
from .models import AttackSurface, AuthActor, ActorSession, RequestRecord, ResponseRecord


class RequestManager:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(config.get("auth", {}).get("headers", {}))
        self.cookies = config.get("auth", {}).get("cookies", {})
        self.session.cookies.update(self.cookies)
        self.delay = config["concurrency"]["delay"]
        self.max_retries = config["concurrency"]["max_retries"]
        self.timeout = config["concurrency"]["timeout"]
        req_cfg = config.get("request", {})
        timeouts_cfg = req_cfg.get("timeouts", {})
        self.connect_timeout = timeouts_cfg.get("connect", self.timeout)
        self.read_timeout = timeouts_cfg.get("read", self.timeout)
        self.max_retries = req_cfg.get("max_retries", self.max_retries)
        self.follow_redirects = req_cfg.get("follow_redirects", False)
        self.circuit_breaker = defaultdict(int)
        self.circuit_window = 60
        self.last_reset = time.time()
        self._lock = threading.Lock()
        self.per_host_limit = int(config.get("concurrency", {}).get("per_host_concurrency", max(1, config["concurrency"].get("threads", 1))))
        self._host_semaphores = defaultdict(lambda: threading.Semaphore(self.per_host_limit))
        scope = config.get("scope", {})
        self.include_domains = scope.get("include_domains", [])
        self.allow_private = scope.get("allow_private", False)
        self.auth_session_manager = None
        self.event_bus = None
        if config.get("auth_verification", {}).get("enabled"):
            try:
                from .auth_session_manager import AuthSessionManager

                self.auth_session_manager = AuthSessionManager(config, requester=self)
                try:
                    from .browser_auth_engine import BrowserAuthEngine

                    self.auth_session_manager.attach_browser_auth_engine(BrowserAuthEngine(config))
                except Exception as exc:  # pragma: no cover - defensive path
                    logger.warning(f"Browser auth engine bootstrap failed: {exc}")
            except Exception as exc:  # pragma: no cover - defensive path
                logger.warning(f"Auth session manager bootstrap failed: {exc}")
                self.auth_session_manager = None

    def attach_auth_session_manager(self, session_manager):
        self.auth_session_manager = session_manager

    def attach_event_bus(self, event_bus):
        self.event_bus = event_bus

    def _request_fingerprint(self, method, url, actor_id="", params=None, data=None, json_body=None):
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
        host_with_port = (host_with_port or host).lower()
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                if not self.allow_private:
                    return False
        except ValueError:
            pass
        if not self.include_domains:
            return True
        for dom in self.include_domains:
            dom = str(dom).lower().strip().rstrip(".")
            if dom.startswith("*."):
                suffix = dom[2:].split(":", 1)[0]
                if host == suffix or host.endswith(f".{suffix}"):
                    return True
            else:
                if ":" in dom:
                    if host_with_port == dom:
                        return True
                elif host == dom:
                    return True
        return False

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
            return max(0, int((when - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return fallback

    def send(self, method, url, params=None, data=None, headers=None, cookies=None, timeout=None, json=None, allow_redirects=None, actor_id="", source="", replay_of=""):
        """Centralized request sending with scope checks, bounded concurrency and retries."""
        self._reset_circuit()
        parsed = urlparse(url)
        host = parsed.hostname or ""
        host_with_port = parsed.netloc or host
        if parsed.scheme not in {"http", "https"}:
            raise RuntimeError(f"Unsupported URL scheme: {parsed.scheme or '<missing>'}")
        if not host:
            raise RuntimeError(f"Invalid host parsed from URL: {url}")
        if not self._host_allowed(host, host_with_port):
            logger.warning(f"Request to host {host_with_port} blocked by scope/SSRF guard.")
            raise RuntimeError(f"Host {host_with_port} not allowed by scope")

        with self._lock:
            if self.circuit_breaker.get(host, 0) >= 3:
                logger.warning(f"Circuit breaker open for host {host}, skipping request.")
                raise RuntimeError(f"Circuit open for host {host}")

        effective_timeout = timeout if timeout is not None else (self.connect_timeout, self.read_timeout)
        sem = self._host_semaphores[host]
        sem.acquire()
        try:
            retries = 0
            backoff = 1
            while retries <= self.max_retries:
                base_delay = max(0, float(self.delay) * (0.5 if self.circuit_breaker.get(host, 0) == 0 else 1.0))
                jitter_window = 0 if self.delay <= 0 else min(0.1, max(0.01, float(self.delay) * 0.25))
                time.sleep(base_delay + random.uniform(0, jitter_window))
                try:
                    resp = self.session.request(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json,
                        headers=headers,
                        cookies=self.cookies if cookies is None else cookies,
                        timeout=effective_timeout,
                        allow_redirects=self.follow_redirects if allow_redirects is None else allow_redirects,
                    )

                    if resp.status_code in (429, 503):
                        wait_time = self._retry_after_seconds(resp.headers.get("Retry-After"), backoff)
                        wait_time = min(wait_time, 30)
                        logger.warning(f"Rate limited ({resp.status_code}). Waiting {wait_time}s before retry.")
                        time.sleep(wait_time)
                        retries += 1
                        backoff = min(backoff * 2, 30)
                        with self._lock:
                            self.circuit_breaker[host] += 1
                        continue
                    with self._lock:
                        self.circuit_breaker[host] = 0
                    if self.event_bus is not None:
                        fingerprint = self._request_fingerprint(method, url, actor_id=actor_id, params=params, data=data, json_body=json)
                        self.event_bus.emit_record(
                            "request",
                            RequestRecord(
                                fingerprint=fingerprint,
                                method=str(method).upper(),
                                url=url,
                                actor_id=actor_id,
                                source=source,
                                params=params or data or json or {},
                                headers=headers or {},
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
                                content_length=len(getattr(resp, "text", "") or ""),
                                headers=dict(getattr(resp, "headers", {}) or {}),
                                excerpt=(getattr(resp, "text", "") or "")[:220],
                            ),
                        )
                    return resp

                except requests.RequestException as e:
                    logger.error(f"Request failed: {e}")
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

    def build_actor_session(self, actor: AuthActor | None) -> ActorSession | None:
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

    def send_as_actor(self, method, url, *, actor: AuthActor | None = None, params=None, data=None, headers=None, cookies=None, timeout=None, json=None, allow_redirects=None, source="direct", replay_of=""):
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
        if actor is None or getattr(actor, "auth_type", "") == "none" or self.auth_session_manager is None or not self.auth_session_manager.response_requires_reauth(response):
            return response
        refreshed_state = self.auth_session_manager.handle_auth_failure(actor, response)
        if not refreshed_state or not getattr(refreshed_state, "actor_ready", False):
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

    def send_surface(self, surface: AttackSurface, param_to_inject=None, payload=None, actor: AuthActor | None = None, replay_of=""):
        base_params = dict(surface.params)
        base_data = {}
        base_headers = self.config.get("auth", {}).get("headers", {}).copy()
        base_cookies = dict(self.cookies)
        actor_session = self.build_actor_session(actor)
        if actor_session:
            base_headers.update(actor_session.headers)
            base_cookies.update(actor_session.cookies)
        has_body_inputs = False
        for field in surface.inputs:
            if field.kind == "body":
                has_body_inputs = True
                base_data[field.name] = field.value or ""
            elif field.kind == "query":
                base_params[field.name] = field.value or ""
            elif field.kind == "header":
                base_headers[field.name] = field.value or ""
            elif field.kind == "cookie":
                base_cookies[field.name] = field.value or ""

        if param_to_inject and payload is not None:
            if param_to_inject in base_params:
                base_params[param_to_inject] = payload
            if param_to_inject in base_data:
                base_data[param_to_inject] = payload

        method = surface.method.upper()
        if has_body_inputs and method == "GET":
            logger.info(f"Adjusting method to POST for body inputs on {surface.url}")
            method = "POST"
        supported = {"GET", "POST", "PUT", "DELETE", "PATCH"}
        if method not in supported:
            logger.warning(f"Unsupported HTTP method {method} for surface {surface.url}, falling back to GET")
            method = "GET"

        json_payload = None
        if surface.meta.get("content_type", "").startswith("application/json"):
            json_payload = base_data
            base_data = None

        def _dispatch(request_headers, request_cookies):
            return self.send(
                method=method,
                url=surface.url,
                params=base_params if method == "GET" else None,
                data=base_data if method != "GET" else None,
                json=json_payload,
                headers=request_headers,
                cookies=request_cookies,
                timeout=self.timeout,
                actor_id=getattr(actor, "actor_id", ""),
                source=surface.source,
                replay_of=replay_of,
            )

        response = _dispatch(dict(base_headers), dict(base_cookies))
        if actor is None or getattr(actor, "auth_type", "") == "none" or self.auth_session_manager is None:
            return response
        if not self.auth_session_manager.response_requires_reauth(response):
            return response
        refreshed_state = self.auth_session_manager.handle_auth_failure(actor, response)
        if not refreshed_state or not getattr(refreshed_state, "actor_ready", False):
            return response
        refreshed_session = self.build_actor_session(actor)
        retry_headers = self.config.get("auth", {}).get("headers", {}).copy()
        retry_cookies = dict(self.cookies)
        if refreshed_session:
            retry_headers.update(refreshed_session.headers)
            retry_cookies.update(refreshed_session.cookies)
        for field in surface.inputs:
            if field.kind == "header":
                retry_headers[field.name] = field.value or ""
            elif field.kind == "cookie":
                retry_cookies[field.name] = field.value or ""
        return _dispatch(retry_headers, retry_cookies)