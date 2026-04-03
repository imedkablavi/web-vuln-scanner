from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

from core.auth_harness import ResponseComparator
from workflows.scenario_models import WorkflowInstance, WorkflowStep, WorkflowStepResult


class StepExecutor:
    """
    Low-level single-step executor.

    This class does not own workflow lifecycle, actor transitions, replay orchestration,
    or workflow verdict decisions. It executes one step at a time using shared runtime
    services provided by the caller.
    """

    def __init__(self, requester, auth_session_manager=None):
        self.requester = requester
        self.auth_session_manager = auth_session_manager or getattr(requester, "auth_session_manager", None)
        self.comparator = ResponseComparator()

    async def execute(self, instance: WorkflowInstance, step: WorkflowStep, runtime: Dict[str, Any]) -> WorkflowStepResult:
        actor_id = str(step.actor_id or runtime.get("current_actor_id") or "").strip()
        variables = runtime["variables"]
        result = WorkflowStepResult(
            step_id=step.step_id,
            step_type=step.step_type,
            actor_id=actor_id,
            status="running",
            target=str(variables.render(step.target, actor_id=actor_id) or ""),
            started_at=_now_iso(),
            finished_at=_now_iso(),
        )
        resolved_input = variables.render(step.input_data, actor_id=actor_id)
        resolved_selectors = variables.render(step.selectors, actor_id=actor_id)
        result.metadata["resolved_input"] = resolved_input
        result.metadata["resolved_selectors"] = resolved_selectors

        if not step.enabled:
            result.status = "skipped"
            result.notes.append("Step disabled in workflow definition.")
            return result

        if step.step_type == "switch_actor":
            target_actor = actor_id or str(resolved_input.get("actor_id", "") or "").strip()
            state = None
            if self.auth_session_manager is not None and target_actor:
                state = self.auth_session_manager.get_state(target_actor)
            result.status = "completed" if target_actor else "failed"
            result.metadata["switch_to_actor_id"] = target_actor
            result.metadata["actor_state"] = state.to_summary() if state is not None else {}
            if not target_actor:
                result.error = "switch_actor step did not specify actor_id"
            return result

        if step.step_type == "ensure_actor_ready":
            actor = self.auth_session_manager.get_actor(actor_id) if self.auth_session_manager is not None else None
            state = self.auth_session_manager.ensure_authenticated(actor or actor_id) if self.auth_session_manager is not None else None
            result.metadata["actor_state"] = state.to_summary() if state is not None else {}
            result.status = "completed" if state is not None and state.actor_ready else "blocked_auth"
            if result.status != "completed":
                result.notes.append("Actor did not reach an authenticated ready state.")
            return result

        if step.step_type in {"visit_url", "api_call"} and not step.use_browser:
            return self._execute_http_step(step, actor_id, resolved_input, result, runtime)

        if step.use_browser or step.step_type in {
            "visit_url",
            "click",
            "fill",
            "submit",
            "wait_for_url",
            "wait_for_selector",
            "extract_text",
            "extract_attribute",
            "capture_dom",
            "capture_screenshot",
        }:
            return await self._execute_browser_step(step, actor_id, resolved_input, resolved_selectors, result, runtime)

        return self._execute_runtime_only_step(step, actor_id, resolved_input, result, runtime)

    def _execute_http_step(self, step: WorkflowStep, actor_id: str, resolved_input: Dict[str, Any], result: WorkflowStepResult, runtime: Dict[str, Any]) -> WorkflowStepResult:
        actor = self.auth_session_manager.get_actor(actor_id) if self.auth_session_manager is not None and actor_id else None
        method = (step.method or "GET").upper()
        url = result.target
        source = f"workflow:{runtime['instance'].workflow_id}:{step.step_id}"
        if method == "GET":
            response = self.requester.send_as_actor(method, url, actor=actor, params=resolved_input or None, source=source)
            params = resolved_input or {}
            data = {}
            json_body = {}
        else:
            body_format = str(step.assertion_rules.get("body_format", "data")).strip().lower()
            params = {}
            data = resolved_input or {}
            json_body = {}
            if body_format == "json":
                json_body = resolved_input or {}
                data = {}
            response = self.requester.send_as_actor(
                method,
                url,
                actor=actor,
                data=data or None,
                json=json_body or None,
                source=source,
            )
        result.status = "completed"
        result.url = getattr(response, "url", url)
        result.status_code = int(getattr(response, "status_code", 0) or 0)
        body_text = getattr(response, "text", "") or ""
        result.response_excerpt = body_text[:240]
        result.metadata["response_headers"] = dict(getattr(response, "headers", {}) or {})
        result.metadata["response_body"] = body_text
        result.metadata["json_body"] = _safe_json_load(body_text)
        result.metadata["observed_status"] = result.status_code
        result.metadata["request_fingerprint"] = self._request_fingerprint(method, url, actor_id, params=params, data=data, json_body=json_body)
        if result.metadata["request_fingerprint"]:
            result.request_fingerprints.append(result.metadata["request_fingerprint"])
        runtime["last_http_response"] = response
        runtime["last_response_actor_id"] = actor_id
        runtime["last_observation"] = {
            "kind": "http",
            "status_code": result.status_code,
            "body": body_text,
            "url": result.url,
        }
        if step.store_as:
            stored = self._extract_http_store_value(step, result.metadata)
            result.extracted_values[step.store_as] = stored
        return result

    async def _execute_browser_step(
        self,
        step: WorkflowStep,
        actor_id: str,
        resolved_input: Dict[str, Any],
        resolved_selectors: Dict[str, str],
        result: WorkflowStepResult,
        runtime: Dict[str, Any],
    ) -> WorkflowStepResult:
        browser = runtime.get("browser")
        if browser is None:
            result.status = "failed"
            result.error = "browser runtime unavailable"
            return result
        page = await runtime["get_actor_page"](actor_id, step)
        result.url = page.url
        timeout = max(500, int(step.timeout_ms or 5000))

        if step.step_type == "visit_url":
            response = await page.goto(result.target, wait_until="networkidle", timeout=timeout)
            result.url = page.url
            result.status_code = getattr(response, "status", 0) if response is not None else 0
            result.status = "completed"
            result.metadata["observed_status"] = result.status_code
        elif step.step_type == "click":
            selector = resolved_selectors.get("selector", "")
            await page.click(selector, timeout=timeout)
            await page.wait_for_load_state("networkidle")
            result.url = page.url
            result.status = "completed"
        elif step.step_type == "fill":
            selector = resolved_selectors.get("selector", "")
            value = str(resolved_input.get("value", ""))
            await page.fill(selector, value, timeout=timeout)
            result.status = "completed"
            result.extracted_values[step.store_as or "filled_value"] = value
        elif step.step_type == "submit":
            selector = resolved_selectors.get("selector") or resolved_selectors.get("submit")
            if selector:
                await page.click(selector, timeout=timeout)
            else:
                await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle")
            result.url = page.url
            result.status = "completed"
        elif step.step_type == "wait_for_url":
            expected = str(resolved_input.get("contains") or step.assertion_rules.get("contains") or "")
            await page.wait_for_url(lambda current: expected in current, timeout=timeout)
            result.url = page.url
            result.metadata["observed_url"] = page.url
            result.status = "completed"
        elif step.step_type == "wait_for_selector":
            selector = resolved_selectors.get("selector", "")
            await page.locator(selector).wait_for(timeout=timeout)
            result.status = "completed"
        elif step.step_type == "extract_text":
            selector = resolved_selectors.get("selector", "")
            value = await page.locator(selector).inner_text(timeout=timeout)
            result.status = "completed"
            if step.store_as:
                result.extracted_values[step.store_as] = value
            result.metadata["extracted_text"] = value
        elif step.step_type == "extract_attribute":
            selector = resolved_selectors.get("selector", "")
            attribute = str(resolved_input.get("attribute") or step.assertion_rules.get("attribute") or "value")
            value = await page.locator(selector).get_attribute(attribute, timeout=timeout)
            result.status = "completed"
            if step.store_as:
                result.extracted_values[step.store_as] = value
            result.metadata["extracted_attribute"] = {"name": attribute, "value": value}
        elif step.step_type == "capture_dom":
            artifact = await runtime["capture_dom"](page, actor_id, step)
            result.status = "completed"
            if artifact:
                result.artifact_refs.append(artifact)
        elif step.step_type == "capture_screenshot":
            artifact = await runtime["capture_screenshot"](page, actor_id, step)
            result.status = "completed"
            if artifact:
                result.artifact_refs.append(artifact)
        elif step.step_type == "assert_text":
            body_text = await page.locator("body").inner_text()
            result.status = "completed"
            result.metadata["observed_text"] = body_text
        elif step.step_type == "assert_visibility":
            selector = resolved_selectors.get("selector", "")
            result.status = "completed"
            result.metadata["visible"] = await page.locator(selector).is_visible()
        else:
            result.status = "failed"
            result.error = f"unsupported browser step type: {step.step_type}"
            return result

        try:
            body_text = await page.locator("body").inner_text()
        except Exception:
            body_text = ""
        result.url = page.url
        result.response_excerpt = body_text[:240]
        result.metadata.setdefault("response_body", body_text)
        runtime["last_browser_page"] = page
        runtime["last_observation"] = {
            "kind": "browser",
            "url": page.url,
            "body": body_text,
            "status_code": result.status_code,
        }
        return result

    def _execute_runtime_only_step(self, step: WorkflowStep, actor_id: str, resolved_input: Dict[str, Any], result: WorkflowStepResult, runtime: Dict[str, Any]) -> WorkflowStepResult:
        last_http_response = runtime.get("last_http_response")
        last_observation = runtime.get("last_observation", {}) or {}
        body = str(last_observation.get("body", "") or "")
        observed_status = int(last_observation.get("status_code", getattr(last_http_response, "status_code", 0) or 0))

        if step.step_type == "store_value":
            value = resolved_input.get("value")
            if step.store_as:
                result.extracted_values[step.store_as] = value
            result.status = "completed"
        elif step.step_type == "reuse_value":
            key = str(resolved_input.get("key") or step.store_as or "")
            value = runtime["variables"].get_value(key, actor_id=actor_id)
            result.status = "completed"
            result.metadata["reused_value"] = value
            if step.store_as:
                result.extracted_values[step.store_as] = value
        elif step.step_type == "assert_status":
            result.status = "completed"
            result.metadata["observed_status"] = observed_status
        elif step.step_type == "assert_text":
            result.status = "completed"
            result.metadata["observed_text"] = body
        elif step.step_type == "assert_visibility":
            result.status = "completed"
            result.metadata["visible"] = bool(last_observation.get("visible", False))
        elif step.step_type == "assert_denied":
            pseudo_response = _PseudoResponse(observed_status, body, last_observation.get("url", result.target), {})
            result.status = "completed"
            result.metadata["denial"] = self.comparator.detect_denial(pseudo_response)
        elif step.step_type == "assert_masked":
            markers = [str(item) for item in (step.assertion_rules.get("markers", []) or []) if str(item).strip()]
            hits = [marker for marker in markers if marker.lower() in body.lower()]
            result.status = "completed"
            result.metadata["masked_markers"] = hits
        elif step.step_type == "assert_policy_outcome":
            result.status = "completed"
            result.metadata["policy_expected"] = str(resolved_input.get("expected") or step.assertion_rules.get("expected") or "")
        else:
            result.status = "failed"
            result.error = f"unsupported runtime step type: {step.step_type}"
        return result

    def _request_fingerprint(self, method: str, url: str, actor_id: str, *, params=None, data=None, json_body=None) -> str:
        if hasattr(self.requester, "_request_fingerprint"):
            return self.requester._request_fingerprint(method, url, actor_id=actor_id, params=params, data=data, json_body=json_body)  # noqa: SLF001
        return ""

    def _extract_http_store_value(self, step: WorkflowStep, metadata: Dict[str, Any]) -> Any:
        json_body = metadata.get("json_body")
        if isinstance(json_body, dict):
            json_path = str(step.assertion_rules.get("json_path") or step.input_data.get("json_path") or "")
            if json_path:
                current: Any = json_body
                for chunk in [part for part in json_path.split(".") if part]:
                    if not isinstance(current, dict):
                        return None
                    current = current.get(chunk)
                return current
        return metadata.get("response_body", "")


class _PseudoResponse:
    def __init__(self, status_code: int, text: str, url: str, headers: Dict[str, Any]):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers


def _safe_json_load(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Compatibility alias for older imports. This is intentionally an executor, not a workflow orchestrator.
WorkflowRunner = StepExecutor
