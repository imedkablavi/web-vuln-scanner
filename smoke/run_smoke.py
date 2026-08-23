import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests
import yaml


ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "smoke_out"
REPORT_PATH = OUTPUT_DIR / "scan_report.json"
CONFIG_PATH = OUTPUT_DIR / "smoke_config.yaml"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 5.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(url, timeout=1)
            if response.status_code in (200, 403, 404, 500):
                return True
        except Exception:
            time.sleep(0.2)
    return False


def _configure_actor(actor, target, username_env, password_env):
    actor["enabled"] = True
    auth = actor.setdefault("auth", {})
    auth["login_url"] = f"{target}/login"
    auth["verify_url"] = f"{target}/dashboard"
    auth["username_env"] = username_env
    auth["password_env"] = password_env
    auth["success_indicators"] = ["Logout"]
    auth["failure_indicators"] = ["Invalid credentials", "/login"]
    auth["session"] = {
        "cookie_names": ["session"],
        "csrf_cookie_names": ["csrf"],
        "refresh": {
            "enabled": True,
            "strategy": "relogin",
            "pre_expiry_seconds": 10,
            "retry_on_401": True,
            "max_attempts": 1,
            "relogin_on_failure": True,
        },
    }


def _prepare_config(target: str) -> None:
    with (ROOT / "config" / "default_config.yaml").open(
        "r", encoding="utf-8"
    ) as handle:
        config = yaml.safe_load(handle)

    scanner = config["scanner"]
    scanner["browser_enabled"] = True
    scanner["browser"]["headless"] = True
    scanner["browser"]["slow_mo"] = 0
    # Auth traces/screenshots/storage retention intentionally remain disabled.
    # The smoke suite validates browser login using in-memory handoff state and
    # must not create credential-bearing diagnostic artifacts by default.
    scanner["rbac_matrix_file"] = str(ROOT / "config" / "rbac_matrix.yaml")
    scanner["workflows"]["enabled"] = True
    scanner["workflows"]["directory"] = str(ROOT / "workflows" / "default")

    auth_cfg = scanner["auth_verification"]
    auth_cfg["enabled"] = True
    auth_cfg["authenticated_crawl"] = {
        "enabled": True,
        "actor_ids": ["low_user", "peer_user", "api_user"],
    }
    actors = {actor["actor_id"]: actor for actor in auth_cfg["actors"]}

    _configure_actor(
        actors["low_user"],
        target,
        "LOW_USER_USERNAME",
        "LOW_USER_PASSWORD",
    )
    _configure_actor(
        actors["admin_user"],
        target,
        "ADMIN_USER_USERNAME",
        "ADMIN_USER_PASSWORD",
    )

    peer_actor = actors["peer_user"]
    peer_actor["enabled"] = True
    peer_actor.setdefault("auth", {}).update(
        {
            "auth_scheme": "browser_form_login",
            "login_url": f"{target}/spa-login",
            "browser_login_url": f"{target}/spa-login",
            "browser_required": True,
            "use_browser": True,
            "verify_url": f"{target}/spa-dashboard",
            "username_env": "PEER_USER_USERNAME",
            "password_env": "PEER_USER_PASSWORD",
            "username_selector": 'input[name="username"]',
            "password_selector": 'input[name="password"]',
            "submit_selector": "#spa-submit",
            "success_selector": 'a[href="/logout"]',
            "wait_for_url_contains": "/spa-dashboard",
            "pre_submit_click_selectors": ["#open-login"],
            "browser_storage_keys": ["access_token"],
            "success_indicators": ["Logout", "/spa-dashboard"],
            "failure_indicators": ["Invalid credentials", "/spa-login"],
            "session": {
                "cookie_names": ["session"],
                "csrf_cookie_names": [],
                "refresh": {
                    "enabled": True,
                    "strategy": "relogin",
                    "pre_expiry_seconds": 10,
                    "retry_on_401": True,
                    "max_attempts": 1,
                    "relogin_on_failure": True,
                },
            },
        }
    )

    api_actor = actors["api_user"]
    api_actor["enabled"] = True
    api_auth = api_actor.setdefault("auth", {})
    api_auth["token_url"] = f"{target}/api/login"
    api_auth["refresh_url"] = f"{target}/api/refresh"
    api_auth["verify_url"] = f"{target}/api/profile"
    api_auth["username_env"] = "API_USER_USERNAME"
    api_auth["password_env"] = "API_USER_PASSWORD"
    api_auth["success_indicators"] = []
    api_auth["session"] = {
        "refresh": {
            "enabled": True,
            "strategy": "refresh_token",
            "pre_expiry_seconds": 10,
            "retry_on_401": True,
            "max_attempts": 1,
            "relogin_on_failure": True,
        }
    }

    auth_cfg["actors"].append(
        {
            "actor_id": "broken_user",
            "display_name": "Broken User",
            "auth_type": "cookie",
            "role": "low",
            "enabled": True,
            "auth": {
                "auth_scheme": "form_login",
                "login_url": f"{target}/login",
                "verify_url": f"{target}/dashboard",
                "username_env": "BROKEN_USER_USERNAME",
                "password_env": "BROKEN_USER_PASSWORD",
                "success_indicators": ["Logout"],
                "failure_indicators": ["Invalid credentials", "/login"],
                "session": {
                    "cookie_names": ["session"],
                    "csrf_cookie_names": ["csrf"],
                    "refresh": {
                        "enabled": True,
                        "strategy": "relogin",
                        "pre_expiry_seconds": 10,
                        "max_attempts": 1,
                    },
                },
            },
        }
    )

    with CONFIG_PATH.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)


def _scan_environment():
    env = os.environ.copy()
    env.update(
        {
            "LOW_USER_USERNAME": "low_user",
            "LOW_USER_PASSWORD": "lowpass",
            "PEER_USER_USERNAME": "peer_user",
            "PEER_USER_PASSWORD": "peerpass",
            "ADMIN_USER_USERNAME": "admin_user",
            "ADMIN_USER_PASSWORD": "adminpass",
            "API_USER_USERNAME": "api_user",
            "API_USER_PASSWORD": "apipass",
            "BROKEN_USER_USERNAME": "low_user",
            "BROKEN_USER_PASSWORD": "wrongpass",
        }
    )
    return env


def _validate_report(data):
    findings = data.get("findings", [])
    scan_info = data.get("scan_info", {})

    has_verified_sqli = any(
        finding.get("plugin") == "sqli"
        and finding.get("verification_status") == "verified"
        for finding in findings
    )
    has_web_posture = any(
        finding.get("plugin") == "web_posture"
        and finding.get("type") == "Missing Security Headers"
        for finding in findings
    )
    has_data_exposure = any(
        finding.get("plugin") == "data_exposure"
        and finding.get("type") == "Exposed File or Backup"
        for finding in findings
    )
    has_api_posture = any(
        finding.get("plugin") == "api_posture"
        and finding.get("type") == "GraphQL Introspection Enabled"
        for finding in findings
    )
    has_dns_tls = any(
        finding.get("plugin") == "dns_tls"
        and finding.get("type") == "HTTPS Not Enabled"
        for finding in findings
    )

    verified_access_control = [
        finding
        for finding in findings
        if finding.get("plugin") == "business_logic"
        and finding.get("verification_status") == "verified"
    ]
    has_verified_bypass = any(
        "/auth_bypass" in finding.get("url", "")
        for finding in verified_access_control
    )
    has_false_verified_safe = any(
        "/auth_safe" in finding.get("url", "")
        for finding in verified_access_control
    )
    has_false_verified_masked = any(
        "/auth_masked" in finding.get("url", "")
        for finding in verified_access_control
    )

    auth_sessions = scan_info.get("auth_sessions", {})
    browser_login_summary = scan_info.get("browser_login_summary", {})
    replay_summary = scan_info.get("replay_summary", {})
    workflow_summary = scan_info.get("workflow_summary", {})
    workflow_replay_summary = scan_info.get("workflow_replay_summary", {})
    rbac_summary = scan_info.get("rbac_policy_summary", {})
    artifact_index = scan_info.get("artifact_index", [])
    auth_states = auth_sessions.get("actor_states", {})

    low_user_ready = auth_states.get("low_user", {}).get("actor_ready") is True
    peer_user_browser_origin = (
        auth_states.get("peer_user", {}).get("session_origin") == "browser_login"
    )
    api_refresh_count = int(
        auth_states.get("api_user", {}).get("refresh_count", 0) or 0
    )
    broken_user_failed = (
        auth_states.get("broken_user", {}).get("session_status") == "login_failed"
    )
    has_browser_login_summary = "peer_user" in (
        browser_login_summary.get("successful_handoff") or []
    )
    has_rbac_verified = int(
        rbac_summary.get("violates_policy_verified", 0) or 0
    ) >= 1
    has_replay_artifact = any(
        item.get("kind") == "replay" for item in artifact_index
    )
    has_replay_summary = int(replay_summary.get("reproduced", 0) or 0) >= 1

    workflow_findings = [
        finding for finding in findings if finding.get("plugin") == "workflow_runner"
    ]
    has_workflow_verified_policy = any(
        finding.get("verification_basis") == "policy-backed"
        and "/auth_bypass" in finding.get("url", "")
        for finding in workflow_findings
        if finding.get("verification_status") == "verified"
    )
    has_workflow_verified_proof = any(
        finding.get("verification_basis") == "proof-backed"
        and "/workflow/documents/view_bypass" in finding.get("url", "")
        for finding in workflow_findings
        if finding.get("verification_status") == "verified"
    )
    has_false_workflow_masked = any(
        "/auth_masked" in finding.get("url", "")
        and finding.get("verification_status") == "verified"
        for finding in workflow_findings
    )
    workflow_executions = (
        workflow_summary.get("executions", [])
        if isinstance(workflow_summary, dict)
        else []
    )
    has_partial_workflow = any(
        item.get("workflow_id") == "partial_auth_workflow"
        and item.get("status") == "partial"
        for item in workflow_executions
    )
    has_workflow_execution_artifact = any(
        item.get("kind") == "workflow-execution" for item in artifact_index
    )
    has_workflow_replay_artifact = any(
        item.get("kind") == "workflow-replay" for item in artifact_index
    )
    has_workflow_replay_summary = int(
        workflow_replay_summary.get("attempted", 0) or 0
    ) >= 1
    has_workflow_replay_reproduced = int(
        workflow_replay_summary.get("replayed", 0) or 0
    ) >= 1

    required = {
        "verified_sqli": has_verified_sqli,
        "web_posture": has_web_posture,
        "data_exposure": has_data_exposure,
        "api_posture": has_api_posture,
        "dns_tls": has_dns_tls,
        "verified_auth_bypass": has_verified_bypass,
        "auth_summary": bool(auth_sessions),
        "low_user_ready": low_user_ready,
        "peer_user_browser_origin": peer_user_browser_origin,
        "browser_login_summary": has_browser_login_summary,
        "rbac_verified": has_rbac_verified,
        "replay_summary": has_replay_summary,
        "replay_artifact": has_replay_artifact,
        "broken_user_failed": broken_user_failed,
        "workflow_verified_policy": has_workflow_verified_policy,
        "workflow_verified_proof": has_workflow_verified_proof,
        "partial_workflow": has_partial_workflow,
        "workflow_execution_artifact": has_workflow_execution_artifact,
        "workflow_replay_artifact": has_workflow_replay_artifact,
        "workflow_replay_summary": has_workflow_replay_summary,
        "workflow_replay_reproduced": has_workflow_replay_reproduced,
        "api_refresh": api_refresh_count >= 1,
    }
    forbidden = {
        "false_verified_safe": has_false_verified_safe,
        "false_verified_masked": has_false_verified_masked,
        "false_workflow_masked": has_false_workflow_masked,
    }
    return required, forbidden


def main() -> int:
    port = _find_free_port()
    server_cmd = [
        sys.executable,
        str(ROOT / "smoke" / "mock_server.py"),
        "--port",
        str(port),
    ]
    server_proc = subprocess.Popen(server_cmd, cwd=ROOT)
    target = f"http://127.0.0.1:{port}"

    try:
        if not _wait_for_server(f"{target}/clean"):
            print("Mock server failed to start", file=sys.stderr)
            return 1

        if OUTPUT_DIR.exists():
            shutil.rmtree(OUTPUT_DIR)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        _prepare_config(target)

        scanner_args = [
            "main_v2.py",
            "scan",
            target,
            "--profile",
            "full-authorized",
            "--config",
            str(CONFIG_PATH),
            "--swagger",
            f"{target}/openapi.json",
            "--graphql",
            f"{target}/graphql",
            "--output",
            str(OUTPUT_DIR),
            "--debug",
        ]
        if os.getenv("SMOKE_COVERAGE") == "1":
            scan_cmd = [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--parallel-mode",
                "--source=core,layers,plugins,workflows",
                *scanner_args,
            ]
        else:
            scan_cmd = [sys.executable, *scanner_args]

        scan_run = subprocess.run(
            scan_cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=_scan_environment(),
        )

        if not REPORT_PATH.exists():
            print("Scan report not generated", file=sys.stderr)
            print(scan_run.stdout)
            print(scan_run.stderr, file=sys.stderr)
            return 1

        with REPORT_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        # This fixture deliberately contains a broken actor and a partial
        # workflow, so the scanner must truthfully return the documented
        # partial/aborted code instead of pretending the run was fully clean.
        if scan_run.returncode != 3:
            print(
                f"Unexpected scanner exit code: {scan_run.returncode} (expected 3)",
                file=sys.stderr,
            )
            print(scan_run.stdout)
            print(scan_run.stderr, file=sys.stderr)
            return 1

        scan_status = str(data.get("scan_info", {}).get("status", "")).lower()
        if scan_status != "partial":
            print(
                f"Unexpected report status: {scan_status!r} (expected 'partial')",
                file=sys.stderr,
            )
            return 1

        required, forbidden = _validate_report(data)
        missing = [name for name, present in required.items() if not present]
        unexpected = [name for name, present in forbidden.items() if present]
        if missing or unexpected:
            if missing:
                print(f"Smoke validation missing: {missing}", file=sys.stderr)
            if unexpected:
                print(
                    f"Smoke validation false-positive regressions: {unexpected}",
                    file=sys.stderr,
                )
            print(json.dumps(data.get("scan_info", {}), indent=2))
            return 1

        print("Smoke run successful.")
        print(json.dumps(required, indent=2, sort_keys=True))
        return 0
    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server_proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
