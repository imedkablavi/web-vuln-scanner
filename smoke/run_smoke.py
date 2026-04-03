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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 5.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(url, timeout=1)
            if resp.status_code in (200, 403, 404, 500):
                return True
        except Exception:
            time.sleep(0.2)
    return False


def main() -> int:
    port = _find_free_port()
    server_cmd = [sys.executable, str(ROOT / "smoke" / "mock_server.py"), "--port", str(port)]
    server_proc = subprocess.Popen(server_cmd, cwd=ROOT)

    target = f"http://127.0.0.1:{port}"
    if not _wait_for_server(f"{target}/clean"):
        server_proc.terminate()
        print("Mock server failed to start", file=sys.stderr)
        return 1

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (ROOT / "config" / "default_config.yaml").open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    config["scanner"]["browser_enabled"] = True
    config["scanner"]["browser"]["headless"] = True
    config["scanner"]["browser"]["slow_mo"] = 0
    config["scanner"]["rbac_matrix_file"] = str(ROOT / "config" / "rbac_matrix.yaml")
    config["scanner"]["workflows"]["enabled"] = True
    config["scanner"]["workflows"]["directory"] = str(ROOT / "workflows" / "default")
    auth_cfg = config["scanner"]["auth_verification"]
    auth_cfg["enabled"] = True
    auth_cfg["authenticated_crawl"] = {"enabled": True, "actor_ids": ["low_user", "peer_user", "api_user"]}
    actors = {actor["actor_id"]: actor for actor in auth_cfg["actors"]}
    for actor_id, username, password in (
        ("low_user", "LOW_USER_USERNAME", "LOW_USER_PASSWORD"),
        ("admin_user", "ADMIN_USER_USERNAME", "ADMIN_USER_PASSWORD"),
    ):
        actor = actors[actor_id]
        actor["enabled"] = True
        actor.setdefault("auth", {})
        actor["auth"]["login_url"] = f"{target}/login"
        actor["auth"]["verify_url"] = f"{target}/dashboard"
        actor["auth"]["username_env"] = username
        actor["auth"]["password_env"] = password
        actor["auth"]["success_indicators"] = ["Logout"]
        actor["auth"]["failure_indicators"] = ["Invalid credentials", "/login"]
        actor["auth"]["session"] = {
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
    peer_actor = actors["peer_user"]
    peer_actor["enabled"] = True
    peer_actor.setdefault("auth", {})
    peer_actor["auth"].update(
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
    api_actor["auth"]["token_url"] = f"{target}/api/login"
    api_actor["auth"]["refresh_url"] = f"{target}/api/refresh"
    api_actor["auth"]["verify_url"] = f"{target}/api/profile"
    api_actor["auth"]["username_env"] = "API_USER_USERNAME"
    api_actor["auth"]["password_env"] = "API_USER_PASSWORD"
    api_actor["auth"]["success_indicators"] = []
    api_actor["auth"]["session"] = {
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
                    "refresh": {"enabled": True, "strategy": "relogin", "pre_expiry_seconds": 10, "max_attempts": 1},
                },
            },
        }
    )
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, sort_keys=False)
    scan_env = os.environ.copy()
    scan_env.update(
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

    scan_cmd = [
        sys.executable,
        "main_v2.py",
        "scan",
        target,
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
    scan_run = subprocess.run(scan_cmd, cwd=ROOT, capture_output=True, text=True, env=scan_env)

    # Ensure mock server is stopped
    server_proc.terminate()
    try:
        server_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server_proc.kill()

    if not REPORT_PATH.exists():
        print("Scan report not generated", file=sys.stderr)
        print(scan_run.stdout)
        print(scan_run.stderr, file=sys.stderr)
        return 1

    with REPORT_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    has_verified_sqli = any(
        f.get("plugin") == "sqli" and f.get("verification_status") == "verified"
        for f in findings
    )
    has_suspected_object_variance = any(
        f.get("plugin") == "business_logic" and f.get("verification_status") == "suspected"
        for f in findings
    )
    has_web_posture = any(
        f.get("plugin") == "web_posture" and f.get("type") == "Missing Security Headers"
        for f in findings
    )
    has_data_exposure = any(
        f.get("plugin") == "data_exposure" and f.get("type") == "Exposed File or Backup"
        for f in findings
    )
    has_api_posture = any(
        f.get("plugin") == "api_posture" and f.get("type") == "GraphQL Introspection Enabled"
        for f in findings
    )
    has_dns_tls = any(
        f.get("plugin") == "dns_tls" and f.get("type") == "HTTPS Not Enabled"
        for f in findings
    )
    verified_access_control = [
        f for f in findings
        if f.get("plugin") == "business_logic" and f.get("verification_status") == "verified"
    ]
    has_verified_bypass = any("/auth_bypass" in f.get("url", "") for f in verified_access_control)
    has_false_verified_safe = any("/auth_safe" in f.get("url", "") for f in verified_access_control)
    has_false_verified_masked = any("/auth_masked" in f.get("url", "") for f in verified_access_control)
    auth_sessions = data.get("scan_info", {}).get("auth_sessions", {})
    browser_login_summary = data.get("scan_info", {}).get("browser_login_summary", {})
    replay_summary = data.get("scan_info", {}).get("replay_summary", {})
    workflow_summary = data.get("scan_info", {}).get("workflow_summary", {})
    workflow_replay_summary = data.get("scan_info", {}).get("workflow_replay_summary", {})
    rbac_summary = data.get("scan_info", {}).get("rbac_policy_summary", {})
    artifact_index = data.get("scan_info", {}).get("artifact_index", [])
    auth_states = auth_sessions.get("actor_states", {})
    has_auth_summary = bool(auth_sessions)
    low_user_ready = auth_states.get("low_user", {}).get("actor_ready") is True
    peer_user_browser_origin = auth_states.get("peer_user", {}).get("session_origin") == "browser_login"
    api_refresh_count = int(auth_states.get("api_user", {}).get("refresh_count", 0) or 0)
    broken_user_failed = auth_states.get("broken_user", {}).get("session_status") == "login_failed"
    has_browser_login_summary = "peer_user" in (browser_login_summary.get("successful_handoff") or [])
    has_rbac_verified = int(rbac_summary.get("violates_policy_verified", 0) or 0) >= 1
    has_replay_artifact = any(item.get("kind") == "replay" for item in artifact_index)
    has_replay_summary = int(replay_summary.get("reproduced", 0) or 0) >= 1
    workflow_findings = [f for f in findings if f.get("plugin") == "workflow_runner"]
    has_workflow_verified_policy = any(f.get("verification_basis") == "policy-backed" and "/auth_bypass" in f.get("url", "") for f in workflow_findings if f.get("verification_status") == "verified")
    has_workflow_verified_proof = any(f.get("verification_basis") == "proof-backed" and "/workflow/documents/view_bypass" in f.get("url", "") for f in workflow_findings if f.get("verification_status") == "verified")
    has_false_workflow_masked = any("/auth_masked" in f.get("url", "") and f.get("verification_status") == "verified" for f in workflow_findings)
    workflow_executions = workflow_summary.get("executions", []) if isinstance(workflow_summary, dict) else []
    has_partial_workflow = any(item.get("workflow_id") == "partial_auth_workflow" and item.get("status") == "partial" for item in workflow_executions)
    has_workflow_execution_artifact = any(item.get("kind") == "workflow-execution" for item in artifact_index)
    has_workflow_replay_artifact = any(item.get("kind") == "workflow-replay" for item in artifact_index)
    has_workflow_replay_summary = int(workflow_replay_summary.get("attempted", 0) or 0) >= 1
    has_workflow_replay_reproduced = int(workflow_replay_summary.get("replayed", 0) or 0) >= 1

    if not all([has_verified_sqli, has_web_posture, has_data_exposure, has_api_posture, has_dns_tls, has_verified_bypass, has_auth_summary, low_user_ready, peer_user_browser_origin, has_browser_login_summary, has_rbac_verified, has_replay_summary, has_replay_artifact, broken_user_failed, has_workflow_verified_policy, has_workflow_verified_proof, has_partial_workflow, has_workflow_execution_artifact, has_workflow_replay_artifact, has_workflow_replay_summary, has_workflow_replay_reproduced]) or has_false_verified_safe or has_false_verified_masked or has_false_workflow_masked or api_refresh_count < 1:
        print("Smoke validation failed: expected truthful layered findings, browser-driven login handoff, deterministic RBAC verification, workflow execution/replay artifacts, auth session summary, and no false verified safe auth route", file=sys.stderr)
        print(json.dumps(findings, indent=2))
        print("--- scanner stdout ---")
        print(scan_run.stdout)
        print("--- scanner stderr ---", file=sys.stderr)
        print(scan_run.stderr, file=sys.stderr)
        return 1

    print("Smoke run successful.")
    print(
        "Layered findings present: "
        f"verified_sqli={has_verified_sqli}, object_variance={has_suspected_object_variance}, "
        f"web_posture={has_web_posture}, data_exposure={has_data_exposure}, api_posture={has_api_posture}, dns_tls={has_dns_tls}, "
        f"verified_auth_bypass={has_verified_bypass}, false_verified_safe={has_false_verified_safe}, false_verified_masked={has_false_verified_masked}, "
        f"auth_summary={has_auth_summary}, low_user_ready={low_user_ready}, peer_user_browser_origin={peer_user_browser_origin}, browser_login_summary={has_browser_login_summary}, "
        f"rbac_verified={has_rbac_verified}, replay_summary={has_replay_summary}, replay_artifact={has_replay_artifact}, "
        f"workflow_verified_policy={has_workflow_verified_policy}, workflow_verified_proof={has_workflow_verified_proof}, partial_workflow={has_partial_workflow}, "
        f"workflow_replay_summary={has_workflow_replay_summary}, workflow_replay_reproduced={has_workflow_replay_reproduced}, "
        f"workflow_execution_artifact={has_workflow_execution_artifact}, workflow_replay_artifact={has_workflow_replay_artifact}, "
        f"api_refresh_count={api_refresh_count}, broken_user_failed={broken_user_failed}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
