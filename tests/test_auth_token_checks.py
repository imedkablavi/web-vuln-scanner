from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from layers.auth_token_checks import AuthTokenPostureScanner


def b64(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def jwt(header, payload):
    return f"{b64(header)}.{b64(payload)}.signature"


@dataclass
class Material:
    access_token: str = ""


@dataclass
class State:
    actor_ready: bool
    session_status: str
    session_material: Material


@dataclass
class Actor:
    actor_id: str
    bearer_token: str = ""


class Context:
    def __init__(self, actors):
        self._actors = actors

    def enabled_actors(self):
        return list(self._actors)


class Manager:
    def __init__(self, actor, state):
        self.context = Context([actor])
        self.states = {actor.actor_id: state}


def config():
    return {
        "passive_checks": {
            "auth_tokens": {
                "enabled": True,
                "max_lifetime_seconds": 3600,
            }
        }
    }


def test_unsigned_ready_jwt_is_high_severity_without_token_disclosure():
    token = jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "42", "iat": 1000, "exp": 8200, "iss": "issuer"},
    )
    actor = Actor("api_user")
    manager = Manager(actor, State(True, "authenticated", Material(token)))

    findings, meta = AuthTokenPostureScanner(config()).scan(manager)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "HIGH"
    assert finding.verification_status == "detected"
    assert "token declares alg=none" in finding.evidence["issues"]
    assert finding.evidence["actor_id"] == "api_user"
    assert token not in json.dumps(finding.evidence)
    assert meta["jwt_tokens_inspected"] == 1


def test_missing_exp_is_reported_but_non_jwt_is_ignored():
    token = jwt({"alg": "RS256"}, {"sub": "42", "iat": 1000})
    actor = Actor("api_user")
    manager = Manager(actor, State(True, "authenticated", Material(token)))
    findings, _meta = AuthTokenPostureScanner(config()).scan(manager)
    assert len(findings) == 1
    assert "exp claim is missing" in findings[0].evidence["issues"]

    actor2 = Actor("opaque")
    manager2 = Manager(actor2, State(True, "authenticated", Material("opaque-token")))
    findings2, meta2 = AuthTokenPostureScanner(config()).scan(manager2)
    assert findings2 == []
    assert meta2["actors_with_tokens"] == 1
    assert meta2["jwt_tokens_inspected"] == 0


def test_disabled_jwt_posture_sends_no_network_and_returns_no_findings():
    actor = Actor("api_user", bearer_token="a.b.c")
    manager = Manager(actor, State(False, "not_started", Material()))
    scanner = AuthTokenPostureScanner(
        {"passive_checks": {"auth_tokens": {"enabled": False}}}
    )
    findings, meta = scanner.scan(manager)
    assert findings == []
    assert meta["enabled"] is False
