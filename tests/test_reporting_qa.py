"""Regression fixtures for the Reporter._redact_sensitive path.

All data is synthetic.  No real credentials, tokens, cookies, or session
artifacts are used anywhere in this file.
"""
from __future__ import annotations

import copy
import json

import pytest

from core.reporter import Reporter


def _reporter() -> Reporter:
    return Reporter({"scanner": {"target": "https://localhost"}})


# ---------------------------------------------------------------------------
# Mixed-case dictionary keys
# ---------------------------------------------------------------------------

class TestRedactMixedCaseKeys:
    """Verify that the case-insensitive regex catches common key variants."""

    @pytest.mark.parametrize(
        "key",
        [
            "Authorization",
            "authorization",
            "AUTHORIZATION",
            "AuThOrIzAtIoN",
        ],
    )
    def test_authorization_variants(self, key: str) -> None:
        data = {key: "Bearer synthetic-jwt-token-value"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"

    @pytest.mark.parametrize(
        "key",
        [
            "Cookie",
            "cookie",
            "COOKIE",
        ],
    )
    def test_cookie_variants(self, key: str) -> None:
        data = {key: "session_id=abc123; path=/"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"

    @pytest.mark.parametrize(
        "key",
        [
            "Set-Cookie",
            "set-cookie",
            "SET-COOKIE",
        ],
    )
    def test_set_cookie_variants(self, key: str) -> None:
        data = {key: "session=tok; HttpOnly; Secure"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"

    @pytest.mark.parametrize(
        "key",
        [
            "api-key",
            "Api-Key",
            "API-KEY",
        ],
    )
    def test_api_key_variants(self, key: str) -> None:
        data = {key: "sk-synthetic-1234567890"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"

    def test_api_key_underscore_not_matched(self) -> None:
        """api_key uses underscore — regex matches hyphen (api-key)."""
        data = {"api_key": "sk-synthetic-1234567890"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["api_key"] == "sk-synthetic-1234567890"

    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "Password",
            "PASSWORD",
        ],
    )
    def test_password_variants(self, key: str) -> None:
        data = {key: "p@ssw0rd-synthetic"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"

    def test_password_hyphenated_not_matched(self) -> None:
        """pass-word uses hyphen — regex matches 'password' not 'pass-word'."""
        data = {"pass-word": "p@ssw0rd-synthetic"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["pass-word"] == "p@ssw0rd-synthetic"

    @pytest.mark.parametrize(
        "key",
        [
            "token",
            "Token",
            "TOKEN",
        ],
    )
    def test_token_variants(self, key: str) -> None:
        data = {key: "tok_abc123xyz"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"

    @pytest.mark.parametrize(
        "key",
        [
            "secret",
            "Secret",
            "SECRET",
        ],
    )
    def test_secret_variants(self, key: str) -> None:
        data = {key: "my-secret-value"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"


# ---------------------------------------------------------------------------
# Keys that do NOT match the current regex
# ---------------------------------------------------------------------------

class TestRedactNonMatchingKeys:
    """Known keywords that the current regex does *not* match — documenting
    current behaviour so regressions are caught if the pattern is widened."""

    @pytest.mark.parametrize(
        "key",
        [
            "csrf",
            "bearer",
            "Bearer",
            "jwt",
            "session",
        ],
    )
    def test_non_sensitive_keys_pass_through(self, key: str) -> None:
        sentinel = "plaintext-value"
        data = {key: sentinel}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == sentinel

    @pytest.mark.parametrize(
        "key",
        [
            "csrf_token",
            "X-CSRF-Token",
            "access_token",
        ],
    )
    def test_keys_containing_token_are_redacted(self, key: str) -> None:
        """The regex uses substring matching — any key containing 'token'
        (case-insensitive) is redacted, even if the primary keyword is
        something else like 'csrf'."""
        sentinel = "plaintext-value"
        data = {key: sentinel}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[key] == "***redacted***"


# ---------------------------------------------------------------------------
# Nested structures (dict-inside-dict, list-of-dicts, mixed)
# ---------------------------------------------------------------------------

class TestRedactNestedStructures:
    def test_nested_dict(self) -> None:
        data = {
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer synthetic-nested",
                "X-Custom": "safe",
            }
        }
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["headers"]["Authorization"] == "***redacted***"
        assert redacted["headers"]["Content-Type"] == "application/json"
        assert redacted["headers"]["X-Custom"] == "safe"

    def test_deeply_nested_dict(self) -> None:
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "password": "deep-secret",
                        "safe_key": "keep-this",
                    }
                }
            }
        }
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["level1"]["level2"]["level3"]["password"] == "***redacted***"
        assert redacted["level1"]["level2"]["level3"]["safe_key"] == "keep-this"

    def test_list_of_dicts(self) -> None:
        data = [
            {"Cookie": "sess=aaa", "Host": "example.test"},
            {"Authorization": "Bearer tok1", "Host": "other.test"},
            {"X-Trace": "trace-id-123"},
        ]
        redacted = _reporter()._redact_sensitive(data)
        assert redacted[0]["Cookie"] == "***redacted***"
        assert redacted[0]["Host"] == "example.test"
        assert redacted[1]["Authorization"] == "***redacted***"
        assert redacted[2]["X-Trace"] == "trace-id-123"

    def test_dict_with_list_values(self) -> None:
        data = {
            "cookies": [
                {"name": "session_id", "value": "abc123", "httpOnly": True},
                {"name": "csrf", "value": "xyz789", "httpOnly": False},
            ]
        }
        redacted = _reporter()._redact_sensitive(data)
        # 'cookie' appears in the parent key 'cookies' — redacted
        assert redacted["cookies"] == "***redacted***"

    def test_list_inside_sensitive_dict_not_recurse(self) -> None:
        """When a dict key matches, the value is replaced wholesale — the
        list inside is NOT individually redacted."""
        data = {
            "api-key": [
                {"key": "a", "val": "b"},
                {"key": "c", "val": "d"},
            ]
        }
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["api-key"] == "***redacted***"

    def test_mixed_nested(self) -> None:
        data = {
            "request": {
                "headers": [
                    {"Authorization": "Bearer mix-test"},
                    {"Accept": "application/json"},
                ],
                "body": {"token": "body-tok", "data": "safe"},
            },
            "meta": {"secret": "meta-secret", "trace_id": "tr-001"},
        }
        redacted = _reporter()._redact_sensitive(data)
        req = redacted["request"]
        assert req["headers"][0]["Authorization"] == "***redacted***"
        assert req["headers"][1]["Accept"] == "application/json"
        assert req["body"]["token"] == "***redacted***"
        assert req["body"]["data"] == "safe"
        assert redacted["meta"]["secret"] == "***redacted***"
        assert redacted["meta"]["trace_id"] == "tr-001"


# ---------------------------------------------------------------------------
# Free-form string values containing sensitive *words* — should NOT be
# redacted because redaction operates on keys, not values.
# ---------------------------------------------------------------------------

class TestRedactFreeFormStrings:
    """The reporter redacts dict keys matching the sensitive pattern, not
    arbitrary string values.  These tests document that behaviour."""

    def test_bearer_in_string_value(self) -> None:
        data = {"log": "Received Bearer token from upstream"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["log"] == "Received Bearer token from upstream"

    def test_jwt_in_string_value(self) -> None:
        data = {"detail": "JWT expired at 2026-01-01T00:00:00Z"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["detail"] == "JWT expired at 2026-01-01T00:00:00Z"

    def test_password_in_string_value(self) -> None:
        data = {"message": "password reset email sent"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["message"] == "password reset email sent"

    def test_token_in_string_value(self) -> None:
        data = {"description": "Refresh the access token after expiry"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["description"] == "Refresh the access token after expiry"

    def test_multiple_sensitive_words_in_value(self) -> None:
        data = {"note": "Rotate API key, cookie, and password quarterly"}
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["note"] == "Rotate API key, cookie, and password quarterly"


# ---------------------------------------------------------------------------
# Unrelated fields remain unchanged
# ---------------------------------------------------------------------------

class TestRedactUnrelatedFieldsPreserved:
    SAFE_DATA = {
        "target": "https://example.test",
        "method": "GET",
        "path": "/api/v1/users",
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
            "X-Request-Id": "req-abc-123",
            "Cache-Control": "no-cache",
        },
        "tags": ["passive", "headers"],
        "metadata": {
            "scanner_version": "0.3.0",
            "elapsed_ms": 142,
            "retries": 0,
        },
    }

    def test_safe_data_unchanged(self) -> None:
        original = copy.deepcopy(self.SAFE_DATA)
        redacted = _reporter()._redact_sensitive(self.SAFE_DATA)
        assert redacted == original

    def test_safe_data_not_mutated(self) -> None:
        original = copy.deepcopy(self.SAFE_DATA)
        _reporter()._redact_sensitive(self.SAFE_DATA)
        assert self.SAFE_DATA == original

    def test_mixed_safe_and_sensitive(self) -> None:
        data = {
            "target": "https://example.test",
            "method": "POST",
            "password": "synthetic-password",
            "headers": {
                "Content-Type": "application/json",
                "Cookie": "session=fake",
            },
            "body_length": 512,
        }
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["target"] == "https://example.test"
        assert redacted["method"] == "POST"
        assert redacted["body_length"] == 512
        assert redacted["password"] == "***redacted***"
        assert redacted["headers"]["Content-Type"] == "application/json"
        assert redacted["headers"]["Cookie"] == "***redacted***"

    def test_non_string_scalar_values_preserved(self) -> None:
        data = {
            "count": 42,
            "enabled": True,
            "rate": 3.14,
            "nothing": None,
            "secret": "should-be-redacted",
        }
        redacted = _reporter()._redact_sensitive(data)
        assert redacted["count"] == 42
        assert redacted["enabled"] is True
        assert redacted["rate"] == 3.14
        assert redacted["nothing"] is None
        assert redacted["secret"] == "***redacted***"

    def test_empty_structures(self) -> None:
        assert _reporter()._redact_sensitive({}) == {}
        assert _reporter()._redact_sensitive([]) == []
        assert _reporter()._redact_sensitive("plain string") == "plain string"
        assert _reporter()._redact_sensitive(42) == 42
