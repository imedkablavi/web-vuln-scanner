import socket

from core.scope import ScopePolicy


def make_config(**scope_overrides):
    scope = {
        "include_domains": ["example.com", "*.example.org"],
        "exclude_paths": ["/logout"],
        "allow_private": False,
        "resolve_dns": True,
    }
    scope.update(scope_overrides)
    return {
        "target": "https://example.com",
        "scope": scope,
        "crawler": {"max_url_length": 2048},
    }


def test_wildcard_scope_does_not_allow_suffix_spoofing():
    policy = ScopePolicy(make_config())
    assert policy.is_allowed("https://example.org/path", resolve_dns=False)
    assert policy.is_allowed("https://api.example.org/path", resolve_dns=False)
    assert not policy.is_allowed("https://badexample.org/path", resolve_dns=False)
    assert not policy.is_allowed(
        "https://example.org.attacker.test/path", resolve_dns=False
    )


def test_exact_port_pattern_requires_matching_port():
    policy = ScopePolicy(
        make_config(include_domains=["example.com:8443"])
    )
    assert policy.is_allowed("https://example.com:8443/a", resolve_dns=False)
    assert not policy.is_allowed("https://example.com/a", resolve_dns=False)
    assert not policy.is_allowed("https://example.com:9443/a", resolve_dns=False)


def test_embedded_userinfo_is_rejected():
    policy = ScopePolicy(make_config())
    decision = policy.evaluate(
        "https://example.com@evil.test/path", resolve_dns=False
    )
    assert decision.allowed is False
    assert "userinfo" in decision.reason


def test_excluded_path_is_rejected():
    policy = ScopePolicy(make_config())
    assert not policy.is_allowed(
        "https://example.com/logout/confirm", resolve_dns=False
    )


def test_private_ip_literal_requires_explicit_opt_in():
    policy = ScopePolicy(
        make_config(include_domains=["127.0.0.1"])
    )
    assert not policy.is_allowed("http://127.0.0.1/", resolve_dns=False)

    private_policy = ScopePolicy(
        make_config(
            include_domains=["127.0.0.1"],
            allow_private=True,
        )
    )
    assert private_policy.is_allowed("http://127.0.0.1/", resolve_dns=False)


def test_hostname_resolving_to_private_address_is_blocked(monkeypatch):
    policy = ScopePolicy(make_config(include_domains=["example.com"]))

    def fake_getaddrinfo(host, port):
        assert host == "example.com"
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 0),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    decision = policy.evaluate("https://example.com/", resolve_dns=True)
    assert decision.allowed is False
    assert "non-public" in decision.reason


def test_hostname_resolving_to_public_address_is_allowed(monkeypatch):
    policy = ScopePolicy(make_config(include_domains=["example.com"]))

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 0),
            )
        ],
    )
    assert policy.is_allowed("https://example.com/", resolve_dns=True)
