from types import SimpleNamespace

from bs4 import BeautifulSoup

from core.js_discovery import JavaScriptEndpointDiscoverer


class Scope:
    def is_allowed(self, url, resolve_dns=False):
        return url.startswith("https://example.test/")


class Requester:
    def __init__(self):
        self.scope_policy = Scope()
        self.calls = []

    def send(self, method, url):
        self.calls.append((method, url))
        return SimpleNamespace(
            status_code=200,
            text="axios.post('/api/orders', {id: 1}); fetch('/api/profile')",
        )


def config(**js_overrides):
    js = {
        "enabled": True,
        "max_scripts": 2,
        "max_script_bytes": 10000,
        "max_endpoints": 10,
    }
    js.update(js_overrides)
    return {
        "target": "https://example.test/",
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
        },
        "crawler": {"max_url_length": 2048, "javascript_discovery": js},
        "concurrency": {"global_timeout_seconds": 60},
    }


def test_inline_fetch_axios_xhr_and_generic_routes_are_discovered():
    requester = Requester()
    discoverer = JavaScriptEndpointDiscoverer(requester, config())
    soup = BeautifulSoup(
        """
        <script>
          fetch('/api/users?id=1');
          axios.patch('/api/users/1', {name: 'x'});
          xhr.open('DELETE', '/api/users/2');
          const graphql = '/graphql';
        </script>
        """,
        "html.parser",
    )
    entries = discoverer.discover_from_soup(soup, "https://example.test/app")
    pairs = {(item["method"], item["url"]) for item in entries}
    assert ("GET", "https://example.test/api/users?id=1") in pairs
    assert ("PATCH", "https://example.test/api/users/1") in pairs
    assert ("DELETE", "https://example.test/api/users/2") in pairs
    assert ("GET", "https://example.test/graphql") in pairs


def test_external_scripts_are_fetched_with_budget_and_stay_in_scope():
    requester = Requester()
    discoverer = JavaScriptEndpointDiscoverer(
        requester, config(max_scripts=1, max_endpoints=10)
    )
    soup = BeautifulSoup(
        """
        <script src="/assets/app.js"></script>
        <script src="/assets/second.js"></script>
        <script src="https://evil.test/off.js"></script>
        """,
        "html.parser",
    )
    entries = discoverer.discover_from_soup(soup, "https://example.test/")
    assert requester.calls == [("GET", "https://example.test/assets/app.js")]
    assert any(item["url"] == "https://example.test/api/orders" for item in entries)
    assert discoverer.report()["scripts_fetched"] == 1


def test_static_assets_and_template_expressions_are_not_promoted_as_endpoints():
    requester = Requester()
    discoverer = JavaScriptEndpointDiscoverer(requester, config())
    soup = BeautifulSoup(
        """
        <script>
          fetch('/assets/app.js');
          fetch('/api/${userId}');
          const image = '/api/logo.png';
        </script>
        """,
        "html.parser",
    )
    assert discoverer.discover_from_soup(soup, "https://example.test/") == []


def test_endpoint_budget_is_global_for_discoverer():
    requester = Requester()
    discoverer = JavaScriptEndpointDiscoverer(requester, config(max_endpoints=2))
    soup = BeautifulSoup(
        "<script>fetch('/api/a'); fetch('/api/b'); fetch('/api/c');</script>",
        "html.parser",
    )
    assert len(discoverer.discover_from_soup(soup, "https://example.test/")) == 2
