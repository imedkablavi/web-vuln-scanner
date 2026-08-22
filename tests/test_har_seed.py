import json

from core.crawler import Crawler
from core.har_import import har_seed_data
from core.scope import ScopePolicy


class Response:
    status_code = 200
    text = "<html><body>ok</body></html>"
    headers = {}


class Requester:
    def __init__(self, config):
        self.scope_policy = ScopePolicy(config)
        self.calls = []

    def send(self, method, url):
        self.calls.append((method, url))
        return Response()


def config(har_path=None, *, active_tests=False):
    crawler = {
        "max_depth": 1,
        "max_urls": 50,
        "max_url_length": 2048,
        "javascript_discovery": {"enabled": False},
    }
    if har_path is not None:
        crawler["har_seed"] = {
            "enabled": True,
            "files": [str(har_path)],
            "max_entries": 100,
            "active_tests": active_tests,
        }
    return {
        "target": "https://example.test/",
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
            "max_depth": 1,
        },
        "crawler": crawler,
        "concurrency": {
            "threads": 1,
            "timeout": 1,
            "global_timeout_seconds": 30,
        },
    }


def har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def entry(method, url, *, headers=None, post_data=None):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": headers or [],
            "postData": post_data or {},
        }
    }


def test_har_seed_retains_names_not_values_and_never_replays():
    cfg = config()
    scope = ScopePolicy(cfg)
    data = har(
        [
            entry(
                "GET",
                "https://example.test/search?q=query-secret&token=another-secret",
                headers=[
                    {"name": "Authorization", "value": "Bearer header-secret"},
                    {"name": "Cookie", "value": "session=cookie-secret"},
                    {"name": "Accept", "value": "application/json"},
                ],
            ),
            entry(
                "POST",
                "https://example.test/update?id=123",
                post_data={
                    "mimeType": "application/json",
                    "text": '{"password":"body-secret"}',
                },
            ),
            entry("GET", "https://outside.test/secret?x=1"),
        ]
    )

    surfaces, report = har_seed_data(data, scope=scope)
    assert len(surfaces) == 1
    surface = surfaces[0]
    assert surface.url == "https://example.test/search"
    assert surface.params == {"q": "", "token": ""}
    assert surface.meta["active_eligible"] is False
    assert surface.meta["observed_header_names"] == ["Accept"]
    assert report["replayed_requests"] == 0
    assert report["skipped"]["non_safe_method"] == 1
    assert report["skipped"]["out_of_scope"] == 1

    rendered = repr((surfaces, report))
    for secret in (
        "query-secret",
        "another-secret",
        "header-secret",
        "cookie-secret",
        "body-secret",
    ):
        assert secret not in rendered


def test_har_seed_active_testing_is_explicit_and_get_only():
    cfg = config()
    surfaces, report = har_seed_data(
        har(
            [
                entry("GET", "https://example.test/search?q=secret"),
                entry("HEAD", "https://example.test/health?probe=secret"),
                entry("DELETE", "https://example.test/account?id=7"),
            ]
        ),
        scope=ScopePolicy(cfg),
        active_tests=True,
    )
    by_method = {surface.method: surface for surface in surfaces}
    assert by_method["GET"].meta["active_eligible"] is True
    assert by_method["HEAD"].meta["active_eligible"] is False
    assert "DELETE" not in by_method
    assert report["active_eligible"] == 1
    assert report["skipped"]["non_safe_method"] == 1


def test_crawler_uses_har_as_sanitized_seed_without_adding_active_surface(tmp_path):
    har_path = tmp_path / "traffic.har"
    har_path.write_text(
        json.dumps(
            har(
                [
                    entry(
                        "GET",
                        "https://example.test/from-har?q=do-not-persist",
                    ),
                    entry("POST", "https://example.test/state-change?id=5"),
                ]
            )
        ),
        encoding="utf-8",
    )
    cfg = config(har_path, active_tests=False)
    requester = Requester(cfg)
    crawler = Crawler(requester, cfg)

    assert requester.calls == []
    assert crawler.get_surfaces() == []
    assert crawler.get_har_seed_report()["surfaces"] == 1
    assert crawler.get_har_seed_report()["replayed_requests"] == 0

    crawler.crawl("https://example.test/")
    called_urls = [url for _method, url in requester.calls]
    assert "https://example.test/from-har" in called_urls
    assert "https://example.test/" in called_urls
    assert all("do-not-persist" not in url for url in called_urls)
    assert all("state-change" not in url for url in called_urls)


def test_crawler_only_adds_har_parameter_surface_when_explicitly_enabled(tmp_path):
    har_path = tmp_path / "traffic.har"
    har_path.write_text(
        json.dumps(har([entry("GET", "https://example.test/search?q=secret")])),
        encoding="utf-8",
    )
    cfg = config(har_path, active_tests=True)
    requester = Requester(cfg)
    crawler = Crawler(requester, cfg)

    surfaces = crawler.get_surfaces()
    assert len(surfaces) == 1
    assert surfaces[0].source == "har-seed"
    assert surfaces[0].params == {"q": ""}
    assert surfaces[0].meta["active_eligible"] is True
    assert "secret" not in repr(surfaces[0])