from pathlib import Path

from core.crawler import Crawler
from core.scope import ScopePolicy


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = {"Content-Type": "text/html"}


class FakeRequester:
    def __init__(self, config, responses):
        self.scope_policy = ScopePolicy(config)
        self.responses = responses
        self.calls = []

    def send(self, method, url, **kwargs):
        self.calls.append((method, url))
        return self.responses.get(url, FakeResponse(404, "not found"))


def _config(tmp_path):
    return {
        "target": "https://example.test/",
        "scope": {
            "allowlist": ["example.test"],
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
            "max_depth": 3,
        },
        "crawler": {
            "max_depth": 3,
            "max_urls": 50,
            "max_url_length": 2048,
            "javascript_discovery": {
                "enabled": False,
                "max_scripts": 0,
                "max_script_bytes": 1024,
                "max_endpoints": 0,
            },
            "har_seed": {"enabled": False, "files": []},
            "discovery_files": {
                "robots_txt": True,
                "sitemap_xml": True,
                "max_sitemap_urls": 20,
                "max_sitemap_files": 5,
                "max_file_bytes": 65536,
            },
            "site_map": {
                "enabled": True,
                "output_file": "crawler_site_map.json",
                "max_entries": 100,
            },
        },
        "output": {"directory": str(tmp_path)},
    }


def test_crawler_uses_robots_nested_sitemaps_and_records_forms(tmp_path):
    root = "https://example.test/"
    responses = {
        root: FakeResponse(
            200,
            """
            <html><body>
              <form action="/submit" method="post" enctype="application/x-www-form-urlencoded">
                <input name="username" value="alice">
                <select name="role"><option value="reader" selected>Reader</option></select>
                <input type="file" name="avatar">
                <input type="submit" name="go" value="Submit">
              </form>
              <a href="/search?q=hello&token=SUPERSECRET">Search</a>
              <iframe src="/frame"></iframe>
            </body></html>
            """,
        ),
        "https://example.test/robots.txt": FakeResponse(
            200,
            """
            User-agent: *
            Disallow: /hidden
            Allow: /public
            Sitemap: https://example.test/map.xml
            Disallow: /wild/*
            """,
        ),
        "https://example.test/sitemap.xml": FakeResponse(404, "not found"),
        "https://example.test/map.xml": FakeResponse(
            200,
            """<?xml version="1.0"?>
            <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <sitemap><loc>https://example.test/map-2.xml</loc></sitemap>
            </sitemapindex>
            """,
        ),
        "https://example.test/map-2.xml": FakeResponse(
            200,
            """<?xml version="1.0"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
              <url><loc>https://example.test/from-map?item=7</loc></url>
            </urlset>
            """,
        ),
        "https://example.test/hidden": FakeResponse(200, "<html></html>"),
        "https://example.test/public": FakeResponse(200, "<html></html>"),
        "https://example.test/from-map?item=7": FakeResponse(200, "<html></html>"),
        "https://example.test/search?q=hello&token=SUPERSECRET": FakeResponse(200, "<html></html>"),
        "https://example.test/frame": FakeResponse(200, "<html></html>"),
    }
    config = _config(tmp_path)
    requester = FakeRequester(config, responses)
    crawler = Crawler(requester, config)

    crawler.crawl(root)

    called_urls = {url for _, url in requester.calls}
    assert "https://example.test/robots.txt" in called_urls
    assert "https://example.test/map.xml" in called_urls
    assert "https://example.test/map-2.xml" in called_urls
    assert "https://example.test/hidden" in called_urls
    assert "https://example.test/public" in called_urls
    assert "https://example.test/from-map?item=7" in called_urls
    assert "https://example.test/frame" in called_urls
    assert not any("/wild/" in url for url in called_urls)

    surfaces = crawler.get_surfaces()
    form = next(surface for surface in surfaces if surface.source == "html-form")
    assert form.method == "POST"
    assert {item.name for item in form.inputs} == {"username", "role"}
    assert {item.kind for item in form.inputs} == {"body"}
    assert "avatar" not in {item.name for item in form.inputs}
    assert "go" not in {item.name for item in form.inputs}

    mapped = next(surface for surface in surfaces if surface.source == "sitemap")
    assert mapped.url == "https://example.test/from-map"
    assert mapped.params == {"item": "7"}

    link = next(
        surface
        for surface in surfaces
        if surface.source == "html-link" and surface.url.endswith("/search")
    )
    assert set(link.params) == {"q", "token"}

    report = crawler.get_discovery_file_report()
    assert report["robots"]["links"] == 2
    assert report["robots"]["sitemaps"] == 1
    assert report["sitemaps"]["files_fetched"] >= 2
    assert report["sitemaps"]["urls"] == 1

    site_map_path = Path(tmp_path) / "crawler_site_map.json"
    assert site_map_path.is_file()
    text = site_map_path.read_text(encoding="utf-8")
    assert "SUPERSECRET" not in text
    assert "?q=" not in text
    assert '"name": "token"' in text


def test_discovery_files_respect_scope_and_size_limit(tmp_path):
    root = "https://example.test/"
    responses = {
        root: FakeResponse(200, "<html></html>"),
        "https://example.test/robots.txt": FakeResponse(
            200,
            "Sitemap: https://offscope.test/map.xml\nDisallow: /local\n",
        ),
        "https://example.test/sitemap.xml": FakeResponse(200, "X" * 70000),
        "https://example.test/local": FakeResponse(200, "<html></html>"),
    }
    config = _config(tmp_path)
    requester = FakeRequester(config, responses)
    crawler = Crawler(requester, config)

    crawler.crawl(root)

    called_urls = {url for _, url in requester.calls}
    assert "https://offscope.test/map.xml" not in called_urls
    assert "https://example.test/local" in called_urls
    assert any(item.get("kind") == "sitemap" for item in crawler.errors)
