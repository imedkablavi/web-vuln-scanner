from core.crawler import Crawler


class Response:
    status_code = 200

    def __init__(self, text):
        self.text = text


class Scope:
    def is_allowed(self, url, resolve_dns=False):
        return url.startswith("https://example.test/")


class Requester:
    def __init__(self):
        self.scope_policy = Scope()
        self.urls = []

    def send(self, method, url):
        self.urls.append((method, url))
        if url.endswith("/start"):
            return Response(
                """
                <html><body>
                  <form action="/submit" method="post">
                    <input name="name" value="alice">
                    <input name="csrf_token" value="csrf-fixture">
                  </form>
                  <a href="/item?id=7">item</a>
                  <a href="https://offscope.test/?id=9">offscope</a>
                </body></html>
                """
            )
        return Response("<html><body>done</body></html>")


def config():
    return {
        "target": "https://example.test/start",
        "scope": {
            "max_depth": 2,
            "include_domains": ["example.test"],
            "exclude_paths": [],
            "allow_private": False,
            "resolve_dns": False,
        },
        "crawler": {
            "max_depth": 2,
            "max_urls": 20,
            "max_url_length": 2048,
        },
    }


def test_crawler_discovers_form_and_query_surface_without_offscope_dispatch():
    requester = Requester()
    crawler = Crawler(requester, config())
    crawler.crawl("https://example.test/start")
    surfaces = crawler.get_surfaces()
    assert any(item.url == "https://example.test/submit" and item.method == "POST" for item in surfaces)
    assert any(item.url == "https://example.test/item" and item.params.get("id") == "7" for item in surfaces)
    assert all("offscope.test" not in url for _, url in requester.urls)


def test_crawler_respects_max_depth_and_scope_before_dispatch():
    requester = Requester()
    crawler = Crawler(requester, config())
    crawler.crawl("https://offscope.test/start")
    assert requester.urls == []
    crawler.crawl("https://example.test/start", depth=99)
    assert requester.urls == []
