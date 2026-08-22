from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

from .har_import import load_har_seed_file
from .js_discovery import JavaScriptEndpointDiscoverer
from .models import AttackSurface, InputField
from .scope import ScopePolicy
from .utils import logger, normalize_url


class Crawler:
    def __init__(self, request_manager, config):
        self.requester = request_manager
        self.config = config
        self.visited = set()
        self.surfaces = []
        crawler_cfg = config.get("crawler", {})
        self.max_depth = crawler_cfg.get("max_depth", config["scope"]["max_depth"])
        self.max_urls = crawler_cfg.get("max_urls", 2000)
        self.max_url_length = crawler_cfg.get("max_url_length", 2048)
        self.dedup = crawler_cfg.get("dedup", "fingerprint")
        scope = config.get("scope", {})
        self.exclude_paths = scope.get("exclude_paths", [])
        self.scope_policy = getattr(request_manager, "scope_policy", None) or ScopePolicy(config)
        self.errors = []
        self.pages_visited = []
        self.js_endpoints = []
        self.js_discovery = JavaScriptEndpointDiscoverer(request_manager, config)
        self.har_seed_urls = []
        self.har_seed_report = {
            "files": [],
            "entries_seen": 0,
            "surfaces": 0,
            "active_eligible": 0,
            "replayed_requests": 0,
            "errors": [],
        }
        self._har_seeds_processed = False
        self._load_har_seeds(crawler_cfg)

    def _load_har_seeds(self, crawler_cfg):
        cfg = crawler_cfg.get("har_seed", {}) or {}
        if not isinstance(cfg, dict) or not cfg.get("enabled", False):
            return
        files = cfg.get("files", []) or []
        max_entries = int(cfg.get("max_entries", 5000) or 5000)
        active_tests = bool(cfg.get("active_tests", False))

        for path in files:
            path_text = str(path or "").strip()
            if not path_text:
                continue
            try:
                surfaces, report = load_har_seed_file(
                    path_text,
                    scope=self.scope_policy,
                    max_entries=max_entries,
                    active_tests=active_tests,
                )
            except Exception as exc:
                error = {"file": path_text, "error": str(exc)}
                self.har_seed_report["errors"].append(error)
                self.errors.append({"kind": "har_seed", **error})
                continue

            self.har_seed_report["files"].append(
                {
                    "path": path_text,
                    "entries_seen": report.get("entries_seen", 0),
                    "surfaces": report.get("surfaces", 0),
                    "active_eligible": report.get("active_eligible", 0),
                    "skipped": report.get("skipped", {}),
                    "truncated": report.get("truncated", False),
                }
            )
            self.har_seed_report["entries_seen"] += report.get("entries_seen", 0)
            self.har_seed_report["surfaces"] += report.get("surfaces", 0)
            self.har_seed_report["active_eligible"] += report.get("active_eligible", 0)

            for surface in surfaces:
                if surface.url not in self.har_seed_urls:
                    self.har_seed_urls.append(surface.url)
                if not surface.meta.get("active_eligible", False):
                    continue
                fp = self._fingerprint(
                    surface.method,
                    surface.url,
                    surface.params.keys(),
                    [item.name for item in surface.inputs],
                )
                if fp in self.visited:
                    continue
                self.visited.add(fp)
                self.surfaces.append(surface)

    def extract_csrf_token(self, soup):
        token_input = soup.find("input", {"name": ["csrf_token", "csrf", "_csrf", "authenticity_token"]})
        if token_input:
            return token_input.get("name"), token_input.get("value")

        meta_token = soup.find("meta", {"name": ["csrf-token", "csrf-param"]})
        if meta_token:
            return "csrf_token", meta_token.get("content")

        return None, None

    def _in_scope(self, url):
        # DNS is validated by RequestManager immediately before dispatch. Avoid
        # repeated DNS lookups for every discovered link while still applying
        # the exact same URL/domain/path policy during discovery.
        return self.scope_policy.is_allowed(url, resolve_dns=False)

    def _fingerprint(self, method, url, params_keys, input_names):
        return f"{method}:{url}:{sorted(params_keys)}:{sorted(input_names)}"

    def _record_javascript_endpoints(self, soup, start_url, depth, actor=None):
        entries = self.js_discovery.discover_from_soup(soup, start_url, actor=actor)
        for entry in entries:
            url = entry.get("url", "")
            method = str(entry.get("method", "GET") or "GET").upper()
            if not url or url in self.js_endpoints:
                continue
            self.js_endpoints.append(url)

            # Static JavaScript discovery is inventory-first. Only GET endpoints
            # with explicit query parameters become attack surfaces; inferred
            # POST/PUT/PATCH/DELETE routes are not invoked or attacked merely
            # because a string appeared in JavaScript.
            if method != "GET":
                continue
            parsed = urlparse(url)
            inputs = parse_qs(parsed.query)
            if not inputs:
                continue
            flat_inputs = {key: values[0] for key, values in inputs.items()}
            surface_inputs = [
                InputField(name=key, value=values[0], kind="query")
                for key, values in inputs.items()
            ]
            url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            fp = self._fingerprint(
                "GET",
                url_clean,
                flat_inputs.keys(),
                [item.name for item in surface_inputs],
            )
            if fp in self.visited:
                continue
            self.visited.add(fp)
            self.surfaces.append(
                AttackSurface(
                    url=url_clean,
                    method="GET",
                    params=flat_inputs,
                    inputs=surface_inputs,
                    source="javascript-static",
                    meta={
                        "depth": depth,
                        "javascript_source": entry.get("source", ""),
                        "visible_to_actor": getattr(actor, "actor_id", ""),
                    },
                )
            )

    def crawl(self, start_url, depth=0, actor=None):
        if depth == 0 and not self._har_seeds_processed:
            self._har_seeds_processed = True
            root_normalized = normalize_url(start_url)
            for seed_url in list(self.har_seed_urls):
                if normalize_url(seed_url) == root_normalized:
                    continue
                self.crawl(seed_url, depth=0, actor=actor)

        if depth > self.max_depth or len(self.visited) >= self.max_urls:
            return
        if not self._in_scope(start_url):
            return

        normalized = normalize_url(start_url)
        if normalized in self.visited:
            return
        self.visited.add(normalized)

        logger.info(f"Crawling: {start_url} (Depth: {depth})")

        try:
            if actor is not None and hasattr(self.requester, "send_as_actor"):
                resp = self.requester.send_as_actor("GET", start_url, actor=actor)
            else:
                resp = self.requester.send("GET", start_url)
            if resp.status_code != 200:
                return
            self.pages_visited.append(start_url)

            soup = BeautifulSoup(resp.text, "html.parser")
            self._record_javascript_endpoints(soup, start_url, depth, actor=actor)

            for form in soup.find_all("form"):
                action = urljoin(start_url, form.get("action", ""))
                if not self._in_scope(action):
                    continue
                method = form.get("method", "get").upper()
                inputs = {}

                for input_tag in form.find_all(["input", "textarea"]):
                    name = input_tag.get("name")
                    if name:
                        inputs[name] = input_tag.get("value", "")

                csrf_name, csrf_value = self.extract_csrf_token(soup)
                if csrf_name and csrf_value:
                    inputs[csrf_name] = csrf_value
                    logger.debug(f"CSRF Token found and added to form: {action}")

                surface_inputs = [
                    InputField(name=k, value=v, kind="body" if method == "POST" else "query")
                    for k, v in inputs.items()
                ]
                url_clean = normalize_url(action)
                fp = self._fingerprint(
                    method,
                    url_clean,
                    (inputs if method != "POST" else {}).keys(),
                    [i.name for i in surface_inputs],
                )
                if fp in self.visited:
                    continue
                self.visited.add(fp)
                self.surfaces.append(
                    AttackSurface(
                        url=url_clean,
                        method=method,
                        params={} if method == "POST" else inputs,
                        inputs=surface_inputs if method == "POST" else [],
                        source="crawler",
                        meta={"depth": depth, "visible_to_actor": getattr(actor, "actor_id", "")},
                    )
                )

            for link in soup.find_all("a", href=True):
                full_url = urljoin(start_url, link["href"])
                if not self._in_scope(full_url):
                    continue

                parsed = urlparse(full_url)
                inputs = parse_qs(parsed.query)
                if inputs:
                    flat_inputs = {k: v[0] for k, v in inputs.items()}
                    surface_inputs = [InputField(name=k, value=v[0], kind="query") for k, v in inputs.items()]
                    url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    fp = self._fingerprint("GET", url_clean, flat_inputs.keys(), [i.name for i in surface_inputs])
                    if fp not in self.visited:
                        self.visited.add(fp)
                        self.surfaces.append(
                            AttackSurface(
                                url=url_clean,
                                method="GET",
                                params=flat_inputs,
                                inputs=surface_inputs,
                                source="crawler",
                                meta={"depth": depth, "href": link["href"], "visible_to_actor": getattr(actor, "actor_id", "")},
                            )
                        )

                self.crawl(full_url, depth + 1, actor=actor)

        except Exception as exc:
            logger.error(f"Crawl error on {start_url}: {exc}")
            self.errors.append({"url": start_url, "error": str(exc)})

    def get_surfaces(self):
        return self.surfaces

    def get_javascript_report(self):
        return self.js_discovery.report()

    def get_har_seed_report(self):
        return self.har_seed_report