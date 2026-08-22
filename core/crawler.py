from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from .har_import import load_har_seed_file
from .js_discovery import JavaScriptEndpointDiscoverer
from .models import AttackSurface, InputField
from .scope import ScopePolicy
from .site_map import SiteMapBuilder
from .utils import logger, normalize_url


class Crawler:
    def __init__(self, request_manager, config):
        self.requester = request_manager
        self.config = config
        self.visited = set()
        self.surface_fingerprints = set()
        self.surfaces = []

        crawler_cfg = config.get("crawler", {})
        self.max_depth = int(crawler_cfg.get("max_depth", config["scope"]["max_depth"]))
        self.max_urls = int(crawler_cfg.get("max_urls", 2000))
        self.max_url_length = int(crawler_cfg.get("max_url_length", 2048))
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

        discovery_cfg = crawler_cfg.get("discovery_files", {}) or {}
        self.discovery_robots = bool(discovery_cfg.get("robots_txt", True))
        self.discovery_sitemap = bool(discovery_cfg.get("sitemap_xml", True))
        self.max_sitemap_urls = max(0, int(discovery_cfg.get("max_sitemap_urls", 500) or 500))
        self.max_sitemap_files = max(1, int(discovery_cfg.get("max_sitemap_files", 10) or 10))
        self.max_discovery_file_bytes = max(
            1024,
            int(discovery_cfg.get("max_file_bytes", 2 * 1024 * 1024) or 2 * 1024 * 1024),
        )
        self.discovery_seed_urls = []
        self.discovery_file_report = {
            "robots": {"attempted": False, "status": None, "links": 0, "sitemaps": 0},
            "sitemaps": {"files_fetched": 0, "urls": 0, "truncated": False},
            "errors": [],
        }
        self._discovery_files_processed = False
        self._root_crawl_active = False

        site_map_cfg = crawler_cfg.get("site_map", {}) or {}
        self.site_map_enabled = bool(site_map_cfg.get("enabled", True))
        self.site_map_output_file = str(
            site_map_cfg.get("output_file", "crawler_site_map.json") or "crawler_site_map.json"
        )
        self.site_map = SiteMapBuilder(
            max_entries=int(site_map_cfg.get("max_entries", 5000) or 5000)
        )
        self.output_dir = Path(config.get("output", {}).get("directory", "reports"))

        self._load_har_seeds(crawler_cfg)

    def _request_get(self, url, actor=None):
        if actor is not None and hasattr(self.requester, "send_as_actor"):
            return self.requester.send_as_actor("GET", url, actor=actor)
        return self.requester.send("GET", url)

    def _append_surface(self, surface):
        self.surfaces.append(surface)
        if self.site_map_enabled:
            self.site_map.record_surface(surface)

    def _surface_seen(self, method, url, params_keys, input_names):
        fp = self._fingerprint(method, url, params_keys, input_names)
        if fp in self.surface_fingerprints:
            return True
        self.surface_fingerprints.add(fp)
        return False

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
                # A configured HAR is explicit user input. Failure to consume it
                # is material to scan completeness, unlike optional robots/sitemap.
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
                if self.site_map_enabled:
                    self.site_map.record_surface(surface)
                if not surface.meta.get("active_eligible", False):
                    continue
                if self._surface_seen(
                    surface.method,
                    surface.url,
                    surface.params.keys(),
                    [item.name for item in surface.inputs],
                ):
                    continue
                self._append_surface(surface)

    def extract_csrf_token(self, soup):
        token_input = soup.find(
            "input",
            {"name": ["csrf_token", "csrf", "_csrf", "authenticity_token"]},
        )
        if token_input:
            return token_input.get("name"), token_input.get("value")

        meta_token = soup.find("meta", {"name": ["csrf-token", "csrf-param"]})
        if meta_token:
            return "csrf_token", meta_token.get("content")

        return None, None

    def _in_scope(self, url):
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return False
        if len(url) > self.max_url_length:
            return False
        # RequestManager repeats DNS validation immediately before dispatch.
        return self.scope_policy.is_allowed(url, resolve_dns=False)

    def _fingerprint(self, method, url, params_keys, input_names):
        return f"{method}:{url}:{sorted(params_keys)}:{sorted(input_names)}"

    def _remember_discovered_url(self, url, source, *, depth=None, actor=None):
        if not self._in_scope(url):
            return False
        if url not in self.discovery_seed_urls:
            self.discovery_seed_urls.append(url)
        if self.site_map_enabled:
            self.site_map.record_url(
                url,
                source=source,
                requested=False,
                depth=depth,
                actor_id=getattr(actor, "actor_id", ""),
            )
        self._record_query_surface_from_url(url, source, depth=depth, actor=actor)
        return True

    def _record_query_surface_from_url(self, url, source, *, depth=None, actor=None):
        parsed = urlparse(url)
        inputs = parse_qs(parsed.query, keep_blank_values=True)
        if not inputs:
            return
        flat_inputs = {
            key: values[0] if values else "" for key, values in inputs.items()
        }
        surface_inputs = [
            InputField(
                name=key,
                value=values[0] if values else "",
                kind="query",
            )
            for key, values in inputs.items()
        ]
        url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if self._surface_seen(
            "GET",
            url_clean,
            flat_inputs.keys(),
            [item.name for item in surface_inputs],
        ):
            return
        self._append_surface(
            AttackSurface(
                url=url_clean,
                method="GET",
                params=flat_inputs,
                inputs=surface_inputs,
                source=source,
                meta={
                    "depth": depth,
                    "visible_to_actor": getattr(actor, "actor_id", ""),
                },
            )
        )

    @staticmethod
    def _origin(url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _bounded_text(self, response):
        content = getattr(response, "content", b"") or b""
        if content and len(content) > self.max_discovery_file_bytes:
            return None
        text = getattr(response, "text", "") or ""
        if len(text.encode("utf-8", errors="ignore")) > self.max_discovery_file_bytes:
            return None
        return text

    def _record_optional_discovery_error(self, kind, url, exc):
        error = {"kind": kind, "url": url, "error": str(exc)}
        self.discovery_file_report["errors"].append(error)
        logger.debug("Optional discovery source %s failed for %s: %s", kind, url, exc)

    def _discover_robots(self, start_url, actor=None):
        report = self.discovery_file_report["robots"]
        report["attempted"] = True
        robots_url = urljoin(self._origin(start_url) + "/", "robots.txt")
        if not self._in_scope(robots_url):
            return []

        sitemap_urls = []
        try:
            resp = self._request_get(robots_url, actor=actor)
            report["status"] = int(resp.status_code)
            if self.site_map_enabled:
                self.site_map.record_url(
                    robots_url,
                    source="robots-file",
                    requested=True,
                    depth=0,
                    actor_id=getattr(actor, "actor_id", ""),
                )
            if resp.status_code != 200:
                return []
            text = self._bounded_text(resp)
            if text is None:
                raise ValueError(
                    "robots.txt exceeded crawler.discovery_files.max_file_bytes"
                )

            for raw_line in text.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line or ":" not in line:
                    continue
                directive, value = line.split(":", 1)
                directive = directive.strip().lower()
                value = value.strip()
                if not value:
                    continue

                if directive == "sitemap":
                    sitemap_url = urljoin(robots_url, value)
                    if self._in_scope(sitemap_url) and sitemap_url not in sitemap_urls:
                        sitemap_urls.append(sitemap_url)
                        report["sitemaps"] += 1
                    continue

                if directive not in {"allow", "disallow"}:
                    continue
                # Wildcard robots rules are policy patterns, not concrete URLs.
                if "*" in value or "$" in value:
                    continue
                candidate = urljoin(
                    self._origin(start_url) + "/",
                    value.lstrip("/"),
                )
                source = f"robots-{directive}"
                if self._remember_discovered_url(
                    candidate,
                    source,
                    depth=1,
                    actor=actor,
                ):
                    report["links"] += 1
        except Exception as exc:
            self._record_optional_discovery_error("robots", robots_url, exc)
        return sitemap_urls

    @staticmethod
    def _local_xml_name(tag):
        return str(tag or "").rsplit("}", 1)[-1].lower()

    def _discover_sitemaps(self, start_url, extra_sitemaps=None, actor=None):
        report = self.discovery_file_report["sitemaps"]
        queue = []
        default_url = urljoin(self._origin(start_url) + "/", "sitemap.xml")
        if self.discovery_sitemap:
            queue.append(default_url)
        for item in extra_sitemaps or []:
            if item not in queue:
                queue.append(item)

        seen_files = set()
        while queue and len(seen_files) < self.max_sitemap_files:
            sitemap_url = queue.pop(0)
            if sitemap_url in seen_files or not self._in_scope(sitemap_url):
                continue
            seen_files.add(sitemap_url)
            try:
                resp = self._request_get(sitemap_url, actor=actor)
                report["files_fetched"] += 1
                if self.site_map_enabled:
                    self.site_map.record_url(
                        sitemap_url,
                        source="sitemap-file",
                        requested=True,
                        depth=0,
                        actor_id=getattr(actor, "actor_id", ""),
                    )
                if resp.status_code != 200:
                    continue
                text = self._bounded_text(resp)
                if text is None:
                    raise ValueError(
                        "sitemap exceeded crawler.discovery_files.max_file_bytes"
                    )
                root = ET.fromstring(text)
                root_name = self._local_xml_name(root.tag)
                loc_values = [
                    str(node.text or "").strip()
                    for node in root.iter()
                    if self._local_xml_name(node.tag) == "loc"
                    and str(node.text or "").strip()
                ]

                if root_name == "sitemapindex":
                    for loc in loc_values:
                        child = urljoin(sitemap_url, loc)
                        if (
                            self._in_scope(child)
                            and child not in seen_files
                            and child not in queue
                        ):
                            queue.append(child)
                    continue

                if root_name != "urlset":
                    raise ValueError(f"unsupported sitemap root element: {root_name}")

                for loc in loc_values:
                    if report["urls"] >= self.max_sitemap_urls:
                        report["truncated"] = True
                        break
                    candidate = urljoin(sitemap_url, loc)
                    if self._remember_discovered_url(
                        candidate,
                        "sitemap",
                        depth=1,
                        actor=actor,
                    ):
                        report["urls"] += 1
                if report["truncated"]:
                    break
            except ET.ParseError as exc:
                self._record_optional_discovery_error(
                    "sitemap_parse",
                    sitemap_url,
                    exc,
                )
            except Exception as exc:
                self._record_optional_discovery_error("sitemap", sitemap_url, exc)

        if queue and len(seen_files) >= self.max_sitemap_files:
            report["truncated"] = True

    def _discover_well_known(self, start_url, actor=None):
        if self._discovery_files_processed:
            return
        self._discovery_files_processed = True
        sitemap_urls = []
        if self.discovery_robots:
            sitemap_urls = self._discover_robots(start_url, actor=actor)
        if self.discovery_sitemap or sitemap_urls:
            self._discover_sitemaps(start_url, sitemap_urls, actor=actor)

    def _record_javascript_endpoints(self, soup, start_url, depth, actor=None):
        entries = self.js_discovery.discover_from_soup(soup, start_url, actor=actor)
        for entry in entries:
            url = entry.get("url", "")
            method = str(entry.get("method", "GET") or "GET").upper()
            if not url or url in self.js_endpoints:
                continue
            self.js_endpoints.append(url)
            if self.site_map_enabled and self._in_scope(url):
                self.site_map.record_url(
                    url,
                    source="javascript-static",
                    method=method,
                    requested=False,
                    depth=depth,
                    actor_id=getattr(actor, "actor_id", ""),
                )

            # JS discovery is inventory-first. Inferred state-changing routes are
            # never dispatched merely because a string appeared in JavaScript.
            if method != "GET":
                continue
            parsed = urlparse(url)
            inputs = parse_qs(parsed.query, keep_blank_values=True)
            if not inputs:
                continue
            flat_inputs = {
                key: values[0] if values else "" for key, values in inputs.items()
            }
            surface_inputs = [
                InputField(
                    name=key,
                    value=values[0] if values else "",
                    kind="query",
                )
                for key, values in inputs.items()
            ]
            url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if self._surface_seen(
                "GET",
                url_clean,
                flat_inputs.keys(),
                [item.name for item in surface_inputs],
            ):
                continue
            self._append_surface(
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

    @staticmethod
    def _field_value(tag):
        if tag.name == "textarea":
            return tag.get_text() or ""
        if tag.name == "select":
            selected = tag.find("option", selected=True) or tag.find("option")
            if selected is None:
                return ""
            return selected.get("value", selected.get_text() or "")
        return tag.get("value", "")

    def _record_forms(self, soup, start_url, depth, actor=None):
        base_tag = soup.find("base", href=True)
        document_base = (
            urljoin(start_url, base_tag.get("href")) if base_tag else start_url
        )
        for form in soup.find_all("form"):
            declared_method = str(
                form.get("method", "get") or "get"
            ).strip().upper()
            if declared_method == "DIALOG":
                continue
            method = declared_method if declared_method in {"GET", "POST"} else "GET"
            action = urljoin(document_base, form.get("action", ""))
            if not self._in_scope(action):
                continue

            values = {}
            field_meta = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = str(input_tag.get("name", "") or "").strip()
                if not name:
                    continue
                field_type = (
                    str(input_tag.get("type", "text") or "text").strip().lower()
                    if input_tag.name == "input"
                    else input_tag.name
                )
                if field_type in {"submit", "button", "reset", "image", "file"}:
                    continue
                values[name] = self._field_value(input_tag)
                field_meta.append({"name": name, "type": field_type})

            csrf_name, csrf_value = self.extract_csrf_token(form)
            if csrf_name and csrf_value and csrf_name not in values:
                values[csrf_name] = csrf_value
                field_meta.append({"name": csrf_name, "type": "csrf"})

            kind = "body" if method == "POST" else "query"
            surface_inputs = [
                InputField(name=key, value=value, kind=kind)
                for key, value in values.items()
            ]
            url_clean = normalize_url(action)
            params = {} if method == "POST" else values
            if self._surface_seen(
                method,
                url_clean,
                params.keys(),
                [item.name for item in surface_inputs],
            ):
                continue
            self._append_surface(
                AttackSurface(
                    url=url_clean,
                    method=method,
                    params=params,
                    inputs=surface_inputs,
                    source="html-form",
                    meta={
                        "depth": depth,
                        "visible_to_actor": getattr(actor, "actor_id", ""),
                        "declared_method": declared_method,
                        "enctype": str(
                            form.get(
                                "enctype",
                                "application/x-www-form-urlencoded",
                            )
                        ),
                        "fields": field_meta,
                    },
                )
            )

    def _record_meta_refresh(self, soup, start_url, depth, actor=None):
        for tag in soup.find_all("meta"):
            if str(tag.get("http-equiv", "")).strip().lower() != "refresh":
                continue
            content = str(tag.get("content", "") or "")
            match = re.search(
                r"(?:^|;)\s*url\s*=\s*['\"]?([^'\";]+)",
                content,
                re.I,
            )
            if not match:
                continue
            candidate = urljoin(start_url, match.group(1).strip())
            if self._remember_discovered_url(
                candidate,
                "meta-refresh",
                depth=depth + 1,
                actor=actor,
            ):
                self.crawl(candidate, depth + 1, actor=actor)

    def _crawl_seed_urls(self, root_url, actor=None):
        root_normalized = normalize_url(root_url)
        seen = set()
        for seed_url in [*self.har_seed_urls, *self.discovery_seed_urls]:
            normalized = normalize_url(seed_url)
            if normalized == root_normalized or seed_url in seen:
                continue
            seen.add(seed_url)
            self.crawl(seed_url, depth=1, actor=actor)

    def _write_site_map(self, actor=None):
        if not self.site_map_enabled:
            return
        filename = self.site_map_output_file
        actor_id = str(getattr(actor, "actor_id", "") or "").strip()
        if actor_id:
            safe_actor = (
                re.sub(r"[^A-Za-z0-9_.-]+", "-", actor_id).strip("-") or "actor"
            )
            stem = Path(filename).stem
            suffix = Path(filename).suffix or ".json"
            filename = f"{stem}-{safe_actor}{suffix}"
        try:
            path = Path(filename)
            if not path.is_absolute():
                path = self.output_dir / path
            self.site_map.write(path)
        except Exception as exc:
            # Site map export is supplemental and must not downgrade scan status.
            self.discovery_file_report["errors"].append(
                {"kind": "site_map", "url": "", "error": str(exc)}
            )
            logger.warning("Unable to write crawler site map: %s", exc)

    def crawl(self, start_url, depth=0, actor=None):
        is_root = depth == 0 and not self._root_crawl_active
        if is_root:
            self._root_crawl_active = True

        try:
            if depth > self.max_depth or len(self.visited) >= self.max_urls:
                return
            if not self._in_scope(start_url):
                return

            normalized = normalize_url(start_url)
            if normalized in self.visited:
                return
            self.visited.add(normalized)
            if self.site_map_enabled:
                self.site_map.record_url(
                    start_url,
                    source="crawler-request",
                    requested=False,
                    depth=depth,
                    actor_id=getattr(actor, "actor_id", ""),
                )

            logger.info("Crawling: %s (Depth: %s)", start_url, depth)
            resp = self._request_get(start_url, actor=actor)
            if self.site_map_enabled:
                self.site_map.record_url(
                    start_url,
                    source="crawler-response",
                    requested=True,
                    depth=depth,
                    actor_id=getattr(actor, "actor_id", ""),
                )
            if resp.status_code != 200:
                return
            self.pages_visited.append(start_url)

            soup = BeautifulSoup(resp.text, "html.parser")
            self._record_javascript_endpoints(soup, start_url, depth, actor=actor)
            self._record_forms(soup, start_url, depth, actor=actor)
            self._record_meta_refresh(soup, start_url, depth, actor=actor)

            # Request the explicitly supplied target first. Only after the root
            # response succeeds do optional discovery metadata and HAR seeds
            # consume the crawler URL budget.
            if is_root:
                self._discover_well_known(start_url, actor=actor)
                self._har_seeds_processed = True
                self._crawl_seed_urls(start_url, actor=actor)

            base_tag = soup.find("base", href=True)
            document_base = (
                urljoin(start_url, base_tag.get("href")) if base_tag else start_url
            )
            for link in soup.find_all("a", href=True):
                full_url = urljoin(document_base, link["href"])
                if not self._in_scope(full_url):
                    continue
                if self.site_map_enabled:
                    self.site_map.record_url(
                        full_url,
                        source="html-link",
                        requested=False,
                        depth=depth + 1,
                        actor_id=getattr(actor, "actor_id", ""),
                    )
                self._record_query_surface_from_url(
                    full_url,
                    "html-link",
                    depth=depth + 1,
                    actor=actor,
                )
                self.crawl(full_url, depth + 1, actor=actor)

            for frame in soup.find_all(["iframe", "frame"], src=True):
                frame_url = urljoin(document_base, frame.get("src", ""))
                if not self._in_scope(frame_url):
                    continue
                if self.site_map_enabled:
                    self.site_map.record_url(
                        frame_url,
                        source="html-frame",
                        requested=False,
                        depth=depth + 1,
                        actor_id=getattr(actor, "actor_id", ""),
                    )
                self.crawl(frame_url, depth + 1, actor=actor)

        except Exception as exc:
            logger.error("Crawl error on %s: %s", start_url, exc)
            self.errors.append({"url": start_url, "error": str(exc)})
        finally:
            if is_root:
                self._write_site_map(actor=actor)

    def get_surfaces(self):
        return self.surfaces

    def get_javascript_report(self):
        return self.js_discovery.report()

    def get_har_seed_report(self):
        return self.har_seed_report

    def get_discovery_file_report(self):
        return self.discovery_file_report

    def get_site_map_report(self):
        return self.site_map.to_dict()
