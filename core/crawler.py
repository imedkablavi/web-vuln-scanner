from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from .utils import logger, normalize_url
from .models import AttackSurface, InputField

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
        self.include_domains = scope.get("include_domains", [])
        self.exclude_paths = scope.get("exclude_paths", [])
        self.errors = []
        self.pages_visited = []

    def extract_csrf_token(self, soup):
        # 1. Common Input Names
        token_input = soup.find("input", {"name": ["csrf_token", "csrf", "_csrf", "authenticity_token"]})
        if token_input:
            return token_input.get("name"), token_input.get("value")
        
        # 2. Meta Tags
        meta_token = soup.find("meta", {"name": ["csrf-token", "csrf-param"]})
        if meta_token:
            return "csrf_token", meta_token.get("content") # Simplified, usually name is in another meta tag
            
        return None, None

    def _in_scope(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if len(url) > self.max_url_length:
            return False
        for p in self.exclude_paths:
            if parsed.path.startswith(p):
                return False
        if self.include_domains:
            host = parsed.netloc
            allowed = False
            for dom in self.include_domains:
                if dom.startswith("*.") and host.endswith(dom[2:]):
                    allowed = True
                elif host == dom:
                    allowed = True
            if not allowed:
                return False
        return True

    def _fingerprint(self, method, url, params_keys, input_names):
        return f"{method}:{url}:{sorted(params_keys)}:{sorted(input_names)}"

    def crawl(self, start_url, depth=0, actor=None):
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
            if resp.status_code != 200: return
            self.pages_visited.append(start_url)

            soup = BeautifulSoup(resp.text, "html.parser")

            # 1. Extract Forms
            for form in soup.find_all("form"):
                action = urljoin(start_url, form.get("action", ""))
                if not self._in_scope(action):
                    continue
                method = form.get("method", "get").upper()
                inputs = {}
                
                # Extract Inputs
                for input_tag in form.find_all(["input", "textarea"]):
                    name = input_tag.get("name")
                    if name:
                        inputs[name] = input_tag.get("value", "")
                
                # CSRF Handling
                csrf_name, csrf_value = self.extract_csrf_token(soup)
                if csrf_name and csrf_value:
                    inputs[csrf_name] = csrf_value
                    logger.debug(f"CSRF Token found and added to form: {action}")

                surface_inputs = [InputField(name=k, value=v, kind="body" if method == "POST" else "query") for k, v in inputs.items()]
                url_clean = normalize_url(action)
                fp = self._fingerprint(method, url_clean, (inputs if method != "POST" else {}).keys(), [i.name for i in surface_inputs])
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

            # 2. Extract URL Params (from links)
            for link in soup.find_all("a", href=True):
                full_url = urljoin(start_url, link['href'])
                if not self._in_scope(full_url):
                    continue
                
                # Add to surfaces if it has params
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
                                meta={"depth": depth, "href": link['href'], "visible_to_actor": getattr(actor, "actor_id", "")},
                            )
                        )

                # Recursive Crawl
                self.crawl(full_url, depth + 1, actor=actor)

        except Exception as e:
            logger.error(f"Crawl error on {start_url}: {e}")
            self.errors.append({"url": start_url, "error": str(e)})

    def get_surfaces(self):
        return self.surfaces
