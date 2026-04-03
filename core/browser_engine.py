import os
import re
from urllib.parse import urlparse, parse_qs, urljoin

from .utils import logger
from .models import AttackSurface, AuthActor, BrowserActionRecord, InputField


class BrowserEngine:
    def __init__(self, config):
        self.config = config
        self.auth_session_manager = None
        self.playwright = None
        self.browser = None
        self.context = None
        self.surfaces = []
        self.xhr_requests = []
        scope = config.get("scope", {})
        self.include_domains = scope.get("include_domains", [])
        self.exclude_paths = scope.get("exclude_paths", [])
        crawler_cfg = config.get("crawler", {})
        browser_cfg = config.get("browser", {})
        self.max_url_length = crawler_cfg.get("max_url_length", 2048)
        self.max_pages = browser_cfg.get("max_pages", 20)
        self.max_actions = browser_cfg.get("max_actions_per_page", 15)
        output_dir = config.get("output", {}).get("directory", "reports")
        self.artifacts_dir = os.path.join(output_dir, "browser_artifacts")
        self.trace_enabled = bool(browser_cfg.get("capture_trace", True))
        self.capture_screenshots = bool(browser_cfg.get("capture_screenshots", True))
        self.visited = set()
        self.errors = []
        self.pages_visited = []
        self.page_artifacts = []
        self.console_errors = []
        self.trace_path = None
        self.event_bus = None
        self.artifact_store = None

    def attach_auth_session_manager(self, session_manager):
        self.auth_session_manager = session_manager

    def attach_event_bus(self, event_bus):
        self.event_bus = event_bus

    def attach_artifact_store(self, artifact_store):
        self.artifact_store = artifact_store

    async def start(self):
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed. Install with 'pip install playwright' and 'playwright install chromium'.") from exc

        os.makedirs(self.artifacts_dir, exist_ok=True)
        self.playwright = await async_playwright().start()
        browser_cfg = self.config.get("browser", {})
        headless = browser_cfg.get("headless", self.config.get("headless", True))
        slow_mo = int(browser_cfg.get("slow_mo", 0))
        self.browser = await self.playwright.chromium.launch(headless=headless, slow_mo=slow_mo)
        self.context = await self.browser.new_context(
            user_agent="WebVulnScanner/1.0",
            ignore_https_errors=True,
        )
        if self.trace_enabled:
            await self.context.tracing.start(screenshots=True, snapshots=True)

        if self.config.get("auth", {}).get("cookies"):
            await self.context.add_cookies(self.config["auth"]["cookies"])

        if self.config.get("auth", {}).get("type") == "form":
            await self._perform_login()

    async def _perform_login(self):
        auth_config = self.config["auth"]
        page = await self.context.new_page()
        try:
            logger.info(f"Attempting login at {auth_config['login_url']}")
            await page.goto(auth_config["login_url"])
            for step in auth_config.get("steps", []):
                if step["action"] == "fill":
                    await page.fill(step["selector"], step["value"])
                elif step["action"] == "click":
                    await page.click(step["selector"])
                elif step["action"] == "wait":
                    await page.wait_for_timeout(int(step["value"]))
            await page.wait_for_load_state("networkidle")
            if auth_config.get("check_url"):
                await page.goto(auth_config["check_url"])
                if page.url == auth_config["check_url"]:
                    logger.info("Login Successful!")
                else:
                    logger.warning("Login Verification Failed.")
            cookies = await self.context.cookies()
            self.config["auth"]["cookies"] = cookies
        except Exception as exc:
            logger.error(f"Login Failed: {exc}")
            self.errors.append({"kind": "auth", "error": str(exc)})
        finally:
            await page.close()

    def _context_kwargs_for_actor(self, actor: AuthActor | None, url: str):
        context_kwargs = {"ignore_https_errors": True, "user_agent": "WebVulnScanner/1.0"}
        if actor is None:
            return context_kwargs, {}, []
        if self.auth_session_manager is not None:
            browser_ctx = self.auth_session_manager.get_browser_context(actor, url)
            if browser_ctx.get("storage_state_path"):
                context_kwargs["storage_state"] = browser_ctx["storage_state_path"]
            return context_kwargs, browser_ctx.get("headers", {}), browser_ctx.get("cookies", [])
        if actor.auth_type == "browser-state" and actor.storage_state_path:
            context_kwargs["storage_state"] = actor.storage_state_path
        return context_kwargs, self._actor_headers(actor), self._actor_cookies(actor, url)

    async def crawl(self, url, actor: AuthActor | None = None):
        active_context = self.context
        temp_context = None
        if actor is not None:
            if self.browser is None:
                raise RuntimeError("Browser engine is not started.")
            context_kwargs, headers, cookies = self._context_kwargs_for_actor(actor, url)
            temp_context = await self.browser.new_context(**context_kwargs)
            active_context = temp_context
            if headers:
                await active_context.set_extra_http_headers(headers)
            if cookies:
                await active_context.add_cookies(cookies)
        page = await active_context.new_page()
        page.on("request", self._handle_request)
        page.on("console", self._handle_console)

        try:
            logger.info(f"Crawling {url}")
            if self.event_bus is not None:
                self.event_bus.emit_record(
                    "browser_action",
                    BrowserActionRecord(action="goto", url=url, actor_id=getattr(actor, "actor_id", ""), details={"phase": "crawl_start"}),
                )
            await page.goto(url, wait_until="networkidle")
            self._remember_page(page.url)
            initial_label = f"initial-{actor.actor_id}" if actor is not None else "initial"
            await self._capture_snapshot(page, initial_label)
            await self._extract_surfaces(page, url)
            await self._interact_with_forms(page)

            interactions = self.config.get("browser", {}).get("interactions", {})
            wait_cfg = self.config.get("browser", {}).get("wait", {})
            if interactions.get("scroll"):
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            selectors = interactions.get("click_selectors", [])[:10]
            actions = 0
            for sel in selectors:
                if actions >= self.max_actions:
                    break
                try:
                    await page.click(sel, timeout=1200)
                    actions += 1
                    await page.wait_for_timeout(wait_cfg.get("network_idle_ms", 1500))
                    self._remember_page(page.url)
                    actor_prefix = f"{actor.actor_id}-" if actor is not None else ""
                    await self._capture_snapshot(page, f"{actor_prefix}click-{actions}")
                    await self._extract_surfaces(page, page.url)
                except Exception:
                    continue
        except Exception as exc:
            logger.error(f"Crawl Error on {url}: {exc}")
            self.errors.append({"url": url, "error": str(exc)})
        finally:
            await page.close()
            if temp_context is not None:
                await temp_context.close()

    async def _interact_with_forms(self, page):
        wait_cfg = self.config.get("browser", {}).get("wait", {})
        forms = await page.query_selector_all("form")
        actions = 0
        for form in forms:
            if actions >= self.max_actions:
                break
            try:
                for field in await form.query_selector_all("input[type=text], input:not([type]), textarea"):
                    try:
                        current = await field.input_value()
                    except Exception:
                        current = await field.get_attribute("value") or ""
                    if not current:
                        await field.fill("1")
                submit = await form.query_selector("button[type=submit], input[type=submit], button")
                if submit is None:
                    continue
                await submit.click(timeout=1200)
                actions += 1
                await page.wait_for_timeout(wait_cfg.get("network_idle_ms", 1500))
                self._remember_page(page.url)
                await self._capture_snapshot(page, f"form-{actions}")
                await self._extract_surfaces(page, page.url)
                if len(self.pages_visited) < self.max_pages:
                    try:
                        await page.go_back(wait_until="networkidle", timeout=1500)
                    except Exception:
                        pass
            except Exception as exc:
                self.errors.append({"kind": "form", "error": str(exc), "url": page.url})

    async def _capture_snapshot(self, page, label):
        if len(self.page_artifacts) >= self.max_pages:
            return
        safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", label).strip("-") or "page"
        filename = f"{len(self.page_artifacts) + 1:02d}-{safe_label}.png"
        screenshot_path = os.path.join(self.artifacts_dir, filename)
        if self.capture_screenshots:
            try:
                await page.screenshot(path=screenshot_path, full_page=True)
            except Exception:
                screenshot_path = ""
        else:
            screenshot_path = ""
        try:
            body_text = await page.locator("body").inner_text()
        except Exception:
            body_text = ""
        try:
            title = await page.title()
        except Exception:
            title = ""
        try:
            form_count = await page.locator("form").count()
            link_count = await page.locator("a").count()
        except Exception:
            form_count = 0
            link_count = 0
        self.page_artifacts.append(
            {
                "url": page.url,
                "title": title,
                "forms": form_count,
                "links": link_count,
                "body_excerpt": re.sub(r"\s+", " ", body_text).strip()[:240],
                "screenshot": screenshot_path,
            }
        )
        if screenshot_path and self.artifact_store is not None:
            self.artifact_store.register_file("screenshot", screenshot_path, description=f"Browser crawl snapshot {label}")
        if self.event_bus is not None:
            self.event_bus.emit_record(
                "browser_action",
                BrowserActionRecord(action="snapshot", url=page.url, details={"label": label, "screenshot": screenshot_path, "forms": form_count, "links": link_count}),
            )

    def _actor_headers(self, actor: AuthActor):
        headers = dict(actor.headers or {})
        if actor.auth_type == "bearer" and actor.bearer_token:
            headers["Authorization"] = f"Bearer {actor.bearer_token}"
        return headers

    def _actor_cookies(self, actor: AuthActor, url: str):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        cookies = []
        for name, value in (actor.cookies or {}).items():
            cookies.append({"name": name, "value": value, "url": base_url})
        return cookies

    async def capture_actor_snapshot(self, url: str, actor: AuthActor, label: str = "actor"):
        if self.browser is None:
            raise RuntimeError("Browser engine is not started.")
        context_kwargs, headers, cookies = self._context_kwargs_for_actor(actor, url)
        temp_context = await self.browser.new_context(**context_kwargs)
        try:
            if headers:
                await temp_context.set_extra_http_headers(headers)
            if cookies:
                await temp_context.add_cookies(cookies)
            page = await temp_context.new_page()
            await page.goto(url, wait_until="networkidle")
            safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", label).strip("-") or "actor"
            screenshot_path = os.path.join(self.artifacts_dir, f"{safe_label}-{actor.actor_id}.png")
            if self.capture_screenshots:
                await page.screenshot(path=screenshot_path, full_page=True)
            else:
                screenshot_path = ""
            if screenshot_path and self.artifact_store is not None:
                self.artifact_store.register_file("screenshot", screenshot_path, actor_id=actor.actor_id, description="Actor browser snapshot")
            return {
                "actor_id": actor.actor_id,
                "display_name": actor.display_name,
                "role": actor.role,
                "url": page.url,
                "title": await page.title(),
                "body_excerpt": re.sub(r"\s+", " ", await page.locator("body").inner_text()).strip()[:240],
                "screenshot": screenshot_path,
            }
        finally:
            await temp_context.close()

    async def create_actor_context(self, actor: AuthActor | None = None, url: str = ""):
        if self.browser is None:
            raise RuntimeError("Browser engine is not started.")
        context_kwargs, headers, cookies = self._context_kwargs_for_actor(actor, url)
        context = await self.browser.new_context(**context_kwargs)
        if headers:
            await context.set_extra_http_headers(headers)
        if cookies:
            await context.add_cookies(cookies)
        return context

    async def create_actor_page(self, actor: AuthActor | None = None, url: str = ""):
        context = await self.create_actor_context(actor, url=url)
        page = await context.new_page()
        page.on("request", self._handle_request)
        page.on("console", self._handle_console)
        return context, page

    async def capture_page_screenshot(
        self,
        page,
        label: str,
        *,
        actor_id: str = "",
        workflow_id: str = "",
        execution_id: str = "",
        step_id: str = "",
        artifact_role: str = "",
        metadata=None,
    ):
        safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", label).strip("-") or "workflow"
        screenshot_path = os.path.join(self.artifacts_dir, f"{safe_label}.png")
        await page.screenshot(path=screenshot_path, full_page=True)
        if self.artifact_store is not None:
            return self.artifact_store.register_file(
                "screenshot",
                screenshot_path,
                actor_id=actor_id,
                workflow_id=workflow_id,
                execution_id=execution_id,
                step_id=step_id,
                artifact_role=artifact_role,
                description="Workflow/browser screenshot",
                metadata=dict(metadata or {}),
            )
        return {"kind": "screenshot", "path": screenshot_path, "actor_id": actor_id, "metadata": dict(metadata or {})}

    async def capture_page_dom(
        self,
        page,
        label: str,
        *,
        actor_id: str = "",
        workflow_id: str = "",
        execution_id: str = "",
        step_id: str = "",
        artifact_role: str = "",
        metadata=None,
    ):
        safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", label).strip("-") or "workflow-dom"
        dom_path = os.path.join(self.artifacts_dir, f"{safe_label}.html")
        with open(dom_path, "w", encoding="utf-8") as handle:
            handle.write(await page.content())
        if self.artifact_store is not None:
            return self.artifact_store.register_file(
                "dom",
                dom_path,
                actor_id=actor_id,
                workflow_id=workflow_id,
                execution_id=execution_id,
                step_id=step_id,
                artifact_role=artifact_role,
                description="Workflow/browser DOM snapshot",
                metadata=dict(metadata or {}),
            )
        return {"kind": "dom", "path": dom_path, "actor_id": actor_id, "metadata": dict(metadata or {})}

    async def _extract_surfaces(self, page, source_url):
        links = await page.eval_on_selector_all("a", "elements => elements.map(e => e.href)")
        for link in links:
            parsed = urlparse(link)
            if not self._in_scope(parsed):
                continue
            params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
            inputs = [InputField(name=k, value=v, kind="query") for k, v in params.items()]
            url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            fp = self._fingerprint("GET", url_clean, params.keys(), [i.name for i in inputs])
            if fp not in self.visited and params:
                self.visited.add(fp)
                self.surfaces.append(
                    AttackSurface(
                        url=url_clean,
                        method="GET",
                        params=params,
                        inputs=inputs,
                        source="browser",
                        meta={"from": source_url},
                    )
                )

        forms = await page.query_selector_all("form")
        for form in forms:
            action = await form.get_attribute("action") or source_url
            action = urljoin(source_url, action)
            if not self._in_scope(urlparse(action)):
                continue
            method = (await form.get_attribute("method") or "GET").upper()
            inputs = await form.query_selector_all("input, textarea")
            input_fields = []
            params = {}
            for inp in inputs:
                name = await inp.get_attribute("name")
                if not name:
                    continue
                try:
                    value = await inp.input_value()
                except Exception:
                    value = await inp.get_attribute("value") or ""
                kind = "body" if method == "POST" else "query"
                input_fields.append(InputField(name=name, value=value, kind=kind))
                if method == "GET":
                    params[name] = value
            url_clean = action.split("#")[0]
            fp = self._fingerprint(method, url_clean, params.keys(), [i.name for i in input_fields])
            if fp not in self.visited:
                self.visited.add(fp)
                self.surfaces.append(
                    AttackSurface(
                        url=url_clean,
                        method=method,
                        params=params,
                        inputs=input_fields if method == "POST" else [],
                        source="browser",
                        meta={"from": source_url},
                    )
                )

    def _handle_request(self, request):
        if request.resource_type not in ["xhr", "fetch"]:
            return
        parsed = urlparse(request.url)
        if not self._in_scope(parsed):
            return
        params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
        inputs = [InputField(name=k, value=v, kind="query") for k, v in params.items()]
        post_data = request.post_data
        if post_data:
            try:
                body_params = parse_qs(post_data)
                for k, v in body_params.items():
                    inputs.append(InputField(name=k, value=v[0] if v else "", kind="body"))
            except Exception:
                pass
        resp = request.response()
        meta = {
            "headers": request.headers,
            "post_data": post_data,
            "from": request.frame.url,
            "status": resp.status if resp else None,
            "content_type": resp.headers.get("content-type") if resp else None,
        }
        url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        fp = self._fingerprint(request.method, url_clean, params.keys(), [i.name for i in inputs])
        if fp not in self.visited:
            self.visited.add(fp)
            surface = AttackSurface(
                url=url_clean,
                method=request.method,
                params=params,
                inputs=inputs,
                source="browser",
                meta=meta,
            )
            self.xhr_requests.append(surface)
            self.surfaces.append(surface)

    def _handle_console(self, message):
        try:
            if message.type not in {"error", "warning"}:
                return
            self.console_errors.append({"type": message.type, "text": message.text})
        except Exception:
            return

    def _remember_page(self, url):
        if url and url not in self.pages_visited:
            self.pages_visited.append(url)

    def _in_scope(self, parsed):
        if parsed.scheme not in ("http", "https"):
            return False
        full = parsed.geturl()
        if len(full) > self.max_url_length:
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

    def _fingerprint(self, method, url, param_keys, input_names):
        return f"{method}:{url}:{sorted(param_keys)}:{sorted(input_names)}"

    def get_surfaces(self):
        return self.surfaces

    def get_xhr_requests(self):
        return self.xhr_requests

    def get_report(self):
        return {
            "pages": self.page_artifacts,
            "requests": [
                {
                    "url": surface.url,
                    "method": surface.method,
                    "source": surface.source,
                    "meta": surface.meta,
                }
                for surface in self.xhr_requests
            ],
            "console_errors": self.console_errors,
            "trace": self.trace_path,
            "artifacts_dir": self.artifacts_dir,
            "pages_visited": self.pages_visited,
            "surfaces_discovered": len(self.surfaces),
            "errors": self.errors,
        }

    async def stop(self):
        if self.context and self.trace_enabled:
            try:
                self.trace_path = os.path.join(self.artifacts_dir, "trace.zip")
                await self.context.tracing.stop(path=self.trace_path)
                if self.artifact_store is not None:
                    self.artifact_store.register_file("trace", self.trace_path, description="Browser crawl trace")
            except Exception as exc:
                self.errors.append({"kind": "trace", "error": str(exc)})
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
