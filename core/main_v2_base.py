import typer
import asyncio
import yaml
import sys
import os
from copy import deepcopy
from core.utils import setup_logger, logger, normalize_url
from core.auth_session_manager import AuthSessionManager
from core.artifact_store import ArtifactStore
from core.browser_auth_engine import BrowserAuthEngine
from core.event_bus import EventBus
from core.replay_engine import ReplayEngine
from core.request_manager import RequestManager
from core.api_engine import APIEngine
from core.auth_harness import AuthVerificationHarness
from core.rbac_verifier import RBACVerifier
from core.crawler import Crawler
from core.scanner import ScannerEngine
from core.reporter import Reporter
from layers.api_checks import APIPostureScanner
from layers.browser_verification import attach_browser_evidence
from layers.data_exposure import DataExposureScanner
from layers.dns_tls_checks import DNSTLSScanner
from layers.web_checks import WebPostureScanner
from workflows.workflow_runner import WorkflowRunner

app = typer.Typer()

def load_config(config_path):
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def validate_threads(config):
    try:
        scanner_cfg = config.get("scanner", {})
        conc = scanner_cfg.get("concurrency", {})
        threads = int(conc.get("threads", 5))
        if threads <= 0:
            raise ValueError("threads must be > 0")
        config.setdefault("scanner", {}).setdefault("concurrency", {})
        config["scanner"]["concurrency"]["threads"] = threads
        return threads
    except Exception as exc:
        typer.echo(f"Invalid thread configuration: {exc}")
        sys.exit(2)


def _mark_partial(scan_meta, message):
    scan_meta["status"] = "partial"
    if message and message not in scan_meta["warnings"]:
        scan_meta["warnings"].append(message)


def _collect_inventory_urls(target, surfaces, crawler=None, browser_report=None, api_engine=None):
    urls = [target]
    for surface in surfaces or []:
        urls.append(surface.url)
    if crawler is not None:
        urls.extend(url for url in getattr(crawler, "visited", set()) if isinstance(url, str) and url.startswith(("http://", "https://")))
        urls.extend(getattr(crawler, "pages_visited", []))
    if browser_report:
        urls.extend(browser_report.get("pages_visited", []))
        urls.extend(page.get("url", "") for page in browser_report.get("pages", []))
        urls.extend(request.get("url", "") for request in browser_report.get("requests", []))
    if api_engine is not None:
        urls.extend(surface.url for surface in api_engine.get_endpoints())
    deduped = []
    seen = set()
    for url in urls:
        if not url:
            continue
        normalized = normalize_url(url)
        if normalized.startswith(("http://", "https://")) and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def _build_browser_login_summary(auth_summary):
    actor_states = auth_summary.get("actor_states", {}) if isinstance(auth_summary, dict) else {}
    browser_actors = []
    browser_only = []
    for actor_id, state in actor_states.items():
        origin = str((state or {}).get("session_origin", "")).strip().lower()
        if not origin:
            continue
        if "browser" in origin:
            browser_actors.append(actor_id)
        if origin == "browser_authenticated_only":
            browser_only.append(actor_id)
    return {
        "attempted": browser_actors,
        "browser_authenticated_only": browser_only,
        "successful_handoff": [actor_id for actor_id in browser_actors if actor_id not in browser_only],
    }


async def run_scan_async(target, config, swagger_url, graphql_url, output_dir=None):
    surfaces = []
    all_findings = []
    if output_dir:
        config["scanner"].setdefault("output", {})
        config["scanner"]["output"]["directory"] = output_dir

    event_bus = EventBus()
    artifact_store = ArtifactStore(config["scanner"].get("output", {}).get("directory", "reports"))

    # Initialize shared Request Manager
    req_manager = RequestManager(config["scanner"])
    req_manager.attach_event_bus(event_bus)
    auth_session_manager = req_manager.auth_session_manager or AuthSessionManager(config["scanner"], requester=req_manager)
    req_manager.attach_auth_session_manager(auth_session_manager)
    auth_session_manager.attach_event_bus(event_bus)
    auth_session_manager.attach_artifact_store(artifact_store)
    browser_auth_engine = BrowserAuthEngine(config["scanner"], artifact_store=artifact_store, event_bus=event_bus)
    auth_session_manager.attach_browser_auth_engine(browser_auth_engine)
    scanner = ScannerEngine(req_manager, config)
    api_engine = APIEngine(config["scanner"], req_manager)
    auth_harness = AuthVerificationHarness(req_manager, config["scanner"])
    rbac_verifier = RBACVerifier(req_manager, auth_session_manager, config["scanner"], event_bus=event_bus, artifact_store=artifact_store)
    replay_engine = ReplayEngine(req_manager, auth_harness=auth_harness, rbac_verifier=rbac_verifier, artifact_store=artifact_store, event_bus=event_bus)
    workflow_runner = WorkflowRunner(
        config["scanner"],
        requester=req_manager,
        auth_session_manager=auth_session_manager,
        browser_engine=None,
        auth_harness=auth_harness,
        rbac_verifier=rbac_verifier,
        event_bus=event_bus,
        artifact_store=artifact_store,
    )
    scanner.auth_harness = auth_harness
    scanner.rbac_verifier = rbac_verifier
    scan_meta = {
        "status": "completed",
        "warnings": [],
        "errors": [],
        "notes": [],
        "skipped_checks": [],
        "execution": {
            "collection_methods": [],
            "surfaces_discovered": 0,
            "loaded_plugins": [plugin.name for plugin in scanner.plugins],
            "layers": {},
        },
    }
    if target.startswith(("http://127.0.0.1", "http://localhost", "https://127.0.0.1", "https://localhost")):
        scan_meta["notes"].append("Results were produced against a local or mock target; they validate scanner behavior, not a third-party asset.")
    auth_session_summary = auth_session_manager.bootstrap_enabled_actors()
    scan_meta["execution"]["layers"]["auth_sessions"] = auth_session_summary
    scan_meta["execution"]["layers"]["browser_login"] = _build_browser_login_summary(auth_session_summary)
    scan_meta["execution"]["layers"]["event_bus"] = event_bus.summary()
    scan_meta["execution"]["layers"]["artifact_index"] = artifact_store.index()
    scan_meta["execution"]["layers"]["rbac_policy"] = rbac_verifier.get_summary()
    if auth_session_summary.get("stats", {}).get("failed_login"):
        _mark_partial(scan_meta, "One or more auth actors failed login or could not be proven ready.")
    if scan_meta["execution"]["layers"]["browser_login"].get("browser_authenticated_only"):
        _mark_partial(scan_meta, "One or more browser-driven logins succeeded visually but could not be handed off to the HTTP layer.")
    if config["scanner"].get("auth_verification", {}).get("enabled") and not auth_session_summary.get("ready"):
        scan_meta["skipped_checks"].append("Some auth verification scenarios were skipped because not enough actors reached an authenticated ready state.")

    try:
        browser_enabled = config["scanner"].get("browser_enabled", True)
        crawler_enabled = config["scanner"].get("crawler_enabled", True)

        browser = None
        crawler = None
        browser_report = None
        workflow_instances = []
        workflow_findings = []
        if browser_enabled:
            try:
                try:
                    from core.browser_engine import BrowserEngine  # Lazy import to handle missing Playwright
                except ImportError as exc:
                    logger.warning(f"Playwright not available ({exc}). Falling back to HTTP crawler.")
                    browser_enabled = False
                    BrowserEngine = None  # type: ignore
                if browser_enabled:
                    browser = BrowserEngine(config["scanner"])
                    browser.attach_auth_session_manager(auth_session_manager)
                    browser.attach_event_bus(event_bus)
                    browser.attach_artifact_store(artifact_store)
                    logger.info("Starting Browser Engine (Playwright)...")
                    await browser.start()
                    workflow_runner.browser_engine = browser
                    await browser.crawl(target)
                    surfaces.extend(browser.get_surfaces())
                    browser_report = browser.get_report()
                    scan_meta["execution"]["collection_methods"].append("browser")
                    if getattr(browser, "errors", []):
                        _mark_partial(scan_meta, "Browser-assisted crawl encountered errors.")
                    logger.info(f"Browser finished. Found {len(surfaces)} surfaces.")
            except Exception as exc:
                logger.warning(f"Browser engine failed, falling back to crawler: {exc}")
                _mark_partial(scan_meta, f"Browser engine failed: {exc}")
                browser_enabled = False
        if crawler_enabled:
            logger.info("Starting HTTP crawler...")
            crawler = Crawler(req_manager, config["scanner"])
            crawler.crawl(target)
            surfaces.extend(crawler.get_surfaces())
            if "crawler" not in scan_meta["execution"]["collection_methods"]:
                scan_meta["execution"]["collection_methods"].append("crawler")
            scan_meta["execution"]["crawler"] = {
                "pages_visited": len(getattr(crawler, "pages_visited", [])),
                "surfaces_discovered": len(crawler.get_surfaces()),
                "errors": getattr(crawler, "errors", []),
            }
            auth_crawl_cfg = config["scanner"].get("auth_verification", {}).get("authenticated_crawl", {})
            if auth_crawl_cfg.get("enabled", False):
                actor_ids = list(auth_crawl_cfg.get("actor_ids", []) or [])
                if not actor_ids and auth_session_manager.context.baseline_actor_id:
                    actor_ids = [auth_session_manager.context.baseline_actor_id]
                actor_crawl_meta = {}
                for actor_id in actor_ids:
                    actor = auth_session_manager.get_actor(actor_id)
                    if actor is None or not auth_session_manager.is_actor_ready(actor):
                        scan_meta["skipped_checks"].append(f"Authenticated crawl skipped for actor {actor_id} because the session was not ready.")
                        continue
                    actor_crawler = Crawler(req_manager, config["scanner"])
                    actor_crawler.crawl(target, actor=actor)
                    actor_surfaces = actor_crawler.get_surfaces()
                    surfaces.extend(actor_surfaces)
                    actor_crawl_meta[actor_id] = {
                        "pages_visited": len(getattr(actor_crawler, "pages_visited", [])),
                        "surfaces_discovered": len(actor_surfaces),
                        "errors": getattr(actor_crawler, "errors", []),
                    }
                if actor_crawl_meta:
                    scan_meta["execution"]["authenticated_crawl"] = actor_crawl_meta
            if getattr(crawler, "errors", []):
                _mark_partial(scan_meta, "HTTP crawler encountered errors.")

        # 2. API Engine (Swagger/GraphQL)
        if swagger_url or config["scanner"].get("api", {}).get("swagger_url"):
            s_url = swagger_url or config["scanner"]["api"]["swagger_url"]
            logger.info(f"Starting API Engine on {s_url}...")
            api_surfaces = api_engine.load_swagger(s_url)
            surfaces.extend(api_surfaces)
            scan_meta["execution"]["collection_methods"].append("swagger")
        if graphql_url:
            gql_surfaces = api_engine.scan_graphql(graphql_url)
            surfaces.extend(gql_surfaces)
            scan_meta["execution"]["collection_methods"].append("graphql")
        if getattr(api_engine, "errors", []):
            _mark_partial(scan_meta, "API parsing/scanning encountered errors.")

        # Deduplicate by surface id
        surfaces = list({s.id: s for s in surfaces}.values())
        scan_meta["execution"]["surfaces_discovered"] = len(surfaces)
        discovery_urls = _collect_inventory_urls(target, surfaces, crawler=crawler, browser_report=browser_report, api_engine=api_engine)
        scan_meta["execution"]["discovered_urls"] = discovery_urls[:50]
        if not surfaces:
            scan_meta["notes"].append("No attack surfaces were discovered.")

        # 3. Layered passive / posture checks
        web_scanner = WebPostureScanner(req_manager, config["scanner"])
        web_findings, web_meta = web_scanner.scan(discovery_urls)
        web_meta["findings"] = len(web_findings)
        scan_meta["execution"]["layers"]["web_checks"] = web_meta
        scan_meta["skipped_checks"].extend(web_meta.get("skipped", []))
        if web_meta.get("errors"):
            _mark_partial(scan_meta, "Web passive checks encountered errors.")

        data_scanner = DataExposureScanner(req_manager, config["scanner"])
        data_findings, data_meta = data_scanner.scan(target, discovery_urls)
        data_meta["findings"] = len(data_findings)
        scan_meta["execution"]["layers"]["data_exposure"] = data_meta
        scan_meta["skipped_checks"].extend(data_meta.get("skipped", []))
        if data_meta.get("errors"):
            _mark_partial(scan_meta, "Data exposure checks encountered errors.")

        api_scanner = APIPostureScanner(config["scanner"])
        api_findings, api_meta = api_scanner.scan(api_engine)
        api_meta["findings"] = len(api_findings)
        scan_meta["execution"]["layers"]["api_checks"] = api_meta
        scan_meta["skipped_checks"].extend(api_meta.get("skipped", []))

        dns_tls_scanner = DNSTLSScanner(config["scanner"])
        dns_tls_findings, dns_tls_meta = dns_tls_scanner.scan(target)
        dns_tls_meta["findings"] = len(dns_tls_findings)
        scan_meta["execution"]["layers"]["dns_tls"] = dns_tls_meta
        scan_meta["skipped_checks"].extend(dns_tls_meta.get("skipped", []))
        if dns_tls_meta.get("errors"):
            _mark_partial(scan_meta, "DNS/TLS checks encountered errors.")
        scan_meta["execution"]["layers"]["auth_verification"] = auth_harness.get_summary()
        scan_meta["execution"]["layers"]["auth_sessions"] = auth_session_manager.get_summary()
        if not auth_harness.is_ready():
            scan_meta["skipped_checks"].append("Auth-aware verification was not run because fewer than two valid actors were configured.")

        # 4. Active Scanning (Concurrent)
        logger.info("Starting Active Scanner...")
        findings = scanner.scan(surfaces)
        scan_meta["execution"]["scanner"] = scanner.last_run_stats
        if scanner.last_run_stats.get("errors"):
            _mark_partial(scan_meta, "Active scanner encountered plugin execution errors.")

        if workflow_runner.enabled():
            try:
                workflow_instances, workflow_findings = await workflow_runner.run_configured(target)
                scan_meta["execution"]["layers"]["workflow_execution"] = workflow_runner.get_summary()
                if any(instance.workflow_status in {"partial", "failed", "indeterminate", "blocked_auth"} for instance in workflow_instances):
                    _mark_partial(scan_meta, "One or more workflow executions completed only partially or indeterminately.")
            except Exception as exc:
                scan_meta["execution"]["layers"]["workflow_execution"] = workflow_runner.get_summary()
                _mark_partial(scan_meta, f"Workflow execution failed: {exc}")
        else:
            scan_meta["execution"]["layers"]["workflow_execution"] = workflow_runner.get_summary()

        all_findings.extend(web_findings)
        all_findings.extend(data_findings)
        all_findings.extend(api_findings)
        all_findings.extend(dns_tls_findings)
        all_findings.extend(findings)
        all_findings.extend(workflow_findings)
        for finding in all_findings:
            if finding.scanner_mode == "workflow":
                continue
            if finding.verification_status != "verified":
                continue
            if finding.category not in {"access-control", "injection"}:
                continue
            replay_result = replay_engine.replay_finding(finding)
            artifact_ref = replay_result.get("artifact_ref")
            if artifact_ref:
                finding.artifact_refs.append(deepcopy(artifact_ref))
            finding.evidence.setdefault("replay", replay_result)
        if workflow_runner.enabled():
            replay_verified_only = bool(config["scanner"].get("workflows", {}).get("replay_verified_only", True))
            for instance in workflow_instances:
                if not instance.definition.replayable:
                    continue
                if replay_verified_only and instance.final_verdict.verification_status != "verified":
                    continue
                replay_result = await replay_engine.replay_workflow_execution(instance, workflow_runner, target=target)
                artifact_ref = replay_result.get("artifact_ref")
                if artifact_ref:
                    instance.artifact_refs.append(deepcopy(artifact_ref))
                for finding in workflow_findings:
                    if finding.workflow_execution_id != instance.execution_id:
                        continue
                    finding.workflow_replay_status = replay_result["record"]["replay_status"]
                    finding.evidence.setdefault("workflow_replay", replay_result["record"])
                    if artifact_ref:
                        finding.artifact_refs.append(deepcopy(artifact_ref))
        if browser is not None and auth_harness.is_ready():
            try:
                await auth_harness.capture_browser_artifacts(all_findings, browser)
            except Exception as exc:
                _mark_partial(scan_meta, f"Browser actor artifact capture failed: {exc}")
        if browser is not None:
            await browser.stop()
            browser_report = browser.get_report()
            scan_meta["execution"]["browser"] = browser_report
        attach_browser_evidence(all_findings, browser_report)
        scan_meta["execution"]["layers"]["auth_verification"] = auth_harness.get_summary()
        scan_meta["execution"]["layers"]["auth_sessions"] = auth_session_manager.get_summary()
        scan_meta["execution"]["layers"]["browser_login"] = _build_browser_login_summary(scan_meta["execution"]["layers"]["auth_sessions"])
        scan_meta["execution"]["layers"]["rbac_policy"] = rbac_verifier.get_summary()
        scan_meta["execution"]["layers"]["replay"] = replay_engine.get_summary()
        scan_meta["execution"]["layers"]["workflow_execution"] = workflow_runner.get_summary()
        scan_meta["execution"]["layers"]["event_bus"] = event_bus.summary()
        scan_meta["execution"]["layers"]["artifact_index"] = artifact_store.index()

    except Exception as e:
        logger.error(f"Scan failed with error: {e}")
        scan_meta["status"] = "failed"
        scan_meta["errors"].append(str(e))
        # Ensure cleanup
        try:
            if 'browser' in locals() and browser is not None:
                await browser.stop()
        except Exception:
            pass
    
    return all_findings, scan_meta

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    config_path: str = typer.Option("config/default_config.yaml", "--config", help="Path to config file"),
    swagger: str = typer.Option(None, help="URL to Swagger/OpenAPI JSON"),
    graphql: str = typer.Option(None, help="GraphQL endpoint"),
    output_dir: str = typer.Option("reports", "--output", help="Directory to save reports"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug counters logging"),
):
    """
    Evidence-first web vulnerability scanner.
    """
    # Load Config
    config = load_config(config_path)

    # Override Config with CLI args
    config["scanner"]["target"] = target
    validate_threads(config)
    from urllib.parse import urlparse
    import ipaddress
    domain = urlparse(target).netloc
    hostname = urlparse(target).hostname or ""
    config["scanner"]["scope"]["allowlist"].append(domain)
    config["scanner"]["scope"].setdefault("include_domains", []).append(domain)
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            config["scanner"]["scope"]["allow_private"] = True
    except ValueError:
        if hostname in {"localhost"}:
            config["scanner"]["scope"]["allow_private"] = True

    setup_logger(level=config["logging"]["level"], log_file=config["logging"]["file"])
    config["scanner"]["debug"] = bool(debug or config["scanner"].get("debug", False))
    logger.info(f"Starting scan on {target}")

    findings = []
    scan_failed = False
    scan_aborted = False
    scan_meta = {"status": "completed", "warnings": [], "errors": [], "notes": [], "execution": {"collection_methods": [], "surfaces_discovered": 0, "loaded_plugins": []}}
    try:
        config["scanner"].setdefault("output", {})
        config["scanner"]["output"]["directory"] = output_dir
        findings, scan_meta = asyncio.run(run_scan_async(target, config, swagger, graphql, output_dir=output_dir))
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        scan_aborted = True
        scan_meta["status"] = "aborted"
    except Exception as exc:
        logger.error(f"Scan failed: {exc}")
        scan_failed = True
        scan_meta["status"] = "failed"
        scan_meta["errors"].append(str(exc))
    finally:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        reporter = Reporter(config, scan_meta=scan_meta)
        for f in findings:
            reporter.add_finding(f)
        json_path = os.path.join(output_dir, "scan_report.json")
        html_path = os.path.join(output_dir, "scan_report.html")
        reporter.generate_json(json_path)
        reporter.generate_html(html_path)
        summary = reporter.get_summary()
        status_counts = summary.get("by_verification_status", {})
        header = "=== Scan Partially Completed ===" if scan_meta.get("status") == "partial" else "=== Scan Completed ==="
        typer.echo(f"\n{header}")
        typer.echo(f"JSON Report: {json_path}")
        typer.echo(f"HTML Report: {html_path}")
        if scan_meta.get("execution", {}).get("surfaces_discovered", 0) == 0:
            typer.echo("\nNo attack surfaces were discovered.")
        elif findings:
            typer.echo(
                f"\nRecorded {summary['total_findings']} reportable findings "
                f"(verified={status_counts.get('verified', 0)}, detected={status_counts.get('detected', 0)}, "
                f"suspected={status_counts.get('suspected', 0)}, informational={status_counts.get('informational', 0)})."
            )
        else:
            typer.echo("\nNo reportable findings were produced.")
        if scan_aborted:
            sys.exit(3)
        if scan_failed:
            sys.exit(2)
        if scan_meta.get("status") == "partial":
            sys.exit(3)
        if findings:
            sys.exit(1)
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "scan":
        # Support both `python main_v2.py scan <target>` and `python main_v2.py <target>`
        sys.argv.pop(1)
    app()
