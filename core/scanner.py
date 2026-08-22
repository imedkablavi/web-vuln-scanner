import concurrent.futures
import threading
import time
from typing import Dict, List, Type

from .models import AttackSurface, Finding
from .plugin_catalog import get_plugin_metadata
from .plugin_request import send_plugin_test
from .utils import get_content_hash, logger
from plugins.base import BasePlugin
from plugins.business_logic import BusinessLogicPlugin
from plugins.cmd_injection import CMDInjectionPlugin
from plugins.lfi import LFIPlugin
from plugins.open_redirect import OpenRedirectPlugin
from plugins.sqli import SQLiPlugin
from plugins.xss_reflected import XSSReflectedPlugin


class PluginRegistry:
    available: Dict[str, Type[BasePlugin]] = {
        "sqli": SQLiPlugin,
        "business_logic": BusinessLogicPlugin,
        "xss_reflected": XSSReflectedPlugin,
        "lfi": LFIPlugin,
        "cmd_injection": CMDInjectionPlugin,
        "open_redirect": OpenRedirectPlugin,
    }

    @classmethod
    def load_plugins(cls, config, request_manager) -> List[BasePlugin]:
        plugins = []
        requested = config.get("plugins", {})
        for name, raw_config in requested.items():
            cfg = (
                raw_config
                if isinstance(raw_config, dict)
                else {"enabled": bool(raw_config)}
            )
            plugin_cls = cls.available.get(name)
            if not plugin_cls:
                continue
            metadata = get_plugin_metadata(name)
            if metadata.get("maturity") != "stable" and cfg.get("enabled"):
                logger.warning(
                    f"Plugin '{name}' is {metadata.get('maturity', 'unknown')} and "
                    "is disabled by the release maturity policy."
                )
                continue
            if plugin_cls.enabled(cfg):
                plugins.append(plugin_cls(request_manager, cfg))
        return plugins


class ScannerEngine:
    def __init__(self, request_manager, config):
        self.requester = request_manager
        self.full_config = config
        self.config = config["scanner"] if "scanner" in config else config
        self.plugins: List[BasePlugin] = PluginRegistry.load_plugins(
            self.config,
            request_manager,
        )
        self.threads = int(self.config["concurrency"]["threads"])
        self.per_host = int(
            self.config["concurrency"].get(
                "per_host_concurrency",
                max(1, self.threads),
            )
        )
        self.global_timeout = float(
            self.config["concurrency"].get(
                "global_timeout_seconds",
                self.config["concurrency"]["timeout"],
            )
        )
        self.verified_only = self.config.get("verified_only", True)
        self.max_findings_per_plugin = max(
            1,
            int(self.config.get("max_findings_per_plugin", 50)),
        )
        self.contract_mode = self.config.get("plugin_contract", "auto")
        self.debug = bool(self.config.get("debug", False))
        self.last_run_stats: Dict = {}
        self.auth_harness = None
        self.rbac_verifier = None

    def _baseline(self, surface: AttackSurface):
        try:
            response = self.requester.send_surface(surface)
        except Exception as exc:
            logger.error(f"Baseline request failed for {surface.url}: {exc}")
            return None
        if not response:
            return None
        return {
            "status": response.status_code,
            "text": response.text or "",
            "hash": get_content_hash(response.text or ""),
            "length": len(response.text or ""),
            "headers": (
                dict(response.headers) if hasattr(response, "headers") else {}
            ),
        }

    def scan(self, surfaces: List[AttackSurface]) -> List[Finding]:
        logger.info(
            f"Starting scan on {len(surfaces)} surfaces with {self.threads} threads."
        )
        all_findings: List[Finding] = []
        baseline_cache: Dict[str, Dict] = {}
        baseline_lock = threading.Lock()
        stats_lock = threading.Lock()
        finding_lock = threading.Lock()
        stop_event = threading.Event()
        started_at = time.monotonic()
        deadline = (
            started_at + self.global_timeout if self.global_timeout > 0 else None
        )
        plugin_finding_counts = {plugin.name: 0 for plugin in self.plugins}
        timeout_recorded = False

        debug_counts = {
            "surfaces_total": len(surfaces),
            "plugins_total": len(self.plugins),
            "details": {},
            "baseline_example": None,
            "first_response_example": None,
            "errors": [],
        }

        def deadline_exceeded() -> bool:
            nonlocal timeout_recorded
            if stop_event.is_set():
                return True
            if deadline is None or time.monotonic() < deadline:
                return False
            stop_event.set()
            with stats_lock:
                if not timeout_recorded:
                    timeout_recorded = True
                    debug_counts["errors"].append(
                        "Active scan global timeout reached; remaining plugin work was cancelled."
                    )
            return True

        def reserve_finding(plugin_name: str) -> bool:
            with finding_lock:
                current = plugin_finding_counts.get(plugin_name, 0)
                if current >= self.max_findings_per_plugin:
                    return False
                plugin_finding_counts[plugin_name] = current + 1
                return True

        def plugin_stats(plugin_name: str):
            with stats_lock:
                return debug_counts["details"].setdefault(
                    plugin_name,
                    {
                        "generated_testcases": 0,
                        "executed_requests": 0,
                        "reported_results": 0,
                        "findings_written": 0,
                        "status_counts": {},
                        "sample_testcase": None,
                        "first_response": None,
                    },
                )

        def get_baseline(surface: AttackSurface):
            with baseline_lock:
                if surface.id in baseline_cache:
                    return baseline_cache[surface.id]
            if deadline_exceeded():
                return None
            baseline = self._baseline(surface)
            with baseline_lock:
                baseline_cache.setdefault(surface.id, baseline)
                return baseline_cache[surface.id]

        def run_surface(surface: AttackSurface):
            if deadline_exceeded():
                return []
            local_findings = []
            baseline = get_baseline(surface)
            if baseline:
                with stats_lock:
                    if debug_counts["baseline_example"] is None:
                        debug_counts["baseline_example"] = {
                            "url": surface.url,
                            "status": baseline.get("status"),
                            "length": baseline.get("length"),
                            "hash": baseline.get("hash"),
                        }
            context = {
                "verified_only": self.verified_only,
                "max_findings": self.max_findings_per_plugin,
                "baseline_cache": baseline_cache,
                "boolean_cache": {},
                "baseline": baseline,
                "errors": [],
                "auth_harness": self.auth_harness,
                "rbac_verifier": self.rbac_verifier,
                "surface": surface,
            }

            for plugin in self.plugins:
                if deadline_exceeded():
                    break
                with finding_lock:
                    if (
                        plugin_finding_counts.get(plugin.name, 0)
                        >= self.max_findings_per_plugin
                    ):
                        continue
                dbg = plugin_stats(plugin.name)
                if not plugin.applicable(surface):
                    continue

                has_v2_contract = all(
                    hasattr(plugin, attr)
                    for attr in ("generate_tests", "verify", "build_finding")
                )
                if self.contract_mode == "v2":
                    use_v2 = has_v2_contract
                elif self.contract_mode == "legacy":
                    use_v2 = False
                else:
                    use_v2 = has_v2_contract

                if use_v2:
                    tests = plugin.generate_tests(surface, context)
                    tests = tests[
                        : plugin.max_tests_per_surface(
                            getattr(plugin, "config", {})
                        )
                    ]
                    with stats_lock:
                        dbg["generated_testcases"] += len(tests)
                        if tests and dbg["sample_testcase"] is None:
                            first = tests[0]
                            dbg["sample_testcase"] = {
                                "param": first.param,
                                "kind": first.kind,
                                "payload": first.payload,
                                "method_override": first.method_override,
                                "allow_redirects": first.allow_redirects,
                            }
                    for testcase in tests:
                        if deadline_exceeded():
                            break
                        with finding_lock:
                            if (
                                plugin_finding_counts.get(plugin.name, 0)
                                >= self.max_findings_per_plugin
                            ):
                                break
                        try:
                            response = send_plugin_test(
                                self.requester,
                                surface,
                                testcase,
                            )
                            with stats_lock:
                                dbg["executed_requests"] += 1
                                if (
                                    response is not None
                                    and dbg["first_response"] is None
                                ):
                                    dbg["first_response"] = {
                                        "status": getattr(
                                            response, "status_code", None
                                        ),
                                        "length": len(response.text or ""),
                                        "hash": get_content_hash(
                                            response.text or ""
                                        ),
                                    }
                                    if debug_counts["first_response_example"] is None:
                                        debug_counts["first_response_example"] = dbg[
                                            "first_response"
                                        ]
                            verification = plugin.verify(
                                testcase,
                                baseline,
                                response,
                                context,
                            )
                            if verification.is_verified:
                                with stats_lock:
                                    dbg["reported_results"] += 1
                                    status = getattr(
                                        verification,
                                        "verification_status",
                                        "suspected",
                                    )
                                    dbg["status_counts"][status] = (
                                        dbg["status_counts"].get(status, 0) + 1
                                    )
                                if reserve_finding(plugin.name):
                                    finding = plugin.build_finding(
                                        testcase,
                                        verification,
                                        surface,
                                    )
                                    local_findings.append(finding)
                                    with stats_lock:
                                        dbg["findings_written"] += 1
                        except Exception as exc:
                            message = (
                                f"Plugin {plugin.name} failed on {surface.url}: {exc}"
                            )
                            logger.error(message)
                            with stats_lock:
                                debug_counts["errors"].append(message)
                else:
                    try:
                        context["baseline"] = baseline
                        results = plugin.run(surface, context) or []
                        with stats_lock:
                            dbg["reported_results"] += len(results)
                        for finding in results:
                            if deadline_exceeded():
                                break
                            if not reserve_finding(plugin.name):
                                break
                            local_findings.append(finding)
                            with stats_lock:
                                dbg["findings_written"] += 1
                                dbg["status_counts"][finding.verification_status] = (
                                    dbg["status_counts"].get(
                                        finding.verification_status,
                                        0,
                                    )
                                    + 1
                                )
                    except Exception as exc:
                        message = (
                            f"Legacy plugin {plugin.name} failed on {surface.url}: {exc}"
                        )
                        logger.error(message)
                        with stats_lock:
                            debug_counts["errors"].append(message)
            return local_findings

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.threads)
        futures = [executor.submit(run_surface, surface) for surface in surfaces]
        try:
            remaining = None
            if deadline is not None:
                remaining = max(0.0, deadline - time.monotonic())
            try:
                completed = concurrent.futures.as_completed(
                    futures,
                    timeout=remaining,
                )
                for future in completed:
                    try:
                        all_findings.extend(future.result() or [])
                    except Exception as exc:
                        message = f"Task failed: {exc}"
                        logger.error(message)
                        with stats_lock:
                            debug_counts["errors"].append(message)
            except concurrent.futures.TimeoutError:
                deadline_exceeded()
        finally:
            if stop_event.is_set():
                for future in futures:
                    future.cancel()
            # Running requests cannot be force-killed safely. Workers observe
            # stop_event between requests, while RequestManager bounds each
            # in-flight network operation with connect/read timeouts.
            executor.shutdown(wait=True, cancel_futures=True)

        debug_counts["findings_total"] = len(all_findings)
        status_counts: Dict[str, int] = {}
        for finding in all_findings:
            status_counts[finding.verification_status] = (
                status_counts.get(finding.verification_status, 0) + 1
            )
        self.last_run_stats = {
            "surfaces_total": len(surfaces),
            "plugins_loaded": [plugin.name for plugin in self.plugins],
            "findings_total": len(all_findings),
            "findings_per_plugin": dict(plugin_finding_counts),
            "status_counts": status_counts,
            "errors": debug_counts["errors"],
            "timed_out": stop_event.is_set(),
            "elapsed_seconds": round(time.monotonic() - started_at, 3),
            "plugin_details": debug_counts["details"],
        }
        if self.debug or not all_findings:
            logger.info(
                "Debug counters summary: "
                f"surfaces={debug_counts['surfaces_total']} "
                f"plugins={debug_counts['plugins_total']} "
                f"findings={debug_counts['findings_total']}"
            )
            if debug_counts.get("baseline_example"):
                logger.info(
                    f"Baseline sample: {debug_counts['baseline_example']}"
                )
            if debug_counts.get("first_response_example"):
                logger.info(
                    f"First response sample: {debug_counts['first_response_example']}"
                )
            for plugin_name, stats in debug_counts["details"].items():
                logger.info(
                    f"[{plugin_name}] generated_testcases={stats['generated_testcases']} "
                    f"executed_requests={stats['executed_requests']} "
                    f"reported_results={stats['reported_results']} "
                    f"status_counts={stats['status_counts']} "
                    f"findings_written={stats['findings_written']} "
                    f"sample_testcase={stats['sample_testcase']} "
                    f"first_response={stats['first_response']}"
                )
        return all_findings
