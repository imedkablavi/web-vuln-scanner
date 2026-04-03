import concurrent.futures
from typing import List, Dict, Type
from .utils import logger, get_content_hash
from .models import AttackSurface, Finding
from plugins.base import BasePlugin
from plugins.sqli import SQLiPlugin
from plugins.business_logic import BusinessLogicPlugin
from plugins.xss_reflected import XSSReflectedPlugin
from plugins.lfi import LFIPlugin
from plugins.cmd_injection import CMDInjectionPlugin
from plugins.open_redirect import OpenRedirectPlugin


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
        unstable = {"xss_reflected", "lfi", "cmd_injection", "open_redirect"}
        for name, cfg in requested.items():
            cfg_obj = cfg if isinstance(cfg, dict) else {"enabled": bool(cfg)}
            plugin_cls = cls.available.get(name)
            if not plugin_cls:
                continue
            if name in unstable and cfg_obj.get("enabled"):
                logger.warning(f"Plugin '{name}' is disabled (incomplete/unstable). Skipping.")
                continue
            if plugin_cls.enabled(cfg_obj):
                plugins.append(plugin_cls(request_manager, cfg_obj))
        return plugins


class ScannerEngine:
    def __init__(self, request_manager, config):
        self.requester = request_manager
        self.full_config = config
        self.config = config["scanner"] if "scanner" in config else config
        self.plugins: List[BasePlugin] = PluginRegistry.load_plugins(self.config, request_manager)
        self.threads = int(self.config["concurrency"]["threads"])
        self.per_host = int(self.config["concurrency"].get("per_host_concurrency", max(1, self.threads)))
        self.global_timeout = self.config["concurrency"].get("global_timeout_seconds", self.config["concurrency"]["timeout"])
        self.verified_only = self.config.get("verified_only", True)
        self.max_findings_per_plugin = self.config.get("max_findings_per_plugin", 50)
        self.contract_mode = self.config.get("plugin_contract", "auto")
        self.debug = bool(self.config.get("debug", False))
        self.last_run_stats: Dict = {}
        self.auth_harness = None
        self.rbac_verifier = None

    def _baseline(self, surface: AttackSurface):
        try:
            resp = self.requester.send_surface(surface)
        except Exception as exc:
            logger.error(f"Baseline request failed for {surface.url}: {exc}")
            return None
        if not resp:
            return None
        return {
            "status": resp.status_code,
            "text": resp.text or "",
            "hash": get_content_hash(resp.text or ""),
            "length": len(resp.text or ""),
            "headers": dict(resp.headers) if hasattr(resp, "headers") else {},
        }

    def scan(self, surfaces: List[AttackSurface]) -> List[Finding]:
        logger.info(f"Starting scan on {len(surfaces)} surfaces with {self.threads} threads.")
        all_findings: List[Finding] = []
        baseline_cache: Dict[str, Dict] = {}
        debug_counts = {
            "surfaces_total": len(surfaces),
            "plugins_total": len(self.plugins),
            "details": {},
            "baseline_example": None,
            "first_response_example": None,
            "errors": [],
        }

        def run_surface(surface: AttackSurface):
            local_findings = []
            baseline = baseline_cache.get(surface.id)
            if baseline is None:
                baseline = self._baseline(surface)
                baseline_cache[surface.id] = baseline
            if baseline and debug_counts["baseline_example"] is None:
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
                dbg = debug_counts["details"].setdefault(
                    plugin.name,
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
                if not plugin.applicable(surface):
                    continue
                use_v2 = False
                if self.contract_mode == "v2":
                    use_v2 = all(hasattr(plugin, attr) for attr in ("generate_tests", "verify", "build_finding"))
                elif self.contract_mode == "legacy":
                    use_v2 = False
                else:  # auto
                    use_v2 = all(hasattr(plugin, attr) for attr in ("generate_tests", "verify", "build_finding"))

                if use_v2:
                    tests = plugin.generate_tests(surface, context)
                    tests = tests[: plugin.max_tests_per_surface(getattr(plugin, "config", {}))]
                    dbg["generated_testcases"] += len(tests)
                    if tests and dbg["sample_testcase"] is None:
                        first = tests[0]
                        dbg["sample_testcase"] = {
                            "param": first.param,
                            "kind": first.kind,
                            "payload": first.payload,
                            "method_override": first.method_override,
                        }
                    for tc in tests:
                        try:
                            resp = self.requester.send_surface(surface, tc.param, tc.payload)
                            dbg["executed_requests"] += 1
                            if resp is not None and dbg["first_response"] is None:
                                dbg["first_response"] = {
                                    "status": getattr(resp, "status_code", None),
                                    "length": len(resp.text or ""),
                                    "hash": get_content_hash(resp.text or ""),
                                }
                                if debug_counts["first_response_example"] is None:
                                    debug_counts["first_response_example"] = dbg["first_response"]
                            vres = plugin.verify(tc, baseline, resp, context)
                            if vres.is_verified:
                                dbg["reported_results"] += 1
                                status = getattr(vres, "verification_status", "suspected")
                                dbg["status_counts"][status] = dbg["status_counts"].get(status, 0) + 1
                                finding = plugin.build_finding(tc, vres, surface)
                                local_findings.append(finding)
                                dbg["findings_written"] += 1
                                if len(local_findings) >= self.max_findings_per_plugin:
                                    break
                        except Exception as exc:
                            msg = f"Plugin {plugin.name} failed on {surface.url}: {exc}"
                            logger.error(msg)
                            debug_counts["errors"].append(msg)
                else:
                    try:
                        context["baseline"] = baseline
                        res = plugin.run(surface, context)
                        if res:
                            local_findings.extend(res)
                            dbg["reported_results"] += len(res)
                            dbg["findings_written"] += len(res)
                            for finding in res:
                                dbg["status_counts"][finding.verification_status] = dbg["status_counts"].get(finding.verification_status, 0) + 1
                    except Exception as exc:
                        msg = f"Legacy plugin {plugin.name} failed on {surface.url}: {exc}"
                        logger.error(msg)
                        debug_counts["errors"].append(msg)

                if len(local_findings) >= self.max_findings_per_plugin:
                    break
            return local_findings

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(run_surface, s) for s in surfaces]
            for f in concurrent.futures.as_completed(futures):
                try:
                    res = f.result()
                    all_findings.extend(res or [])
                except Exception as exc:
                    msg = f"Task failed: {exc}"
                    logger.error(msg)
                    debug_counts["errors"].append(msg)
        debug_counts["findings_total"] = len(all_findings)
        status_counts: Dict[str, int] = {}
        for finding in all_findings:
            status_counts[finding.verification_status] = status_counts.get(finding.verification_status, 0) + 1
        self.last_run_stats = {
            "surfaces_total": len(surfaces),
            "plugins_loaded": [plugin.name for plugin in self.plugins],
            "findings_total": len(all_findings),
            "status_counts": status_counts,
            "errors": debug_counts["errors"],
            "plugin_details": debug_counts["details"],
        }
        if self.debug or not all_findings:
            logger.info(f"Debug counters summary: surfaces={debug_counts['surfaces_total']} plugins={debug_counts['plugins_total']} findings={debug_counts['findings_total']}")
            if debug_counts.get("baseline_example"):
                logger.info(f"Baseline sample: {debug_counts['baseline_example']}")
            if debug_counts.get("first_response_example"):
                logger.info(f"First response sample: {debug_counts['first_response_example']}")
            for plugin_name, stats in debug_counts["details"].items():
                logger.info(
                    f"[{plugin_name}] generated_testcases={stats['generated_testcases']} "
                    f"executed_requests={stats['executed_requests']} reported_results={stats['reported_results']} "
                    f"status_counts={stats['status_counts']} findings_written={stats['findings_written']} sample_testcase={stats['sample_testcase']} "
                    f"first_response={stats['first_response']}"
                )
        return all_findings
