import difflib
import re
from typing import List, Dict
from .base import BasePlugin, TestCase, VerificationResult
from core.models import AttackSurface, Finding
from core.utils import get_content_hash


class SQLiPlugin(BasePlugin):
    name = "sqli"
    supported_input_kinds = ["query", "body"]
    error_patterns = [
        r"SQL syntax",
        r"mysql_fetch",
        r"ORA-01756",
        r"SQLite.Exception",
        r"PostgreSQL.*ERROR",
        r"Warning.*mssql_",
        r"SQLSTATE",
        r"syntax error at or near",
        r"unterminated quoted string",
        r"unclosed quotation mark",
        r"JDBCException",
    ]

    @classmethod
    def enabled(cls, config: Dict) -> bool:
        return bool(config.get("enabled", False))

    def applicable(self, surface: AttackSurface) -> bool:
        return bool(surface.params or surface.inputs)

    def max_tests_per_surface(self, config: Dict) -> int:
        return int(config.get("max_tests_per_surface", 6))

    def _excerpt(self, text: str, limit: int = 160) -> str:
        return re.sub(r"\s+", " ", text or "").strip()[:limit]

    @staticmethod
    def _active_input_supported(surface: AttackSurface, item) -> bool:
        if item.kind != "body":
            return True
        path = str(getattr(item, "path", "") or "")
        nested_json = path.startswith("/") and path.count("/") > 1
        if nested_json and not bool((surface.meta or {}).get("nested_active_supported", False)):
            return False
        return True

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        tests: List[TestCase] = []
        max_tests = self.max_tests_per_surface(self.config)
        payloads = ["'", "' AND '1'='2", "' OR '1'='1", "\""]
        targets = [(name, "query", name) for name in surface.params.keys()]
        targets.extend(
            (
                inp.name,
                inp.kind,
                str(getattr(inp, "path", "") or inp.name),
            )
            for inp in surface.inputs
            if inp.kind in self.supported_input_kinds
            and self._active_input_supported(surface, inp)
        )
        deduped = []
        seen = set()
        for param, kind, input_path in targets:
            key = (kind, input_path or param)
            if key in seen:
                continue
            seen.add(key)
            deduped.append((param, kind, input_path))

        for param, kind, input_path in deduped:
            baseline_identity = input_path or param
            for p in payloads:
                tc = TestCase(
                    plugin=self.name,
                    surface_id=surface.id,
                    param=param,
                    kind=kind,
                    payload=p,
                    baseline_key=f"{surface.id}:{kind}:{baseline_identity}",
                    input_path=input_path if input_path != param else "",
                )
                tests.append(tc)
                if ("' AND '1'='2" in p or "' OR '1'='1" in p) and len(tests) + 1 < max_tests:
                    tests.append(tc)
                if len(tests) >= max_tests:
                    return tests[:max_tests]
        return tests

    def _target_evidence(self, testcase: TestCase) -> Dict:
        return {
            "param": testcase.param,
            "insertion_path": testcase.input_path,
        }

    def verify(self, testcase: TestCase, baseline, response, context: Dict) -> VerificationResult:
        if response is None or baseline is None:
            return VerificationResult(
                False,
                "LOW",
                {"reason": "missing_baseline_or_response"},
                {},
                severity="MEDIUM",
                verification_status="not_reproducible",
                rationale="A baseline and a candidate response are both required before reporting SQLi.",
            )
        body = response.text or ""
        status = response.status_code
        base_hash = baseline["hash"]
        resp_hash = get_content_hash(body)
        sim = difflib.SequenceMatcher(None, baseline["text"], body).ratio()
        length_delta_ratio = abs(len(body) - baseline["length"]) / max(1, baseline["length"])

        for pat in self.error_patterns:
            if re.search(pat, body, re.IGNORECASE):
                evidence = self._target_evidence(testcase)
                evidence.update(
                    {
                        "signal": "sql_error_pattern",
                        "pattern": pat,
                        "status": status,
                        "baseline_status": baseline.get("status"),
                        "length_delta_ratio": length_delta_ratio,
                        "response_excerpt": self._excerpt(body),
                    }
                )
                return VerificationResult(
                    True,
                    "HIGH",
                    evidence,
                    {
                        "param": testcase.param,
                        "input_path": testcase.input_path,
                        "payload": testcase.payload,
                    },
                    severity="HIGH",
                    verification_status="detected",
                    rationale="A database-specific error pattern was observed in the response.",
                )

        if status >= 500:
            evidence = self._target_evidence(testcase)
            evidence.update(
                {
                    "signal": "server_error_after_payload",
                    "status": status,
                    "baseline_status": baseline.get("status"),
                    "length_delta_ratio": length_delta_ratio,
                    "response_excerpt": self._excerpt(body),
                }
            )
            return VerificationResult(
                True,
                "LOW",
                evidence,
                {
                    "param": testcase.param,
                    "input_path": testcase.input_path,
                    "payload": testcase.payload,
                },
                severity="MEDIUM",
                verification_status="suspected",
                rationale="A payload-triggered 5xx can indicate SQLi, but it is not sufficient to confirm exploitability.",
            )

        min_delta = float(self.config.get("min_length_delta_ratio", 0.15))
        cache = context.setdefault("boolean_cache", {})
        entry = cache.setdefault(testcase.baseline_key, {"false": [], "true": []})
        is_false = "' AND '1'='2" in testcase.payload
        is_true = "' OR '1'='1" in testcase.payload
        current = {"hash": resp_hash, "sim": sim, "len": len(body), "status": status}

        if is_false:
            entry["false"].append(current)
            return VerificationResult(
                False,
                "LOW",
                {"reason": "boolean_false_baseline"},
                {},
                verification_status="not_reproducible",
            )

        if is_true:
            entry["true"].append(current)
            false_hits = entry.get("false", [])
            if not false_hits:
                return VerificationResult(
                    False,
                    "LOW",
                    {"reason": "no_false_baseline"},
                    {},
                    verification_status="not_reproducible",
                )
            ref = false_hits[-1]
            if (
                resp_hash != base_hash
                and ref["hash"] != resp_hash
                and length_delta_ratio >= min_delta
                and sim < 0.98
                and abs(len(body) - ref["len"]) / max(1, ref["len"]) >= min_delta
            ):
                evidence = self._target_evidence(testcase)
                evidence.update(
                    {
                        "signal": "boolean_differential",
                        "hash_true": resp_hash,
                        "hash_false": ref["hash"],
                        "hash_baseline": base_hash,
                        "status_true": status,
                        "status_false": ref["status"],
                        "length_delta_ratio": length_delta_ratio,
                        "response_excerpt_true": self._excerpt(body),
                    }
                )
                return VerificationResult(
                    True,
                    "HIGH",
                    evidence,
                    {
                        "param": testcase.param,
                        "input_path": testcase.input_path,
                        "payload_true": testcase.payload,
                        "payload_false": "' AND '1'='2",
                    },
                    severity="HIGH",
                    verification_status="verified",
                    rationale="Boolean true/false probes produced materially different responses against the same baseline.",
                )

        if not is_false and not is_true and status == baseline.get("status") and resp_hash != base_hash and length_delta_ratio >= min_delta:
            evidence = self._target_evidence(testcase)
            evidence.update(
                {
                    "signal": "response_delta",
                    "status": status,
                    "baseline_status": baseline.get("status"),
                    "length_delta_ratio": length_delta_ratio,
                    "baseline_hash": base_hash,
                    "candidate_hash": resp_hash,
                    "response_excerpt": self._excerpt(body),
                }
            )
            return VerificationResult(
                True,
                "LOW",
                evidence,
                {
                    "param": testcase.param,
                    "input_path": testcase.input_path,
                    "payload": testcase.payload,
                },
                severity="MEDIUM",
                verification_status="suspected",
                rationale="Response diffs alone are heuristic and can be caused by non-SQL application behavior.",
            )

        return VerificationResult(False, "LOW", {}, {}, verification_status="not_reproducible")

    def build_finding(self, testcase: TestCase, vres: VerificationResult, surface: AttackSurface) -> Finding:
        return Finding(
            plugin=self.name,
            type="SQL Injection",
            title="SQL Injection Signal",
            category="injection",
            severity=vres.severity,
            confidence=vres.confidence,
            surface_id=surface.id,
            url=surface.url,
            evidence=vres.evidence,
            remediation="Use parameterized queries/ORM bindings and validate inputs.",
            reproduction={
                "param": testcase.param,
                "input_path": testcase.input_path,
                "payload": testcase.payload,
                "kind": testcase.kind,
                "method_override": testcase.method_override,
            },
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=vres.verification_status == "verified",
            target={
                "source": surface.source,
                "method": surface.method,
                "parameter": testcase.param,
                "insertion_path": testcase.input_path,
            },
            notes=[vres.rationale] if vres.rationale else [],
        )
