import difflib
import re
from typing import Dict, List

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
        r"PDOException",
        r"You have an error in your SQL syntax",
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
    def _boolean_kind(payload: str) -> str:
        normalized = " ".join((payload or "").upper().split())
        if "AND '1'='2" in normalized or normalized.endswith("AND 1=2"):
            return "false"
        if "OR '1'='1" in normalized or normalized.endswith("OR 1=1"):
            return "true"
        return ""

    def generate_tests(self, surface: AttackSurface, context: Dict) -> List[TestCase]:
        tests: List[TestCase] = []
        max_tests = self.max_tests_per_surface(self.config)
        payloads = [
            "'",
            "' AND '1'='2",
            "' OR '1'='1",
            "0 AND 1=2",
            "0 OR 1=1",
            '"',
        ]
        targets = [(name, "query") for name in surface.params.keys()]
        targets.extend([(inp.name, inp.kind) for inp in surface.inputs if inp.kind in self.supported_input_kinds])
        seen = set()
        targets = [target for target in targets if not (target in seen or seen.add(target))]

        for param, kind in targets:
            for payload in payloads:
                tests.append(
                    TestCase(
                        plugin=self.name,
                        surface_id=surface.id,
                        param=param,
                        kind=kind,
                        payload=payload,
                        baseline_key=f"{surface.id}:{param}",
                    )
                )
                if len(tests) >= max_tests:
                    return tests[:max_tests]
        return tests

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
        baseline_text = baseline.get("text") or ""
        status = response.status_code
        base_hash = baseline["hash"]
        resp_hash = get_content_hash(body)
        sim = difflib.SequenceMatcher(None, baseline_text, body).ratio()
        length_delta_ratio = abs(len(body) - baseline["length"]) / max(1, baseline["length"])

        # Error-based detection must be newly introduced by the candidate request.
        for pat in self.error_patterns:
            candidate_hit = re.search(pat, body, re.IGNORECASE)
            baseline_hit = re.search(pat, baseline_text, re.IGNORECASE)
            if candidate_hit and not baseline_hit:
                return VerificationResult(
                    True,
                    "HIGH",
                    {
                        "param": testcase.param,
                        "signal": "new_sql_error_pattern",
                        "pattern": pat,
                        "status": status,
                        "baseline_status": baseline.get("status"),
                        "length_delta_ratio": length_delta_ratio,
                        "response_excerpt": self._excerpt(body),
                    },
                    {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
                    severity="HIGH",
                    verification_status="detected",
                    rationale="A database-specific error pattern appeared only after the SQL probe.",
                )

        if status >= 500 and int(baseline.get("status", 0) or 0) < 500:
            return VerificationResult(
                True,
                "LOW",
                {
                    "param": testcase.param,
                    "signal": "new_server_error_after_payload",
                    "status": status,
                    "baseline_status": baseline.get("status"),
                    "length_delta_ratio": length_delta_ratio,
                    "response_excerpt": self._excerpt(body),
                },
                {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
                severity="MEDIUM",
                verification_status="suspected",
                rationale="A payload-triggered new 5xx can indicate SQLi, but it is not sufficient to confirm exploitability.",
            )

        min_delta = float(self.config.get("min_length_delta_ratio", 0.15))
        cache = context.setdefault("boolean_cache", {})
        entry = cache.setdefault(testcase.baseline_key, {"false": [], "true": []})
        boolean_kind = self._boolean_kind(testcase.payload)
        current = {
            "hash": resp_hash,
            "sim": sim,
            "len": len(body),
            "status": status,
            "payload": testcase.payload,
        }

        if boolean_kind == "false":
            entry["false"].append(current)
            return VerificationResult(
                False,
                "LOW",
                {"reason": "boolean_false_baseline"},
                {},
                verification_status="not_reproducible",
            )

        if boolean_kind == "true":
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
            pair_delta = abs(len(body) - ref["len"]) / max(1, ref["len"])
            if (
                resp_hash != base_hash
                and ref["hash"] != resp_hash
                and length_delta_ratio >= min_delta
                and sim < 0.98
                and pair_delta >= min_delta
            ):
                return VerificationResult(
                    True,
                    "HIGH",
                    {
                        "param": testcase.param,
                        "signal": "boolean_differential",
                        "hash_true": resp_hash,
                        "hash_false": ref["hash"],
                        "hash_baseline": base_hash,
                        "status_true": status,
                        "status_false": ref["status"],
                        "length_delta_ratio": length_delta_ratio,
                        "pair_delta_ratio": pair_delta,
                        "response_excerpt_true": self._excerpt(body),
                    },
                    {
                        "param": testcase.param,
                        "payload_true": testcase.payload,
                        "payload_false": ref["payload"],
                        "kind": testcase.kind,
                    },
                    severity="HIGH",
                    verification_status="verified",
                    rationale="Boolean true/false probes produced materially different responses against the same baseline.",
                )

        if not boolean_kind and status == baseline.get("status") and resp_hash != base_hash and length_delta_ratio >= min_delta:
            return VerificationResult(
                True,
                "LOW",
                {
                    "param": testcase.param,
                    "signal": "response_delta",
                    "status": status,
                    "baseline_status": baseline.get("status"),
                    "length_delta_ratio": length_delta_ratio,
                    "baseline_hash": base_hash,
                    "candidate_hash": resp_hash,
                    "response_excerpt": self._excerpt(body),
                },
                {"param": testcase.param, "payload": testcase.payload, "kind": testcase.kind},
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
                **vres.reproduction,
                "param": testcase.param,
                "kind": testcase.kind,
                "method_override": testcase.method_override,
            },
            verification_status=vres.verification_status,
            scanner_mode="active-web",
            reproducible=vres.verification_status == "verified",
            target={"source": surface.source, "method": surface.method, "parameter": testcase.param},
            notes=[vres.rationale] if vres.rationale else [],
        )
