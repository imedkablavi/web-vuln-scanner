from __future__ import annotations

import concurrent.futures
import json
import statistics
import time
from pathlib import Path

from core.request_manager import RequestManager
from tests.local_corpus import run_regression_corpus


def _config(base_url: str):
    hostport = base_url.split("//", 1)[1]
    return {
        "concurrency": {
            "delay": 0,
            "max_retries": 0,
            "timeout": 1,
            "threads": 8,
            "per_host_concurrency": 4,
        },
        "request": {
            "timeouts": {"connect": 1, "read": 1},
            "max_retries": 0,
            "follow_redirects": False,
        },
        "scope": {"include_domains": [hostport], "allow_private": True},
        "auth": {"headers": {}, "cookies": {}},
        "auth_verification": {"enabled": False},
    }


def percentile(values, percent):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, int(round((percent / 100) * (len(ordered) - 1))))
    return ordered[index]


def main():
    samples = 80
    workers = 8
    with run_regression_corpus() as (_, base_url):
        manager = RequestManager(_config(base_url))

        def one_request(_):
            started = time.perf_counter()
            response = manager.send("GET", f"{base_url}/safe")
            elapsed_ms = (time.perf_counter() - started) * 1000
            if response.status_code != 200:
                raise RuntimeError(f"unexpected status: {response.status_code}")
            return elapsed_ms

        wall_started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            latencies = list(executor.map(one_request, range(samples)))
        wall_seconds = time.perf_counter() - wall_started

    result = {
        "target": "local-synthetic-only",
        "samples": samples,
        "workers": workers,
        "per_host_concurrency": 4,
        "wall_seconds": round(wall_seconds, 6),
        "requests_per_second": round(samples / max(wall_seconds, 1e-9), 3),
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 3),
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "max": round(max(latencies), 3),
        },
    }
    output = Path("benchmark_out") / "local-performance.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
