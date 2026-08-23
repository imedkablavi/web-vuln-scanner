# Security & Responsible Use

- **Authorized scanning only**: Run the scanner only against assets you own or have explicit permission to test.
- **Scope controls**: Configure `scanner.scope.include_domains` / `allowlist`; the shared request layer blocks hosts outside scope and private IPs unless private targets are explicitly allowed.
- **No remote CI targets**: GitHub Actions security regressions, smoke tests, and benchmarks must use localhost or synthetic fixtures only. Do not add public websites, internet-wide targets, or external vulnerable services to CI.
- **No mass exploitation**: Do not add broad exploitation, credential harvesting, destructive actions, persistence, evasion, or unsafe automatic follow-up behavior.
- **Data handling**: Findings/evidence may contain sensitive data. Store reports securely and avoid sharing outside trusted channels.
- **Secret redaction**: Configuration and finding dictionaries redact sensitive keys, and logging applies best-effort redaction for bearer values, JWT-like values, passwords, tokens, cookies, API keys, secrets, and CSRF material. Redaction is a defense-in-depth control, not permission to place production secrets in fixtures.
- **Browser automation**: Playwright-driven verification may execute target scripts. Use isolated environments and keep browsers patched.

## Evidence-first interpretation

- `verified` means the current implementation captured stronger, reproducible proof.
- `detected` means a concrete signal was observed, but exploit confirmation is incomplete.
- `suspected` means behavior was interesting enough to report, but not strong enough to call confirmed.
- `informational` means posture or inventory data that may matter operationally but is not itself exploit confirmation.
- Anything not evidenced should be treated as untrusted and manually reviewed before action.
- Anything not reproducible must not be treated as confirmed.

## Plugin promotion gate

Stable active plugins must satisfy the v2 execution contract:

1. use the shared `RequestManager`;
2. remain inside the active surface/scope;
3. declare bounded `max_tests_per_surface`, `request_budget`, and `timeout_seconds` values;
4. return valid `TestCase` and `VerificationResult` objects;
5. attach reportable evidence and reproduction metadata using `webvulnscanner/evidence-v1`;
6. have local positive and negative fixtures covering false-negative and false-positive boundaries;
7. pass report/redaction and concurrency/rate-limit regression checks.

`xss_reflected`, `lfi`, `cmd_injection`, and `open_redirect` remain experimental and registry-blocked. They must not be promoted based on implementation presence alone.

## Authentication harness

- Access-control findings must include cross-actor evidence before they can remain `verified`.
- Actors are not considered ready unless login, verify, or refresh produced explicit proof.
- Browser-driven login does not count as successful unless it yields a usable session state and HTTP or verification proof.
- Placeholder credentials in `config/default_config.yaml` use environment variable references only; do not commit real secrets.
- If login or refresh fails, the affected actor is reported as degraded/login_failed/refresh_failed and related verification scenarios remain partial.
- Browser actor artifacts are optional supporting evidence, not the sole basis for confirmation.
- Deterministic RBAC verification requires an explicit policy matrix plus actor readiness; otherwise the engine stays heuristic or partial by design.
- Replay results are evidence aids, not independent proof, unless they reproduce the actor-scoped scenario truthfully.
- Workflow verification requires step-level evidence and checkpoint agreement; a workflow marked `partial`, `failed`, `blocked_auth`, or `indeterminate` must not be treated as a completed verification.
- Workflow replay is separate from request replay and only counts as reproduced when the replayed workflow matches the original checkpoint trail.

## Local fixture policy

Reports classify localhost/private targets as test environments so demo or smoke results are not mistaken for production findings. Synthetic intentionally vulnerable behavior belongs in `tests/local_corpus.py` or similarly isolated fixtures, not in a network-accessible demo service.

## Reporting a project vulnerability

Prefer GitHub private vulnerability reporting / a draft security advisory when enabled for this repository. Include the smallest reproducible description, affected version/commit, impact, and a proposed mitigation if known. Do not publish exploitable details in a public issue before maintainers have had a reasonable opportunity to assess them.

For vulnerabilities in third-party systems discovered using this tool, follow the affected party's disclosure policy and applicable authorization terms.
