# Configuration Reference (default_config.yaml)

- `scanner.target`: URL to scan.
- `scanner.scope`:
  - `allowlist`: hostnames explicitly allowed.
  - `blocklist`: paths/keywords to skip.
  - `include_domains`: globbed host filters used by HTTP and browser scope checks.
  - `exclude_paths`: path prefixes to skip.
  - `allow_private`: allow private/loopback IPs (default false).
  - `max_depth`: crawl recursion limit.
- `scanner.crawler`:
  - `max_depth`, `max_urls`, `max_url_length`, `respect_robots`, `dedup`.
- `scanner.concurrency`:
  - `threads`: global worker count.
  - `per_host_concurrency`: semaphore per host.
  - `delay`: base delay between requests (+ jitter).
  - `timeout`: per-request timeout (seconds).
  - `max_retries`: request retries with backoff.
  - `global_timeout_seconds`: scan task timeout budget.
- `scanner.plugin_contract`: `v2` or `legacy`.
- `scanner.browser_enabled` / `crawler_enabled`: toggle browser/HTTP crawling.
- `scanner.browser`: `headless`, `slow_mo`, tracing, screenshots, interaction settings, plus:
  - `dom_xss.enabled`: enable bounded Chromium DOM-XSS execution verification (default false).
  - `dom_xss.max_urls`: maximum URLs to verify, hard-capped at 5.
  - `dom_xss.timeout_ms`: navigation timeout, hard-capped at 5000 ms.
- `scanner.auth_verification`:
  - `enabled`: enable cross-actor access-control verification.
  - `default_comparison_mode`: currently `semantic`.
  - `compare_unauthenticated`: suppress false verified access-control claims when the same resource appears public without auth.
  - `baseline_actor_id`: optional preferred owner/reference actor.
  - `authenticated_crawl`: optional per-actor crawl bootstrap for authenticated discovery.
  - `actors`: list of actors with identity, role and static/dynamic authentication material.
- `scanner.rbac_matrix_file`: YAML file containing deterministic authorization expectations.
- `scanner.rbac_matrix`: inline alternative to `rbac_matrix_file`.
- `scanner.workflows`: declarative authenticated workflow execution and replay settings.
- `scanner.plugins`: enable/disable and tune active plugins.
  - stable/default plugins include `sqli` and `business_logic`.
  - registry-blocked experimental plugins include `xss_reflected`, `lfi`, `cmd_injection`, `open_redirect`, `ssti`, `crlf_injection`, `ssrf`, and `host_header`.
  - `ssrf.callback_url` + `ssrf.expected_marker` are required for callback-proof verification.
  - `ssrf.allow_external_callback` defaults false; without explicit opt-in only loopback callbacks are accepted.
  - `host_header.canary_host` defaults to the reserved `scanner-host-canary.invalid` domain.
- `scanner.active_verification`:
  - `cors.enabled`: two-origin credentialed CORS verification.
  - `cors.max_urls`: bounded URL count, hard-capped at 25.
  - `cors.origins`: exactly the first two configured synthetic origins are used; defaults are `.invalid` origins.
  - `graphql.enabled`: bounded GraphQL-specific verification.
  - `graphql.max_requests`: hard-capped at 2 non-mutating requests per configured GraphQL endpoint.
- `scanner.output`: `format`, `file`, `directory`.
- `scanner.api`: `swagger_url`, `graphql_url`.
- `scanner.passive_checks`:
  - `web`: security headers, cookies, baseline CORS posture, redirects, verbose errors.
  - `data_exposure`: backup/debug/config probes and sensitive indicator heuristics.
  - `api`: passive API posture findings derived from Swagger/GraphQL inventory.
  - `dns_tls`: DNS inventory and TLS/HTTPS posture checks.
- `scanner.verified_only`: HTML report filter. When true, show only verified findings.
- `scanner.max_findings_per_plugin`: cap per plugin per scan.
- `scanner.request`: timeouts, retries, user agents, follow redirects.
- `logging`: `level`, `file`.

## Verification semantics

CORS verification is stronger than the passive single-Origin posture check: two unrelated synthetic origins must both be reflected exactly with credentials enabled. A wildcard origin plus credentials is not treated as verified credentialed cross-origin read access.

GraphQL verification sends at most two non-mutating requests: one introspection observation and one invalid-field validation query used to detect stack traces, exception objects, server paths or debug extensions. It never sends mutations, deep-recursion probes, alias floods or batch floods.

DOM-XSS verification is disabled by default. When enabled, Chromium receives a fragment-only canary. A finding requires actual JavaScript execution that sets one DOM data attribute; the canary performs no network callback, cookie/storage access, navigation, persistence or data extraction.

SSRF remains experimental and registry-blocked. Its implementation does not guess cloud metadata or internal addresses. It can prove only a server-side fetch of the explicitly configured scanner-controlled callback whose expected marker appears in the target response.

Host-header verification remains experimental and registry-blocked. It requires the reserved canary host to control a redirect or security-sensitive absolute URL. Plain reflection does not qualify.

## Operational tips

- Always add the authorized target domain to `include_domains`/`allowlist`.
- Explicit CLI scans against loopback/private targets auto-enable `allow_private` for that exact target so local validation remains possible.
- Tune `per_host_concurrency` lower for fragile targets.
- Browser-driven login should use environment-based secrets and a `verify_url` or equivalent success proof.
- Auth verification remains dormant until at least two valid enabled actors are configured.
- When a matching RBAC policy exists, deterministic policy verification takes precedence over heuristic access-control inference.
- Use environment variables for secrets. Do not commit real usernames, passwords, cookies, bearer tokens or refresh tokens.
- Public CI targets must remain local/synthetic.
