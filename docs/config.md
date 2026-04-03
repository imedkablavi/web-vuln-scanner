# Configuration Reference (default_config.yaml)

- `scanner.target`: URL to scan.
- `scanner.scope`:
  - `allowlist`: hostnames explicitly allowed.
  - `blocklist`: paths/keywords to skip.
  - `include_domains`: globbed host filters (required for SSRF guard).
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
  - `global_timeout_seconds`: informational; scan not forcibly aborted.
- `scanner.plugin_contract`: `v2` or `legacy`.
- `scanner.browser_enabled` / `crawler_enabled`: toggle browser/HTTP crawling.
- `scanner.browser`: `headless`, `slow_mo`, tracing, screenshots, and interaction settings when Playwright enabled.
- `scanner.auth_verification`:
  - `enabled`: enable cross-actor access-control verification.
  - `default_comparison_mode`: currently `semantic`.
  - `compare_unauthenticated`: suppress false verified access-control claims when the same resource appears public without auth.
  - `baseline_actor_id`: optional preferred owner/reference actor.
  - `authenticated_crawl`: optional per-actor crawl bootstrap for authenticated discovery.
  - `actors`: list of actors with:
    - identity: `actor_id`, `display_name`, `role`, `enabled`
    - static material: `headers`, `cookies`, `bearer_token`, `storage_state_path`
    - dynamic auth config under `auth`:
      - `auth_scheme`: `form_login`, `json_login`, `bearer_with_refresh`, `static_cookie`, `static_bearer`, `browser_state`, `none`
      - `login_url` / `token_url` / `refresh_url` / `verify_url`
      - browser-driven login fields when a browser flow is required:
        - `browser_login_url`
        - `use_browser`
        - `browser_required`
        - `username_selector`, `password_selector`, `submit_selector`
        - `success_selector`, `wait_for_url_contains`
        - `pre_submit_click_selectors`, `post_login_click_selectors`
        - `browser_storage_keys`
      - `username_env` / `password_env` or non-secret test placeholders
      - `success_indicators` / `failure_indicators`
      - `auth_headers_template`
      - `session.cookie_names`, `session.csrf_cookie_names`
      - `session.refresh.enabled`, `strategy`, `pre_expiry_seconds`, `retry_on_401`, `max_attempts`, `relogin_on_failure`
- `scanner.rbac_matrix_file`: YAML file containing deterministic authorization expectations.
- `scanner.rbac_matrix`: inline alternative to `rbac_matrix_file`.
- `scanner.workflows`:
  - `enabled`: enable declarative workflow execution.
  - `directory`: directory containing workflow YAML files.
  - `files`: optional explicit workflow file list.
  - `replay_verified_only`: replay only workflows that produced verified results.
- `scanner.plugins`: enable/disable and tune per plugin (`max_tests_per_surface`, thresholds).
- `scanner.output`: `format`, `file`, `directory`.
- `scanner.api`: `swagger_url`, `graphql_url`.
- `scanner.passive_checks`:
  - `web`: security headers, cookies, CORS, redirects, verbose errors.
  - `data_exposure`: backup/debug/config probes and sensitive indicator heuristics.
  - `api`: passive API posture findings derived from Swagger/GraphQL inventory.
  - `dns_tls`: DNS inventory and TLS/HTTPS posture checks.
- `scanner.verified_only`: HTML report filter. When `true`, show only findings with `verification_status=verified`.
- `scanner.max_findings_per_plugin`: cap per plugin per scan.
- `scanner.request`: timeouts, retries, user agents, follow redirects.
- `logging`: `level`, `file`.

Tips:
- Always add your target domain to `include_domains`/`allowlist` to satisfy SSRF guard.
- Explicit CLI scans against loopback/private targets auto-enable `allow_private` for that exact target so local authorized validation remains possible.
- Tune `per_host_concurrency` lower for fragile targets; reduce `delay` for small test targets.
- Enable Playwright for browser-assisted surface collection and artifact capture. It is not a full browser spider.
- Browser-driven login should always use env-based secrets and a `verify_url` or equivalent success proof. Visual success alone is not treated as actor readiness.
- Auth verification remains dormant until at least two valid enabled actors are configured.
- When a matching RBAC policy exists, deterministic verification takes precedence over heuristic access-control inference.
- Workflow definitions are declarative YAML files. They support:
  - `ensure_actor_ready`
  - HTTP/API steps such as `visit_url` and `api_call`
  - browser steps such as `click`, `fill`, `wait_for_selector`, `capture_screenshot`, `capture_dom`
  - checkpoints such as `assert_status`, `assert_text`, `assert_denied`, `assert_masked`, `assert_policy_outcome`, and `proof_access`
- Minimal workflow example:
```yaml
workflow_id: peer_access_policy
title: Peer actor policy-backed access check
replayable: true
actors: [low_user, peer_user]
steps:
  - step_id: ensure_low_ready
    step_type: ensure_actor_ready
    actor_id: low_user

  - step_id: switch_to_peer
    step_type: switch_actor
    actor_id: peer_user

  - step_id: peer_open_same_resource
    step_type: visit_url
    actor_id: peer_user
    target: /auth_bypass?doc=1
    checkpoints:
      - checkpoint_id: peer_policy_verdict
        checkpoint_type: assert_policy_outcome
        expected: deny
```
- Request replay and workflow replay are different:
  - request replay proves a single finding/scenario can be reproduced
  - workflow replay proves a multi-step execution still agrees with the original checkpoint trail
- Workflow `verified` results require step-level checkpoint evidence and cannot survive `partial`, `failed`, or `blocked_auth` execution states.
- Use environment variables for secrets. Do not commit real usernames, passwords, cookies, bearer tokens, or refresh tokens.
- Actors that fail login or refresh are reported explicitly and do not count as ready verification actors.
- Treat experimental plugins (`xss_reflected`, `lfi`, `cmd_injection`, `open_redirect`) as incomplete unless you harden and validate them in your own test harness.
