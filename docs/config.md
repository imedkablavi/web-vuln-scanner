# Configuration reference

The installed default configuration is intentionally neutral. It contains no target-specific RBAC policy, workflow scenario, live endpoint, username, password, cookie, token, or pre-enabled auth actor. Test policies and test workflows are used only by the repository QA/smoke suite and are excluded from the wheel and final Docker runtime.

## Scanner and scope

- `scanner.target`: URL to scan; the CLI normally supplies this.
- `scanner.scope.allowlist` / `include_domains`: additional explicitly authorized hosts.
- `scanner.scope.exclude_paths`: path prefixes to skip.
- `scanner.scope.allow_private`: allow private/loopback destinations when explicitly authorized.
- `scanner.scope.resolve_dns`: perform DNS destination preflight checks.
- `scanner.crawler.max_depth`, `max_urls`, `max_url_length`: discovery bounds.
- `scanner.crawler.javascript_discovery`: bounded static JavaScript endpoint extraction.
- `scanner.crawler.har_seed`: sanitized HAR-assisted discovery. Captured requests are not replayed.

## Concurrency and request behavior

- `scanner.concurrency.threads`: active worker count.
- `scanner.concurrency.per_host_concurrency`: per-host concurrency bound.
- `scanner.concurrency.delay`: base delay between requests.
- `scanner.concurrency.timeout`: compatibility timeout setting.
- `scanner.concurrency.max_retries`: retry bound.
- `scanner.concurrency.global_timeout_seconds`: enforced active-scanner deadline.
- `scanner.request.timeouts.connect` / `read`: HTTP timeout bounds.
- `scanner.request.max_retries`: request retry bound.
- `scanner.request.max_redirects`: manual redirect limit.
- `scanner.request.follow_redirects`: redirect behavior; active release profiles force this off where verification requires observing `Location` directly.

## Browser

- `scanner.browser_enabled`: enable Playwright-assisted discovery.
- `scanner.browser.headless`, `slow_mo`: browser execution settings.
- `scanner.browser.capture_trace`, `capture_screenshots`: generic browser evidence controls.
- `capture_auth_trace`, `capture_auth_screenshots`, `retain_storage_state`: sensitive auth artifacts; off by default.
- `scanner.browser.interactions.enabled`: permit configured generic interactions.
- `submit_forms`: separately permit form submission.
- `click_selectors`: explicit selectors only; avoid broad production selectors.
- `scanner.browser.xss_verification`: bounded Chromium execution confirmation for reflected XSS candidates.

## Auth and RBAC

`scanner.auth_verification.actors` contains disabled schema stubs in the default YAML so users can see the supported fields, but all target URLs/selectors are blank and all actors are disabled. Configure real authorized accounts before enabling auth verification.

Actor fields include:

- identity: `actor_id`, `display_name`, `role`, `enabled`;
- static material: `headers`, `cookies`, `bearer_token`, `storage_state_path`;
- dynamic auth under `auth`:
  - `auth_scheme`: `form_login`, `json_login`, `bearer_with_refresh`, `static_cookie`, `static_bearer`, `browser_state`, or `none`;
  - `login_url`, `token_url`, `refresh_url`, `verify_url`;
  - browser fields such as `browser_login_url`, selectors, storage keys, and wait conditions;
  - `username_env` / `password_env` for secrets supplied through the environment;
  - session cookie names and refresh policy.

- `scanner.auth_verification.baseline_actor_id`: preferred reference/owner actor.
- `authenticated_crawl`: optional per-actor discovery using established real sessions.
- `scanner.rbac_matrix_file`: path to a user-supplied target-specific RBAC YAML file. The installed default is empty.
- `scanner.rbac_matrix`: inline alternative to a file.

The scanner does not ship a target-specific RBAC policy in its runtime package.

## Workflows

- `scanner.workflows.enabled`: execute user-supplied declarative workflows.
- `directory`: directory containing target-specific workflow YAML files.
- `files`: explicit workflow file list.
- `replay_verified_only`: replay only workflows with verified results.

The installed runtime does not ship QA workflow scenarios as defaults. Repository smoke fixtures remain source-only test material.

Workflow steps can perform real authorized HTTP/API/browser actions, so create workflows specifically for the application being assessed. Do not copy an example route into production and assume it proves a vulnerability.

## Active checks

`scanner.active_checks.web` controls bounded live HTTP probes for SSTI, CRLF/response-header injection, TRACE reflection, and same-origin URL-fetch behavior.

`scanner.active_checks.templates` controls conservative same-origin GET/HEAD templates:

- `enabled`;
- `include_builtin`;
- `directory` / `files` for user templates;
- `max_templates`, `max_requests`, `max_body_bytes`.

Built-in safe templates perform real requests and require deterministic response matchers. They are not pre-generated findings.

`scanner.active_checks.xml` is an explicit opt-in internal-entity parser probe and remains disabled in all built-in profiles.

`scanner.plugins` configures stable active plugins and their bounds. LFI/path traversal and command injection remain experimental and blocked by the release maturity policy. SQLi, reflected-markup, open-redirect, and business-logic checks use live responses through the scoped request layer.

## Passive checks

- `scanner.passive_checks.web`: real response header/cookie/CORS/redirect/error posture.
- `auth_tokens`: local metadata review of configured or already-issued JWTs; tokens are not modified.
- `data_exposure`: observed-URL inspection and bounded path probes where the selected profile permits them.
- `api`: posture derived from actual OpenAPI/GraphQL discovery.
- `dns_tls`: live DNS/TLS/HTTPS posture.

A passive observation can be informational or detected rather than verified. The status reflects evidence strength; the scanner does not invent exploit confirmation when only posture evidence exists.

## Checkpoints, output, and logging

- `scanner.checkpoint`: resumable active-test state. It stores completed test fingerprints and redacted findings, not cookies, Authorization headers, response bodies, or raw parameter values.
- `scanner.output`: report format, file name, and directory.
- `scanner.verified_only`: HTML report filter.
- `scanner.max_findings_per_plugin`: global per-plugin finding cap.
- `logging.level`, `logging.file`: explicit runtime logging configuration.

## Operational guidance

Always scope the real target explicitly. Use environment variables for secrets and disposable authorized test identities where possible. `passive` is the default profile; `safe-active` sends bounded live probes; `full-authorized` adds browser capability and can run target-specific auth/RBAC/workflows only when you configure them.

Test fixtures under `tests/` and `smoke/` exist only to verify scanner correctness. CI explicitly rejects those fixtures if they leak into the installed wheel or final Docker runtime.
