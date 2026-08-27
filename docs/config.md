# Configuration Reference (default_config.yaml)

- `scanner.target`: URL to scan.
- `scanner.scope`:
  - `allowlist`: hostnames explicitly allowed.
  - `blocklist`: paths/keywords to skip.
  - `include_domains`: globbed host filters used by HTTP and browser scope checks.
  - `exclude_paths`: path prefixes to skip.
  - `allow_private`: allow private/loopback IPs (default false).
  - `max_depth`: crawl recursion limit.
- `scanner.crawler`: `max_depth`, `max_urls`, `max_url_length`, `respect_robots`, `dedup`.
- `scanner.concurrency`: global/per-host limits, delay, timeout, retries, and global timeout.
- `scanner.plugin_contract`: `v2` or `legacy`.
- `scanner.browser_enabled` / `crawler_enabled`: toggle browser/HTTP crawling.
- `scanner.browser.dom_xss`:
  - `enabled`: bounded Chromium DOM-XSS execution verification (default false).
  - `max_urls`: hard-capped at 5.
  - `timeout_ms`: hard-capped at 5000 ms.
- `scanner.auth_verification`: authenticated actors, browser/form/API login, cross-actor checks, and optional authenticated crawling.
- `scanner.rbac_matrix_file` / `scanner.rbac_matrix`: deterministic authorization expectations.
- `scanner.workflows`: declarative authenticated workflow execution and replay settings.
- `scanner.plugins`:
  - stable/default plugins include `sqli` and `business_logic`.
  - registry-blocked experimental plugins include `xss_reflected`, `lfi`, `cmd_injection`, `open_redirect`, `ssti`, `crlf_injection`, `ssrf`, and `host_header`.
  - `ssrf.callback_url` + `ssrf.expected_marker` are required for callback proof.
  - `ssrf.allow_external_callback` defaults false; without explicit opt-in only loopback callbacks are accepted.
  - `host_header.canary_host` defaults to reserved `scanner-host-canary.invalid`.

## Bounded verification layers

`scanner.active_verification` contains verification layers that are separate from the plugin registry. High-impact layers added during the hardening pass are disabled by default.

- `cors`: two-origin credentialed CORS verification. Enabled in the current default profile, bounded by `max_urls` and exactly two configured origins.
- `graphql`: at most two non-mutating requests per configured GraphQL endpoint.
- `xxe` (default false): requires an explicit XML endpoint, controlled callback URL, and proof marker. External callbacks require `allow_external_callback: true`; otherwise only loopback is accepted.
- `csrf` (default false): requires `explicit_opt_in: true`, an explicitly safe state-changing endpoint, token field/value, synthetic form data, and a success marker. The verifier compares same-origin-with-token vs cross-site-without-token while reusing authorized ambient cookies without recording cookie values.
- `nosql` (default false): requires `explicit_opt_in: true`, an endpoint and user-controlled field. The only active operator is `$eq`; `$where`, JavaScript, regex-DoS, destructive mutations, and broad auth-bypass payloads are not used.
- `jwt` (default false): offline-only token posture. `token_env` names an environment variable; raw tokens are never persisted. Checks include algorithm policy, expiration, issuer and audience binding. This does **not** prove server-side token acceptance or signature bypass.
- `oidc` (default false): one discovery-metadata GET. Checks issuer policy, endpoint transport, and PKCE S256 advertisement for public clients. It does not submit credentials or exchange codes/tokens.
- `oauth_flow` (default false): requires `explicit_opt_in: true`. Tests redirect-URI binding and state preservation using two authorization GETs with no credentials. By default both authorization and registered redirect endpoints must be loopback; public-provider probing requires `allow_external_flow: true`.
- `file_upload` (default false): requires `explicit_opt_in: true` on a disposable authorized upload endpoint. Uploads harmless static HTML with no JavaScript/polyglot behavior, follows only same-origin retrieval, and reports only when the marker is served inline as `text/html`.
- `cache_poisoning` (default false): requires `explicit_opt_in: true`. Uses a unique query key plus reserved `.invalid` `X-Forwarded-Host` canary and reports only if the canary is replayed from the same cache key without the header.

## Verification semantics

CORS verification is stronger than the passive single-Origin posture check: two unrelated synthetic origins must both be reflected exactly with credentials enabled. A wildcard origin plus credentials is not treated as verified credentialed cross-origin read access.

GraphQL verification sends at most two non-mutating requests: one introspection observation and one invalid-field validation query used to detect stack traces, exception objects, server paths or debug extensions. It never sends mutations, deep-recursion probes, alias floods or batch floods.

DOM-XSS verification is disabled by default. Chromium receives a fragment-only canary. A finding requires actual JavaScript execution that sets one DOM data attribute; the canary performs no network callback, cookie/storage access, navigation, persistence or data extraction.

SSRF remains experimental and registry-blocked. It does not guess cloud metadata or internal addresses; it can prove only a server-side fetch of the explicitly configured scanner-controlled callback whose expected marker appears in the target response.

Host-header verification remains experimental and registry-blocked. It requires the reserved canary host to control a redirect or security-sensitive absolute URL. Plain reflection does not qualify.

XXE similarly requires a controlled entity-resolution marker. It never reads `file://` targets or guesses internal services. CSRF verification is categorized as request-integrity rather than generic access-control so its proof is not confused with the scanner's separate cross-actor authorization gate.

## Operational rules

- Always add the authorized target domain to scope.
- High-impact verification endpoints must be explicitly configured; do not enable them against an endpoint whose side effects are unknown.
- `explicit_opt_in` layers should use disposable/synthetic actions where possible.
- Keep public OAuth/OIDC providers disabled unless the test client/provider is expressly authorized.
- Use environment variables for secrets. Do not commit usernames, passwords, cookies, bearer tokens, JWTs or refresh tokens.
- Public CI targets must remain local/synthetic.
- Tune per-host concurrency and timeouts lower for fragile systems.
