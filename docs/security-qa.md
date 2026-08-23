# Security QA and Detector Promotion Gates

This project is for authorized security assessment only. Automated CI targets must be local or synthetic; CI must not scan public third-party systems.

## Regression corpus

The intentionally-vulnerable local corpus is implemented by `smoke/mock_server.py` plus focused fixtures in `tests/corpus/additional_vuln_server.py`; cases are indexed by `tests/corpus/manifest.yaml`.

Required CI coverage now includes positive and negative controls for:

- SQL injection and safe queries;
- authenticated sessions, unauthenticated denial, and cross-actor authorization;
- SSTI arithmetic expression evaluation;
- CRLF response-header injection;
- SSRF scanner-controlled callback proof;
- Host-header security-sensitive URL influence;
- two-origin credentialed CORS;
- GraphQL debug/error disclosure;
- Chromium DOM-XSS execution;
- XXE scanner-controlled external-entity resolution;
- CSRF same-origin-with-token vs cross-site-without-token request integrity;
- NoSQL `$eq` operator semantics vs scalar-schema enforcement;
- JWT offline policy checks using synthetic environment-provided tokens;
- OIDC discovery/PKCE metadata posture;
- OAuth redirect-URI binding/state preservation on the local synthetic provider;
- file-upload inline active-content handling vs safe download behavior;
- isolated cache poisoning using a unique cache key and reserved forwarding-host canary.

The suite also gates scope rejection, request budgets/timeouts, per-host concurrency, bounded retry behavior, JSON/HTML redaction, SARIF conversion, wheel installation, and Docker/non-root CLI behavior.

## Runtime and scope contract

Active plugins must use the scanner runtime. Direct `requests`, `httpx`, raw sockets, subprocess networking or embedded browser automation from a plugin are not accepted. Plugins must keep a bounded request budget, explicit timeout, originating surface identity, structured evidence/reproduction, and must not expand target scope.

Browser and specialized verification layers are separate bounded layers. They must independently enforce their own safety constraints and must remain disabled by default when the check can alter state or requires an explicitly known-safe endpoint.

## Promotion rule

A detector cannot move to stable solely because implementation exists. Promotion requires:

1. deterministic local positive fixture;
2. deterministic local negative fixture;
3. explicit FP/FN assertions;
4. bounded request count and timeout;
5. scope enforcement before dispatch;
6. structured minimal evidence and reproduction metadata;
7. secret/log/report redaction QA;
8. repeated CI passes without external targets;
9. documented limitations stating exactly what the detector does and does not prove.

## Registry-blocked experimental plugins

The following active plugins remain registry-blocked even when configuration attempts to enable them:

- `xss_reflected`
- `lfi`
- `cmd_injection`
- `open_redirect`
- `ssti`
- `crlf_injection`
- `ssrf`
- `host_header`

The newer XXE/CSRF/NoSQL/JWT/OIDC/OAuth/file-upload/cache-poisoning capabilities are verification layers rather than registry plugins. All are disabled by default except the previously bounded CORS/GraphQL posture layers.

## Safety boundaries

### SSTI
Only deterministic arithmetic-expression evaluation. No command execution, subprocess access, file reads, object traversal, environment access, sandbox escape or network callbacks.

### CRLF
Only one inert response-header canary. No `Set-Cookie`, redirect, cache-control, HTML/script or other state-changing header injection.

### SSRF
No guessed cloud metadata, RFC1918, link-local, loopback, alternate-IP or internal-service destinations. Requires an explicit scanner-controlled callback plus marker. Public CI callback is loopback-only.

### Host Header
Uses a reserved `.invalid` canary and reports only security-sensitive absolute URL or redirect influence. Plain reflection is insufficient.

### CORS
Two distinct synthetic untrusted origins must be reflected exactly with credentials enabled. Wildcard-plus-credentials is not treated as verified credentialed browser read access.

### GraphQL
Maximum two non-mutating requests: introspection observation and one invalid-field query. No mutations, recursion/depth bombs, alias floods, batch floods or DoS probes.

### DOM-XSS
Disabled by default. Chromium gets a fragment-only canary; proof requires actual JavaScript execution that sets one DOM data attribute. No callback, cookie/storage access, navigation, persistence or extraction.

### XXE
Disabled by default. One XML POST to an explicitly configured endpoint and one explicitly configured HTTP(S) entity callback. Without external-callback opt-in, only loopback callback hosts are accepted. `file://`, metadata and arbitrary internal-service probes are prohibited.

### CSRF
Disabled by default and requires `explicit_opt_in`. Exactly two POSTs to a known-safe configured action: same-origin with token, then cross-site without token while reusing ambient authorized cookies. Cookie values are not persisted. The finding category is `request-integrity`, distinct from cross-actor authorization.

### NoSQL
Disabled by default and requires `explicit_opt_in`. Exactly two JSON POSTs comparing a scalar value with the equivalent `$eq` object. No `$where`, JavaScript, regex DoS, destructive writes or broad authentication-bypass operator lists.

### JWT
Disabled by default and offline-only. Token comes from a named environment variable and is not recorded. It checks header/claim policy; it does not forge tokens, brute-force keys, test signature bypass acceptance, or contact a target.

### OIDC / OAuth
OIDC uses one discovery GET. OAuth flow probing is disabled by default and requires `explicit_opt_in`; default flow scope is loopback-only. No credentials are submitted, no code/token exchange occurs, and external-provider probing requires an additional opt-in.

### File Upload
Disabled by default and requires `explicit_opt_in` on a disposable authorized endpoint. Payload is harmless static HTML without JavaScript or polyglot/executable content. Retrieval must be same-origin and is capped at one follow-up GET.

### Cache Poisoning
Disabled by default and requires `explicit_opt_in`. Uses one unique query-key canary and one reserved `.invalid` `X-Forwarded-Host`; proof requires replay on the same isolated cache key after the header is removed.

## Report QA

JSON, HTML and SARIF are product interfaces. Credential-bearing values, common secret formats, passwords, bearer tokens, cookies, API keys, JWT raw values and refresh tokens must not appear in persisted evidence/logs/reports.

## Request/Performance bounds

CI verifies local invariants instead of benchmarking public targets: plugin budgets, capped specialized-layer requests, per-host concurrency, explicit timeouts, bounded 429/503 retry, local-only callbacks, and absence of unbounded mass-target/mass-exploitation modes.
