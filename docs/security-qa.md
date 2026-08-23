# Security QA and Plugin Promotion Gates

This project is for authorized security assessment only. Automated CI targets must be local or synthetic; CI must not scan public third-party systems.

## Regression corpus

The intentionally-vulnerable local corpus is implemented by `smoke/mock_server.py` plus the focused fixtures in `tests/corpus/additional_vuln_server.py`; both are described by `tests/corpus/manifest.yaml`.

The required CI gates now cover:

- SQL injection positive and safe-query negative cases;
- authenticated cookie-session and unauthenticated-denial behavior;
- SSTI arithmetic-expression positive and negative cases;
- CRLF response-header injection positive and negative cases;
- SSRF callback-proof positive and safe-fetch-disabled negative cases;
- Host-header security-sensitive URL influence positive and canonical-origin negative cases;
- two-origin credentialed CORS positive and allowlisted-origin negative cases;
- GraphQL introspection observation plus verbose-error positive and sanitized-error negative cases;
- Chromium DOM-XSS JavaScript-execution positive and `textContent` negative cases;
- scope rejection before network dispatch;
- plugin request-budget and timeout enforcement;
- per-host concurrency and bounded `Retry-After` handling;
- JSON/HTML redaction and SARIF conversion shape;
- Docker and Python distribution smoke tests.

## Plugin runtime contract

Plugins must use the scanner runtime. Direct use of `requests`, `httpx`, raw sockets, browser automation, or subprocess network tools from a plugin is not accepted.

Each plugin must provide:

1. A bounded `request_budget` per surface.
2. A request `timeout_seconds` that cannot exceed the scanner-wide timeout.
3. `TestCase` values tied to the originating `surface_id`.
4. Structured `VerificationResult` evidence and reproduction metadata.
5. No reportable result without evidence.
6. No reportable result without bounded reproduction metadata.
7. No target-scope expansion. Outbound requests continue through `RequestManager.send`, which owns scope/SSRF, concurrency, retry and rate-limit enforcement.

Browser verification is a separate bounded layer. It must independently enforce URL scope and may not be embedded inside active plugins.

## False-positive / false-negative gates

A stable detector must have dedicated local positive and negative fixtures.

Minimum promotion rule:

- all known-positive corpus cases produce the expected `detected` or `verified` result;
- known-negative cases do not produce a finding for that detector;
- request count and timeout remain within explicit bounds;
- evidence is serializable, minimal and redacted;
- tests pass repeatedly without external services;
- limitations state exactly what the detector does and does not prove.

One passing positive test is not enough to promote an experimental detector.

## Experimental plugin status

The following active plugins remain registry-blocked even when configuration attempts to enable them:

- `xss_reflected`
- `lfi`
- `cmd_injection`
- `open_redirect`
- `ssti`
- `crlf_injection`
- `ssrf`
- `host_header`

`ssrf` and `host_header` use an extended experimental registry gate so the previously tested experimental registry contract remains backward-compatible.

### SSTI safety boundary

SSTI is limited to deterministic arithmetic-expression evaluation. It must not add command execution, subprocess access, file reads, object traversal, sandbox-escape chains, environment-variable access, or network callbacks.

### CRLF safety boundary

CRLF may create only one inert `X-Scanner-Canary` response header. It must not inject `Set-Cookie`, `Location`, cache directives, HTML/script content, or other state-changing/security-sensitive headers.

### SSRF safety boundary

SSRF does not guess cloud metadata, RFC1918, link-local, loopback, alternate-IP encodings, or internal service destinations. It requires an explicit scanner-controlled callback URL plus a proof marker. External callbacks require a separate explicit opt-in; the public CI callback is loopback-only.

### Host-header safety boundary

Host-header verification uses a reserved `.invalid` canary and reports only when that value controls a redirect destination or a security-sensitive absolute URL such as reset/recovery/invite/login. Plain text reflection is not a vulnerability proof.

### CORS verification boundary

Credentialed CORS is verified only after two different synthetic untrusted origins are reflected exactly with `Access-Control-Allow-Credentials: true`. A wildcard origin combined with credentials is not reported as verified credentialed cross-origin access because conforming browsers reject that combination for credentialed reads.

### GraphQL verification boundary

GraphQL verification is capped at two non-mutating requests: introspection observation and an invalid-field validation query. It does not send mutations, deep-recursion probes, alias floods, batching floods, or denial-of-service payloads.

### DOM-XSS browser boundary

DOM-XSS verification is disabled by default. Chromium receives a fragment-only canary whose JavaScript side effect is limited to setting one DOM data attribute. The canary performs no network callback, storage access, cookie access, navigation, persistence, or data extraction. A reportable result requires actual canary execution; static source/sink strings are not enough.

## Report QA

JSON, HTML and SARIF are treated as product interfaces.

Required checks:

- JSON remains parseable and includes scan metadata and findings.
- HTML escapes evidence and reproduction content.
- SARIF remains version 2.1.0 and preserves rule/result metadata.
- credential-bearing keys are redacted.
- common inline secret formats are redacted before logs/evidence are persisted.
- reports must not contain captured passwords, bearer tokens, session cookies, API keys or raw discovered secret values.

## Performance and rate limiting

CI does not benchmark the public internet. It verifies local invariants instead:

- per-host concurrency never exceeds configuration;
- plugin candidate requests never exceed the per-surface budget;
- plugin timeout is explicit and capped by the scanner timeout;
- CORS is capped by URL count and exactly two Origin probes per checked URL;
- GraphQL is capped at two non-mutating requests per endpoint;
- DOM-XSS is capped by browser URL count and one fragment canary per URL;
- 429/503 retry behavior remains bounded;
- no unbounded mass-target or mass-exploitation mode is permitted.

Release benchmarking against real infrastructure must be performed only with explicit authorization and is not part of public CI.
