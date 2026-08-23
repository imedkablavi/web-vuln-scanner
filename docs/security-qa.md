# Security QA and Plugin Promotion Gates

This project is for authorized security assessment only. Automated CI targets must be local or synthetic; CI must not scan public third-party systems.

## Regression corpus

The intentionally-vulnerable local corpus is implemented by `smoke/mock_server.py` plus the focused additional fixtures in `tests/corpus/additional_vuln_server.py`; both are described by `tests/corpus/manifest.yaml`.

The required CI gates cover:

- a known SQL injection positive case;
- a known safe-query negative case;
- authenticated cookie-session behavior;
- unauthenticated denial behavior;
- SSTI arithmetic-expression positive and negative cases;
- CRLF response-header injection positive and negative cases;
- scope rejection before network dispatch;
- plugin request-budget enforcement;
- per-request timeout enforcement;
- per-host concurrency enforcement;
- bounded `Retry-After` handling;
- JSON/HTML redaction;
- SARIF conversion shape;
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

## False-positive / false-negative gates

A stable plugin must have dedicated local positive and negative fixtures.

Minimum promotion rule:

- all known-positive corpus cases must produce the expected `detected` or `verified` result;
- known-negative cases must not produce a finding for that plugin;
- the plugin must remain within its configured request budget;
- report evidence must be serializable and redacted;
- tests must pass repeatedly in CI without external services.

One passing positive test is not enough to promote an experimental plugin.

## Experimental plugin status

The following plugins remain registry-blocked even when configuration attempts to enable them:

- `xss_reflected`
- `lfi`
- `cmd_injection`
- `open_redirect`
- `ssti`
- `crlf_injection`

Do not remove this block until each plugin has its own deterministic positive/negative corpus coverage, evidence-quality assertions, scope/budget tests and false-positive review.

### SSTI safety boundary

The experimental SSTI detector is intentionally limited to deterministic arithmetic-expression evaluation. It must not add command execution, subprocess access, file reads, object traversal, sandbox-escape chains, environment-variable access, or network callbacks as verification payloads.

### CRLF safety boundary

The experimental CRLF detector may create only one inert `X-Scanner-Canary` response header. It must not inject `Set-Cookie`, `Location`, cache directives, HTML/script content or other state-changing/security-sensitive headers.

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
- 429/503 retry behavior remains bounded;
- no unbounded mass-target or mass-exploitation mode is permitted.

Release benchmarking against real infrastructure must be performed only with explicit authorization and is not part of public CI.
