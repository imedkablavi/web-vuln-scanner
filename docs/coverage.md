# Security Testing Coverage

This project intentionally does **not** claim complete OWASP Top 10, WSTG, or
ASVS coverage. Automated DAST is one part of an assessment; business context,
architecture review, source review, and manual verification remain necessary.

Coverage labels:

- **Stable** — implemented, release-enabled in an appropriate explicit profile,
  and exercised by positive/negative integration fixtures.
- **Partial** — useful automated evidence exists, but the implementation does
  not cover the whole testing area.
- **Experimental** — code exists but is blocked by release maturity policy.
- **Not implemented** — no release-quality check currently exists.

## Current capability matrix

| Area | Status | Scanner capability |
| --- | --- | --- |
| SQL injection | Stable | Bounded error/boolean differential testing in active profiles; time-based probes disabled by release defaults. |
| Object-level authorization / IDOR | Stable | Actor-aware comparison, RBAC-policy verification, workflow/replay evidence. |
| Security headers | Stable | Passive CSP, framing, MIME, referrer and HSTS posture observations. |
| Cookie attributes | Stable | Passive Secure, HttpOnly and SameSite observations. |
| CORS | Partial | Credentialed origin reflection / wildcard posture checks. |
| Verbose server errors | Stable | Passive error-pattern detection. |
| Exposed backup/config resources | Stable | Observed-resource inspection by default; bounded guessed paths only in explicitly active/custom configurations. Secret values are redacted before persistence. |
| OpenAPI/Swagger inventory | Partial | Scoped document loading and endpoint/security metadata inventory. |
| GraphQL introspection | Partial | Explicit introspection check and schema inventory. |
| DNS/TLS posture | Partial | Basic DNS/TLS/HTTPS inventory, not a full TLS compliance scanner. |
| Authentication | Partial | Form, browser-form and bearer/refresh actor bootstrapping for authorized verification scenarios. |
| Session management | Partial | Actor-isolated HTTP state, refresh/relogin handling and browser-to-HTTP handoff evidence. |
| Workflow/business logic | Partial | Declarative multi-step actor workflows and replay; application-specific workflows still require operator modeling. |
| Reflected XSS | Experimental | Reflection heuristic exists but is blocked pending executable-context verification fixtures. |
| Local file inclusion | Experimental | Heuristic implementation exists but is blocked pending stronger proof/negative fixtures. |
| Command injection | Experimental | Heuristic implementation exists but is blocked pending execution-specific non-destructive proof. |
| Open redirect | Experimental | Heuristic implementation exists but is blocked pending stronger redirect-verification fixtures. |
| CSRF | Not implemented | Token discovery exists for crawling, but there is no release-quality CSRF vulnerability verifier. |
| OAuth/OIDC | Not implemented | No protocol-specific authorization-flow verifier. |
| JWT security | Not implemented | Bearer tokens can be used as actor material; token cryptographic/policy analysis is not implemented. |
| WebSocket security | Not implemented | No WebSocket protocol scanner. |
| SSRF vulnerability detection | Not implemented | The scanner protects itself from off-scope/SSRF-style dispatch; it does not claim to find application SSRF. |
| XXE | Not implemented | No release-quality XML external entity verifier. |
| SSTI | Not implemented | No release-quality template-injection verifier. |
| HTTP request smuggling | Not implemented | Requires lower-level connection semantics than the current Requests/Playwright transport. |
| Cache poisoning/deception | Not implemented | No release-quality cache behavior verifier. |

## Reference model

The coverage vocabulary is aligned with the areas in the OWASP Web Security
Testing Guide (WSTG), while verification requirements should be mapped to OWASP
ASVS where a deterministic requirement exists. The plugin catalog separately
records CWE and OWASP Top 10:2025 metadata for categorization; those mappings do
not imply comprehensive category coverage.

Official references:

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10:2025: https://owasp.org/Top10/2025/

## Promotion requirement for experimental checks

An experimental plugin should not be marked stable until it has, at minimum:

1. deterministic or clearly bounded verification semantics;
2. known-vulnerable true-positive fixtures;
3. known-safe and misleading-response negative fixtures;
4. scope and request-budget tests;
5. secret-safe evidence and reproduction output;
6. a documented CWE/WSTG/ASVS relationship where applicable;
7. successful authorized end-to-end smoke coverage.
