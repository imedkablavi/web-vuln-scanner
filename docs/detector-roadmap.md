# Detector Roadmap

This roadmap prioritizes deterministic proof over payload count. Public CI remains local/synthetic and no detector is promoted solely because implementation exists.

## Implemented in the hardening branch

### SSTI expression evaluation — experimental

- CWE-1336.
- Marker-only arithmetic expression verification.
- Dedicated local positive/negative fixtures.
- Maximum two candidate requests per surface.
- No command execution, file access, environment access, object traversal, sandbox escape, or network callbacks.

### CRLF / response-header injection — experimental

- CWE-113.
- One inert response-header canary only.
- Dedicated local positive/negative fixtures.
- Maximum two candidate requests per surface.
- No cookie, redirect, cache-control, HTML, or script injection.

### SSRF callback proof — experimental

- CWE-918.
- Requires an explicitly configured scanner-controlled callback and expected proof marker.
- Local CI uses a second loopback HTTP server on an ephemeral port and the vulnerable fixture performs a real server-side fetch.
- Maximum one candidate request per surface.
- No guessed cloud-metadata, RFC1918, link-local, alternate-IP, or internal-service probes.
- External callback use requires explicit opt-in and remains registry-blocked pending broader quality review.

### Host-header trust — experimental

- CWE-346 / CWE-644.
- Uses a reserved `.invalid` Host canary.
- Reports only when the canary reaches a redirect destination or security-sensitive absolute URL.
- Plain Host reflection is intentionally insufficient.
- Maximum one candidate request per surface.

### Credentialed CORS verification — bounded verification layer

- Two different untrusted synthetic Origin values are required.
- Both must be reflected exactly with credentials enabled before a finding is verified.
- Allowlisted-origin negative fixture prevents reflection-only false positives.
- Wildcard-plus-credentials is not mislabeled as verified credentialed cross-origin read access.

### GraphQL-specific verification — bounded verification layer

- Introspection is observed as posture metadata.
- One non-mutating invalid-field query checks for stack traces, exception objects, server paths, and debug extensions.
- Dedicated verbose-error positive and sanitized-error negative fixtures.
- Maximum two requests per configured GraphQL endpoint.
- No mutation, deep-recursion, alias flood, batch flood, or DoS probe.

### DOM-XSS Chromium verification — experimental browser layer

- Fragment-only canary through `location.hash`.
- A finding requires actual JavaScript execution in Chromium, not string reflection or static sink matching.
- Canary side effect is limited to one DOM data attribute.
- No network callback, storage/cookie access, navigation, persistence, or data extraction.
- Dedicated `innerHTML` positive and `textContent` negative fixtures.
- Disabled by default and gated by a dedicated Chromium CI test.

## High-priority next detector families

### XXE / unsafe XML parsing

Use only synthetic XML endpoints and a local controlled entity-resolution fixture. The detector must not read real local files or contact arbitrary network destinations. Positive evidence should prove entity resolution using a synthetic canary resource; negatives should include hardened parsers and unsupported content types.

### CSRF

Avoid "form has no token" heuristics as a verified finding. A useful detector needs authenticated state-changing local workflows, same-site/origin controls, token lifecycle tests, and deterministic proof that a cross-site request can change synthetic state without the required anti-CSRF control.

### NoSQL / document-query injection

Require local synthetic data stores or deterministic mock query semantics. Promotion should prove query-operator influence without destructive mutations and include safe-query negatives.

### LDAP / XPath injection

Add only after a local directory/XML query fixture exists. Detection should prove unintended query semantic changes using synthetic records rather than destructive or privilege-changing actions.

### JWT / token validation weaknesses

Prefer validation-focused checks: algorithm policy, issuer/audience binding, expiry handling, key selection, and token confusion. CI should use only synthetic keys/tokens. Do not add brute-force recovery or attacks against real credentials.

### OAuth/OIDC flow validation

Focus on state/nonce/PKCE, redirect URI binding, issuer/audience validation, and token leakage. Promotion requires a synthetic authorization-server/client pair.

### File-upload security

Start with synthetic upload handlers and inert files. Any active validation must enforce strict size limits and never attempt executable payloads or persistence.

### Cache poisoning / cache-key confusion

Requires a local cache fixture with deterministic cache state. A reportable result should prove a synthetic response variant is stored under an incorrect cache key without executable content.

## Lower-priority / research-heavy families

- HTTP request smuggling/desynchronization: requires a purpose-built local proxy/origin harness and strict request/time bounds.
- WebSocket authorization: needs authenticated local channel fixtures and cross-actor access checks.
- GraphQL authorization depth: build on the existing GraphQL/auth harness with local schema fixtures and per-object authorization expectations.
- Race-condition/business-logic checks: only with synthetic idempotent state transitions and bounded concurrency.
- Web cache deception: requires deterministic local proxy/cache fixtures.
- Prototype pollution: relevant only when JavaScript execution paths can be verified safely in a controlled fixture.

## Promotion rule

No detector moves to stable until it has all of the following:

1. deterministic local positive fixtures;
2. deterministic local negative fixtures;
3. explicit false-positive and false-negative assertions;
4. bounded request count and timeout;
5. scope enforcement before dispatch;
6. structured evidence and reproduction metadata;
7. redaction QA;
8. repeated CI passes without external targets;
9. documented limitations describing what the detector does **not** prove.
