# Detector Roadmap

This roadmap prioritizes coverage that can be verified deterministically without unsafe defaults. Public CI must remain local/synthetic, and no detector is promoted based on feature presence alone.

## Added in this hardening branch

### SSTI expression evaluation — experimental

- CWE-1336
- Marker-only arithmetic expression verification.
- Dedicated local positive and negative fixtures.
- Maximum two candidate requests per surface.
- No command execution, file access, environment access, object traversal, sandbox escape or network callback probes.

### CRLF / response-header injection — experimental

- CWE-113
- One inert response-header canary only.
- Dedicated local positive and negative fixtures.
- Maximum two candidate requests per surface.
- No cookie, redirect, cache-control, HTML or script injection.

## High-priority next detector families

### SSRF

Do not implement as a generic loopback/private-network probe. A professional detector needs a dedicated local callback service or controlled OAST-style test harness, redirect-chain validation, DNS-rebinding-resistant scope checks, and explicit proof that no real internal service can be contacted during CI.

Promotion evidence should include positive/negative URL-fetch fixtures, redirect handling, encoded-address normalization, IPv4/IPv6 scope tests and proof that the detector cannot escape the authorized target policy.

### XXE / unsafe XML parsing

Use only synthetic XML endpoints and a local controlled entity-resolution fixture. The detector must not read real local files or contact arbitrary network destinations. Positive evidence should prove entity resolution using a synthetic canary resource; negative fixtures should include hardened parsers and unsupported content types.

### CSRF

Avoid "form has no token" heuristics as a verified finding. A useful detector needs authenticated state-changing local workflows, same-site/origin controls, token lifecycle tests and deterministic proof that a cross-site request can change synthetic state without the required anti-CSRF control.

### NoSQL / document-query injection

Require local synthetic data stores or deterministic mock query semantics. Promotion should prove query-operator influence without destructive mutations, and must include safe-query negatives to control false positives.

### LDAP / XPath injection

Only add after a local directory/XML query fixture exists. Detection should prove unintended query semantic changes using synthetic records rather than destructive or privilege-changing actions.

### JWT / token validation weaknesses

Prefer validation-focused checks: accepted algorithm policy, issuer/audience binding, expiry handling, key selection and token confusion. CI should use only synthetic keys/tokens. Do not add token forging against real services or brute-force key recovery.

### OAuth/OIDC flow validation

Focus on state/nonce/PKCE, redirect URI binding, issuer/audience validation and token leakage. Promotion requires a synthetic authorization server/client pair so the scanner can distinguish exploitable flow errors from configuration differences.

### Host-header / forwarded-host trust

Use a synthetic canary host and prove that attacker-controlled host metadata reaches a security-sensitive generated URL or trust decision. Avoid treating ordinary reflection as a verified vulnerability.

### File-upload security

Start with passive/configuration observations and synthetic upload handlers. Any active validation must use inert files only, enforce strict size limits and never attempt executable payloads or persistence.

### Cache poisoning / cache-key confusion

Requires a local cache fixture with deterministic cache state. A reportable result should prove a synthetic response variant is stored under an incorrect cache key without injecting executable content.

## Lower-priority / research-heavy families

- HTTP request smuggling/desynchronization: requires a purpose-built local proxy/origin harness and strict request-count/time bounds.
- WebSocket authorization: needs authenticated local channel fixtures and cross-actor access checks.
- GraphQL authorization depth: build on the existing API/auth harness with local schema fixtures and per-object authorization expectations.
- Race-condition/business-logic checks: only with synthetic idempotent state transitions and bounded concurrency.
- Web cache deception: requires deterministic local proxy/cache fixtures.
- Prototype pollution: relevant only when JavaScript server/client execution paths can be verified safely in a controlled fixture.

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
