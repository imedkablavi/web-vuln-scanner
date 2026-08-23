# Detector Roadmap

This roadmap prioritizes deterministic proof over payload count. Public CI remains local/synthetic and no detector is promoted solely because implementation exists.

## Implemented on the hardening branch

### Active plugins / browser layers

- **SSTI expression evaluation — experimental:** arithmetic marker only; max two requests; no command/file/sandbox/network execution.
- **CRLF response-header injection — experimental:** one inert header canary; max two requests.
- **SSRF callback proof — experimental:** one candidate request to an explicitly configured scanner callback; no internal-address guessing.
- **Host-header trust — experimental:** reserved `.invalid` canary; reports security-sensitive absolute URL/redirect influence only.
- **Credentialed CORS verification:** two unrelated synthetic origins must both be reflected with credentials.
- **GraphQL verification:** introspection observation plus one invalid-field debug query; no mutations or resource-exhaustion probes.
- **DOM-XSS Chromium verification — experimental browser layer:** fragment canary must actually execute; `innerHTML` positive and `textContent` negative fixtures.

### New bounded verification layers — disabled by default

#### XXE / unsafe XML

- One explicitly configured XML endpoint and controlled entity callback.
- Local positive fixture performs real entity resolution against a second loopback server; hardened negative rejects DTD processing.
- No `file://`, local-file reads, metadata addresses, arbitrary private services or callback guessing.
- Maximum one target POST; external callbacks require explicit opt-in.

#### CSRF request-integrity verification

- Requires `explicit_opt_in` and a known-safe configured action.
- Two requests only: authenticated same-origin request with token, then cross-site request without token.
- Positive proof requires both requests to satisfy the configured success marker; negative fixture enforces the token.
- Ambient cookie values are reused but never written into evidence.

#### NoSQL document-query semantics

- Requires `explicit_opt_in`, a configured endpoint and field.
- Compares scalar input with exactly one equivalent `$eq` object.
- Positive fixture interprets the operator; negative fixture enforces scalar schema.
- No `$where`, JavaScript execution, regex DoS or destructive writes.

#### JWT token-policy validation

- Offline-only; zero target requests.
- Synthetic/current sample is read from a named environment variable and never persisted.
- Checks unsecured/missing algorithm, configured algorithm allowlist, expiration, issuer and audience policy.
- Does **not** prove server-side signature bypass or token acceptance and does not brute-force keys.

#### OIDC discovery validation

- One metadata GET only.
- Checks exact configured issuer binding, HTTPS-or-loopback advertised endpoints, and PKCE S256 advertisement for public clients.
- No credentials, authorization request, code exchange or token exchange.

#### OAuth flow validation

- Requires `explicit_opt_in`; default authorization/redirect endpoints are loopback-only.
- Two credential-free authorization GETs compare the registered redirect with a reserved `.invalid` redirect and check state preservation.
- Public-provider probing requires a separate `allow_external_flow` opt-in.

#### File-upload handling

- Requires `explicit_opt_in` on a disposable authorized upload endpoint.
- Harmless static HTML marker only; no JavaScript, executable file, polyglot or persistence payload.
- Maximum one upload plus one same-origin retrieval request.
- Reports only when the marker is served inline as `text/html`; safe fixture serves as download/octet-stream.

#### Cache poisoning / cache-key confusion

- Requires `explicit_opt_in` on a known-safe cacheable URL.
- Uses a unique query key and reserved `.invalid` `X-Forwarded-Host` canary to isolate test state.
- Two GETs only; proof requires the second request to replay the canary without the header.
- No executable content or shared generic cache key is used.

## Next detector families

### LDAP / XPath injection
Build only after a local directory/XML-query fixture exists. Proof should demonstrate unintended synthetic query semantics without destructive or privilege-changing actions.

### JWT server-side validation harness
The current JWT layer is offline posture only. A future synthetic issuer/resource-server harness can validate signature enforcement, key selection, issuer/audience binding and token confusion without attacks against real credentials.

### OAuth/OIDC synthetic provider expansion
Add nonce, response-mode, code-use, PKCE verifier and issuer mix-up fixtures using a fully synthetic authorization server/client pair before considering stronger claims.

### WebSocket authorization
Requires authenticated local channel fixtures and deterministic cross-actor policy expectations.

### GraphQL authorization depth
Build on the existing schema/auth harness with synthetic object ownership and field-level authorization expectations.

### HTTP request smuggling/desynchronization
Research-heavy: requires a purpose-built local proxy/origin harness, raw-protocol isolation and strict request/time bounds. Do not probe arbitrary production proxy chains by default.

### Race-condition/business-logic checks
Only with synthetic idempotent state transitions, bounded concurrency and rollback/reset support.

### Web cache deception
Requires deterministic local proxy/cache fixtures distinct from the implemented unkeyed-header cache-poisoning proof.

### Prototype pollution
Relevant only when a controlled JavaScript execution path and reliable positive/negative fixtures can prove a concrete effect safely.

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
