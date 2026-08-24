# Detector Roadmap

This roadmap prioritizes deterministic proof over payload count. Public CI remains local/synthetic and no detector is promoted solely because implementation exists.

## Implemented on the hardening branch

### Active plugins / browser layers

- **SSTI expression evaluation — experimental:** arithmetic marker only; max two requests; no command/file/sandbox/network execution.
- **CRLF response-header injection — experimental:** one inert header canary; max two requests.
- **SSRF callback proof — experimental:** one candidate request to an explicitly configured scanner callback; no internal-address guessing.
- **Host-header trust — experimental:** reserved `.invalid` canary; reports security-sensitive absolute URL/redirect influence only.
- **Credentialed CORS verification:** two unrelated synthetic origins must both be reflected with credentials.
- **GraphQL debug verification:** introspection observation plus one invalid-field debug query; no mutations or resource-exhaustion probes.
- **DOM-XSS Chromium verification — experimental browser layer:** fragment canary must actually execute; `innerHTML` positive and `textContent` negative fixtures.

### Bounded verification layers — disabled by default where active

- **XXE:** controlled loopback entity-resolution proof; no `file://`, metadata or arbitrary private-service probes.
- **CSRF:** explicit safe workflow, same-origin-with-token baseline versus cross-site-without-token proof.
- **NoSQL:** scalar control versus one equivalent `$eq` object; no `$where`, JavaScript or regex-DoS probes.
- **JWT offline policy:** zero-network algorithm/expiry/issuer/audience posture from environment-provided samples.
- **OIDC discovery:** one metadata request for issuer/transport/PKCE-S256 posture.
- **OAuth redirect/state:** credential-free redirect-URI binding and state preservation, loopback-only by default.
- **File upload:** harmless static HTML marker with same-origin retrieval only.
- **Cache poisoning:** isolated unique cache key plus reserved `.invalid` forwarding-host canary.

## Next-wave verification implemented

### LDAP / XPath query semantics

- `directory_query_verification` supports explicit `ldap` or `xpath` mode.
- Exactly two JSON POSTs: scalar control and one inert synthetic query canary.
- Local vulnerable and safe fixtures prove query-semantic influence without writes.
- Loopback-only by default; external probes require a second opt-in.
- No directory enumeration, credential guessing, mutations or payload spraying.

### JWT server-side rejection harness

- `jwt_server_validation` uses one known-good control token and one operator-supplied invalid token, both referenced by environment-variable name.
- Adds an unauthenticated control so a finding requires: good token accepted, negative token accepted, unauthenticated request rejected.
- Maximum three requests.
- The scanner does not forge, mutate, brute-force or persist tokens.

### OAuth/OIDC code-flow verification

- `oauth_code_flow_verification` uses a synthetic/public client with no client secret or user credentials.
- Verifies PKCE wrong-verifier rejection, state preservation, OIDC nonce binding and authorization-code single use.
- Loopback-only by default and hard-capped at five requests.
- Codes, tokens, nonces and verifiers are not persisted in findings.

### WebSocket handshake authentication

- `websocket_auth_verification` compares authenticated and isolated anonymous HTTP Upgrade handshakes.
- Two requests only; zero WebSocket frames, subscriptions or long-lived sessions.
- Reports only when both handshakes are accepted with status 101.

### GraphQL object/field authorization

- `graphql_authorization_verification` executes one explicit query as two explicitly configured actors.
- Actor headers come from environment variables and each actor receives an isolated RequestManager.
- Positive proof requires both owner/reference and comparison actor to receive the protected configured value.
- Integrates with the scanner's existing cross-actor verification evidence model.

### Web Cache Deception

- `web_cache_deception_verification` uses an explicitly configured deceptive URL and private marker.
- A unique query parameter isolates the cache key.
- Proof requires authenticated private content followed by the same content on an isolated anonymous replay with a cache-hit signal.
- The anonymous replay uses a separate RequestManager so ambient session cookies cannot leak between identities.

### HTTP request smuggling / desynchronization research lab

- A local-only parser-boundary differential harness now exists in `tests/corpus/http_desync_lab.py`.
- Positive fixture contains a single HTTP/1 request and an inert trailing byte; it proves only that two toy framing policies disagree on the message boundary.
- Negative fixture has matching Content-Length/chunked boundaries.
- There is intentionally **no active production-target dispatcher**, second request, proxy poisoning, victim request, or external-host support.
- Moving this beyond research requires a dedicated local proxy/origin harness plus a separate safety and false-positive review.

## Architecture hardening discovered during this wave

Cross-actor and anonymous verification uncovered an important session-isolation issue: `requests.Session` can retain configured cookies/headers even when an individual call passes an empty cookie dictionary. `core/requester_variants.py` now creates ephemeral RequestManager instances with replaced auth material while preserving scope, retry, timeout, concurrency and event-bus policy. WebSocket, GraphQL authorization and Web Cache Deception use these isolated requesters.

## Remaining research-heavy families

- Race-condition/business-logic checks with synthetic idempotent transitions and rollback/reset support.
- Prototype pollution only when a controlled JavaScript execution path proves a concrete effect safely.
- Deeper WebSocket per-message/channel authorization after a synthetic frame-level policy harness exists.
- Deeper GraphQL mutations/subscription authorization only with explicit non-destructive local schemas.
- HTTP desynchronization beyond parser research only after a purpose-built local reverse-proxy/origin harness is available.

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
