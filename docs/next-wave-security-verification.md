# Next-Wave Security Verification

This document covers the LDAP/XPath, JWT server validation, OAuth code-flow, WebSocket authentication, GraphQL authorization, Web Cache Deception, and HTTP desynchronization research work added after corpus v3.

All active checks are for explicitly authorized targets. Public CI uses local/synthetic fixtures only.

## Default configuration

All next-wave active verification layers are disabled by default.

### `active_verification.directory_query`

- `enabled: false`
- `explicit_opt_in: false`
- `allow_external_probes: false`
- `mode`: `ldap` or `xpath`
- `endpoint_url`: exact authorized endpoint
- `field`: JSON field to test
- `control_value`: inert scalar control
- `success_json_path` / `expected_value`: deterministic proof contract
- hard request bound: 2

### `active_verification.jwt_server`

- `enabled: false`
- `explicit_opt_in: false`
- `endpoint_url`: exact protected endpoint
- `control_token_env`: environment variable containing a known-good token
- `negative_token_env`: environment variable containing an operator-supplied invalid token
- `negative_token_class`: descriptive label only
- `success_marker` / `success_statuses`: expected authorized response contract
- hard request bound: 3

Raw tokens are never persisted. The scanner does not create or mutate the negative token.

### `active_verification.oauth_code_flow`

- `enabled: false`
- `explicit_opt_in: false`
- `allow_external_flow: false`
- `authorization_url`, `token_url`, `client_id`, `redirect_uri`
- `expect_id_token: true`
- hard request bound: 5

Default safety scope requires authorization, token, and redirect URLs to be loopback. The verifier uses a public client with no client secret and no user credentials.

### `active_verification.websocket_auth`

- `enabled: false`
- `explicit_opt_in: false`
- `endpoint_url`: exact HTTP(S) WebSocket upgrade endpoint
- hard request bound: 2

Only HTTP upgrade handshakes are sent; WebSocket frame count is zero.

### `active_verification.graphql_authorization`

- `enabled: false`
- `explicit_opt_in: false`
- `endpoint_url`, explicit `query`, optional `variables`
- `protected_json_path` + `expected_value`
- `baseline_headers_env`, `comparison_headers_env`: environment variables containing JSON header objects
- `baseline_actor_id`, `comparison_actor_id`
- hard request bound: 2

Each actor uses an isolated RequestManager. Header values are not persisted.

### `active_verification.web_cache_deception`

- `enabled: false`
- `explicit_opt_in: false`
- exact `url` and `private_marker`
- configurable `cache_hit_header` / `cache_hit_value`
- hard request bound: 2

The verifier adds one unique query key, performs an authorized request, then repeats the same cache key with a separate anonymous RequestManager. The marker value and auth material are not persisted.

## Requester isolation

`core/requester_variants.py` exists because a shared `requests.Session` can retain ambient cookies/headers. Cross-actor or anonymous checks must not rely on `cookies={}` alone to clear session authentication. The helper clones scanner policy and replaces auth state, preserving scope, timeout, retry, concurrency and event-bus behavior.

## Local corpus

`tests/corpus/advanced_vuln_server.py` provides deterministic positive/negative fixtures for:

- LDAP semantics;
- XPath semantics;
- JWT invalid-token rejection;
- OAuth PKCE/nonce/code reuse;
- WebSocket upgrade authentication;
- GraphQL cross-actor protected-field access;
- Web Cache Deception.

`tests/corpus/http_desync_lab.py` is research-only. It compares two toy HTTP/1 framing policies over synthetic bytes and never opens a network connection.

## HTTP desynchronization boundary

No general raw HTTP request-smuggling detector is exposed by the application. The research fixture:

- contains exactly one HTTP request;
- uses `Host: 127.0.0.1`;
- has no second/follow-up request;
- has no external URL;
- proves only a one-byte parser-boundary disagreement;
- cannot be directed at a production proxy/origin chain.

A future active detector would require a purpose-built loopback reverse-proxy/origin harness, deterministic connection-state cleanup, strict request/time budgets, negative fixtures across parser combinations, and a separate safety review.

## Promotion status

Implementation plus one green CI run is not enough for stable promotion. These capabilities remain bounded verification/research features until repeated FP/FN passes, report redaction QA, operational documentation, and broader fixture variance establish reliable behavior.
