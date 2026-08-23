# Check reference

This page describes what a check must observe before it writes a finding. The distinction matters: some checks prove a specific condition, while others only identify behavior that needs manual validation.

## Stable active checks

| Check | Profile | Verification rule | Main limit |
| --- | --- | --- | --- |
| SQL injection | safe-active | database error evidence or bounded differential evidence | no timing probes in release profiles |
| Reflected markup injection | safe-active | injected inert element is reconstructed by the HTML parser | does not prove JavaScript execution |
| Browser XSS confirmation | full-authorized | Chromium executes a harmless inline handler that sets a DOM marker | GET/query only, three candidates by default, no storage/cookie access or callback |
| Open redirect | safe-active | 3xx `Location` resolves to the exact reserved `wvs.invalid` canary | redirect is not followed |
| SSTI | safe-active | two arithmetic expressions produce two distinct expected results | no command, file, callback, or timing primitive |
| CRLF / response-header injection | safe-active | a unique canary appears as a separate response header | no cache-poisoning or response-splitting follow-up |
| TRACE reflection | safe-active | a successful TRACE response reflects a unique request header | checked once per origin |
| Same-origin URL fetch behavior | safe-active | a URL-like parameter causes the response to become strongly similar to a directly fetched page on the same authorized origin | does not target private IPs, metadata services, or external callbacks; does not claim internal-network SSRF |
| Safe YAML templates | safe-active | the configured status/word/header matcher set is satisfied on a same-origin GET/HEAD response | no raw HTTP, DSL/eval, redirects, callbacks, or non-GET/HEAD methods |
| Business logic / access control | safe-active | response variance is a signal; verified status requires actor/RBAC evidence | requires suitable test identities for strong conclusions |

The safe-active profile has separate limits for URLs, parameters per URL, active web requests, and safe-template requests. Reaching a request budget stops new work in that layer and is recorded in scan metadata.

## Safe YAML template checks

The template engine exists to make conservative exposure/misconfiguration checks extensible without embedding arbitrary execution in the scanner. Packaged checks currently cover strong markers for:

- PHP `phpinfo()` exposure;
- Apache `server-status` exposure;
- Nginx `stub_status` exposure;
- Go `/debug/vars` expvar exposure.

A template is rejected unless it stays within the release schema:

- request method must be `GET` or `HEAD`;
- request path must be one absolute same-origin path;
- redirects are never followed;
- template variables, DSL expressions, raw HTTP, command execution, and callback behavior are unsupported;
- matchers are limited to HTTP status, words in body/headers, and named response headers;
- matcher/value counts and body bytes are bounded;
- the final URL still passes the centralized scope policy.

Built-ins are enabled by `safe-active` and `full-authorized` with separate hard request/template budgets. They are disabled by `passive`. Custom templates can be loaded from `scanner.active_checks.templates.directory` or `.files`; relative paths are resolved relative to the user configuration file.

A safe-template match is reported as `detected`: it proves that the declared response condition exists, not that a broader exploit chain is possible.

## Browser XSS confirmation

`full-authorized` adds a small browser confirmation pass for HTML GET endpoints that already expose query parameters. The injected payload can only set `data-wvs-xss` on the document root. Chromium requests remain behind the same scope policy and off-scope HTTP(S) requests are aborted.

A successful browser confirmation is reported as `verified` reflected XSS. The non-browser reflected-markup plugin remains useful on `safe-active`, but its result is intentionally weaker because HTML reconstruction alone does not prove JavaScript execution.

## Passive checks

Passive and posture checks include:

- browser security headers;
- cookie attributes;
- explicit caching of responses that appear user-specific;
- credentialed CORS behavior;
- redirect posture;
- verbose error disclosure;
- observed data exposure;
- OpenAPI inventory, including path/query/header/cookie/body inputs;
- GraphQL root query/mutation and argument inventory when introspection is available;
- local JWT metadata review for configured or already-issued bearer tokens;
- DNS and TLS inventory.

The cache check does not report a missing `Cache-Control` header by itself. It requires an explicit public/shared/positive cache policy and an additional signal that the response may be user-specific.

JWT review is local only. Tokens are decoded for header/claim metadata, but the scanner does not modify, re-sign, brute-force, or replay a changed JWT. Raw token values and subject values are not written to findings.

The passive profile does not send the injection payloads or safe-template requests listed in the active sections.

## XML parser probe

An internal-entity XML parser probe is available as an explicit opt-in under `active_checks.xml.enabled`. It is disabled in every built-in profile because XML endpoints commonly use POST, PUT, or PATCH and may change state.

The payload contains one internal DTD entity with a random canary. It never uses a file URI, external entity URL, private address, metadata service, parameter-entity fetch, or recursive expansion. A positive result means the endpoint processes DTD entities; it is not reported as proven XXE data exfiltration.

## Experimental checks

`lfi` and `cmd_injection` remain experimental. They are present for development and fixture work but are blocked by the release maturity policy in all built-in profiles.

A check should not be promoted to stable just because it finds a positive fixture. Promotion requires useful negative fixtures and a verification rule that rejects ordinary reflection, template variation, authentication drift, and unrelated response noise.

## Plugin request contract

Plugin test cases now carry the injection location as part of the request contract. Query, body, header, cookie, and discovered path inputs are sent to their declared location. Method overrides and redirect policy are also forwarded by the scanner. This prevents a header or cookie test from silently becoming a query-string test.

## Status language

The reporter uses verification status deliberately:

- `informational`: inventory or context, not a vulnerability claim;
- `suspected`: a heuristic signal that needs manual validation;
- `detected`: the stated condition was observed, but exploitability was not proven;
- `verified`: the check met its stronger reproducibility or execution rule.

Examples: same-origin URL-fetch behavior is `detected`, not verified internal-network SSRF. Internal DTD entity expansion is `detected`, not verified XXE data exfiltration. A safe-template match is `detected`. Browser-confirmed reflected XSS can be `verified` because the marker was produced by actual browser execution.

## Mappings

Mappings shown by `web-vuln-scanner checks` are navigation references, not claims that the scanner covers an entire CWE, WSTG chapter, or OWASP category.