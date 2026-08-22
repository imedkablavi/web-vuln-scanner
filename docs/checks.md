# Check reference

This page describes what each release check proves before it writes a finding. It is intentionally narrower than a list of payloads.

## Stable active checks

| Check | Default active profile | Verification rule | Main limit |
| --- | --- | --- | --- |
| SQL injection | safe-active | database error evidence or bounded differential evidence | no timing probes in release profiles |
| Reflected markup injection | safe-active | injected inert element is reconstructed by the HTML parser | does not prove JavaScript execution |
| Open redirect | safe-active | 3xx `Location` resolves to the exact reserved `wvs.invalid` canary | redirect is not followed |
| SSTI | safe-active | two arithmetic expressions produce two distinct expected results | no command, file, callback, or timing primitive |
| CRLF / response-header injection | safe-active | a unique canary appears as a separate response header | no cache-poisoning or response-splitting follow-up |
| TRACE reflection | safe-active | a successful TRACE response reflects a unique request header | checked once per origin |
| Business logic / access control | safe-active | response variance is a signal; verified status requires actor/RBAC evidence | requires suitable test identities for strong conclusions |

The safe-active profile limits the number of URLs considered by the active web layer and has a separate request budget. Hitting the budget stops new active web requests and is recorded in scan metadata.

## Passive checks

Passive checks inspect responses already fetched during discovery or perform low-impact posture requests. Current coverage includes:

- browser security headers;
- cookie attributes;
- credentialed CORS behavior;
- redirect posture;
- verbose error disclosure;
- observed data exposure;
- OpenAPI and GraphQL inventory/posture;
- DNS and TLS inventory.

The passive profile does not send the active payloads listed above.

## Experimental checks

`lfi` and `cmd_injection` remain experimental. They are present for development and fixture work but are blocked by the release maturity policy in all built-in profiles.

A check should not be promoted to stable just because it finds a positive fixture. Promotion requires useful negative fixtures and a verification rule that rejects ordinary reflection, template variation, authentication drift, and unrelated response noise.

## Status language

The reporter uses verification status deliberately:

- `informational`: inventory or context, not a vulnerability claim;
- `suspected`: a heuristic signal that needs manual validation;
- `detected`: the stated condition was observed, but exploitability was not proven;
- `verified`: the check met its stronger reproducibility rule.

For example, reflected markup is `detected`, not `verified XSS`, because the scanner currently proves HTML element injection rather than script execution.

## Mappings

Mappings shown by `web-vuln-scanner checks` are references for navigation, not claims of framework coverage. The current active checks touch OWASP WSTG areas such as SQL injection, reflected XSS, HTTP response splitting, SSTI, authorization testing, and HTTP methods.
