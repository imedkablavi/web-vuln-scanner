# Web Vulnerability Scanner

A Python CLI for scoped web application security testing. It can crawl a target, inventory modern web/API surfaces, inspect common security controls, run a bounded set of active checks, compare authenticated users, and export findings as JSON, HTML, or SARIF.

The default profile is passive. Active payloads are not sent unless an active profile is selected.

> This project is alpha software. Use it only on systems you own or are authorized to test, and review findings before treating them as confirmed vulnerabilities.

## What it checks

The scanner currently covers four areas:

- discovery: HTTP crawling, bounded static JavaScript endpoint extraction, optional HAR discovery seeding, optional Playwright crawling, OpenAPI/Swagger, GraphQL, technology fingerprinting, DNS and TLS inventory;
- passive web checks: security headers, CSP posture, cookie flags, cache policy, CORS, redirects, multi-runtime stack traces, verbose server errors, JWT posture, and observed data exposure;
- bounded active checks: SQL injection, reflected markup injection, open redirect, server-side template injection, CRLF/response-header injection, TRACE reflection, same-origin URL-fetch behavior, and conservative same-origin GET/HEAD YAML templates;
- authorization testing: actor-aware object access checks, RBAC policy verification, authenticated crawling, replay, and workflow scenarios.

`full-authorized` can additionally confirm a subset of reflected XSS candidates in Chromium using an inert DOM marker. Experimental LFI/path traversal and command-injection code remains disabled by the release maturity policy.

The project also supports resumable active-test checkpoints and sanitized HAR-assisted discovery. Neither feature stores or replays captured authentication material by default.

## Install

Python 3.10 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

On Windows:

```powershell
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e .
```

For browser-assisted scans:

```bash
python -m pip install -e '.[browser]'
playwright install chromium
```

For development and QA:

```bash
python -m pip install -r requirements.txt
python -m pip install -e '.[dev]'
```

## CLI

The main installed command is `web-vuln-scanner`.

```bash
web-vuln-scanner --help
web-vuln-scanner scan --help
```

A normal passive scan:

```bash
web-vuln-scanner scan https://target.example --profile passive
```

The old short form still works:

```bash
web-vuln-scanner https://target.example
```

Useful scanner commands:

```bash
web-vuln-scanner checks
web-vuln-scanner checks --json
web-vuln-scanner profiles
web-vuln-scanner validate-config config/default_config.yaml
web-vuln-scanner doctor
web-vuln-scanner version
```

Additional installed helpers:

```bash
web-vuln-sarif --help
web-vuln-profile --help
web-vuln-diff --help
web-vuln-har --help
```

`checks` lists available checks with maturity, activity level, and useful CWE/WSTG mappings. `doctor` verifies the installed runtime and packaged configuration before a scan.

### Resume a long scan

Start an active scan with a minimal checkpoint ledger:

```bash
web-vuln-scanner scan https://staging.example \
  --profile safe-active \
  --checkpoint .scanner-state/staging.json
```

Resume only after a partial/interrupted run:

```bash
web-vuln-scanner scan https://staging.example \
  --profile safe-active \
  --resume .scanner-state/staging.json
```

`--checkpoint` and `--resume` are mutually exclusive. A testcase is recorded only after its request and verification step complete successfully. Failed or interrupted testcases remain eligible for retry.

Checkpoint files contain completed-test fingerprints plus redacted findings. They do not persist cookies, Authorization headers, response bodies, or raw parameter values. Resume is rejected when the target, profile, or relevant active-test configuration does not match. Completed checkpoint files are removed by default to prevent stale reuse.

### Seed discovery from a HAR

A browser/proxy HAR can feed normal scanner discovery directly:

```bash
web-vuln-scanner scan https://staging.example \
  --profile passive \
  --har-seed artifacts/session.har
```

This is **not** request replay. The scanner parses the HAR locally, rejects out-of-scope entries, discards captured values and credential headers, and uses only same-scope GET/HEAD URLs as fresh discovery seeds. Captured POST/PUT/PATCH/DELETE requests are not dispatched because they appeared in the HAR.

HAR-derived active parameter surfaces stay off unless `scanner.crawler.har_seed.active_tests` is explicitly enabled in YAML.

## Profiles

### passive

```bash
web-vuln-scanner scan https://target.example --profile passive
```

This is the default. It crawls and inventories the application, then runs passive posture checks. It does not send SQLi, XSS, redirect, SSTI, CRLF, SSRF-style, safe-template, or other active payloads.

### safe-active

```bash
web-vuln-scanner scan https://target.example --profile safe-active
```

This profile adds bounded active checks while keeping browser interaction and auth workflows off.

Enabled checks include:

- SQL injection differential/error checks;
- reflected markup injection using an inert custom HTML element;
- open redirect using a reserved `.invalid` destination;
- SSTI using two arithmetic canaries rather than command execution;
- CRLF/response-header injection using a dedicated response-header canary;
- TRACE reflection;
- same-origin URL-fetch behavior on observed URL-like parameters;
- bounded safe YAML exposure checks using same-origin GET/HEAD requests only.

The same-origin URL-fetch check never targets cloud metadata services, private address ranges, or external callback infrastructure. It reports fetch-like behavior rather than claiming internal-network SSRF.

The scanner does not use time-based SQLi payloads in release profiles.

Safe-template defaults are limited to 10 templates and 10 requests in this profile.

### full-authorized

```bash
web-vuln-scanner scan https://target.example \
  --profile full-authorized \
  --config config/default_config.yaml
```

This profile keeps the stable active checks and also enables browser-assisted discovery. Auth actors, RBAC verification, and workflows are available when configured. The safe-template budget increases to 25 templates/requests.

Browser XSS confirmation is bounded to a small set of GET/query candidates. Chromium must execute an inert handler that only sets a DOM marker before the condition can be marked `verified`.

Generic browser form submission and broad button clicking are still off by default. Browser login flows are separate and must be configured with explicit selectors.

## Active check behavior

The active checks are intentionally narrow.

### SQL injection

Uses bounded error and response-differential probes. Boolean checks compare responses against the same baseline. A generic response change is not reported as verified SQL injection.

### Reflected markup and browser XSS

The safe-active reflected-markup check injects an inert `<wvs-probe>` element and parses the returned HTML. It reports only when that element is reconstructed as markup; HTML reconstruction alone is not described as JavaScript execution.

In `full-authorized`, the browser verifier can run a separate inert event-handler canary against bounded GET/query candidates. A result is marked `verified` only if Chromium executes the handler and writes the expected DOM marker.

### Open redirect

Tests common redirect parameters with a destination under `wvs.invalid`. Redirects are not followed. A finding requires the response `Location` to resolve to the exact reserved canary destination.

### Server-side template injection

Tests observed query parameters with arithmetic expressions. A finding requires two distinct expressions to produce their two expected evaluated values. The check does not use file reads, command execution, external callbacks, or timing primitives.

### CRLF / response-header injection

Places a CR/LF canary in one observed query parameter and checks whether the server creates the dedicated canary response header. It does not send cache-poisoning or second-response payloads.

### TRACE

Sends a TRACE request with a unique header and reports when the server reflects that header in a successful TRACE response.

### Same-origin URL fetch

Tests URL-like observed query parameters using a reference URL on the already-authorized origin. The check is designed to identify server-side fetch behavior without contacting private networks or callback infrastructure. A positive result is not treated as proof of internal-network reachability.

### Safe YAML templates

The safe-template engine is an intentionally constrained extension mechanism for deterministic exposure/misconfiguration checks. Packaged templates currently look for strong markers associated with:

- PHP `phpinfo()` exposure;
- Apache `server-status` exposure;
- Nginx `stub_status` exposure;
- Go `/debug/vars` expvar exposure.

The engine accepts only GET/HEAD requests to one same-origin path and status/word/header matchers. It does **not** support raw HTTP, external origins, redirects, DSL/eval, shell commands, callbacks, file reads, template variables, or state-changing HTTP methods. Body inspection and request/template counts are bounded.

A safe-template match is reported as `detected`: the declared response condition was observed, but a broader exploit chain is not claimed.

These checks correspond to OWASP WSTG areas including reflected XSS (`WSTG-INPV-01`), HTTP response splitting (`WSTG-INPV-15`), SSTI (`WSTG-INPV-18`), HTTP methods (`WSTG-CONF-06`), SSRF (`WSTG-INPV-19`), and SQL injection (`WSTG-INPV-05`). Coverage is not a claim of complete WSTG or OWASP Top 10 testing.

## Scope controls

The target host is added to runtime scope automatically. Extra authorized hosts can be added in YAML:

```yaml
scanner:
  scope:
    include_domains:
      - app.example.com
      - api.example.com
      - "*.staging.example.com"
    exclude_paths:
      - /logout
      - /signout
    allow_private: false
    resolve_dns: true
```

Wildcard matching is boundary-aware. `*.example.com` does not match `badexample.com` or `example.com.attacker.test`.

Before HTTP dispatch, the request layer checks scope, URL scheme, redirects, and hostname resolution. Private, loopback, link-local, reserved, multicast, and unspecified IP destinations are blocked unless private targets were explicitly allowed.

The current DNS guard is a preflight check; it is not socket-level IP pinning, so a narrow DNS rebinding TOCTOU window remains.

## JavaScript endpoint discovery

The HTTP crawler can inspect inline JavaScript and a bounded number of same-scope script files for obvious literal endpoints used by `fetch()`, Axios, `XMLHttpRequest`, and common API route strings.

```yaml
scanner:
  crawler:
    javascript_discovery:
      enabled: true
      max_scripts: 10
      max_script_bytes: 250000
      max_endpoints: 100
```

JavaScript is scanned as text and is not evaluated. Inferred non-GET routes remain inventory-only. Only same-scope GET routes with explicit query parameters are promoted to normal attack surfaces. Static assets and unresolved template expressions are ignored.

This complements browser discovery; it does not replace browser execution for complex SPAs.

## Browser behavior

Playwright is optional. When it is enabled:

- off-scope HTTP(S) requests are intercepted and blocked;
- Service Workers are disabled in scoped browser contexts;
- arbitrary form submission is off by default;
- generic button clicking is off by default;
- auth traces and auth screenshots are opt-in;
- retained browser storage state is opt-in.

A controlled interaction config can look like this:

```yaml
scanner:
  browser:
    interactions:
      enabled: true
      submit_forms: true
      click_selectors:
        - "#known-safe-test-action"
```

Avoid broad selectors on production systems.

## Passive intelligence

Passive web analysis records conservative technology observations from response headers, cookie **names**, generator metadata, and framework-specific HTML markers. Technology detection is inventory and does not automatically assert that a detected version is vulnerable.

Additional posture analysis includes:

- enforced CSP versus report-only CSP;
- risky script sources such as `unsafe-inline`, `unsafe-eval`, wildcards, and `data:`;
- missing `form-action` on HTML pages that contain forms;
- high-confidence stack traces for Python, PHP, Java, .NET, Node.js, Ruby, and Go without copying the disclosed stack trace into finding evidence;
- TLS certificate verification failures as target findings rather than generic scanner errors;
- certificate expiry windows;
- cache policy checks on responses that appear user-specific;
- local JWT metadata/lifetime posture without modifying or replaying tokens.

## Auth and RBAC testing

Auth actors are defined in the config and should get credentials from environment variables. Sessions are isolated per actor and worker thread so one actor's Set-Cookie state is not reused by another actor.

The scanner can compare two authenticated users, evaluate a configured RBAC matrix, run authenticated crawls, and replay verified authorization findings. Access-control findings are downgraded when required actor state or comparison evidence is missing.

The sample actors in `config/default_config.yaml` are placeholders. Replace their URLs/selectors and set environment variables only for authorized test accounts.

## API discovery

OpenAPI/Swagger and GraphQL endpoints can be supplied directly:

```bash
web-vuln-scanner scan https://target.example \
  --profile full-authorized \
  --swagger https://target.example/openapi.json \
  --graphql https://target.example/graphql
```

OpenAPI 3 discovery inventories query, path, header, cookie, and request-body inputs and materializes path placeholders into testable surfaces. GraphQL introspection records root queries, mutations, and their arguments rather than only reporting a type count.

API requests pass through the same request manager and scope policy as crawler traffic.

## Active parameter suppression

V2 plugin requests pass through a centralized attack policy before dispatch. The default configuration excludes common CSRF, password, and token field names from active plugin payloads.

```yaml
scanner:
  attack_policy:
    skip_parameters:
      - csrf_token
      - password
      - access_token
    skip_parameter_patterns:
      - '^dangerous_action_'
```

Suppressed test cases are counted in scan diagnostics. Invalid regex patterns fail config validation instead of silently changing behavior.

## HAR import and discovery seeding

`web-vuln-har` converts a browser/proxy HAR into a sanitized attack-surface inventory without replaying requests:

```bash
web-vuln-har session.har \
  --target https://target.example \
  --output surfaces.json
```

It preserves method, base URL, parameter names, selected non-secret header names, and content type. Query/body values and credential headers such as Authorization and Cookie are intentionally discarded.

The scan-integrated seed mode is configured separately:

```yaml
scanner:
  crawler:
    har_seed:
      enabled: false
      files: []
      max_entries: 5000
      active_tests: false
```

`--har-seed PATH` enables this discovery input for one CLI run without modifying the original user YAML. Relative configured paths are resolved relative to the config file.

For an explicitly authorized loopback/private target with the standalone importer, add `--allow-private`.

## Checkpoint configuration

The CLI flags materialize a temporary runtime config, but the feature can also be configured in YAML:

```yaml
scanner:
  checkpoint:
    enabled: false
    path: ""
    resume: false
    flush_every: 10
    keep_completed: false
```

Use checkpoint files as resumable execution state, not as the canonical report. They are secret-minimized and best-effort permission hardened, but should still be handled as assessment artifacts.

## Safe template configuration

```yaml
scanner:
  active_checks:
    templates:
      enabled: false
      include_builtin: true
      directory: ""
      files: []
      max_templates: 10
      max_requests: 10
      max_body_bytes: 131072
```

`safe-active` overrides `enabled` to true with the 10/10 limits above. `full-authorized` raises the limits to 25/25. `passive` forces the engine off.

Custom template paths can be absolute or relative to the user YAML file. Invalid templates are rejected rather than interpreted permissively.

See [`docs/advanced-workflows.md`](docs/advanced-workflows.md) for a custom template example and recommended HAR/checkpoint CI patterns.

## Reports

Each scan writes:

- `scan_report.json` for automation and further processing;
- `scan_report.html` for review in a browser.

Convert a JSON report to SARIF:

```bash
web-vuln-sarif reports/scan_report.json \
  --output reports/scan_report.sarif
```

Compare two JSON reports using a stable cross-scan issue identity:

```bash
web-vuln-diff reports/baseline/scan_report.json \
  reports/current/scan_report.json
```

Gate only on newly introduced high/critical findings:

```bash
web-vuln-diff reports/baseline/scan_report.json \
  reports/current/scan_report.json \
  --fail-on-new \
  --min-severity high
```

`--fail-on-regression` also fails when an existing issue moves to a stronger severity or verification state.

The reporter redacts common credential forms before persistence. CI also scans smoke-test artifacts for known secret sentinels. Reports, screenshots, traces, replay files, checkpoint files, and browser state can still contain sensitive application/assessment data, so handle the output and state directories accordingly.

## CI exit gates

Normal scanner exit codes are:

- `0`: completed with no reportable findings;
- `1`: completed with findings;
- `2`: configuration or runtime failure;
- `3`: partial or aborted run.

For CI, the installed wrapper can fail only when findings meet a chosen floor:

```bash
web-vuln-scanner scan https://target.example \
  --profile safe-active \
  --fail-on-severity high \
  --fail-on-verification verified
```

Runtime failures and partial scans are never converted into success by these gates. `web-vuln-diff` has separate baseline-oriented gates for new or regressed issues.

## Configuration

The default config is `config/default_config.yaml`. Active web probes, safe templates, HAR discovery seeding, attack policy, checkpoint behavior, auth actors, and scope are all visible there. `web-vuln-scanner validate-config` validates release-critical types and bounds before the scan starts.

Profiles override active `enabled` flags and request budgets as needed. XML internal-entity probing remains off in every built-in profile and requires explicit configuration because XML POST/PUT/PATCH routes may change application state.

## Docker

```bash
docker build -t web-vuln-scanner .
docker run --rm web-vuln-scanner --help
```

The image runs as Playwright's non-root `pwuser`. CI builds the image, checks that `/app` is writable by the runtime user, and runs a local passive scan inside the container.

## Development checks

```bash
python -m pytest -q
ruff check . --select E9,F63,F7,F82
python -m compileall -q core layers plugins policies workflows smoke main_v2.py
python -m pip_audit -r requirements.txt
python -m build
```

The CI workflow also tests Python 3.10, 3.11, and 3.12, installs the built wheel in a clean virtual environment, verifies the packaged safe-template YAML files from that wheel, exercises `web-vuln-diff` and sanitized HAR import, runs the local browser/auth/workflow smoke target, checks smoke artifacts for test secrets, converts the report to SARIF, and exercises the Docker runtime.

## Adding a check

Before promoting a new check to stable, add both positive and negative fixtures. A stable check should have a bounded request count, clear verification semantics, a useful remediation, and a reason it will not report ordinary reflection or response noise as a vulnerability.

For declarative exposure checks, prefer the safe-template schema when GET/HEAD plus deterministic response matchers are sufficient. Do not extend the release engine with raw HTTP, shell execution, arbitrary DSL/eval, or external callback behavior.

Keep destructive techniques, broad exploitation, and external callback behavior out of the default release profiles.

Security issues in the scanner itself should be reported according to `SECURITY.md`.
