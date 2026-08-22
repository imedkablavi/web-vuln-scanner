# Web Vulnerability Scanner

A Python CLI for scoped web application security testing. It can crawl a target, inspect common security controls, run a small set of bounded active checks, compare authenticated users, and export findings as JSON, HTML, or SARIF.

The default profile is passive. Active payloads are not sent unless an active profile is selected.

> This project is alpha software. Use it only on systems you own or are authorized to test, and review findings before treating them as confirmed vulnerabilities.

## What it checks

The scanner currently covers four areas:

- discovery: HTTP crawling, optional Playwright crawling, OpenAPI/Swagger, GraphQL, DNS and TLS inventory;
- passive web checks: security headers, cookie flags, CORS, redirects, verbose server errors, and observed data exposure;
- bounded active checks: SQL injection, reflected markup injection, open redirect, server-side template injection, CRLF/response-header injection, and TRACE reflection;
- authorization testing: actor-aware object access checks, RBAC policy verification, authenticated crawling, replay, and workflow scenarios.

Experimental LFI/path traversal and command-injection code is kept disabled by the release maturity policy.

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

The installed command is `web-vuln-scanner`.

```bash
web-vuln-scanner --help
```

A normal passive scan:

```bash
web-vuln-scanner scan https://target.example --profile passive
```

The old short form still works:

```bash
web-vuln-scanner https://target.example
```

Useful CLI commands:

```bash
web-vuln-scanner checks
web-vuln-scanner profiles
web-vuln-scanner doctor
web-vuln-scanner version
```

`checks` lists the available checks with their maturity, activity level, CWE, and WSTG mapping. `doctor` verifies the installed runtime and packaged configuration before a scan.

## Profiles

### passive

```bash
web-vuln-scanner scan https://target.example --profile passive
```

This is the default. It crawls and inventories the application, then runs passive posture checks. It does not send SQLi, XSS, redirect, SSTI, CRLF, or other active payloads.

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
- TRACE reflection.

The scanner does not use time-based SQLi payloads in release profiles.

### full-authorized

```bash
web-vuln-scanner scan https://target.example \
  --profile full-authorized \
  --config config/default_config.yaml
```

This profile keeps the stable active checks and also enables browser-assisted discovery. Auth actors, RBAC verification, and workflows are available when they are configured.

Generic browser form submission and broad button clicking are still off by default. Browser login flows are separate and must be configured with explicit selectors.

## Active check behavior

The active checks are intentionally narrow.

### SQL injection

Uses bounded error and response-differential probes. Boolean checks compare responses against the same baseline. A generic response change is not reported as verified SQL injection.

### Reflected markup / XSS candidate

The scanner injects an inert `<wvs-probe>` element and parses the returned HTML. It reports only when that element is reconstructed as markup. It does **not** claim JavaScript execution unless a future browser verifier proves it.

### Open redirect

Tests common redirect parameters with a destination under `wvs.invalid`. Redirects are not followed. A finding requires the response `Location` to resolve to the exact reserved canary destination.

### Server-side template injection

Tests observed query parameters with arithmetic expressions. A finding requires two distinct expressions to produce their two expected evaluated values. The check does not use file reads, command execution, external callbacks, or timing primitives.

### CRLF / response-header injection

Places a CR/LF canary in one observed query parameter and checks whether the server creates the dedicated canary response header. It does not send cache-poisoning or second-response payloads.

### TRACE

Sends a TRACE request with a unique header and reports when the server reflects that header in a successful TRACE response.

These checks correspond to OWASP WSTG areas including reflected XSS (`WSTG-INPV-01`), HTTP response splitting (`WSTG-INPV-15`), SSTI (`WSTG-INPV-18`), HTTP methods (`WSTG-CONF-06`), and SQL injection (`WSTG-INPV-05`). Coverage is not a claim of complete WSTG or OWASP Top 10 testing.

## Scope controls

The target host is added to the runtime scope automatically. Extra authorized hosts can be added in YAML:

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

## Auth and RBAC testing

Auth actors are defined in the config and should get credentials from environment variables. Sessions are isolated per actor and worker thread so one actor's Set-Cookie state is not reused by another actor.

The scanner can compare two authenticated users, evaluate a configured RBAC matrix, run authenticated crawls, and replay verified authorization findings. Access-control findings are downgraded when the required actor state or comparison evidence is missing.

The sample actors in `config/default_config.yaml` are placeholders. Replace their URLs/selectors and set environment variables only for authorized test accounts.

## API discovery

OpenAPI/Swagger and GraphQL endpoints can be supplied directly:

```bash
web-vuln-scanner scan https://target.example \
  --profile full-authorized \
  --swagger https://target.example/openapi.json \
  --graphql https://target.example/graphql
```

API requests pass through the same request manager and scope policy as crawler traffic.

## Reports

Each scan writes:

- `scan_report.json` for automation and further processing;
- `scan_report.html` for review in a browser.

Convert a JSON report to SARIF:

```bash
web-vuln-sarif reports/scan_report.json \
  --output reports/scan_report.sarif
```

The reporter redacts common credential forms before persistence. CI also scans smoke-test artifacts for known secret sentinels. Reports, screenshots, traces, replay files, and browser state can still contain sensitive application data, so handle the output directory as assessment evidence.

## CI exit gates

Normal exit codes are:

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

Runtime failures and partial scans are never converted into success by these gates.

## Configuration

The default config is `config/default_config.yaml`. Active web probes are visible under:

```yaml
scanner:
  active_checks:
    web:
      enabled: false
      max_urls: 10
      ssti: true
      crlf: true
      trace: true
```

Profiles override `enabled` as needed. `safe-active` uses 10 URLs; `full-authorized` uses 20 unless the config is changed.

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

The CI workflow also tests Python 3.10, 3.11, and 3.12, installs the built wheel in a clean virtual environment, runs the local browser/auth/workflow smoke target, checks smoke artifacts for test secrets, converts the report to SARIF, and exercises the Docker runtime.

## Adding a check

Before promoting a new check to stable, add both positive and negative fixtures. A stable check should have a bounded request count, clear verification semantics, a useful remediation, and a reason it will not report ordinary reflection or response noise as a vulnerability.

Keep destructive techniques, broad exploitation, and external callback behavior out of the default release profiles.

Security issues in the scanner itself should be reported according to `SECURITY.md`.
