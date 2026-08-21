# Web Vulnerability Scanner

Evidence-first command-line web security scanner for **explicitly authorized** targets.

The project combines scoped crawling, posture analysis, API discovery, optional browser evidence, bounded active plugins, actor-aware authorization verification, replay/workflow evidence, and JSON/HTML/SARIF reporting. The release defaults are intentionally conservative: a normal CLI invocation starts in the `passive` profile and does not enable payload-based plugins or generic browser form submission.

> **Alpha software:** findings are evidence to review, not a substitute for manual validation or a complete security assessment.

## Safety Model

Use this project only on systems you own or have explicit permission to test.

The scanner now treats safety controls as runtime boundaries rather than documentation-only conventions:

- one centralized HTTP(S) scope policy is shared by discovery and request dispatch;
- redirect targets are scope-checked before following them;
- hostname resolution is checked for private/loopback/link-local/reserved destinations unless private targets are explicitly allowed;
- worker threads use isolated Requests sessions and do not inherit `.netrc` or proxy credentials through `trust_env`;
- Playwright contexts intercept requests before dispatch and block off-scope HTTP(S) traffic;
- Service Workers are blocked in scoped browser contexts so they cannot bypass request interception;
- generic browser clicks and form submissions are disabled unless the operator explicitly opts in;
- sensitive artifacts use restrictive file permissions where the platform supports them;
- experimental plugins remain blocked by the release maturity policy.

See `SECURITY.md` for disclosure and artifact-handling guidance.

## Highlights

- HTTP crawler with centralized scope controls, DNS checks, redirect validation, bounded retries, and per-host concurrency.
- Optional Playwright discovery and authenticated browser flows.
- Web posture checks for headers, cookies, CORS, redirects, and verbose errors.
- Data-exposure inspection; guessed sensitive-path probes are disabled in the default passive profile.
- Swagger/OpenAPI and GraphQL discovery.
- DNS/TLS inventory.
- Stable bounded SQL injection and business-logic/access-control plugins for explicit active profiles.
- Auth-aware actor comparison, deterministic RBAC verification, replay artifacts, and workflow scenarios.
- JSON and HTML reports plus SARIF 2.1.0 conversion.
- Deterministic process exit codes for automation.
- CI across Python 3.10, 3.11, and 3.12, dependency audit, package build/install, local smoke validation, and Docker runtime validation.

## Installation

Python 3.10+ is required.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e .
```

For browser-assisted scanning:

```bash
python -m pip install -e '.[browser]'
playwright install chromium
```

For development and release QA:

```bash
python -m pip install -r requirements.txt
python -m pip install -e '.[dev]'
```

`requirements.txt` contains pinned runtime/browser dependencies. Development QA tools are kept in the `dev` extra so production containers do not carry pytest/audit/build tooling.

## Quick Start: Passive by Default

The safest normal invocation is also the default:

```bash
web-vuln-scanner https://target.example \
  --config config/default_config.yaml \
  --output reports
```

This is equivalent to:

```bash
web-vuln-scanner https://target.example \
  --profile passive \
  --config config/default_config.yaml \
  --output reports
```

The direct Python entry point remains available:

```bash
python main_v2.py scan https://target.example --profile passive
```

`main.py` is only a deprecated compatibility shim. New integrations should use `web-vuln-scanner` or `main_v2.py`.

## Scan Profiles

### `passive` — default

```bash
web-vuln-scanner https://target.example --profile passive
```

- browser disabled;
- SQLi/business-logic payload plugins disabled;
- experimental plugins disabled;
- auth verification/workflows disabled;
- crawler and posture analysis enabled;
- observed data-exposure signals are inspected, but guessed sensitive paths such as `/.env` are not probed by this profile.

### `safe-active`

Use only when bounded active testing is authorized:

```bash
web-vuln-scanner https://target.example --profile safe-active
```

This enables the stable SQLi and business-logic plugins with conservative test limits. Time-based SQL injection probes and experimental plugins remain disabled.

### `full-authorized`

For controlled assessments that require browser discovery, configured actors, API discovery, or workflows:

```bash
web-vuln-scanner https://target.example \
  --profile full-authorized \
  --config config/default_config.yaml
```

The profile enables browser capability and stable active plugins, but **does not automatically submit arbitrary forms or click generic page buttons**.

Profiles can still be materialized to YAML for auditing or reproducible pipelines:

```bash
web-vuln-profile passive \
  --config config/default_config.yaml \
  --output config/passive.generated.yaml
```

## Explicit Browser Interactions

Browser discovery is non-mutating by default. If an authorized test specifically requires generic interactions, opt in deliberately in a dedicated test config:

```yaml
scanner:
  browser:
    interactions:
      enabled: true
      submit_forms: true
      click_selectors:
        - "#known-safe-test-action"
```

Do not use broad selectors such as all buttons on production targets. Prefer purpose-built staging fixtures and explicit selectors whose side effects are understood.

Browser authentication flows are a separate mechanism: their selectors and submit actions are explicitly defined per configured actor/login flow.

## Scope

The CLI automatically adds the target authority to the runtime scope. Additional authorized domains can be declared explicitly:

```yaml
scanner:
  scope:
    include_domains:
      - "app.example.com"
      - "api.example.com"
      - "*.staging.example.com"
    exclude_paths:
      - "/logout"
      - "/signout"
    allow_private: false
    resolve_dns: true
```

Wildcard matching is boundary-aware: `*.example.com` does not match `badexample.com` or `example.com.attacker.test`.

Private/localhost targets are supported for local authorized testing. The CLI explicitly enables private-target access when the requested target itself is a localhost/private IP.

## API Discovery

```bash
web-vuln-scanner https://target.example \
  --profile full-authorized \
  --swagger https://target.example/openapi.json \
  --graphql https://target.example/graphql \
  --output reports
```

API URLs still pass through the same outbound request scope policy.

## Reports

A scan writes:

- `scan_report.json` — machine-readable evidence and scan metadata;
- `scan_report.html` — human-readable evidence report.

Convert JSON to SARIF 2.1.0:

```bash
web-vuln-sarif reports/scan_report.json \
  --output reports/scan_report.sarif
```

SARIF includes severity, confidence, verification status, category, plugin, scanner mode, URL, and remediation metadata without copying the entire raw evidence payload into result properties.

Browser storage state, traces, screenshots, replay artifacts, and reports may contain sensitive information. Protect and delete them according to the assessment's retention policy.

## Plugin Maturity

Metadata lives in `core/plugin_catalog.py` and records maturity, activity type, CWE references, and OWASP Top 10:2025 mappings.

Stable but opt-in active plugins:

- `sqli` — CWE-89 / A05:2025 Injection;
- `business_logic` — access-control/IDOR verification / A01:2025 Broken Access Control.

Experimental and blocked from release execution:

- `xss_reflected`;
- `lfi`;
- `cmd_injection`;
- `open_redirect`.

Experimental code must pass dedicated true-positive/false-positive fixtures and verification-quality review before promotion.

## Exit Codes

The CLI has a deterministic automation contract:

- `0` — completed with no reportable findings;
- `1` — completed and produced findings;
- `2` — configuration/runtime failure;
- `3` — partial or aborted run.

A failed scan cannot fall through to exit code `0` merely because it produced no findings.

## Local Smoke Test

The bundled smoke harness starts only a local mock target and intentionally exercises active/auth/browser/workflow behavior:

```bash
python smoke/run_smoke.py
```

The harness explicitly uses `full-authorized`, validates known vulnerable and known-safe routes, expects truthful partial-run semantics for intentionally broken fixtures, and writes evidence to `smoke_out/`.

## Tests and Release QA

```bash
python -m pytest -q
ruff check . --select E9,F63,F7,F82
python -m compileall -q core layers plugins workflows smoke main_v2.py
python -m pip_audit -r requirements.txt
python -m build
```

CI additionally:

- tests Python 3.10/3.11/3.12 with coverage output;
- validates installed CLI entry points;
- audits pinned runtime dependencies;
- builds a wheel and installs it in a clean virtual environment;
- installs Chromium and runs the authorized local smoke harness;
- converts smoke JSON to SARIF and uploads short-lived smoke evidence;
- builds the Docker image and verifies the runtime user is non-root and `/app` is writable.

## Docker

The image is aligned with Playwright 1.62 and runs as the non-root `pwuser` from the official Playwright image.

```bash
docker build -t web-vuln-scanner .
docker run --rm web-vuln-scanner --help
```

Runtime report/log directories are writable by the non-root user. `.dockerignore` excludes repository metadata, local secrets, caches, reports, and development output from the build context.

## Responsible Development

See `CONTRIBUTING.md` before adding scanners or plugins. New checks should be:

- scope-aware through the centralized request layer;
- bounded in requests/time/findings;
- non-destructive by default;
- explicit about authentication context;
- evidence-driven and false-positive conscious;
- covered by local positive and negative fixtures;
- disabled until verification quality is sufficient for its stated maturity.

Security issues in the scanner itself should follow `SECURITY.md` rather than being disclosed with exploit details in a public issue.
