# Web Vulnerability Scanner

Evidence-first command-line scanner for **authorized** web targets.

It crawls in-scope pages, inspects forms and query parameters, checks common web posture issues, looks for exposed files, inspects Swagger/GraphQL endpoints, records DNS/TLS details, runs bounded SQLi checks, and can verify access-control behavior when authorized actor accounts are configured.

> **Authorized security testing only.** Do not run this project against systems you do not own or have explicit permission to assess.

## Highlights

- HTTP crawler with strict scope controls and bounded concurrency.
- Optional Playwright-assisted discovery and authenticated browser flows.
- Passive web posture checks: security headers, cookies, CORS, redirects, and verbose errors.
- Bounded exposure checks for common backup/debug/config paths.
- Swagger/OpenAPI and GraphQL discovery.
- DNS and TLS inventory.
- Active SQLi and business-logic/access-control checks.
- Auth-aware actor comparison, RBAC verification, replay artifacts, and workflow scenarios.
- JSON and HTML reports, plus SARIF 2.1.0 conversion for security tooling.
- Conservative scan profiles for passive and authorized testing modes.
- Local intentionally-vulnerable regression corpus used by CI.
- Plugin request-budget, timeout, evidence and scope-enforcement quality gates.
- Python packaging and Docker release QA.
- CI across Python 3.10, 3.11, and 3.12.

## Safety Model

The scanner is intentionally bounded:

- outbound plugin traffic goes through the shared request manager and its scope/SSRF controls;
- private/loopback targets require explicit permission in configuration;
- per-host concurrency and retry behavior are bounded;
- plugins receive a per-surface request budget and request timeout;
- experimental plugins remain blocked even when configuration attempts to enable them;
- public CI does not scan third-party vulnerability targets; all security regression targets are local/synthetic;
- no mass-exploitation mode or unsafe default is part of the supported design.

See [`SECURITY.md`](SECURITY.md) and [`docs/security-qa.md`](docs/security-qa.md) for the security contract and promotion gates.

## Installation

Create a virtual environment:

```bash
python -m venv .venv
```

Windows:

```bash
.\.venv\Scripts\activate
```

macOS / Linux:

```bash
source .venv/bin/activate
```

Install the project for normal HTTP scanning:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

For development:

```bash
python -m pip install -e .[dev]
```

For browser-assisted scanning:

```bash
python -m pip install -e .[browser]
playwright install chromium
```

The legacy `requirements.txt` workflow remains available for compatibility.

## Quick Local Check

The bundled mock target exercises the scanner without contacting a third-party system:

```bash
python smoke/run_smoke.py
```

It starts a server bound to loopback, runs a scan, and writes reports to `smoke_out/`.

The regression corpus contract is documented in [`tests/corpus/manifest.yaml`](tests/corpus/manifest.yaml). It includes known-positive and known-negative cases so CI can catch both false negatives and false positives.

## Run a Scan

Installed CLI:

```bash
web-vuln-scanner https://target.tld --config config/default_config.yaml --output reports
```

Direct Python entry point:

```bash
python main_v2.py scan https://target.tld --config config/default_config.yaml --output reports
```

With API discovery:

```bash
web-vuln-scanner https://target.tld \
  --config config/default_config.yaml \
  --swagger https://target.tld/openapi.json \
  --graphql https://target.tld/graphql \
  --output reports
```

`main.py` is retained only as a deprecated compatibility shim. New integrations should use `web-vuln-scanner` or `main_v2.py`.

## Scan Profiles

Profiles are materialized into a normal YAML configuration, so the scanner keeps one configuration contract and profiles remain easy to audit.

Passive posture assessment:

```bash
web-vuln-profile passive --config config/default_config.yaml --output config/passive.generated.yaml
web-vuln-scanner https://target.tld --config config/passive.generated.yaml --output reports
```

Bounded active assessment:

```bash
web-vuln-profile safe-active --config config/default_config.yaml --output config/safe-active.generated.yaml
```

Authorized browser-capable baseline:

```bash
web-vuln-profile full-authorized --config config/default_config.yaml --output config/full-authorized.generated.yaml
```

Available profiles:

- `passive` — crawler plus passive/posture layers; active plugins disabled.
- `safe-active` — enables stable bounded SQLi and business-logic checks; experimental plugins stay disabled.
- `full-authorized` — browser-capable authorized baseline with stable plugins; credentials/workflows are still explicitly configured by the operator.

## Authenticated Testing

Authorized actor credentials are supplied through environment variables or explicitly configured session material. The local corpus covers cookie-authenticated and unauthenticated behavior so session isolation and scope behavior can regress safely in CI.

Do not commit real credentials, session cookies, bearer tokens or browser storage state. Reports and logs use redaction helpers, but operators should still treat generated reports as sensitive assessment artifacts.

## Reports

A scan produces:

- `scan_report.json` — complete machine-readable report.
- `scan_report.html` — human-readable evidence report.

Convert JSON to SARIF 2.1.0:

```bash
web-vuln-sarif reports/scan_report.json --output reports/scan_report.sarif
```

or:

```bash
python -m core.sarif reports/scan_report.json
```

SARIF results preserve severity, confidence, verification status, category, plugin, scanner mode, target URL, and remediation metadata.

### Example report

A sanitized local example is committed at [`docs/example-report.json`](docs/example-report.json). It contains only synthetic loopback data and demonstrates redacted evidence.

Example summary:

```text
Target: http://127.0.0.1:8123 (local-test)
Findings: 2
- HIGH / detected / sqli
- HIGH / detected / data_exposure
Secrets in evidence: ***redacted***
```

For a current HTML example, run `python smoke/run_smoke.py` and open `smoke_out/scan_report.html`. Review any screenshot for secrets before committing or using it as a social preview.

## Plugin Maturity

Plugin metadata lives in `core/plugin_catalog.py` and records maturity, activity type, CWE references, and OWASP mappings.

Stable plugins:

- `sqli`
- `business_logic`

Experimental plugins currently blocked by the registry:

- `xss_reflected`
- `lfi`
- `cmd_injection`
- `open_redirect`

Experimental code is **not** promoted because it merely exists or can find one positive sample. Promotion requires dedicated local positive/negative fixtures, false-positive review, scope and budget tests, structured evidence assertions and repeatable CI results. See [`docs/security-qa.md`](docs/security-qa.md).

## Plugin Contract

Active plugins must:

- use the scanner runtime rather than independent HTTP clients;
- stay tied to the originating attack surface;
- obey `request_budget` and `timeout_seconds` limits;
- return structured evidence and bounded reproduction metadata;
- never report a positive result without evidence;
- never expand target scope on their own.

The scanner records request counts, budget, timeout and contract violations in run statistics for QA.

## Exit Codes

- `0` — no reportable findings.
- `1` — findings were produced.
- `2` — runtime or configuration failure.
- `3` — partial or aborted run.

## Tests

Baseline checks:

```bash
python -m pytest -q
ruff check . --select E9,F63,F7,F82
python -m compileall -q core layers plugins workflows smoke main_v2.py
```

Security-tool regression gates:

```bash
python -m pytest -q tests/test_security_tool_regressions.py
python smoke/run_smoke.py
```

These gates exercise local FP/FN cases, cookie sessions, scope blocking, plugin budgets/timeouts, evidence requirements, report redaction, concurrency and rate-limit handling.

## Packaging and Release QA

Build and validate Python distributions locally:

```bash
python -m pip install -e .[dev]
python -m build
python -m twine check dist/*
```

The release QA workflow also performs a clean wheel-install smoke test. Publishing to PyPI is intentionally separate from validation so a pull request cannot publish packages.

Docker:

```bash
docker build -t web-vuln-scanner .
docker run --rm web-vuln-scanner --help
```

The Docker image is aligned with Playwright 1.62 and runs the scanner as the non-root `pwuser` supplied by the Playwright image.

## Repository Metadata

The repository includes an MIT license and package metadata. Recommended GitHub description, topics and social-preview guidance are documented in [`docs/repository-metadata.md`](docs/repository-metadata.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before adding scanners or plugins. New checks should be bounded, scope-aware, evidence-driven, false-positive conscious, and tested against local fixtures.
