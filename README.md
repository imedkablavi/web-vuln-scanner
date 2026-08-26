# Web Vulnerability Scanner

Evidence-first command-line scanner for **authorized** web targets.

It crawls in-scope pages, inspects forms and query parameters, checks common web posture issues, looks for exposed files, inspects Swagger/GraphQL endpoints, records DNS/TLS details, runs bounded SQLi checks, and can verify access-control behavior when authorized actor accounts are configured.

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
- CI across Python 3.10, 3.11, and 3.12.

## Authorization and Safety

Use this project only on systems you own or have explicit permission to test.

The default configuration is intentionally bounded. Experimental plugins remain disabled by the registry and are not enabled automatically by any scan profile. Authentication checks require test credentials supplied through configuration/environment variables.

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

It starts a local mock server, runs a scan, and writes reports to `smoke_out/`.

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

- `passive` - crawler plus passive/posture layers; active plugins disabled.
- `safe-active` - enables stable bounded SQLi and business-logic checks; experimental plugins stay disabled.
- `full-authorized` - browser-capable authorized baseline with stable plugins; credentials/workflows are still explicitly configured by the operator.

## Reports

A scan produces:

- `scan_report.json` - complete machine-readable report.
- `scan_report.html` - human-readable evidence report.

Convert JSON to SARIF 2.1.0:

```bash
web-vuln-sarif reports/scan_report.json --output reports/scan_report.sarif
```

or:

```bash
python -m core.sarif reports/scan_report.json
```

SARIF results preserve severity, confidence, verification status, category, plugin, scanner mode, target URL, and remediation metadata.

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

Experimental code must pass dedicated positive/negative tests and verification-quality review before promotion.

## Exit Codes

- `0` - no reportable findings.
- `1` - findings were produced.
- `2` - runtime or configuration failure.
- `3` - partial or aborted run.

## Tests

```bash
python -m pytest
```

Critical static checks used by CI:

```bash
ruff check . --select E9,F63,F7,F82
python -m compileall -q core layers plugins workflows smoke main_v2.py
```

The smoke harness is also executed in CI, and its JSON report is converted to SARIF to validate the reporting pipeline.

## Container

The Docker image is aligned with Playwright 1.62 and runs the scanner as the non-root `pwuser` supplied by the Playwright image.

```bash
docker build -t web-vuln-scanner .
docker run --rm web-vuln-scanner --help
```

## Contributing

See `CONTRIBUTING.md` before adding scanners or plugins. New checks should be bounded, scope-aware, evidence-driven, false-positive conscious, and tested against local fixtures.
