# Web Vulnerability Scanner

Command-line scanner for authorized web targets.

It can crawl pages, inspect forms and query parameters, check common web posture issues, look for exposed files, inspect Swagger/GraphQL endpoints, record DNS/TLS details, run SQLi checks, and verify some access-control cases when actor accounts are configured.

## What It Does

- Crawls in-scope pages and forms over HTTP.
- Optionally uses Playwright for browser-assisted discovery and login flows.
- Checks web posture issues such as missing headers, weak cookies, permissive CORS, redirects, and verbose errors.
- Probes a small set of common backup/debug/config file paths.
- Reads Swagger/OpenAPI and GraphQL exposure when available.
- Records DNS and TLS inventory.
- Runs active SQLi checks.
- Supports auth-aware verification, replay artifacts, and workflow-based checks.

## Before You Start

- Use it only on systems you own or are allowed to test.
- For browser-assisted crawl and browser login, install Playwright and Chromium.
- Access-control verification needs valid actor credentials in the config or environment.

## Setup

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

Install Python dependencies:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

If you want browser-assisted crawling or browser login:

```bash
pip install playwright
playwright install chromium
```

## Quick Local Check

The easiest way to try the project is the bundled mock target:

```bash
python smoke/run_smoke.py
```

This command:

- starts the local mock server
- runs a full scan against it
- writes output into `smoke_out/`

After it finishes, open:

- `smoke_out/scan_report.html`
- `smoke_out/scan_report.json`

## Run a Scan

Basic scan:

```bash
python main_v2.py scan https://target.tld --config config/default_config.yaml --output reports
```

With extra API endpoints:

```bash
python main_v2.py scan https://target.tld --config config/default_config.yaml --swagger https://target.tld/openapi.json --graphql https://target.tld/graphql --output reports
```

With debug logging:

```bash
python main_v2.py scan https://target.tld --config config/default_config.yaml --output reports --debug
```

## Output

Each run writes two files in the output directory:

- `scan_report.json`
- `scan_report.html`

The JSON report keeps the full data.
The HTML report is easier to review quickly in a browser.

## Exit Codes

- `0` no reportable findings
- `1` findings were produced
- `2` runtime or configuration failure
- `3` partial or aborted run

## Tests

Run the Python test suite:

```bash
python -m pytest
```

## Notes

- Browser-assisted discovery helps coverage, but it is not a full browser spider.
- Complex auth flows like MFA, SSO, or captcha are not handled.
- Experimental plugins are disabled by default:
  - `xss_reflected`
  - `lfi`
  - `cmd_injection`
  - `open_redirect`
