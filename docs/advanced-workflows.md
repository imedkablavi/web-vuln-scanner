# Advanced workflows

This guide covers the scanner features intended for repeatable engineering and CI use. These workflows do not expand authorization: every live request still follows the scanner scope policy.

## 1. Compare a scan with a baseline

`web-vuln-diff` compares two JSON reports using a stable issue identity that ignores volatile evidence and timestamps.

```bash
web-vuln-diff previous/scan_report.json current/scan_report.json
```

Machine-readable output:

```bash
web-vuln-diff previous/scan_report.json current/scan_report.json --json
```

Fail CI only when a new high-or-critical finding appears:

```bash
web-vuln-diff previous/scan_report.json current/scan_report.json \
  --fail-on-new \
  --min-severity high
```

Fail when an existing finding becomes more severe or moves to a stronger verification state:

```bash
web-vuln-diff previous/scan_report.json current/scan_report.json \
  --fail-on-regression
```

A report can contain changed evidence without being classified as a changed issue. The comparison intentionally focuses on issue identity, severity, and verification state.

## 2. Import a HAR without persisting credentials

`web-vuln-har` converts a browser, proxy, or test-run HAR into a sanitized surface inventory. The importer does **not** replay any request.

```bash
web-vuln-har session.har \
  --target https://app.example.com \
  --output surfaces.json
```

For an explicitly authorized private or loopback target:

```bash
web-vuln-har local.har \
  --target http://127.0.0.1:8080 \
  --allow-private \
  --output surfaces.json
```

The generated inventory keeps:

- method and base URL
- query parameter names
- form or top-level JSON field names
- selected non-secret header names
- content type

It intentionally discards:

- query parameter values
- form and JSON values
- Authorization and Proxy-Authorization values
- Cookie and Set-Cookie values
- API key and auth-token header values

Treat the original HAR as sensitive even though the generated inventory is sanitized.

## 3. Use a HAR as live discovery seed

A HAR can also seed a normal scan directly:

```bash
web-vuln-scanner scan https://app.example.com \
  --profile passive \
  --har-seed artifacts/session.har
```

This is not request replay. The live scanner parses the HAR locally, rejects out-of-scope entries, strips captured values, and promotes only same-scope `GET`/`HEAD` URLs into fresh discovery visits. Captured `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS` entries remain inventory-only and are never dispatched simply because they were present in the HAR.

The equivalent YAML configuration is:

```yaml
scanner:
  crawler:
    har_seed:
      enabled: true
      files:
        - artifacts/session.har
      max_entries: 5000
      active_tests: false
```

`active_tests` is intentionally false by default. If an authorized assessment explicitly enables it, only sanitized GET parameter shapes can become active surfaces; captured values still do not enter plugin requests.

Relative HAR paths are resolved relative to the user YAML file before the temporary runtime config is created.

## 4. Resume an interrupted active scan

Long active assessments can persist a minimal progress ledger:

```bash
web-vuln-scanner scan https://staging.example.com \
  --profile safe-active \
  --checkpoint .scanner-state/staging.json
```

Resume a partial/interrupted run:

```bash
web-vuln-scanner scan https://staging.example.com \
  --profile safe-active \
  --resume .scanner-state/staging.json
```

Checkpoint rules:

- a testcase is recorded only after request + verification complete successfully;
- interrupted or failed testcases remain eligible for retry;
- completed testcase fingerprints are skipped on resume;
- prior redacted findings are restored so the final report remains complete;
- cookies, Authorization headers, response bodies, and raw parameter values are not persisted;
- the target, profile, and relevant active-test configuration must match before resume is accepted;
- checkpoint files use restrictive permissions where the platform supports them;
- completed checkpoint files are removed by default to avoid accidental stale reuse.

For deliberate retention:

```yaml
scanner:
  checkpoint:
    enabled: true
    path: .scanner-state/staging.json
    resume: false
    flush_every: 10
    keep_completed: true
```

Do not use retained checkpoints as a substitute for the JSON report; they are an execution ledger, not the canonical assessment artifact.

## 5. Add bounded safe YAML templates

The safe-template engine supports conservative same-origin checks without a general scripting or raw-request language.

Built-in templates are packaged under `config/safe_templates/` and currently cover strong response markers for PHP `phpinfo()`, Apache `server-status`, Nginx `stub_status`, and Go `/debug/vars` expvar exposure.

Active profiles enable the built-ins with explicit budgets. Passive mode keeps them off.

```yaml
scanner:
  active_checks:
    templates:
      enabled: true
      include_builtin: true
      directory: security/templates
      files: []
      max_templates: 10
      max_requests: 10
      max_body_bytes: 131072
```

Custom paths are resolved relative to the user YAML file. The schema intentionally supports only:

- `GET` and `HEAD`;
- one same-origin absolute path such as `/server-status`;
- status matchers;
- body/header word matchers;
- named response-header matchers;
- `any` / `all` and negative matcher conditions.

It intentionally does **not** support raw HTTP, external origins, redirects, DSL/eval, shell commands, callbacks, file reads, template variables, or state-changing HTTP methods.

Minimal example:

```yaml
id: example-debug-page
info:
  name: Example debug page exposed
  severity: medium
  confidence: high
  category: exposure
  remediation: Disable the debug endpoint outside controlled environments.
request:
  method: GET
  path: /debug/status
matchers_condition: all
matchers:
  - type: status
    values: [200]
  - type: word
    part: body
    values: ["Example Debug Console"]
    condition: all
```

A matching template produces a `detected` finding for the declared condition. It does not imply that a larger exploit chain has been demonstrated.

## 6. Static JavaScript endpoint discovery

The HTTP crawler can inspect inline JavaScript and a bounded number of same-scope script files for obvious endpoint strings.

Default configuration:

```yaml
scanner:
  crawler:
    javascript_discovery:
      enabled: true
      max_scripts: 10
      max_script_bytes: 250000
      max_endpoints: 100
```

The extractor recognizes common literal forms such as `fetch()`, `axios.get/post/...`, and `XMLHttpRequest.open()` plus obvious `/api`, `/graphql`, `/rest`, and versioned API route strings.

Safety rules:

- JavaScript is parsed as text; it is not evaluated.
- External scripts must remain in HTTP scope.
- Static assets and template-expression URLs are ignored.
- Inferred non-GET endpoints are inventory only and are not invoked simply because they were found in JavaScript.
- Only discovered GET routes with explicit query parameters are promoted to active scanner surfaces.

This complements browser discovery; it does not replace browser execution for complex SPAs.

## 7. Suppress sensitive parameters from active plugins

The centralized attack policy can prevent V2 plugins from generating active requests against sensitive or state-related fields.

Default configuration includes common authentication and CSRF names:

```yaml
scanner:
  attack_policy:
    skip_parameters:
      - csrf
      - csrf_token
      - _csrf
      - authenticity_token
      - password
      - passwd
      - token
      - access_token
      - refresh_token
      - id_token
    skip_parameter_patterns: []
```

Project-specific example:

```yaml
scanner:
  attack_policy:
    skip_parameters:
      - payment_nonce
      - destructive_confirmation
    skip_parameter_patterns:
      - '^admin_action_'
      - '_secret$'
```

Suppressed V2 test cases are counted in scanner diagnostics. Invalid regular expressions fail configuration validation instead of silently changing behavior.

## 8. Technology and posture inventory

Passive web analysis records conservative technology observations using response headers, cookie **names**, generator metadata, and framework-specific HTML markers. Cookie values and page contents are not copied into the technology inventory.

Additional passive signals include:

- CSP report-only versus enforcement posture
- risky `script-src` sources and missing `form-action` on pages with forms
- high-confidence stack traces for Python, PHP, Java, .NET, Node.js, Ruby, and Go
- explicit user-specific cache policy observations
- TLS certificate validation failures and near-expiry certificates

These observations do not automatically enable unrelated active checks. Technology detection is inventory, not proof of a vulnerable software version.

## 9. Recommended CI pattern

A practical CI flow is:

1. Run a scoped `passive` scan on every deployment candidate.
2. Optionally seed discovery from a sanitized HAR captured by an authorized browser/test job.
3. Run `safe-active` only against a dedicated authorized test environment.
4. Use a checkpoint for long active jobs that may be interrupted by CI time limits.
5. Store `scan_report.json` as a short-retention build artifact.
6. Compare the current report to the approved baseline with `web-vuln-diff`.
7. Gate on new high/critical findings or on stronger verification regressions.
8. Keep `full-authorized` for controlled jobs where browser/auth/workflow actions are explicitly expected.

Example:

```bash
web-vuln-scanner scan https://staging.example.com \
  --profile safe-active \
  --har-seed artifacts/staging.har \
  --checkpoint .scanner-state/staging.json \
  --output reports/current

web-vuln-diff reports/baseline/scan_report.json \
  reports/current/scan_report.json \
  --fail-on-new \
  --fail-on-regression \
  --min-severity high
```

The scanner exit code and the diff exit code serve different purposes: the scanner reports the state of the current assessment, while the diff command reports change relative to a baseline.