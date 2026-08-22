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

## 3. Static JavaScript endpoint discovery

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

## 4. Suppress sensitive parameters from active plugins

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

## 5. Technology and posture inventory

Passive web analysis now records conservative technology observations using response headers, cookie **names**, generator metadata, and framework-specific HTML markers. Cookie values and page contents are not copied into the technology inventory.

Additional passive signals include:

- CSP report-only versus enforcement posture
- risky `script-src` sources and missing `form-action` on pages with forms
- high-confidence stack traces for Python, PHP, Java, .NET, Node.js, Ruby, and Go
- explicit user-specific cache policy observations
- TLS certificate validation failures and near-expiry certificates

These observations do not automatically enable unrelated active checks. Technology detection is inventory, not proof of a vulnerable software version.

## 6. Recommended CI pattern

A practical CI flow is:

1. Run a scoped `passive` scan on every deployment candidate.
2. Run `safe-active` only against a dedicated authorized test environment.
3. Store `scan_report.json` as a short-retention build artifact.
4. Compare the current report to the approved baseline with `web-vuln-diff`.
5. Gate on new high/critical findings or on stronger verification regressions.
6. Keep `full-authorized` for controlled jobs where browser/auth/workflow actions are explicitly expected.

Example:

```bash
web-vuln-scanner scan https://staging.example.com \
  --profile safe-active \
  --output reports/current

web-vuln-diff reports/baseline/scan_report.json \
  reports/current/scan_report.json \
  --fail-on-new \
  --fail-on-regression \
  --min-severity high
```

The scanner exit code and the diff exit code serve different purposes: the scanner reports the state of the current assessment, while the diff command reports change relative to a baseline.
