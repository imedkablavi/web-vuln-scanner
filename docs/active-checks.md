# Active vulnerability checks

Web Vulnerability Scanner is intended for authorized targets only. Active checks use the shared request manager, scope enforcement, request budgets, per-host concurrency limits, and report redaction.

## Current support

| Plugin | Maturity | What it verifies | Default |
| --- | --- | --- | --- |
| `sqli` | stable | New SQL error signatures plus bounded boolean response differentials | enabled |
| `business_logic` | stable | Actor-aware access-control / IDOR scenarios when authentication is configured | enabled |
| `xss_reflected` | experimental | Unescaped attacker-controlled markup parsed as an HTML element; no JavaScript execution | disabled |
| `lfi` | experimental | Known OS-file signatures appearing only after bounded traversal probes | disabled |
| `open_redirect` | experimental | Exact external `Location` header to a `.invalid` marker; redirect is not followed | disabled |
| `cmd_injection` | experimental | Unique non-destructive `echo` marker appearing after a bounded shell-separator probe | disabled |

The experimental checks have local positive and negative regression fixtures, but they are intentionally not promoted to stable yet. More corpus diversity and real-world false-positive data are required before promotion.

## Explicit opt-in

Experimental plugins require all of the following:

1. an explicit scope through `scanner.scope.include_domains` or `scanner.scope.allowlist`;
2. `scanner.allow_experimental_plugins: true`;
3. the individual plugin's `enabled: true` flag.

Command-injection probing has a second gate: `allow_command_probe: true`.

Example:

```yaml
scanner:
  scope:
    include_domains:
      - app.example.test
  allow_experimental_plugins: true
  plugins:
    xss_reflected:
      enabled: true
      request_budget: 3
      timeout_seconds: 8
    lfi:
      enabled: true
      request_budget: 4
      timeout_seconds: 8
    open_redirect:
      enabled: true
      request_budget: 2
      timeout_seconds: 8
    cmd_injection:
      enabled: false
      allow_command_probe: false
```

Do not enable command probing unless the authorization explicitly permits active command-injection testing.

## Evidence model

### SQL injection

The scanner rejects database-error text that was already present in the baseline. Error-based findings require a new database-specific error after the probe. Boolean verification compares paired true/false responses against the same baseline. Time-based SQL injection is not enabled by default.

### Reflected XSS

The scanner injects a non-executable custom HTML element with a random marker. It reports a candidate only when the response is HTML and the marker is parsed structurally as that element. HTML-escaped reflection does not trigger. This proves an HTML injection sink, not JavaScript execution, so the plugin remains experimental.

### Path traversal / LFI

A 200 response or content-length change is not enough. The candidate must contain a known Unix/Windows file signature that was absent from the baseline. Reports retain the signature name rather than copying the discovered file contents.

### Open redirect

The scanner supplies a unique `https://redirect.invalid/...` target and verifies only the returned 30x `Location` header. It does not follow the external redirect.

### Command injection

The scanner uses a unique `echo` marker only. It does not write files, create persistence, make outbound callbacks, or execute destructive commands. The feature remains double-opt-in and experimental.

## CI policy

All regression targets for these checks live in `tests/local_corpus.py` and bind to localhost. Each active detector has a deliberately vulnerable fixture and a safe twin used for false-positive regression testing. Public or third-party targets must not be added to CI.
