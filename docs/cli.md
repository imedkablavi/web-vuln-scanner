# CLI reference

## Scan

```bash
web-vuln-scanner scan https://target.example --profile passive
```

The original form remains valid:

```bash
web-vuln-scanner https://target.example
```

Common options:

```text
--profile NAME                  passive, safe-active, full-authorized
--config PATH                   scanner YAML
--swagger URL                   OpenAPI/Swagger JSON endpoint
--graphql URL                   GraphQL endpoint
--output DIR                    report directory
--debug                         scanner counters and diagnostics
--fail-on-severity LEVEL        CI finding threshold
--fail-on-verification STATUS   CI verification threshold
```

Use `web-vuln-scanner scan --help` for the same information from the installed command.

## Inspect available checks

Human-readable table:

```bash
web-vuln-scanner checks
```

Machine-readable output:

```bash
web-vuln-scanner checks --json
```

Each entry includes maturity, activity mode, CWE references, WSTG references, and a short implementation note.

## Inspect profiles

```bash
web-vuln-scanner profiles
web-vuln-scanner profiles --json
```

`passive` sends no active vulnerability payloads. `safe-active` enables bounded stable checks. `full-authorized` adds browser capability and can use configured auth/workflow features.

## Validate configuration

Validate the packaged default:

```bash
web-vuln-scanner validate-config
```

Validate a project config without starting a scan:

```bash
web-vuln-scanner validate-config config/assessment.yaml
```

Invalid types or release-critical values return exit code `2`. Compatibility warnings are printed separately.

## Runtime diagnostics

```bash
web-vuln-scanner doctor
```

`doctor` checks the packaged config and required Python modules. Playwright is shown as optional because passive and safe-active scans do not require browser support.

## Version

```bash
web-vuln-scanner version
```

## CI gates

A normal completed scan returns `1` when findings exist. CI can narrow that behavior without hiding runtime failures:

```bash
web-vuln-scanner scan https://target.example \
  --profile safe-active \
  --fail-on-severity high \
  --fail-on-verification verified
```

The gate changes only the finding exit decision. Configuration/runtime failures still return `2`, and partial/aborted scans still return `3`.
