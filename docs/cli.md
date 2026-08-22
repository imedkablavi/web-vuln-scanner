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
--har-seed PATH                 seed discovery from a sanitized HAR view
--checkpoint PATH               save resumable active-test progress
--resume PATH                   resume an interrupted/partial checkpoint
--debug                         scanner counters and diagnostics
--fail-on-severity LEVEL        CI finding threshold
--fail-on-verification STATUS   CI verification threshold
```

`--checkpoint` and `--resume` are mutually exclusive. Checkpoints contain completed-test fingerprints and redacted findings; they do not persist cookies, Authorization headers, response bodies, or raw parameter values. A checkpoint is accepted for resume only when its target, profile, and relevant scanner configuration match the current run.

`--har-seed` adds an existing browser/proxy HAR as discovery input. The scanner does not replay captured HAR requests. Only same-scope GET/HEAD URLs become live discovery seeds, and captured credential/value material is discarded. HAR-derived active parameter surfaces remain disabled unless `scanner.crawler.har_seed.active_tests` is explicitly enabled in YAML.

Use `web-vuln-scanner scan --help` for the same information from the installed command.

## Resume a long active scan

Start a scan with a checkpoint ledger:

```bash
web-vuln-scanner scan https://staging.example \
  --profile safe-active \
  --checkpoint .scanner-state/staging.json
```

If the run is interrupted or ends partial, resume it with:

```bash
web-vuln-scanner scan https://staging.example \
  --profile safe-active \
  --resume .scanner-state/staging.json
```

A testcase is marked complete only after its request and verification step finish successfully. Failed/interrupted testcases remain eligible for retry. Completed checkpoints are removed by default so stale state is not reused accidentally; set `scanner.checkpoint.keep_completed: true` only when there is a specific evidence-retention need.

## Seed discovery from a HAR

```bash
web-vuln-scanner scan https://staging.example \
  --profile passive \
  --har-seed artifacts/session.har
```

The original HAR should still be treated as sensitive. The live scanner reads it locally, strips captured values, rejects out-of-scope entries, and does not dispatch the original non-GET requests.

For a standalone sanitized inventory instead of a scan seed, use:

```bash
web-vuln-har artifacts/session.har \
  --target https://staging.example \
  --output artifacts/surfaces.json
```

## Inspect available checks

Human-readable table:

```bash
web-vuln-scanner checks
```

Machine-readable output:

```bash
web-vuln-scanner checks --json
```

Each entry includes maturity, activity mode, CWE references, WSTG references, and a short implementation note. Safe-template checks are a separate bounded engine controlled by `scanner.active_checks.templates`; they use packaged or explicitly configured YAML files and are enabled by active profiles only.

## Inspect profiles

```bash
web-vuln-scanner profiles
web-vuln-scanner profiles --json
```

`passive` sends no active vulnerability payloads. `safe-active` enables bounded stable checks and safe GET/HEAD templates. `full-authorized` adds browser capability and can use configured auth/workflow features.

## Validate configuration

Validate the packaged default:

```bash
web-vuln-scanner validate-config
```

Validate a project config without starting a scan:

```bash
web-vuln-scanner validate-config config/assessment.yaml
```

Invalid types or release-critical values return exit code `2`. Compatibility warnings are printed separately. Relative HAR/template/workflow paths in a user config are resolved relative to that YAML file before the temporary runtime configuration is created.

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