# Security Tool Audit — 2026-08-24

## Scope

Repository: `imedkablavi/web-vuln-scanner`

Audit goal: harden the project as a professional, evidence-first scanner for authorized targets without adding mass exploitation, destructive behavior or unsafe defaults.

Public CI is constrained to local/synthetic targets.

## Executive assessment

The repository already had several strong foundations before this pass:

- a centralized `RequestManager` with scope checks, private-IP guarding, retries and per-host concurrency;
- a substantial local mock application with intentionally vulnerable and intentionally safe behavior;
- auth/session/RBAC support;
- JSON/HTML reporting plus SARIF conversion;
- registry blocking for experimental XSS/LFI/command-injection/open-redirect plugins;
- a non-root Playwright Docker image;
- basic Python CI.

The largest product-quality gaps were not missing scanner features. They were missing regression gates and enforceable contracts around existing behavior.

## Findings and remediations

### 1. Local vulnerable corpus existed but was not a formal FP/FN contract

**Risk:** a detector could regress silently, or a safe case could begin producing false positives while smoke output still looked plausible.

**Remediation:** added `tests/corpus/manifest.yaml` and `tests/test_security_tool_regressions.py` with known-positive and known-negative assertions. Added a dedicated `Security Regression` workflow that runs only local/synthetic targets.

### 2. Plugin API described a v2 shape but did not enforce budget/evidence/runtime rules centrally

**Risk:** a plugin could produce malformed evidence, exceed intended requests or bypass the expected runtime conventions.

**Remediation:** added:

- `PluginContractError`;
- per-surface `request_budget`;
- per-request `timeout_seconds` capped by scanner timeout;
- testcase origin/input-kind validation;
- verification status/confidence validation;
- mandatory structured evidence and reproduction metadata for reportable results;
- `core/plugin_runtime.py`, which routes active-plugin HTTP traffic through `RequestManager.send` so scope/SSRF, concurrency, retry and rate-limit behavior remain centralized.

### 3. Experimental plugin promotion needed an explicit quality gate

**Risk:** a future configuration or refactor could enable experimental detectors before false-positive/false-negative quality was proven.

**Remediation:** preserved and made explicit the registry block for:

- `xss_reflected`;
- `lfi`;
- `cmd_injection`;
- `open_redirect`.

Regression tests assert that configuration alone cannot enable these plugins. Promotion requirements are documented in `docs/security-qa.md` and `CONTRIBUTING.md`.

### 4. Secret redaction was inconsistent across logs and evidence

**Risk:** data-exposure findings could include raw values from intentionally exposed `.env`/debug resources, and log strings had no final redaction filter.

**Remediation:** added centralized recursive/string redaction helpers, a logging redaction filter, stronger config sanitization and data-exposure evidence redaction. Regression tests assert that synthetic passwords/API keys do not appear in JSON/HTML output.

### 5. Report formats needed explicit QA coverage

**Risk:** report changes could break downstream tools or leak secret-bearing fields.

**Remediation:** combined existing SARIF tests with new JSON/HTML redaction tests and a CI SARIF conversion gate. Added a sanitized `docs/example-report.json`.

### 6. Release packaging was documented but not validated as a release interface

**Risk:** source tests could pass while wheel installation or Docker CLI packaging failed.

**Remediation:** added `Release QA` workflow:

- builds sdist/wheel;
- runs `twine check`;
- installs the built wheel in a clean virtual environment;
- smoke-tests installed entry points;
- uploads Python distributions as workflow artifacts;
- builds the Docker image and runs a container CLI smoke test.

Publishing is deliberately not performed from pull-request validation.

### 7. Concurrency and rate-limit behavior lacked regression assertions

**Risk:** refactors could bypass per-host limits or create unbounded retry behavior.

**Remediation:** added tests for:

- per-host concurrency limits;
- bounded 429 retry behavior;
- plugin request budgets;
- explicit plugin request timeouts;
- scope rejection before network dispatch.

These tests use synthetic/fake transports or local loopback only.

### 8. Public repository metadata was incomplete

**Remediation completed in code:** added MIT `LICENSE`, package license classifier and project URLs.

**Repository-setting work still requires GitHub Settings:** description, topics and social preview cannot be changed by the repository-content workflow used for this audit. Recommended exact values are in `docs/repository-metadata.md`.

### 9. README needed a safe product-quality proof path

**Remediation:** README now documents:

- local regression corpus;
- FP/FN gates;
- plugin contract;
- auth/session safety;
- release QA;
- sanitized example report;
- experimental promotion rules;
- repository metadata recommendations.

A real README screenshot/social preview should be captured only from sanitized local HTML output and reviewed before upload.

## Security regression coverage

The new regression suite covers:

| Area | Gate |
| --- | --- |
| SQLi false negative | known vulnerable local route must produce SQLi detection |
| SQLi false positive | known safe local route must not produce SQLi finding |
| Auth session | local static session cookie receives authenticated response |
| Unauthenticated state | same protected route rejects no-cookie request |
| Scope | loopback is blocked unless explicitly enabled |
| Experimental plugins | config cannot enable registry-blocked plugins |
| Plugin budget | generated tests are truncated to request budget |
| Plugin timeout | candidate requests receive capped explicit timeout |
| Evidence contract | reportable result without evidence/reproduction is rejected |
| Concurrency | per-host active request count cannot exceed configured limit |
| Rate limiting | 429 retry behavior remains bounded |
| Secret evidence | synthetic password/API-key values are redacted |
| JSON/HTML | secret-bearing fields do not survive report serialization |
| SARIF | local smoke JSON converts to SARIF 2.1.0 |
| Packaging | wheel/sdist and Docker CLI are release-smoke tested |

## Experimental maturity decision

No experimental plugin was promoted during this audit.

`xss_reflected`, `lfi`, `cmd_injection`, and `open_redirect` remain experimental and registry-blocked. This is intentional: the audit improved the quality system rather than increasing scanner aggressiveness.

## Residual / manual items

1. Apply the recommended GitHub repository description and topics from `docs/repository-metadata.md`.
2. Upload a sanitized 1280x640 social preview generated only from synthetic/local data.
3. Optionally commit a sanitized screenshot of `smoke_out/scan_report.html` after visual review.
4. Configure PyPI Trusted Publishing only when a release owner is ready; do not add long-lived PyPI tokens to repository secrets.
5. Consider requiring the `CI`, `Security Regression`, and `Release QA` checks in branch protection after the PR proves stable.
6. Each experimental plugin still needs its own deterministic positive/negative corpus before any maturity promotion.

## Release decision

This branch is intended as a hardening/QA change, not an assertion that every scanner detector is production-grade. Stable/experimental claims should continue to follow tested evidence rather than feature presence.
