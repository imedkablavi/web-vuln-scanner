# Changelog

## 0.4.0 - Unreleased

### New checks
- Added bounded SSTI verification for observed query parameters. The verifier requires two arithmetic expressions to produce two expected values and does not use command execution, file reads, callbacks, or timing payloads.
- Added CRLF/response-header injection verification with a dedicated canary response header.
- Added a TRACE reflection check using a unique request header.
- Reworked reflected XSS testing into parser-backed reflected markup verification. Encoded text reflection is ignored; a finding requires the injected inert custom element to be reconstructed as HTML.
- Reworked open-redirect testing around an exact `wvs.invalid` destination and reserved-host canary path.
- Promoted the hardened reflected-markup and open-redirect checks to stable, opt-in active checks. LFI and command injection remain experimental.
- Added a bounded safe-template engine for same-origin GET/HEAD checks. It supports status/word/header matchers but intentionally excludes raw HTTP, DSL/eval, redirects, callbacks, and state-changing methods.
- Added packaged safe templates for PHP `phpinfo()`, Apache `server-status`, Nginx `stub_status`, and Go expvar exposure using strong response markers.

### CLI and scan workflow
- Added `web-vuln-scanner checks` to show check maturity, mode, CWE, and WSTG mappings.
- Added `web-vuln-scanner profiles` to explain the built-in safety profiles.
- Added `web-vuln-scanner doctor` to validate the installed runtime and packaged configuration.
- Added `web-vuln-scanner version` and explicit `scan <target>` syntax while keeping the original `web-vuln-scanner <target>` form compatible.
- Added `--checkpoint PATH` and `--resume PATH` for resumable active-test progress without persisting cookies, authorization headers, response bodies, or raw parameter values.
- Added `--har-seed PATH` to feed sanitized same-scope GET/HEAD URLs from a HAR into normal discovery without replaying captured requests.
- Kept CI finding gates for minimum severity and verification status.

### Safety and scope
- Added a centralized HTTP(S) scope policy shared by discovery and request dispatch.
- Added DNS preflight checks for private, loopback, link-local, multicast, unspecified, and reserved destinations unless private-target access is explicitly authorized.
- Added boundary-aware wildcard/port matching and rejection of embedded URL credentials.
- Added scope validation for followed redirects and removal of sensitive credentials on cross-origin redirects.
- Added Playwright request interception and blocked Service Workers in scoped browser contexts.
- Generic browser form submission and broad click automation remain disabled by default.
- The passive profile does not send the new active web or safe-template probes.
- `safe-active` and `full-authorized` force redirect following off while redirect verification runs.
- HAR scan seeding never dispatches captured POST/PUT/PATCH/DELETE requests, and HAR-derived active parameter tests require a separate YAML opt-in.
- Safe-template requests are restricted to same-origin GET/HEAD paths and remain behind the centralized scope policy and hard request/body limits.

### Runtime correctness
- Added deterministic exit codes: clean=0, findings=1, failure=2, partial/aborted=3.
- Added thread-local HTTP sessions and disabled Requests environment credential/proxy inheritance with `trust_env=False`.
- Added an enforced active-scanner timeout and global per-plugin finding caps.
- Plugin maturity is enforced from catalog metadata rather than a hard-coded deny list.
- Removed import-time log-file creation.
- Added restrictive best-effort permissions for reports and sensitive scanner artifacts.
- Added report/event redaction for common credential forms, including quoted JSON secret values.
- Checkpoint resume verifies target/profile/relevant configuration identity, restores redacted prior findings, retries unfinished testcases, and removes completed ledgers by default.
- Relative workflow, HAR-seed, and custom safe-template paths are resolved relative to the user's YAML configuration before runtime materialization.

### Release engineering
- Updated runtime dependencies and package dependency floors.
- Added dependency auditing, SBOM generation, wheel build/install validation, CLI entry-point checks, coverage reporting, browser smoke setup, and Docker runtime validation to CI.
- CI now verifies that packaged safe-template YAML files are present and schema-valid from the installed wheel outside the source tree.
- CI scans smoke artifacts for known credential sentinels before upload.
- Fixed Docker runtime ownership for the non-root Playwright user.
- Added `.dockerignore`, `SECURITY.md`, release provenance workflow, and a security-focused pull-request checklist.
- Added positive and negative fixtures for stable plugins, scope behavior, redaction, CLI commands, web posture checks, HAR seeding, checkpoint resume, safe templates, and the active probes.
- Updated plugin metadata to OWASP Top 10:2025 and OWASP WSTG references where applicable.

### Reporting and documentation
- HTML reports now support filtering/search and shorter evidence presentation.
- SARIF uses logical web-target locations instead of pretending remote URLs are repository files.
- README and CLI wording were rewritten around actual behavior and verification limits rather than generic feature claims.
- Added advanced workflow documentation for resumable scans, live HAR discovery seeding, and custom safe-template checks.

## Known limitations
- DNS validation is still a preflight guard rather than socket-level IP pinning. A narrow DNS rebinding time-of-check/time-of-use window remains.
- Some lifecycle stages rely on component/request timeouts rather than one hard whole-process kill deadline.
- Strict browser scope blocks third-party HTTP(S) resources unless those hosts are explicitly authorized in scope.
- Reflected markup verification proves HTML injection, not JavaScript execution.
- HAR seeding intentionally does not reproduce captured authenticated/state-changing requests; it is discovery input, not session replay.
- The safe-template engine is intentionally less expressive than general template scanners: no raw HTTP, DSL, external callbacks, or state-changing methods.
- LFI/path traversal and command injection remain experimental until stronger verification fixtures are available.