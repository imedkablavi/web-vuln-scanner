# Changelog

## Unreleased

### Safety and scope
- Added a centralized HTTP(S) scope policy shared by discovery and request dispatch.
- Added DNS preflight checks that reject private, loopback, link-local, multicast, unspecified, and reserved destinations unless private-target access is explicitly authorized.
- Added boundary-aware wildcard/port matching and rejection of embedded URL credentials.
- Added scope validation for every followed redirect and stripping of sensitive cross-origin redirect credentials.
- Added browser-context request interception and blocked Service Workers so browser requests cannot silently bypass interception.
- Disabled generic browser form submission and broad click automation by default, including the full-authorized profile; operators must explicitly opt into known-safe selectors/actions.
- Disabled guessed sensitive-path probes in the default passive profile.

### Runtime correctness
- Added deterministic exit codes: clean=0, findings=1, failure=2, partial/aborted=3.
- Added thread-local HTTP sessions and disabled Requests environment credential/proxy inheritance with `trust_env=False`.
- Added an enforced active-scanner global timeout and global per-plugin finding caps.
- Replaced the hard-coded experimental-plugin blacklist with metadata-driven maturity enforcement.
- Removed import-time log-file creation and made configured file logging degrade safely to console logging when unwritable.
- Added restrictive best-effort permissions for reports, traces, screenshots, storage state, and other scanner artifacts.

### Release engineering
- Updated pinned runtime/browser dependencies and secure package dependency floors.
- Added dependency auditing, wheel build/install validation, CLI entry-point checks, coverage reporting, Playwright/Chromium smoke setup, and Docker non-root runtime validation to CI.
- Fixed Docker runtime ownership so the non-root Playwright user can write scanner outputs.
- Added `.dockerignore`, `SECURITY.md`, and a security-focused pull-request checklist.
- Added regression tests for scope spoofing, DNS-to-private resolution, redirects, session isolation, exit semantics, passive defaults, artifact permissions, plugin maturity, global finding caps, and active-scan timeout behavior.
- Updated plugin metadata to OWASP Top 10:2025 mappings.

### Existing scanner improvements retained
- Fixed XSS and CMD injection plugins crashing due to wrong TestCase parameters.
- Improved SQLi boolean testing order with differential verification and repeats.
- Added HTTP method support (PUT/DELETE/PATCH) and per-host concurrency limits.
- Reporter aligns counts with verified-only filtering and standardized finding headings.

## Known limitations
- DNS address validation is a preflight guard, not socket-level IP pinning; a narrow DNS time-of-check/time-of-use rebinding window remains possible and should be addressed before claiming complete anti-rebinding protection.
- `global_timeout_seconds` currently bounds the active plugin engine; crawling, browser discovery, authentication bootstrap, workflows, report generation, and cleanup are bounded by their component/request timeouts rather than one whole-process wall-clock deadline.
- Browser scope enforcement intentionally blocks third-party HTTP(S) resources unless those hosts are explicitly included in scope. Applications that require trusted CDN or identity-provider resources may need additional authorized scope entries.
- Experimental XSS/LFI/command-injection/open-redirect plugins remain blocked from release execution pending stronger true-positive/false-positive verification fixtures.
