# Changelog

## Unreleased
- Fixed XSS and CMD injection plugins crashing due to wrong TestCase parameters.
- Improved SQLi boolean testing order with differential verification and repeats.
- Added HTTP method support (PUT/DELETE/PATCH) and SSRF guard with per-host concurrency limits.
- Removed global future timeout to avoid premature scan termination.
- Reporter now aligns counts with verified-only filter, adds anchors, safe links, and standardized heading `Findings (N)`.
- Added pytest coverage for plugins, request methods, scanner timeout handling, reporter counts, and verification gating.
- Added project README and config documentation.
