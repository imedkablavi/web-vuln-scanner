# Security & Responsible Use

- **Authorized scanning only**: Run the scanner only against assets you own or have explicit permission to test.
- **Scope controls**: Configure `scanner.scope.include_domains` / `allowlist`; SSRF guard blocks hosts outside scope and private IPs unless `allow_private=true`.
- **Data handling**: Findings/evidence may contain sensitive data. Store reports securely and avoid sharing outside trusted channels.
- **Browser automation**: Playwright-driven verification may execute target scripts. Use isolated environments and keep browsers patched.
- **Evidence-first interpretation**:
  - `verified` means the current implementation captured stronger, reproducible proof.
  - `detected` means a concrete signal was observed, but exploit confirmation is incomplete.
  - `suspected` means the behavior was interesting enough to report, but not strong enough to call confirmed.
  - `informational` means the scanner observed posture or inventory data that may matter operationally but is not itself an exploit confirmation.
  - Anything not evidenced should be treated as untrusted and manually reviewed before action.
  - Anything not reproducible must not be treated as confirmed.
- **Auth harness**:
  - Access-control findings must include cross-actor evidence before they can remain `verified`.
  - Actors are not considered ready unless login, verify, or refresh produced explicit proof.
  - Browser-driven login does not count as successful unless it yields a usable session state and HTTP or verification proof.
  - Placeholder credentials in `config/default_config.yaml` use environment variable references only; do not commit real secrets.
  - If login or refresh fails, the affected actor is reported as degraded/login_failed/refresh_failed and related verification scenarios remain partial.
  - Browser actor artifacts are optional supporting evidence, not the sole basis for confirmation.
  - Deterministic RBAC verification requires an explicit policy matrix plus actor readiness; otherwise the engine stays heuristic or partial by design.
  - Replay results are evidence aids, not independent proof, unless they reproduce the actor-scoped scenario truthfully.
  - Workflow verification requires step-level evidence and checkpoint agreement; a workflow marked `partial`, `failed`, `blocked_auth`, or `indeterminate` must not be treated as a completed verification.
  - Workflow replay is separate from request replay and only counts as reproduced when the replayed workflow matches the original checkpoint trail.
- **Local/mock labeling**: Reports classify localhost/private targets as local test environments so demo or smoke results are not mistaken for production findings.
- **Disclosure**: Report vulnerabilities responsibly to the affected parties following their disclosure policy.

If you discover a security issue in this project, open a private issue or contact the maintainers with a minimal, reproducible description.
