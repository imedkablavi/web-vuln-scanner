# Security & Responsible Use

This project is intended only for systems the operator owns or has explicit authorization to test.

## Supported security boundaries

- **Authorized scanning only**: Do not use the scanner against assets without explicit permission.
- **No mass exploitation**: Do not add bulk exploitation, destructive actions, persistence, credential harvesting, stealth/evasion features or unsafe defaults.
- **Scope controls**: Configure `scanner.scope.include_domains` / `allowlist`; the shared request manager blocks hosts outside scope and private/loopback IPs unless local/private testing is explicitly allowed.
- **Centralized plugin transport**: Active plugins must use the scanner request runtime. They must not create independent HTTP clients or otherwise bypass scope, concurrency, retry or rate-limit controls.
- **Bounded active checks**: Plugins are constrained by a per-surface request budget and a request timeout capped by the scanner-wide timeout.
- **Local-only public CI**: Security regression workflows may use only local or synthetic targets. Public CI must not scan third-party vulnerable applications or public hosts.
- **Experimental plugins**: `xss_reflected`, `lfi`, `cmd_injection`, and `open_redirect` remain blocked by the registry until dedicated positive and negative regression tests, evidence-quality assertions and false-positive review justify promotion.

## Evidence-first interpretation

- `verified` means the current implementation captured stronger, reproducible proof.
- `detected` means a concrete signal was observed, but exploit confirmation is incomplete.
- `suspected` means the behavior was interesting enough to report, but not strong enough to call confirmed.
- `informational` means the scanner observed posture or inventory data that may matter operationally but is not itself an exploit confirmation.
- Anything not evidenced should be treated as untrusted and manually reviewed before action.
- Anything not reproducible must not be treated as confirmed.

Reportable plugin results must contain structured evidence and bounded reproduction metadata. A plugin must not promote a result merely because an injected request changed a response.

## Authentication and authorization testing

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

## Secrets, logs and reports

Assessment output can still be sensitive even when the target is authorized.

- Never commit real passwords, bearer tokens, API keys, session cookies, refresh tokens, CSRF values or browser storage state.
- The scanner applies redaction to configured secrets, log messages and captured data-exposure evidence. Treat redaction as defense in depth rather than permission to publish raw assessment artifacts.
- Store JSON/HTML/SARIF reports securely and review them before sharing.
- Screenshots and social-preview images must be generated from the local synthetic corpus or otherwise sanitized before publication.
- Local/mock reports classify localhost/private targets as test environments so demo results are not mistaken for production findings.

## Plugin promotion policy

A check cannot move from experimental to stable solely because it detects one intentionally vulnerable sample. Promotion requires all of the following:

1. Dedicated local positive fixtures.
2. Dedicated local negative fixtures.
3. False-positive and false-negative regression assertions.
4. Request-budget and timeout enforcement tests.
5. Scope enforcement tests.
6. Structured evidence and reproduction-format assertions.
7. Secret-redaction review.
8. Repeatable CI results with no third-party targets.

The detailed QA contract lives in `docs/security-qa.md`.

## Reporting a vulnerability in this repository

Do not post credentials, exploitable secrets or sensitive proof-of-concept details in a public issue.

Prefer GitHub's private security-reporting / Security Advisory flow when it is enabled for this repository. If private reporting is unavailable, contact the maintainer through a private channel or open a minimal public coordination issue that contains no exploit details and asks for a private contact method.

For reports about vulnerabilities found in third-party systems, follow the affected party's disclosure policy and applicable authorization rules.
