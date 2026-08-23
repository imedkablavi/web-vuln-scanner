# Security Policy

## Authorized use

Run this scanner only against assets you own or have explicit permission to assess. Prefer local fixtures, intentionally vulnerable labs, staging systems, and other controlled targets for development and reproduction.

The default CLI profile is intentionally passive. Active payload testing requires an explicit active profile, and generic browser form submission/clicking remains opt-in even in the fully authorized profile.

## Reporting a scanner vulnerability

Do **not** publish exploit details, credentials, cookies, tokens, browser storage, traces, screenshots, or vulnerable target data in a public issue.

Use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available. If that private channel is unavailable, open a minimal public issue asking the maintainer for a private security contact channel **without including exploit details or secrets**.

A useful private report includes:

- affected commit or release;
- component and security boundary affected;
- minimal reproduction against a local/mock target when possible;
- expected versus observed behavior;
- impact and prerequisites;
- whether reports, browser artifacts, credentials, cookies, tokens, or storage state may be exposed.

## Security-sensitive scanner defects

Treat these as security issues even when they do not directly compromise the host running the scanner:

- scope bypass or off-target requests;
- DNS rebinding or redirect scope bypass;
- unexpected state-changing browser actions;
- authentication/session crossover between actors or worker threads;
- leakage of credentials, cookies, tokens, traces, screenshots, reports, or storage-state files;
- report injection or unsafe rendering;
- a failed scan being reported as successful;
- default behavior that performs active testing without explicit operator intent.

## Evidence and verification semantics

- `verified`: stronger reproducible proof was captured by the implemented verifier.
- `detected`: a concrete signal was observed, but exploit confirmation is incomplete.
- `suspected`: behavior is noteworthy but insufficient for a confirmed finding.
- `informational`: posture or inventory data, not exploit confirmation.
- Failed, partial, blocked-auth, or indeterminate workflows must not be represented as completed verification.
- Browser screenshots and traces are supporting evidence, not a substitute for deterministic authorization or exploit proof.

## Authentication and artifact handling

- Access-control verification should use isolated actor state and explicit actor comparison.
- Placeholder credentials in `config/default_config.yaml` reference environment variables; never commit real secrets.
- Browser storage state, traces, screenshots, replay records, and reports can contain sensitive material. The scanner applies restrictive file permissions where supported, but operators remain responsible for secure storage, retention, and deletion.
- A login/refresh failure degrades the affected scenario instead of being silently treated as success.

## Scope controls

Outbound HTTP(S) traffic is checked against the configured target/scope policy, including redirect targets and resolved IP addresses. Private, loopback, link-local, multicast, unspecified, and reserved addresses are rejected unless private-target access is explicitly permitted for an authorized local/private assessment.

Browser traffic is intercepted at the browser-context layer as an additional enforcement boundary. Service Workers are blocked in hardened browser contexts so they cannot bypass request interception.
