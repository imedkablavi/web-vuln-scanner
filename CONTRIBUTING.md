# Contributing

Contributions are welcome for defensive and authorized security-testing use cases.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For browser-assisted features:

```bash
python -m pip install -e ".[browser,dev]"
playwright install chromium
```

## Before opening a pull request

Run the baseline checks used by CI:

```bash
python -m compileall -q core layers plugins workflows smoke main_v2.py
ruff check . --select E9,F63,F7,F82
python -m pytest -q
```

For changes that affect crawling, request handling, plugins, authentication, workflows, reporting, rate limiting or redaction, also run:

```bash
python -m pytest -q tests/test_security_tool_regressions.py
python smoke/run_smoke.py
```

All automated security targets added to this repository must be local or synthetic. Do not add a public third-party host as a CI fixture.

## Plugin contract

New and modified active plugins must:

- stay inside the configured target scope;
- use the shared scanner request runtime / `RequestManager` instead of creating ad-hoc HTTP clients;
- never use direct `requests`, `httpx`, raw sockets, browser automation or subprocess network tools to bypass the shared transport;
- keep request volume bounded with a per-surface request budget;
- use an explicit request timeout that cannot exceed the scanner-wide timeout;
- return `TestCase` values tied to the originating attack surface;
- return structured `VerificationResult` evidence and bounded reproduction metadata;
- distinguish informational, suspected, detected and verified results accurately;
- provide no reportable result without evidence;
- provide reproducible evidence without storing credentials or session secrets;
- include focused positive and negative tests for verification logic and false-positive boundaries;
- default to disabled when a check is destructive, experimental or insufficiently verified.

See `docs/security-qa.md` for the complete quality contract.

## Experimental plugin promotion

The current experimental registry block covers:

- `xss_reflected`
- `lfi`
- `cmd_injection`
- `open_redirect`

Do not remove a plugin from the experimental block in the same change that merely adds its first working detector.

A promotion pull request must demonstrate:

1. Local intentionally-vulnerable positive fixtures.
2. Local intentionally-safe negative fixtures.
3. False-positive and false-negative regression assertions.
4. Scope blocking before network dispatch.
5. Request-budget and timeout assertions.
6. Evidence-format and redaction assertions.
7. Repeatable CI results.
8. A short explanation of why the evidence proves the claimed verification level.

If any item is missing, leave the plugin experimental.

## Regression corpus

`smoke/mock_server.py` is the local synthetic application used by security regression tests, and `tests/corpus/manifest.yaml` documents expected cases.

When extending the corpus:

- bind only to loopback / ephemeral local ports;
- keep vulnerable behavior deterministic and minimal;
- add a negative twin where practical;
- never include real credentials or production data;
- do not turn the corpus into a reusable mass-exploitation service.

## Reports and secrets

JSON, HTML and SARIF are product interfaces. Changes to reporting must preserve parseability, escaping and redaction.

Do not commit real passwords, bearer tokens, API keys, cookies, refresh tokens, browser state or captured third-party secrets. Synthetic secret-like values are useful for redaction tests, but they must be clearly fake and local.

## Packaging changes

For changes to `pyproject.toml`, package entry points or Docker packaging, validate distributions before requesting review:

```bash
python -m build
python -m twine check dist/*
docker build -t web-vuln-scanner:local .
docker run --rm web-vuln-scanner:local --help
```

Publishing is intentionally separate from PR validation. A pull request should not publish to PyPI or a container registry.

## Security boundaries

Do not add features designed to bypass authorization, evade detection, persist on targets, harvest credentials, perform destructive actions, conduct mass exploitation or enable unsafe defaults. The project is intended for systems the operator owns or has explicit permission to test.

## Pull requests

Keep changes focused. Describe the behavior change, risk, test coverage, local/synthetic fixtures used, and any configuration migration needed. Avoid mixing broad refactors with new scanner checks unless the refactor is required by the feature.
