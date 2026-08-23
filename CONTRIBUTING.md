# Contributing

Contributions are welcome for defensive and authorized security testing use cases.

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

Run the same baseline checks used by CI:

```bash
python -m compileall -q core layers plugins workflows smoke scripts tests main_v2.py
ruff check . --select E9,F63,F7,F82
python -m pytest -q
```

For changes that affect crawling, request handling, plugins, authentication, workflows, or reporting, also run:

```bash
python smoke/run_smoke.py
python -m pytest -q tests/test_security_regression.py tests/test_reporting_qa.py tests/test_concurrency.py
```

For packaging changes:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
docker build -t web-vuln-scanner:dev .
```

## Plugin expectations

New checks must:

- stay inside the configured target scope;
- use the shared `RequestManager` instead of creating ad-hoc HTTP clients;
- keep request volume bounded and respect configured delays/concurrency;
- configure or inherit `max_tests_per_surface`, `request_budget`, and `timeout_seconds` limits;
- emit valid v2 `TestCase` / `VerificationResult` objects;
- include reportable evidence and reproduction metadata using `webvulnscanner/evidence-v1`;
- distinguish informational, suspected, detected, and verified results accurately;
- avoid storing credentials, bearer tokens, cookies, or session secrets;
- include local positive and negative tests for false-negative and false-positive boundaries;
- default to disabled when destructive, experimental, or insufficiently verified.

## Experimental plugin promotion

The current experimental plugins are `xss_reflected`, `lfi`, `cmd_injection`, and `open_redirect`. Do not remove their registry block until the pull request contains all of the following:

1. a localhost/synthetic intentionally vulnerable positive fixture;
2. at least one negative fixture that previously could have produced a false positive;
3. deterministic evidence assertions and reproduction metadata checks;
4. scope-escape and request-budget regressions;
5. rate-limit/concurrency behavior where the plugin can create repeated requests;
6. JSON/HTML/SARIF report QA for its evidence shape;
7. a documented manual review of remaining false-positive/false-negative risk.

An implementation existing in `plugins/` is not sufficient evidence of release quality.

## Local corpus rules

CI security targets must be local or synthetic only. Extend `tests/local_corpus.py` for scanner behavior that requires a server. Do not add a public website, public vulnerable application, external lab, or internet-wide scan to GitHub Actions.

Keep synthetic fixtures narrowly scoped to the behavior under test. They are QA fixtures, not exploitation demos or deployable vulnerable applications.

## Security boundaries

Do not add features designed to bypass authorization, evade detection, persist on targets, harvest credentials, perform destructive actions, or automatically expand scope. The project is intended for systems the operator owns or has explicit permission to test.

## Good first issues

Good first issues should be small, testable maintenance tasks that do not expand exploit capability. Suitable examples include report schema tests, documentation improvements, fixture cleanup, additional redaction cases, packaging checks, type hints, and deterministic parser tests.

## Pull requests

Keep changes focused. Describe behavior changes, risk, test coverage, and any configuration migration needed. Avoid mixing broad refactors with new scanner checks unless the refactor is required by the feature.
