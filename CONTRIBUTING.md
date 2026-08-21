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
python -m compileall -q core layers plugins workflows smoke main_v2.py
ruff check . --select E9,F63,F7,F82
python -m pytest -q
```

For changes that affect crawling, request handling, plugins, authentication, workflows, or reporting, also run:

```bash
python smoke/run_smoke.py
```

## Plugin expectations

New checks should:

- stay inside the configured target scope;
- use the shared `RequestManager` instead of creating ad-hoc HTTP clients;
- keep request volume bounded and respect configured delays/concurrency;
- distinguish observed, suspected, detected, and verified results accurately;
- provide reproducible evidence without storing credentials or session secrets;
- include focused tests for verification logic and false-positive boundaries;
- default to disabled when a check is destructive, experimental, or insufficiently verified.

## Security boundaries

Do not add features designed to bypass authorization, evade detection, persist on targets, harvest credentials, or perform destructive actions. The project is intended for systems the operator owns or has explicit permission to test.

## Pull requests

Keep changes focused. Describe the behavior change, risk, test coverage, and any configuration migration needed. Avoid mixing broad refactors with new scanner checks unless the refactor is required by the feature.
