## Summary

Describe the behavior changed and why.

## Safety / scope impact

- [ ] This change does not broaden default target scope unexpectedly.
- [ ] Outbound HTTP(S) still flows through the centralized scoped request layer, or the exception is documented and tested.
- [ ] New active behavior is explicit opt-in and bounded.
- [ ] Browser actions cannot mutate target state by default.
- [ ] Authentication state is isolated between actors/workers.
- [ ] No credentials, tokens, cookies, storage state, traces, or target secrets are committed.

## Verification quality

- [ ] Positive fixture added/updated where relevant.
- [ ] Negative/false-positive fixture added/updated where relevant.
- [ ] Verification status reflects the actual evidence strength.
- [ ] Experimental plugins remain disabled unless promotion criteria are met.

## Release checks

- [ ] `python -m compileall -q core layers plugins workflows smoke main_v2.py`
- [ ] `ruff check . --select E9,F63,F7,F82`
- [ ] `python -m pytest -q`
- [ ] dependency audit passes
- [ ] package build/install passes
- [ ] local authorized smoke passes when scanner behavior changed
- [ ] Docker build/runtime passes when container behavior changed

## Notes

List compatibility changes, known limitations, and any follow-up work that should not block this PR.
