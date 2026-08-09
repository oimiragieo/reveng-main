# Tutorial: Unit tests and honesty gates

> **Maturity:** preview · process is load-bearing for release claims
>
> Trust: green scripts are necessary but not sufficient — open tracked JSON evidence. Match claims to [Support matrix](../../support/support-matrix.md) / [`support_matrix.json`](../../support_matrix.json).

## Goal

Run the everyday unit suite, architecture contracts, and GA readiness profiles the way this repo expects contributors to verify honesty.

## Prerequisites

- [Dev setup](01-dev-setup.md) completed (`pip install -e . --no-deps`)
- For honesty-shaped environments: `requirements-honesty.txt` (not full `requirements.txt`)

## Unit tests and markers

```bash
make test-unit
# or
python3.9 -m pytest tests/unit -q --no-cov
```

Useful filters (`pytest.ini` markers):

```bash
# Fast local loop — skip heavy env
python3.9 -m pytest -m "not requires_external_tools and not slow and not requires_network" --no-cov

# Marker examples
python3.9 -m pytest -m unit --no-cov
python3.9 -m pytest -m "integration and not requires_network" --no-cov
```

Common markers: `unit`, `integration`, `e2e`, `slow`, `requires_external_tools`, `requires_network`, `ghidra`, `poc`, `tracked_bundle`. Prefer `--no-cov` when you want a quick loop (coverage is often enabled via addopts / project config).

## Import-linter (architecture)

Domain boundaries live in `.importlinter` (e.g. `reveng.core` is foundation; `reveng.security` must not import AI providers).

```bash
lint-imports --no-cache
# or via the fuller gate:
make lint
```

`make lint` also runs black/isort/pylint/mypy (+ hadolint). Fix contract breaks in the layer that introduced the illegal import — do not weaken the contract to silence CI.

## GA readiness — baseline **and** ga

```bash
python3.9 scripts/verify_ga_readiness.py --profile baseline
python3.9 scripts/verify_ga_readiness.py --profile ga
```

**Never trust a green verifier alone.** Open the tracked report JSON the script cites and confirm evidence fields (analyze/recompile paths, statuses). A hollow gate that passes with empty evidence is broken — [Honesty rules](../../support/honesty-rules.md).

## Native analyze probe (when measuring natives)

```bash
python3.9 scripts/probe_native_analyze_timeout.py \
  --job reports/native_analyze_probe/wave_a_job.json
```

Remember: process `completed` ≠ native GA (**DF-5**). `test_samples/native/` is **fixture_only** until measured green with required evidence — see [Maturity badges](../../support/maturity-badges.md).

## Scoped git status (DrvFS / large trees)

Full `git status` can hang on dirty `reports/` / analysis trees under WSL DrvFS. Prefer:

```bash
bash scripts/git_status_scoped.sh
```

Named-path adds/commits only (DF-4). Details: [Scoped git and commits](../../how-to/engineer/scoped-git-and-commits.md).

## Suggested local sequence before claiming “ready”

1. Unit filter without external tools / network
2. `lint-imports --no-cache` if you touched package imports
3. `verify_ga_readiness.py --profile baseline` **and** `--profile ga`
4. Open the referenced JSON stamps; confirm fields match the claim you want to make
5. Scoped `git status` before staging

## Related

- [Honesty rules](../../support/honesty-rules.md)
- [Corpus & GA scripts](../../reference/corpus-and-ga-scripts.md) (if present in your tree)
- [Reading validation grades](../../support/reading-validation-grades.md)
- Release skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
