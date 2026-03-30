# Bun Real-Sample Matrix

This page records the current live-sample validation matrix for the Bun recovery and rebuild pipeline.

## Why this exists

The Bun pipeline now has strong fixture coverage and contract coverage, but fixture-only confidence is not enough for product claims.

The matrix exists to keep at least one real Bun sample and one negative control in a rerunnable loop while making it easy to add more binaries as they become available.

## Current matrix shape

The matrix runner is driven by:

- `.reveng\bun_sample_matrix.json`

The default registry currently covers:

- `C:\dev\droid.exe` when it exists in the local environment
- `test_samples\sample.exe` as a negative control to confirm non-Bun binaries do not route through the Bun workflow
- any additional binaries passed through `--binary`

## What the runner validates

For live Bun samples, the runner executes:

1. `analyze`
2. `recompile`
3. report extraction from:
   - `bun_analysis.json`
   - `bun_sea_build.json`

It then records:

- detection indicators
- recovery mode and module layout
- `report_severity`
- `runtime_escalation`
- `equivalence_validation`
- `differential_validation`
- `sea_build.verification`
- optional smoke-validation results for the original and rebuilt binaries

For negative controls, the runner records Bun detection only.

## Rerun the matrix

```bash
python scripts\run_bun_sample_matrix.py
```

Add more binaries like this:

```bash
python scripts\run_bun_sample_matrix.py --binary C:\path\to\another-bun-sample.exe
```

Or point the runner at a different registry:

```bash
python scripts\run_bun_sample_matrix.py --config C:\path\to\bun_sample_matrix.json
```

The report is written to:

- `reports\bun_sample_matrix.json`

Per-sample CLI outputs are written under:

- `reports\bun_sample_matrix\`

## Current interpretation guidance

- `matrix_status == pass` means at least two live Bun samples rebuilt cleanly
- `matrix_status == pass_with_limitations` means the live matrix is working, but the environment still exposes fewer than two real Bun anchors
- `matrix_status == insufficient_live_bun_samples` means no live Bun sample completed the loop

This keeps the reporting honest: the matrix can be productized before the environment contains a broad collection of real Bun executables.

The registry also keeps expectations version-controlled, so matrix status can fail honestly when required samples disappear or known-good Bun outputs regress.

For live Bun samples, the registry can also enable smoke validation by reusing `.reveng\validation_policy.json`. This keeps timeout, exit-code, and CLI expectations aligned with the existing binary validation policy instead of duplicating them in the matrix runner.

## Current observed snapshot

Latest local matrix run:

- `matrix_status`: `pass_with_limitations`
- `live_bun_sample_count`: `1`
- `successful_rebuild_count`: `1`

| Sample | Kind | Bun route | Recovery / layout | Severity | Runtime escalation | Rebuild verification | Equivalence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `C:\dev\droid.exe` | live Bun sample | `bun` / `bun_node_sea` | `module_graph` / `full` | `high` (`score: 100`) | `targeted_runtime_observation` | `pass_with_warnings` | `structural_candidate` |
| `test_samples\sample.exe` | negative control | not Bun | n/a | n/a | n/a | n/a | n/a |

Observed `droid.exe` highlights from the current matrix report:

- analysis still routes cleanly through the Bun workflow
- recovery remains on the module-graph path with `full` layout parsing
- rebuild verification is now expected to land at `pass_with_warnings` for the current Droid sample:
  - the normalized workspace bundle is valid and rerunnable
  - the rebuilt `bun-sea.exe` still warns on a naked copied-executable probe, so the product does not overclaim standalone portability
- differential validation is `pass`
- equivalence is currently a `structural_candidate`, not a runtime-equivalence claim
- smoke validation now uses higher-signal CLI characterization anchors before the interactive no-args path:
  - `--version`
  - `--help`
  - `-h`
  - `[]` as an interactive characterization check
- smoke parity no longer treats matching timeouts alone as sufficient:
  - parity now compares pass/fail, exit code, timeout state, normalized output, and error state per smoke test
  - timeout output is retained so interactive startup drift is visible instead of collapsing to `null`
- for the current `droid.exe` sample, the no-args path is still characterization-only because both the original and rebuilt binaries enter interactive mode rather than terminating with a stable batch result
- runtime escalation remains recommended because native startup still looks loader-heavy
- operationally, the deployable output for the current Bun path is the normalized workspace bundle, not just the copied `bun-sea.exe` by itself

This is the correct product posture today: the static and rebuild pipeline is working on the live sample, and the matrix now anchors that claim on stable CLI surfaces while still surfacing interactive-runtime limitations honestly.

## Droid completion criteria

For this session, treat the current Droid sample as complete when all of the following are true:

- Bun `analyze` and `recompile` continue to route cleanly through the productized workflow
- matrix row status for `droid.exe` is `completed`
- rebuild verification remains `pass_with_warnings` or better, with any warnings documented rather than hidden
- differential validation remains `pass`
- higher-signal CLI characterization (`--version`, `--help`, `-h`) remains matched, while the interactive no-args path is explicitly documented as characterization-only
- deployability is described honestly:
  - the normalized workspace bundle is the supported runtime artifact
  - a naked copied `bun-sea.exe` is still a warning path, not a claimed success case

## Current limitation

At the time of writing, the local environment exposes only one known real Bun sample path in policy and prior reports: `C:\dev\droid.exe`.

That means this matrix is now rerunnable and documented, but it still needs additional user-supplied Bun executables to become a broader real-world regression net.
