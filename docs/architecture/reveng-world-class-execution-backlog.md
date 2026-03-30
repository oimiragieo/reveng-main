# REVENG world-class execution backlog

## Purpose

This document turns the world-class roadmap into a concrete backlog for the active work now in front of the repository:

- the `hexyl` native reconstruction frontier
- the multiple-codebase corpus gate
- the Bun live-sample matrix
- the evidence and validation contracts those workflows depend on

It is intentionally near-term and operational. Longer-range service extraction and analyst workspace work should follow this backlog, not run ahead of it.

## Current tracked evidence

Use these as the starting anchors for planning and reporting:

- `.reveng/source_binary_benchmarks.json` currently registers one native benchmark, `hexyl`
- `reports/source_binary_benchmarks_report.json` is the current tracked native benchmark report; in that tracked run, `hexyl` ended at `analyze_failed`, with both analyze and recompile timing out after 1200 seconds
- `.reveng/bun_sample_matrix.json` currently requires two live Bun samples for a clean pass and includes one live sample plus one negative control
- `reports/bun_sample_matrix.json` is the current tracked Bun matrix report; in that tracked run, `matrix_status` is `pass_with_limitations`, `live_bun_sample_count` is `1`, and `successful_rebuild_count` is `1`
- `HARDENING_PRIORITIES.md` documents the current three-slice hexyl hardening plan for `src/reveng/ai/recompilation_engine.py`

## Backlog operating rules

### Rule 1: tracked reports outrank intent

If the current tracked report says a benchmark timed out or a corpus gate is incomplete, the backlog should treat that as the truth until a newer tracked report proves otherwise.

### Rule 2: corpus breadth is a gate

Multiple codebases are not a nice-to-have. They are part of the definition of "world class."

### Rule 3: validation grades outrank readability

Source that looks plausible but is not validated does not count as success.

### Rule 4: do not start worker extraction early

Do not move major effort into worker extraction, gateway refactors, or analyst UX until the benchmark and reconstruction gates below are stable.

## Milestone queue

| Milestone | Focus | Status |
| --- | --- | --- |
| M0 | Baseline and reporting discipline | active |
| M1 | Multiple-codebase corpus gate | active |
| M2 | Hexyl frontier hardening | active |
| M3 | Validation and evidence grade lift | next |
| M4 | CI and release gate enforcement | next |
| M5 | Post-gate architecture extraction | queued |

## M0: baseline and reporting discipline

### Objective

Make the existing benchmark and contract surfaces trustworthy enough to act as merge gates.

### Acceptance gates

- `pytest tests/unit/test_source_binary_benchmark.py tests/unit/test_bun_sample_matrix.py tests/unit/test_result_contracts.py tests/unit/test_validation_contracts.py` passes
- `python scripts/run_source_binary_benchmark.py --benchmark hexyl` always writes a report JSON, even when the run fails or times out
- `python scripts/run_bun_sample_matrix.py` preserves `pass_with_limitations` or better for the current tracked sample set
- docs and roadmap references call these artifacts the "current tracked report" rather than making timeless claims

### Benchmark additions

- no new benchmarks yet; stabilize the existing `hexyl`, `droid`, and `sample-control` anchors first

### Repo tasks

- `scripts/run_source_binary_benchmark.py`: keep failure paths reportable and machine-readable
- `scripts/run_bun_sample_matrix.py`: keep matrix rollup semantics stable
- `tests/unit/test_source_binary_benchmark.py`: add regression cases for timeout, missing report, and required benchmark status handling
- `tests/unit/test_bun_sample_matrix.py`: add regression cases for required sample failure and matrix rollup drift
- `docs/architecture/reveng-world-class-implementation-roadmap.md`: keep qualifiers aligned with tracked evidence

### Current blockers

- local docs verification is environment-limited when `mkdocs-material` is missing

## M1: multiple-codebase corpus gate

### Objective

Turn the current single-native-benchmark setup into a real corpus gate.

### Acceptance gates

- `.reveng/source_binary_benchmarks.json` contains at least 5 native benchmarks across at least 3 implementation families
- `.reveng/bun_sample_matrix.json` contains at least 2 live Bun samples and at least 2 negative controls
- every required native benchmark has at least 2 deterministic behavior checks, ideally `--version` and `--help` plus one content-oriented command where applicable
- every required Bun row includes explicit rebuild expectations and smoke-validation policy where supported

### Benchmark additions

- native benchmark 2: Rust CLI with deterministic `--version` and `--help`
- native benchmark 3: C CLI with deterministic `--version` and `--help`
- native benchmark 4: C++ CLI or Windows-native CLI with deterministic `--version` and `--help`
- native benchmark 5: one more file-processing CLI with at least one content-oriented behavior check
- Bun live sample 2: a second user-supplied Bun executable with stable rebuild expectations
- negative control 2: one additional non-Bun native sample

### Repo tasks

- `.reveng/source_binary_benchmarks.json`: add benchmark metadata such as `family`, `language`, `platform`, and `required`
- `.reveng/bun_sample_matrix.json`: add second live Bun anchor and second negative control
- `.reveng/validation_policy.json`: add smoke policies for new required corpus entries
- `scripts/run_source_binary_benchmark.py`: preserve benchmark metadata into the report output
- `scripts/run_bun_sample_matrix.py`: preserve sample metadata and expectation status into the report output
- `tests/unit/test_source_binary_benchmark.py`: add coverage for metadata preservation and required-row logic
- `tests/unit/test_bun_sample_matrix.py`: add coverage for multi-live-sample rollups and negative-control handling

### Current blockers

- the repository currently exposes only one tracked live Bun sample path, `C:\dev\droid.exe`
- additional native anchors need curated source repos, build recipes, and deterministic command expectations

## M2: hexyl frontier hardening

### Objective

Collapse the current `hexyl` timeout frontier into a measurable reconstruction improvement loop.

### Acceptance gates

- the three hardening slices from `HARDENING_PRIORITIES.md` land with regression tests
- `python scripts/run_source_binary_benchmark.py --benchmark hexyl` produces tracked analyze and recompile report artifacts instead of both stages ending as full timeouts
- the tracked `hexyl` benchmark status advances beyond `analyze_failed`
- original-behavior checks for `hexyl` remain passing
- if a rebuilt binary is produced, behavior comparisons are present in the tracked report rather than omitted

### Benchmark additions

- no new native benchmark required before this milestone closes; the focus is making `hexyl` a trustworthy frontier anchor

### Repo tasks

- `src/reveng/ai/recompilation_engine.py`: implement the three documented normalization slices in the order already specified
- `tests/unit/test_recompilation_engine_feedback_loop.py`: add focused regression tests for:
  - undeclared split locals
  - fragment local unification
  - context-aware `undefined8*` parameter widening
- `reports/source_binary_benchmarks/hexyl/`: refresh tracked artifacts after each hardening slice
- `HARDENING_PRIORITIES.md`: update with before/after evidence once each slice lands
- `HARDENING_SUMMARY.txt`: keep the tracked impact summary current

### Current blockers

- the current tracked `hexyl` run still times out before producing analyze or recompile reports
- Ghidra and recompilation heavy paths remain the current long pole

## M3: validation and evidence grade lift

### Objective

Make Bun and native benchmark reporting use one clear validation language and one evidence story.

### Acceptance gates

- native and Bun reports both use the same validation-grade vocabulary
- `src/reveng/result_contracts.py` carries explicit validation and evidence reference fields needed by CLI, API, and MCP consumers
- benchmark reports expose enough provenance to explain why a run passed, failed, or only reached a structural candidate state
- AI-facing outputs cite evidence references rather than standalone summaries

### Benchmark additions

- add at least one benchmark command per required native sample that exercises more than a pure metadata path
- extend Bun sample expectations to include smoke parity where the runtime path is stable enough to judge it

### Repo tasks

- `src/reveng/result_contracts.py`: add a shared validation-grade and evidence-reference shape
- `src/reveng/api.py`: propagate validation/evidence fields into programmatic outputs
- `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`: propagate the same fields into MCP results
- `scripts/run_source_binary_benchmark.py`: surface validation-grade summaries in the report rollup
- `scripts/run_bun_sample_matrix.py`: keep parity, verification, and equivalence reporting aligned with the shared vocabulary
- `tests/unit/test_result_contracts.py`: add assertions for validation-grade and evidence-reference presence
- `tests/unit/test_validation_contracts.py`: extend coverage for validation detail round-tripping
- `tests/unit/test_mcp_contracts.py`: add MCP-level schema checks for the new shared fields

### Current blockers

- evidence exists today in several places, but not yet as one unified, benchmark-visible contract

## M4: CI and release gate enforcement

### Objective

Make the corpus and reconstruction milestones part of normal delivery, not manual spot checks.

### Acceptance gates

- pull requests run the minimum benchmark gate in CI
- the main branch runs the wider corpus nightly or on a schedule
- releases fail if required corpus entries regress, disappear, or lose validation grade without an approved waiver
- docs CI continues to build with the same authoritative architecture set named in `mkdocs.yml`

### Benchmark additions

- add one CI-safe native benchmark subset for pull requests
- keep the full native corpus and Bun matrix as a scheduled or main-branch gate

### Repo tasks

- `.github/workflows/test.yml`: add a benchmark gate job or invoke a dedicated benchmark workflow
- `.github/workflows/ci.yml`: enforce benchmark status checks for required rows
- `.github/workflows/docs.yml`: keep docs build and link-check aligned with the architecture docs set
- `Makefile`: add explicit targets such as `benchmark-source` and `benchmark-bun`
- `docs/README.md`: document which benchmark jobs are expected on pull requests versus scheduled runs
- `.github/RELEASE_CHECKLIST.md`: add corpus and validation-grade release checks

### Current blockers

- current workflows run tests and docs, but not the native benchmark or Bun matrix as first-class gates

## M5: post-gate architecture extraction

### Objective

Start bounded-context cleanup and worker extraction only after M0-M4 are stable.

### Acceptance gates

- the corpus gate is stable across multiple tracked runs
- `hexyl` is no longer a timeout-only frontier
- validation and evidence contracts are stable enough to survive cross-process boundaries

### Repo tasks

- reconcile `pipeline/` and `pipelines/` behind one orchestration model
- extract ports for static analysis, decompilation, reconstruction, validation, and reporting
- move Ghidra, dynamic analysis, and compilation/equivalence into isolated workers behind contract tests

## Priority ordering

Do the work in this order:

1. M0 baseline and reporting discipline
2. M1 corpus gate
3. M2 hexyl frontier hardening
4. M3 validation and evidence grade lift
5. M4 CI and release enforcement
6. M5 post-gate architecture extraction

## Summary

The immediate mission is not broad refactoring. It is to make REVENG provably trustworthy on more than one codebase, with `hexyl` as the active native frontier and the Bun matrix as the live-sample companion gate. When those two anchors are stable, the rest of the platform work becomes much safer and much more defensible.
