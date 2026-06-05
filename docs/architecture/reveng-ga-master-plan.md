# REVENG GA Master Plan

## Purpose

This document defines the shortest defensible path from the current beta platform to a customer-safe GA release.

It is stricter than the current implementation roadmap. GA here means a smaller supported product with enforceable release gates, not broad claims across every subsystem in the repo.

## Current starting point

Use these existing documents as the verified baseline:

- `docs/architecture/current-platform-status.md`
- `docs/architecture/reveng-world-class-implementation-roadmap.md`
- `docs/architecture/reveng-world-class-execution-backlog.md`
- `docs/architecture/app-reverse-engineering-tdd-plan.md`

## GA definition

REVENG can claim GA for a workflow only when:

- the workflow is explicitly listed as supported
- the workflow has stable CLI, API, and MCP contracts where exposed
- the workflow is covered by tracked corpus or benchmark gates
- release notes and docs describe only validated behavior
- operational prerequisites and failure modes are documented

## TDD-centric execution order

### Phase 0: Freeze the supported surface

- Support only the workflows that can be benchmarked and regression-tested today.
- Mark exploit generation, deep symbolic execution, and broad binary equivalence claims as non-GA.
- Add tests first for support-matrix serialization and release-verifier behavior.

### Phase 1: Baseline release gates

- Keep `reports/app_reverse_engineering_corpus_report.json`, `reports/source_binary_benchmarks_report.json`, and `reports/bun_sample_matrix.json` as tracked artifacts.
- Use `scripts/verify_ga_readiness.py --profile baseline` as the minimum release gate.
- Add failing tests for any missing report field before changing the report contract.

### Phase 2: GA target gates

- Provision public source mirrors and release assets with `scripts/provision_ga_assets.py`.
- Maintain at least 5 tracked source-backed validation rows across the benchmark, Bun, and app-corpus surfaces.
- Raise the Bun matrix to a clean `pass` with at least 2 live samples.
- Remove synthetic required rows from the app corpus.
- Use `scripts/verify_ga_readiness.py --profile ga` as the strict audit.

### Phase 3: Operational hardening

- Install and run real external-tool lanes in CI for `ilspycmd`, `pyi-archive_viewer`, Java, and Ghidra where supported.
- Add worker isolation, retries, timeouts, and artifact retention tests around heavy analysis paths.
- Treat observability and support diagnostics as release features.

### Phase 4: Customer packaging

- Publish a support matrix, installation requirements, and troubleshooting guide.
- Add versioned release notes tied to readiness reports.
- Keep `.github/RELEASE_CHECKLIST.md` aligned with the actual shipping process.

## Non-negotiable GA gates

- Baseline readiness verifier passes
- Strict GA verifier passes before using GA language
- CI and docs workflows are green on the release candidate
- Public docs match the verified platform state
- Required corpus and benchmark artifacts are fresh and reviewable

## What is still not enough

The following do not justify GA on their own:

- broad feature count
- passing unit tests without tracked corpus evidence
- readable reconstructed output without validation context
- manual spot checks that are not preserved in reports

## Summary

The correct path to GA is disciplined narrowing, not expansion:

1. freeze the supported product
2. enforce baseline gates
3. close the GA-target gaps with real corpus growth
4. harden operations and packaging
5. only then market the platform as GA
