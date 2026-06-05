# REVENG world-class implementation roadmap

## Why this document exists

This document turns the system paper, feature roadmap, TDD microservices plan, and current benchmark artifacts into an execution plan.

For the concrete milestone backlog tied to the current `hexyl` and corpus work, see `reveng-world-class-execution-backlog.md`.

It uses two rules:

- state validated repo facts as facts
- label durations and future sequencing as planning guidance, not as current repository truth

## Current validated starting point

The strongest validated statements today are:

- the core platform exists: central analyzer, CLI, Python APIs, MCP surface, Ghidra integration points, Ollama-aware paths, and explicit output artifacts
- versioned result contracts and provenance-bearing public results exist in `src/reveng/result_contracts.py`
- the Bun real-sample matrix exists, and the current tracked matrix status is `pass_with_limitations`
- the source-vs-binary benchmark runner exists, and the current tracked report covers one registered benchmark, `hexyl`; that tracked run timed out

Those are the right foundations, but they are not enough for a world-class claim yet.

## Non-negotiable gates

### 1. Multiple-codebase corpus gate

Treat this as a release gate, not a later improvement.

Before claiming world-class reconstruction or integration quality, REVENG should have a tracked corpus that includes:

- at least 5 native benchmarks across multiple codebases and implementation styles
- at least 2 live Bun executables
- at least 2 negative controls
- at least 1 golden JavaScript deobfuscation flow

Every corpus entry should record:

- sample identity and hashes
- expected CLI behaviors
- expected validation grade
- artifact locations
- report status over time

### 2. Evidence gate

No AI-generated statement should stand alone. Every important conclusion must link back to evidence, provenance, and reproducible artifacts.

### 3. Validation gate

Compilation alone is not success. Reconstruction claims should be graded as compile-only, structural candidate, partial equivalence, or behavior-matched.

### 4. Contract gate

CLI, API, and MCP outputs must remain stable, versioned, and regression-tested.

## Phased implementation plan

Durations below are planning estimates for sequencing and staffing. They are not current repo facts.

### Phase 0: trustworthy baseline

Planning guidance: 2-3 weeks

Goals:

- make CI trustworthy
- freeze a minimum no-regression suite
- capture current behavior before major refactors

Concrete work:

- quarantine flaky tests and environment-heavy tests that cannot gate merges
- require fast unit, CLI characterization, API schema, MCP contract, one golden binary flow, one JS flow, and one reconstruction flow on every merge
- publish a dated status snapshot so docs, reports, and product claims match tracked evidence

Exit criteria:

- merges are blocked on a stable baseline suite
- known failures are explicit, not hidden in noise

### Phase 1: corpus-first regression net

Planning guidance: 2-4 weeks

Goals:

- make multiple codebases part of the platform definition
- turn current benchmark scripts into real product gates

Concrete work:

- expand `.reveng/source_binary_benchmarks.json` beyond `hexyl`
- add representative C, C++, Rust, and Windows-native binaries with behavior checks
- expand the Bun matrix from one live sample to at least two live anchors
- add negative controls and record expected non-routing behavior
- publish nightly and per-merge benchmark reports

Exit criteria:

- benchmark reports cover multiple codebases, not one hero sample
- tracked reports can show both progress and regressions honestly

### Phase 2: evidence and schema spine

Planning guidance: 3-4 weeks

Goals:

- make evidence a first-class data model
- unify result, provenance, and artifact references across surfaces

Concrete work:

- define a versioned evidence schema beside the existing result contracts
- add repository interfaces for sample, evidence, validation, and reporting
- require evidence identifiers in AI summaries, validation reports, and MCP responses
- preserve sample hashes, environment metadata, and stage provenance in every major run

Exit criteria:

- every major result can be traced to supporting artifacts
- serialization is stable across CLI, API, and MCP

### Phase 3: reconstruction and equivalence hardening

Planning guidance: 4-6 weeks

Goals:

- improve the platform's differentiator
- make reconstruction outcomes measurable and explainable

Concrete work:

- implement the reusable normalization fixes already documented in `HARDENING_PRIORITIES.md`
- rerun the tracked `hexyl` frontier and fold successful fixes into regression tests
- add deterministic behavior harnesses where possible
- surface validation grades and reasons directly in reports

Exit criteria:

- reconstruction failures are explainable
- reconstruction successes are backed by explicit validation grades

### Phase 4: bounded contexts inside the monolith

Planning guidance: 2-4 weeks

Goals:

- reduce structural overlap before extracting services
- keep `REVENGAnalyzer` working while internals become composable

Concrete work:

- reconcile overlapping orchestration areas such as `pipeline/` and `pipelines/`
- extract ports for static analysis, decompilation, AI enrichment, reconstruction, validation, and reporting
- replace deep internal coupling with contract-tested adapters

Exit criteria:

- major workflows depend on interfaces rather than direct cross-package reach-through

### Phase 5: heavy worker extraction

Planning guidance: 4-6 weeks

Goals:

- isolate expensive and risky operations
- scale by worker type rather than one large process

Concrete work:

- extract Ghidra, dynamic analysis, and compilation/equivalence workers first
- add queue, retry, timeout, idempotency, and cancellation tests
- keep artifacts and provenance stable across process boundaries

Exit criteria:

- heavy failures are isolated and observable
- the control plane remains thin and predictable

### Phase 6: MCP and AI productization

Planning guidance: 3-5 weeks

Goals:

- make agent-facing integration stable
- make Ollama-backed workflows operationally trustworthy

Concrete work:

- version MCP tool schemas, prompts, and resources
- add streaming progress events and evidence-oriented resource references
- make model routing explicit by task
- record prompt, context, model, and output provenance for every AI stage

Exit criteria:

- MCP becomes a stable product surface
- AI outputs remain policy-aware and evidence-linked

### Phase 7: analyst review and governance

Planning guidance: 4-6 weeks

Goals:

- support serious investigations rather than one-shot runs
- make review, approval, and auditability normal behavior

Concrete work:

- add analyst review workspace and case export flows
- add approval hooks for sensitive actions
- add redaction, retention, and audit-log completeness checks

Exit criteria:

- analysts can review evidence, not just generated summaries
- governance is part of the platform, not an external process

### Phase 8: production discipline

Planning guidance: ongoing

Goals:

- keep the platform honest under change
- make progress measurable over time

Concrete work:

- add benchmark trend dashboards and release gates
- publish recurring status snapshots tied to tracked artifacts
- set release criteria for performance, validation coverage, and contract stability
- harden deployment for gateway and worker topologies

Exit criteria:

- releases are tied to evidence, not aspiration

## What done should mean

REVENG can reasonably call itself world class when:

- multiple independent codebases pass tracked validation loops
- major claims are evidence-backed and reproducible
- reconstruction quality is measured by validation outcomes, not readability alone
- CLI, API, and MCP surfaces stay stable under regression pressure
- heavy analysis runs in isolated, observable workers
- analysts stay in control of sensitive actions and final judgments

## Summary

The correct path is not feature sprawl. It is disciplined trust-building:

1. establish a trustworthy baseline
2. make the multiple-codebase corpus a first-class gate
3. build the evidence spine
4. harden reconstruction and validation
5. extract workers only after contracts are stable
6. productize MCP, AI routing, and analyst review on top of that base
