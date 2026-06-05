# REVENG TDD implementation backlog

## Purpose

This document translates the earlier architecture findings into a tests-first implementation plan. It is intentionally more concrete than the high-level microservices plan. The goal is to implement the identified fixes in a sequence that improves trust, preserves current behavior where intended, and minimizes regression risk.

## Research basis

This plan is informed by two inputs:

1. direct inspection of the REVENG repository and earlier architecture findings
2. external TDD and modernization guidance emphasizing:
   - characterization tests for legacy behavior capture
   - contract tests before service extraction
   - golden and approval tests for complex outputs
   - incremental strangler-style migration rather than a big-bang rewrite
   - CI-enforced anti-regression gates during decomposition

## Findings to fix

The earlier deep dive identified the following high-priority issues:

1. the current test baseline is not clean enough to support aggressive refactoring
2. the platform lacks a single evidence and provenance model
3. `pipeline/` and `pipelines/` indicate overlapping orchestration seams
4. service boundaries are weak even though the repository is aiming toward an enterprise platform
5. AI stages need stronger evidence grounding
6. recompilation and similarity validation need to be elevated from feature claims to first-class quality gates
7. MCP needs a more stable contract and capability model
8. Ollama support exists, but needs stronger operational routing and validation
9. analyst review, governance, and policy enforcement should be built into the architecture

## TDD rules for the whole program

Every epic below follows the same rule set:

### Red

- write or extend tests that expose the gap
- capture current behavior before changing internals
- codify both success paths and failure paths

### Green

- make the smallest implementation change that satisfies the new tests
- preserve existing public behavior unless the epic explicitly changes it

### Refactor

- simplify internals only after tests pass
- keep public contracts versioned
- rerun characterization, contract, and integration suites after each refactor slice

## Anti-regression gates

No epic should be considered complete unless all of the following pass:

- characterization tests for existing CLI and API behavior
- contract tests for any changed interface
- integration tests for at least one end-to-end analysis flow
- golden artifact checks for representative samples
- nonfunctional checks relevant to the change, such as performance, timeout, or memory

## Epic 0: establish a trustworthy baseline

### Goal

Make the current repository testable enough to support controlled change.

### Problems addressed

- existing collection failures in performance tests
- inconsistent confidence in the test suite as a release gate

### Tests to write first

- characterization tests for:
  - `reveng --help`
  - core CLI subcommands
  - `REVENGAPI.analyze_binary()`
  - `REVENG_AI_API.triage_binary()`
  - MCP initialize and tool-list flows
- regression tests that reproduce the current performance-test nesting issue in a minimal isolated way
- smoke tests for docs-referenced commands

### Implementation steps

1. quarantine or refactor the problematic performance tests into flatter helper-based structures
2. separate smoke, unit, integration, performance, and experimental suites clearly
3. define a baseline CI profile that must pass before feature work continues

### Exit criteria

- the repository has a stable default test target
- unstable or long-running suites are isolated but not lost
- CLI and API characterization coverage exists for core flows

## Epic 1: define canonical result schemas

### Goal

Create a versioned schema for analysis, reconstruction, and validation outputs.

### Problems addressed

- inconsistent structured outputs across analyzer, APIs, and future services
- weak contracts for future extraction

### Tests to write first

- schema validation tests for analyzer results
- schema snapshot tests for `REVENGAPI`
- schema snapshot tests for `REVENG_AI_API`
- backward-compatibility tests for key fields already exposed in docs

### Implementation steps

1. define schema modules for:
   - analysis result
   - reconstruction result
   - vulnerability result
   - validation result
   - MCP tool payloads
2. add serialization tests for JSON round-tripping
3. update existing APIs to emit versioned schema objects or dictionaries derived from them

### Exit criteria

- every public result shape is explicit and versioned
- future service boundaries can reuse those contracts directly

## Epic 2: introduce evidence and provenance

### Goal

Make evidence a first-class architectural concept.

### Problems addressed

- no unified model linking static findings, dynamic traces, AI outputs, and validation results
- weak explainability for analyst-facing and AI-facing conclusions

### Tests to write first

- evidence graph creation tests
- provenance immutability tests
- artifact linkage tests
- confidence propagation tests
- tests proving that AI outputs reference specific evidence identifiers

### Implementation steps

1. define entities for sample, artifact, finding, assertion, provenance event, and confidence
2. introduce an evidence repository interface
3. update the analyzer to record evidence as steps complete
4. expose evidence references in API and MCP responses

### Exit criteria

- every major finding can be traced to supporting artifacts
- evidence references survive serialization and cross-service boundaries

## Epic 3: split bounded contexts inside the monolith

### Goal

Refactor toward a modular monolith before extracting services.

### Problems addressed

- weak service boundaries
- subsystem sprawl
- deep imports across unrelated concerns

### Tests to write first

- port and adapter tests for each planned boundary
- dependency-direction tests
- module import boundary tests
- contract tests for analyzer-facing ports

### Implementation steps

1. define ports for static analysis, decompilation, AI enrichment, reconstruction, validation, reporting, and evidence
2. adapt current implementations behind those ports
3. make `REVENGAnalyzer` depend on the ports, not on deeply nested concrete modules

### Exit criteria

- the analyzer becomes an orchestrator over explicit interfaces
- the repository has bounded contexts suitable for later extraction

## Epic 4: reconcile orchestration layers

### Goal

Unify or clearly separate `pipeline/` and `pipelines/`.

### Problems addressed

- ambiguity around orchestration ownership
- increased maintenance and migration complexity

### Tests to write first

- characterization tests for existing pipeline behaviors
- orchestration DAG tests
- failure-isolation tests
- concurrency tests for asynchronous execution paths

### Implementation steps

1. inventory both packages and map active usage
2. select the canonical orchestration abstraction
3. deprecate or fold overlapping logic behind adapters
4. document the single approved orchestration path

### Exit criteria

- one primary orchestration model exists
- deprecated layers are isolated or removed behind compatibility wrappers

## Epic 5: stabilize MCP as a product surface

### Goal

Turn MCP from an implementation detail into a stable contract.

### Problems addressed

- tool and resource evolution risk
- future service extraction needs stronger contracts

### Tests to write first

- protocol handshake tests
- tool schema snapshot tests
- resource read tests
- prompt template tests
- error contract tests
- progress-event tests

### Implementation steps

1. version MCP tool schemas
2. expose evidence-oriented resources
3. add progress and cancellation semantics consistently
4. define approval hooks for sensitive operations

### Exit criteria

- MCP clients can rely on stable, versioned behavior
- resources and tools align with internal schemas

## Epic 6: harden Ollama and AI routing

### Goal

Make local-model usage operationally robust and evidence-grounded.

### Problems addressed

- implicit model routing
- weak separation between local and cloud AI strategies
- limited validation around AI enrichment behavior

### Tests to write first

- local-model availability tests
- route-selection tests
- prompt-construction tests using retrieved evidence
- output schema tests for enrichment and repair flows
- failure-path tests for unavailable local models

### Implementation steps

1. define an AI routing interface
2. add policy-aware local-versus-cloud routing
3. make Ollama profiles explicit by task
4. record prompt, context, and output provenance

### Exit criteria

- local inference is a first-class, testable path
- AI enrichment outputs are evidence-linked and policy-aware

## Epic 7: elevate reconstruction and validation

### Goal

Make recompilation and equivalence a formal quality gate.

### Problems addressed

- reconstruction success is not yet encoded as a durable validation discipline
- risk of readable but behaviorally misleading recovered code

### Tests to write first

- golden reconstruction tests for selected binaries
- compilation retry-loop tests
- binary metadata comparison tests
- partial-equivalence tests
- deterministic harness tests
- validation-report snapshot tests

### Implementation steps

1. define validation service interfaces
2. collect similarity metrics in a structured schema
3. separate "generated source" from "validated reconstruction"
4. expose validation grades in CLI, API, and MCP results

### Exit criteria

- reconstruction claims always include validation status
- users can distinguish partial, weak, and strong reconstruction outcomes

## Epic 8: extract heavy workers

### Goal

Move long-running and risky workloads out of process.

### Problems addressed

- monolithic runtime pressure
- poor isolation for heavy analysis and sandboxed execution

### Tests to write first

- worker API contract tests
- retry and timeout tests
- idempotency tests
- job-state transition tests
- queue integration tests

### Implementation steps

1. extract Ghidra worker
2. extract dynamic-analysis worker
3. extract compilation and validation worker
4. keep compatibility adapters so the analyzer still works during migration

### Exit criteria

- heavy tasks are isolated and observable
- orchestration can scale by worker type

## Epic 9: analyst review and governance

### Goal

Add enterprise trust controls around the analysis workflow.

### Problems addressed

- lack of explicit review workflow
- need for approval and audit around sensitive actions

### Tests to write first

- analyst-approval workflow tests
- policy enforcement tests
- audit-log completeness tests
- case export integrity tests
- redaction tests

### Implementation steps

1. add analyst review state to cases
2. gate sensitive actions such as exploit-generation workflows
3. add redaction and retention controls
4. export evidence bundles for downstream review

### Exit criteria

- the platform supports professional review and governance workflows

## Recommended implementation order

1. Epic 0: trustworthy baseline
2. Epic 1: canonical schemas
3. Epic 2: evidence and provenance
4. Epic 3: bounded contexts
5. Epic 4: orchestration reconciliation
6. Epic 5: MCP stabilization
7. Epic 6: Ollama and AI routing
8. Epic 7: reconstruction and validation
9. Epic 8: heavy worker extraction
10. Epic 9: analyst review and governance

## Minimum no-regression suite for every merge

- fast unit suite
- core CLI characterization suite
- API schema suite
- MCP contract suite
- one golden binary analysis flow
- one golden JavaScript deobfuscation flow
- one reconstruction validation flow

## Summary

The safest implementation path is to treat REVENG as a modular monolith that must first earn a trustworthy test baseline and explicit contracts. Only then should it move toward service extraction. The central TDD lesson from both the repository and external practice is simple: capture current behavior first, extract behind contracts second, and only then redistribute responsibilities across processes and services.
