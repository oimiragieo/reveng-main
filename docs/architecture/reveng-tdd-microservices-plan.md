# REVENG TDD refactor plan for an enterprise microservice platform

## Goal

Refactor REVENG from a broad modular monolith into a microservice-oriented enterprise platform that:

- supports human analysts and AI agents equally well
- exposes stable MCP capabilities
- supports local-model execution with Ollama
- preserves reverse-engineering evidence and provenance
- reconstructs and recompiles binaries with measurable validation

This is a plan, not an implementation.

## Target architecture

### Control plane

- **API gateway service**
  - external REST and WebSocket entry point
  - authentication, rate limiting, tenancy, request tracing
- **MCP gateway service**
  - stable MCP tools, prompts, and resources
  - transport support for stdio and HTTP
  - approval hooks for sensitive actions
- **Workflow orchestrator**
  - case lifecycle
  - job scheduling
  - dependency tracking
  - retry policies

### Analysis plane

- **ingestion service**
  - sample intake
  - hashing
  - metadata extraction
  - storage registration
- **static analysis service**
  - file typing
  - strings, imports, sections, entropy, resource extraction
- **ghidra worker service**
  - decompilation
  - symbol extraction
  - CFG and call-graph export
- **dynamic analysis service**
  - sandbox execution
  - trace capture
  - IOC extraction
- **AI enrichment service**
  - Ollama and optional cloud-model routing
  - retrieval-augmented prompts
  - structured semantic summaries
- **reconstruction service**
  - source generation
  - missing-stub strategies
  - type-recovery integration
- **compilation and equivalence service**
  - rebuild attempts
  - behavior comparison
  - similarity scoring
- **reporting service**
  - analyst reports
  - case exports
  - evidence bundles

### Shared platform services

- **artifact store**
  - raw samples
  - intermediate artifacts
  - reconstructed outputs
- **evidence graph store**
  - provenance, references, and confidence
- **policy service**
  - legal, ethical, and approval controls
- **observability service**
  - audit logs
  - metrics
  - traces

## Refactor principles

- keep the current `REVENGAnalyzer` functioning during migration
- extract capabilities behind interfaces before moving them to services
- use contract tests before cross-process extraction
- do not move AI stages ahead of deterministic evidence stages
- treat recompilation and equivalence as validation services, not optional polish

## TDD strategy

### Phase 0: baseline and safety net

Before extracting anything:

1. fix or quarantine unstable pre-existing tests so the suite can act as a gate
2. create golden-case fixtures for representative binaries and JS samples
3. define a canonical analysis result schema
4. capture current CLI and API behavior with characterization tests

Tests to add first:

- CLI contract tests for `analyze`, `decompile`, `recompile`, and MCP startup
- API contract tests for `REVENGAPI` and `REVENG_AI_API`
- artifact-layout tests for `analysis_<binary>/`
- error-path tests for missing Ghidra, missing Ollama, and invalid samples

### Phase 1: domain boundaries inside the monolith

Extract interfaces without changing deployment shape:

- `SampleRepository`
- `EvidenceRepository`
- `StaticAnalysisPort`
- `DecompilerPort`
- `AIEnrichmentPort`
- `ReconstructionPort`
- `ValidationPort`
- `ReportPort`

Tests to drive the extraction:

- unit tests per port using in-memory adapters
- service-level tests for structured results and errors
- schema tests ensuring all outputs are JSON-serializable and versioned

Exit criteria:

- analyzer depends on interfaces rather than deep imports
- outputs remain backward-compatible

### Phase 2: evidence-first architecture

Introduce a shared evidence model:

- sample
- finding
- artifact
- relation
- assertion
- confidence
- provenance event

Tests to write first:

- evidence creation and linkage tests
- provenance immutability tests
- confidence propagation tests
- serialization and migration tests

Exit criteria:

- every major analysis result is backed by evidence entries
- AI outputs reference source artifacts

### Phase 3: worker extraction

Extract the first workers:

- Ghidra worker
- dynamic-analysis worker
- compilation and equivalence worker

Tests to write first:

- contract tests for each worker API
- queue and retry tests
- idempotency tests for repeated job submission
- timeouts and cancellation tests

Exit criteria:

- heavy analysis steps run out-of-process
- failures are isolated and observable

### Phase 4: MCP stabilization

Make MCP a stable product surface rather than a thin adapter.

Tests to write first:

- MCP protocol handshake tests
- tool schema snapshot tests
- resource URI tests
- approval-flow tests for sensitive tools
- streaming progress tests

Exit criteria:

- versioned tool contracts
- stable resources and prompts
- safe defaults for high-risk actions

### Phase 5: Ollama and AI routing

Add a dedicated AI service with policy-aware routing.

Tests to write first:

- local-model availability tests
- route-selection tests by task type
- prompt-construction tests using retrieved evidence
- output-schema tests for summaries, renaming hints, and reconstruction suggestions

Exit criteria:

- Ollama is first-class
- cloud models are optional policy-controlled fallbacks
- all AI outputs remain evidence-linked

### Phase 6: reconstruction and recompilation hardening

Focus on the platform's differentiator.

Tests to write first:

- golden reconstruction tests for selected binaries
- compiler retry-loop tests
- partial-equivalence tests
- deterministic harness tests where behavior is known
- report tests that show why reconstruction passed or failed

Exit criteria:

- reconstruction claims are tied to measurable outcomes
- failures are explainable, not opaque

### Phase 7: analyst experience and governance

Add user-facing review and governance workflows.

Tests to write first:

- analyst approval workflow tests
- case export integrity tests
- redaction tests
- audit-log completeness tests

Exit criteria:

- platform supports professional analyst workflows
- governance is part of normal operation

## Proposed service contracts

Each service should follow the same principles:

- explicit request and response schemas
- correlation IDs
- machine-readable errors
- progress events
- artifact references instead of giant inline payloads

Example core request types:

- `CreateCase`
- `IngestSample`
- `RunStaticAnalysis`
- `RunDecompiler`
- `RunAIEnrichment`
- `RunReconstruction`
- `RunEquivalenceValidation`
- `GenerateCaseReport`

## Test matrix

The future test suite should be organized as:

- **unit tests** for parsers, mappers, schema validators, and scoring logic
- **contract tests** for service APIs and MCP tools
- **golden-case tests** for representative binaries
- **integration tests** for end-to-end case flows
- **nonfunctional tests** for performance, memory, timeout, and concurrency
- **security tests** for sandbox boundaries, authz, and policy enforcement

## Initial repository changes recommended before any major refactor

1. normalize documentation around one authoritative architecture and one authoritative API surface
2. clean up test failures so CI is trustworthy
3. identify duplicate or overlapping modules in `pipeline/` and `pipelines/`
4. define a versioned analysis-result schema
5. define a versioned evidence schema
6. add golden binary fixtures and expected outputs

## What "done" should mean

The refactor is successful when:

- analysts can ingest a binary and trace every conclusion back to evidence
- MCP clients can use stable tools with predictable schemas
- Ollama-backed local workflows are production-ready
- reconstructed outputs are validated against the original binary
- the system scales by worker type rather than by one giant process
- tests prove both functional correctness and trustworthiness

## Summary

The correct TDD path is to extract bounded contexts gradually, beginning with contracts and evidence, then splitting heavy workers, then stabilizing MCP and AI routing, and finally hardening reconstruction and analyst review. That path preserves today's usable core while moving the repository toward a real enterprise platform.
