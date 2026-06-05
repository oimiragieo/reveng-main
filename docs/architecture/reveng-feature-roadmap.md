# REVENG feature research and improvement roadmap

## Purpose

This document turns codebase analysis plus external research into a concrete feature roadmap. The emphasis is on features that improve trust, reproducibility, scalability, and analyst value rather than just increasing the number of modules.

## Research-informed themes

Recent work on LLM-assisted reverse engineering points to a few repeated themes:

- graph and data-flow context improve model quality
- decompilation quality should be judged by recompilation and behavior, not readability alone
- human analysts need confidence scores and evidence, not unsupported summaries
- local-model and tool-interoperable architectures are increasingly important for privacy and enterprise adoption

Those themes suggest that REVENG should prioritize platform depth over feature sprawl.

## Highest-value features to add

### 1. Evidence graph and provenance ledger

Create a first-class evidence model that stores:

- binary metadata and hashes
- static findings
- control-flow and call-graph exports
- strings, imports, resources, symbols, and recovered types
- dynamic traces and sandbox observations
- LLM prompts, retrieved context, and outputs
- reconstruction attempts and validation results

Why it matters:

- makes AI outputs inspectable
- enables analyst review
- supports auditability for enterprise customers
- provides shared ground truth across services

### 2. Equivalence validation service

Add a dedicated validation workflow for reconstructed outputs:

- compile reconstructed code
- compare exported symbols and sections
- run deterministic harnesses where possible
- compare traces or state transitions
- emit similarity and confidence reports

Why it matters:

- aligns with research that favors recompilability and re-executability
- reduces "hallucinated decompilation" risk
- makes the platform useful for serious rebuild work

### 3. Retrieval-augmented binary context for AI stages

Before asking an LLM to explain or reconstruct code, retrieve:

- CFG and call-graph summaries
- strings and imports
- known library signatures
- malware-family or packer fingerprints
- prior analyst notes

Why it matters:

- moves the platform toward evidence-grounded AI
- aligns with retrieval-enhanced decompilation ideas in current literature

### 4. Service-level Ghidra and dynamic-analysis workers

Separate long-running and heavy dependencies into dedicated workers:

- Ghidra analysis worker
- sandbox and dynamic trace worker
- compilation and validation worker
- LLM enrichment worker

Why it matters:

- improves reliability and scheduling
- isolates risk
- enables queue-based scaling

### 5. Analyst review workspace

Add a human-centered workspace that lets users:

- inspect evidence and findings
- review reconstructed functions
- approve or reject LLM suggestions
- track uncertainty hotspots
- export case packages

Why it matters:

- keeps humans in the loop
- makes the platform suitable for real investigations

### 6. Corpus and benchmark management

Create a benchmark system for known binaries and expected outputs:

- curated sample corpora
- expected imports, strings, or behaviors
- expected function maps for selected targets
- expected reconstruction and validation scores

Why it matters:

- enables TDD for reverse engineering
- prevents regressions during refactors
- gives objective progress metrics

### 7. Policy and safety guardrails

Expand responsible-use and execution controls:

- sample classification and handling policy
- exploit-generation authorization gates
- network egress restrictions for sandbox workers
- redaction and case-retention policies

Why it matters:

- reverse-engineering platforms need trust and policy enforcement
- important for enterprise adoption

### 8. Better MCP productization

Improve the MCP surface with:

- stable tool schemas
- versioned capabilities
- streaming progress events
- evidence-resource URIs
- analyst approval hooks for sensitive tools

Why it matters:

- makes REVENG more useful as an AI tool backend
- fits the protocol's strengths around tools, prompts, and resources

### 9. Stronger local-model orchestration

Deepen Ollama support with:

- model profiles by task
- fallback routing
- token and latency accounting
- prompt templates tuned for decompiler enhancement and analyst Q&A

Why it matters:

- keeps privacy-sensitive work local
- makes local inference operationally usable

### 10. Recompilation developer kit

Add a rebuild SDK around the existing reconstruction ambition:

- compiler profiles
- platform-specific shims
- stub replacement strategies
- artifact comparison tools
- reproducible build recipes

Why it matters:

- directly supports the codebase's defining goal of open-source-grade reconstruction

## Prioritized feature sequence

Implementation note:

- treat multiple-codebase corpus coverage as a release gate, not as a later optimization
- use the execution order and evidence-backed qualifiers in `reveng-world-class-implementation-roadmap.md`

### Foundation

1. evidence graph and provenance ledger
2. corpus and benchmark management
3. equivalence validation service

### Platform hardening

4. service-level Ghidra, sandbox, and validation workers
5. better MCP productization
6. stronger local-model orchestration

### Analyst experience

7. analyst review workspace
8. case export and evidence packaging
9. policy and safety controls

### Advanced reconstruction

10. retrieval-augmented AI reconstruction
11. recompilation developer kit
12. cross-binary diff and patch provenance workflows

## Reverse-engineering best practices to bake into every feature

- never present an AI inference without citing its supporting evidence
- preserve the original sample hash and analysis environment metadata
- separate untrusted sample execution from control-plane services
- favor deterministic analysis steps before probabilistic ones
- track confidence by artifact, not just by overall run
- require equivalence or partial-equivalence checks before claiming successful reconstruction
- keep analysts in control of exploit or active-testing paths
- export machine-readable artifacts for reproducibility

## Summary

The best path forward is not "more features everywhere." It is a smaller number of foundational capabilities that make all higher-level features more trustworthy: evidence, validation, service isolation, local-model orchestration, and human review.
