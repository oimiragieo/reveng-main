# Architecture Overview

REVENG is composed of loosely coupled packages that cooperate via explicit interfaces and shared data contracts. The core principles are modularity, lazy loading of optional capabilities, and deterministic orchestration for AI agents.

## High-Level Layers

1. **Pipeline Core (`reveng.analyzer`, `reveng.pipeline`)**
   - Provides the state machine that executes analysis steps.
   - Defines shared dataclasses and helpers used by step implementations.
2. **Analyzer Steps (`reveng.pipeline.steps`)**
   - Each phase (disassembly, enrichment, vulnerability discovery, threat intelligence, reporting) is implemented as a standalone function.
   - Steps receive the analyzer context, making them easy to extend or replace.
3. **Agents (`reveng.agents`)**
   - Houses automation and AI helpers such as the natural-language interface and advanced triage engine.
   - Interfaces are JSON-serialisable so autonomous systems can orchestrate runs and consume output.
4. **Security Analytics (`reveng.security`)**
   - ML pipelines, heuristics, and correlators for malware classification, vulnerability prediction, and APT attribution.
   - Uses defensive optional imports so the platform gracefully degrades when heavy dependencies are absent.
5. **Reporting (`reveng.reporting`)**
   - Visualization and executive-report generators for analysts and stakeholders.
   - Integrates with external graph stacks only when required.
6. **Integrations (`reveng.integrations`)**
   - Connectors for Ghidra MCP and other tooling, exposed through service classes to avoid direct third-party coupling.

## Execution Model

```
CLI / API / Agent
        │
        ▼
REVENGAnalyzer  ──▶ Pipeline Steps (reveng.pipeline.steps)
        │
        ├─ Uses reveng.integrations for tooling I/O
        ├─ Calls reveng.security for analytics
        └─ Publishes artefacts through reveng.reporting
```

Each package is documented in more detail in the [package map](package-map.md). For data flow between steps refer to the [pipeline documentation](pipeline.md).
