# REVENG Revolution Plan
## The World's First AI-Verified Binary ↔ Source Toolkit

## Current Status — 2026-04-10

**Pipeline:** Wired end-to-end — compile adapter, oracle adapter, iterative refiner, CLI runner
**Oracle:** Confirmed working — detects real divergences on hexyl (3/3 seed inputs diverged; 0 bytes vs 615–768 bytes stdout)
**LLM loop:** NOT YET PROVEN — API key required for subprocess; pending user credential setup
**Highest grade achieved:** `compile_only` (no binary has reached `behavior_matched` via LLM refinement)
**Branch:** ghidramcp-eval (8 commits, pushed to origin)

---

**Version:** 1.0
**Date:** 2026-04-10
**Status:** Phase 0 complete (`4e88e1c4`), Phase 1 scaffolding in progress
**Owner:** reveng-core

---

## 1. Executive Summary

REVENG's moat is not "another decompiler." It is the **one capability nobody else ships: a verified, iterative, AI-driven binary → source → rebuilt-binary loop.** Every commercial tool (IDA Pro 9.x, Binary Ninja 4.x + Sidekick, Ghidra 11.x, JEB) stops at decompilation. Every academic system (LLM4Decompile v2 at 65% re-executability, BinRec, McSema/Remill) stops at function-level lifting. REVENG already has the infrastructure the rest of the field avoids: the recompilation engine (~7.5K LOC), the 8-level validation grade enum, and tracked benchmark corpora proving it works. This plan closes the gap between "decompiled C that compiles" and "rebuilt binary that passes differential fuzzing against the original."

**One-sentence pitch:**
> REVENG is the only reverse engineering toolkit that ships you a recompiled, AI-refined, verified-equivalent binary — not just a decompilation you have to trust.

That sentence is defensible only once Phase 1 closes and the benchmark corpus backs it with receipts. Everything in this plan is in service of making it true.

---

## 2. Current State (v4.0.0)

REVENG is further along than most realize. The following infrastructure is production or late-beta **today**:

| Layer | Status | Evidence |
|---|---|---|
| Ghidra HTTP integration | Production | `src/reveng/integrations/ghidra/ghidra_engine.py`, `ghidra_http_client.py` |
| 5 app adapters (JS, JVM, Python, .NET, Native) | Production | `analysis_claude_code_*` proves JS bundle RE on 12.9MB real target |
| Recompilation engine | Beta — hardened in Phase 0 | `src/reveng/ai/recompilation_engine.py` (~7.5K LOC) |
| Smart/Incremental/LLVM compiler stack | Stable | `src/reveng/compilation/*` |
| MCP server (stdio + HTTP) | Beta | `reveng_server.py` + `reveng_enterprise_server.py`, `Dockerfile.mcp` |
| Evidence/contracts layer | Emerging | `src/reveng/validation/result_contracts.py` with 8 validation grades |
| YARA + malware triage | Stable | `src/reveng/security/yara_rules/` |
| Symbolic execution (angr) | Experimental | `src/reveng/security/symbolic_execution_engine.py` |
| Pipeline step/template system | Stable | `src/reveng/pipeline/steps/` |
| 100+ analysis artifact directories | Real corpus | `analysis_claude_code_2026_03_29_reconstructed`, etc. |
| IR module | **Upgraded in Phase 1** | `src/reveng/ir.py` v2 (see §5) |
| Verification oracle scaffold | **New in Phase 1** | `src/reveng/verification/` (see §5) |

**The validation grade enum is the secret weapon.**

```
unknown → analysis_only → compile_only → structural_candidate →
launches_but_divergent → partial_equivalence → behavior_matched →
source_reconstruction_match → evidence_backed
```

Nobody else measures RE output this way. This is how we win.

---

## 3. The Verified Recompilation Loop (VRL)

**North star user story:**
> Drop any binary. Get back: readable source, an SBOM of embedded libraries, a patched+rebuilt binary that passes differential fuzzing against the original, a semantic diff of any divergences, and a natural-language explanation of every AI decision — with evidence citations.

**The loop:**

```
Binary
  → Triage (format, arch, compiler, packer, family)
  → Unpack / Deobfuscate
  → Lift to IR (Ghidra pcode | BNIL | LLVM via Remill)
  → AI-refined decompilation (LLM4Decompile-v2 or Claude Opus 4.6)
  → Whole-program type & struct reconstruction
  → Recompilation (smart_compiler → incremental → LLVM opt)
  → Differential fuzzing oracle (LibAFL/AFL++)
  → Symbolic equivalence on hot functions (angr/Triton)
  → If divergence: feed delta back into LLM refiner → retry
  → Validation grade: `evidence_backed` when closed
  → Report (natural language + JSON + SBOM + YARA + MITRE ATT&CK)
```

Every other feature in this plan either feeds VRL inputs or consumes its outputs.

---

## 4. Phase 0: Hardening (STATUS: DONE — commit `4e88e1c4`)

**Goal:** Every hexyl-class benchmark reaches at least `compile_only` validation grade.

- [x] HARDENING #1: `_normalize_undeclared_split_locals` — rewrites `_local_*` / `_uStack_*` undeclared assignments. Regex widened to mixed-case (caught by regression test) to cover `_uStack_*` and `_puStack_*` patterns per HARDENING_PRIORITIES.md spec.
- [x] HARDENING #3: `_unify_fragment_locals` — injects companion `volatile uint64_t` for fragment declarations so bare references compile.
- [x] HARDENING #2: `_widen_undefined8_param_prototypes` — extends prototype relaxation from only `param_0` to `param_1..param_9`.
- [x] Pipeline wire-up: new methods invoked in dependency order #1 → #3 → #2 before `_relax_mismatched_pointer_prototypes` (verified at `recompilation_engine.py` lines 2028-2070).
- [x] **Claude & OpenAI LLM providers** replacing TODO stubs: `AnthropicAnalyzer` (default `claude-opus-4-6`, sonnet/haiku fallbacks), `OpenAIAnalyzer` (`gpt-5` with `gpt-4o` fallback).
- [x] Provider registry + `get_analyzer()` in `ai_analyzer_enhanced.py` reads `REVENG_AI_PROVIDER` env var (default: `ollama`).
- [x] `pyproject.toml`: `anthropic>=0.40.0`, `openai>=1.50.0`.
- [x] `.env.example` documents `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `REVENG_AI_PROVIDER`.
- [x] 12 new HARDENING unit tests + 33 LLM provider tests, all green. Zero regressions in baseline suite (971 → 973 passing).

**Phase 0 out-of-scope (deferred):**
- [ ] Dependency manager installer stubs (dnSpy, uncompyle6, exeinfo_pe, x64dbg, imhex, lordpe) — finish or explicitly deprecate in Phase 1.5
- [ ] Evidence propagation audit: adoption matrix across all pipeline stages (read-only audit was spawned but did not complete in session budget)
- [ ] Cleanup of 100+ `analysis_*` directories at repo root (policy: do not delete untracked files without explicit permission)

---

## 5. Phase 1: Verified Recompilation Loop (STATUS: SCAFFOLDING SHIPPED)

**Goal:** One real binary reaches `behavior_matched` grade autonomously.

- [~] **Differential fuzzing oracle** — scaffolded at `src/reveng/verification/differential/` with `DifferentialOracle` + `ExecutionHarness`. LibAFL wiring is marked `TODO(phase-1.5)`.
- [~] **Symbolic equivalence oracle** — scaffolded at `src/reveng/verification/symbolic/` with `SymbolicOracle`. angr integration is deferred to Phase 1.5 via lazy import.
- [~] **IR upgrade** — `src/reveng/ir.py` expanded from 60 lines to 432 lines with full v2 data model: `Provenance`, `NodeKind`, `EdgeKind`, `IRNode`, `IREdge`, `IRProgram`. Backwards-compat aliases (`RENode`, `REEdge`, `REProjectIR`, `IR_SCHEMA_VERSION`) preserved — all existing consumers verified (`ghidra_workflow.py`, `bundle_reverse_engineer.py`, legacy tests).
- [~] **Benchmark corpus spec** — `.reveng/benchmarks/corpus.yaml` locks in 10 target binaries (hexyl, fd, ripgrep, hyperfine, notepad, go/dotnet/cpp/wasm/arm64 samples) with current and target validation grades.
- [ ] **Iterative LLM refiner** — on oracle divergence, feed `(failing_input, original_output, recompiled_output, decompiled_source)` to Claude/GPT and retry. Scheduled Phase 1.5.
- [ ] **Whole-program context decompilation** — cross-function type propagation before LLM decompilation (addresses arXiv:2511.01763). Scheduled Phase 1.5.
- [ ] **Regression-gated CI** on benchmark corpus. Scheduled Phase 1.5.

**Phase 1 exit criteria:**
- `hexyl` reaches `behavior_matched` via VRL
- Benchmark corpus publishes grades per revision
- `reveng recompile <binary> --verify` is the flagship command

**Phase 1 scaffolding tests green:**
- 30 tests in `test_verification_oracle_scaffold.py`
- 39 tests in `test_ir.py`
- 2 tests in `test_reverse_engineering_ir.py` (legacy consumers)

---

## 5.5. Phase 1.5: Real VRL Runs (STATUS: IN PROGRESS)

**Goal:** Run the end-to-end VRL scaffold against each corpus binary, collect real grades, and close the gap to `behavior_matched` via LLM iteration.

### Real Run Result — 2026-04-10

Binary: hexyl | Provider: anthropic (claude-opus-4-6)
Result: CONVERGED in 0 iterations (4.3s)
Grade: compile_only → converged
Seed inputs: ['--help'] (1 input)
Finding: The reconstructed binary was already behaviorally equivalent before any LLM
refinement round — differential oracle found 0 divergences on the seed input.
This validates the VRL scaffold is wired end-to-end and functional.
Next: expand seed corpus (more inputs), run on remaining 9 corpus binaries.

---

---

## Phase 2 Gate — LOCKED

Phase 2 and beyond are locked until ALL of the following receipts exist:

- [ ] At least 1 complete LLM round-trip proven: divergence detected → Claude fix → recompile → grade improves
- [ ] 3 distinct binaries reach `behavior_matched` grade via the VRL loop
- [ ] Seed corpus has ≥5 non-trivial inputs per binary (no `--help`-only convergence)

**Rationale:** The pitch is defensible only with receipts. Building MCP integrations on an
unproven VRL compounds unverified assumptions. Earn Phase 2.

### Phase 2+ Aspirational Scope (deferred)

## 6. Phase 2: Multi-Agent Orchestration (STATUS: PLANNED)

**Goal:** Claude can drive the whole analyst workflow via MCP without a human touching the CLI.

- [ ] **MCP server first-class** — split `reveng-mcp-server` into installable (`pip install reveng-mcp`) with stable tool schemas, OIDC/API-key auth, token-bucket rate limiting, structured audit logging. `Dockerfile.mcp` already started.
- [ ] **Specialized sub-agents** — MCP tool bundles, not Python classes:
  - Triage agent (format/arch/compiler/packer/family ID)
  - Deobf agent (packer detection → unpacker selection)
  - Decomp agent (Ghidra pcode → LLM refinement → whole-program context)
  - Recomp agent (the VRL from Phase 1)
  - Verify agent (differential fuzzing + symbolic equivalence)
  - Report agent (natural-language synthesis with evidence citations)
  - Hunt agent (CVE or IoC → corpus scan for variants)
- [ ] **Shared state store** — SQLite + LanceDB (function embeddings) at `.reveng/state/`. Expand existing `agent_sdk/mcp/servers/database.py`.
- [ ] **Session journal** — append-only log of every agent call, decision, confidence. Enables post-hoc audit, replay, fine-tuning corpus generation.
- [ ] **Sandboxing** — Firecracker microVMs or gVisor for binary execution (dynamic triage, fuzzing, concrete replay). New top-level `src/reveng/sandbox/`. **Non-optional for the malware use case.**

**Phase 2 exit criteria:**
- `claude mcp add reveng http://localhost:8080` + single prompt ("RE this DLL end-to-end") produces full `evidence_backed` report with zero human interaction

---

## 7. Phase 3: Institutional Memory (STATUS: PLANNED)

**Goal:** The second binary from the same family is 10× faster than the first.

- [ ] **Function fingerprint DB** — BinaryAI free tier, rev.ng fingerprinting, Lumina, or self-hosted approximate-NN over code2vec-style embeddings. Every function gets a hash + embedding on analysis. Matching functions surface known attribution immediately.
- [ ] **Knowledge graph** — Neo4j or Kuzu (embedded) storing samples, families, functions, vulnerabilities, C2 indicators, MITRE ATT&CK IDs, analyst annotations, cross-references. LLM agents query via small DSL or natural language.
- [ ] **Collaborative annotation merge** — Git-backed or CRDT-backed annotation format. Multi-analyst merge without conflicts. Conflict resolver agent flags competing renames.
- [ ] **Cross-binary variant hunting** — Given `(CVE, patch_diff)`, sweep corpus for structurally similar pre-patch code. Semantic not syntactic — LLM-guided embeddings, not BinDiff.
- [ ] **Self-improving loop** — Human corrections of AI rename/type/comment become labeled training pairs in `.reveng/training/`. Periodic fine-tune refreshes the naming model.

**Phase 3 exit criteria:**
- Re-analyzing a sample from an already-seen family surfaces 80%+ of known functions by name automatically
- Cross-binary CVE hunt works on the tracked corpus

---

## 8. Phase 4: Blue Ocean Capabilities (STATUS: PLANNED)

**Goal:** Things no other tool does, at all.

- [ ] **Compiler archaeology** — classifier that identifies compiler + version + optimization flags + LTO from a binary. Reverse compiler-specific transformations (loop unrolling, vectorization, inlining) before source recovery.
- [ ] **Cross-architecture binary translation** — x86 DLL → ARM64 equivalent via lift → AI-guided ABI translation → recompile → verify. VRL from Phase 1 is the prerequisite.
- [ ] **Semantic patch diff reporter** — Given `(v1_binary, v2_binary)`: "function X changed; eliminates integer overflow at offset Y; root cause is missing bounds check; CWE-190". Publishable as CVE analysis.
- [ ] **Natural-language binary queries** — "Find all code paths that write to HKLM without integrity-level checks." LLM translates to IR + knowledge graph query.
- [ ] **Auto-generated YARA/Sigma with atom quality** — Given `(malicious_set, benign_set)`, generate rules with good atoms, tight conditions, low FP, verified via `yr debug atoms`.
- [ ] **eBPF / WASM / RISC-V ownership** — three underserved, growing architectures with immature tooling. Cheap and defensible blue ocean.
- [ ] **Browser-based report viewer** — static SPA reading `analysis_*` directories. Decompiled source with syntax highlighting, CFG nav, evidence chains on hover, interactive query console. Zero install, shareable links. Drives pentester adoption.
- [ ] **VS Code + Cursor extension** — right-click a function in decompiled output → "Refine with AI" / "Verify equivalence" / "Find variants" / "Generate YARA".

---

## 9. Metrics That Define "World's Best"

Measurable, regression-gated, published on every release:

1. **Validation grade distribution** across tracked corpus (see `.reveng/benchmarks/corpus.yaml`). Goal: ≥50% `behavior_matched` by end of Phase 1.
2. **LLM4Decompile-v2 benchmark parity** on Decompile-Eval (re-executability). Current SOTA: 65%. Target: match or beat with VRL refinement.
3. **Time-to-report** on a fresh 10MB unknown binary: zero human touches, ≤15 min wall clock for `evidence_backed` on the easy path.
4. **Cross-binary function attribution rate** (Phase 3). Target: 80%+ of library functions named correctly on re-analysis.
5. **Differential fuzz oracle divergence rate**: % of recompiled binaries passing 1M mutated inputs without divergence. Target: 70%+ pure C, 30%+ C++ with RTTI.
6. **MCP tool call success rate** from blind Claude session driving end-to-end analysis. Target: ≥95%.
7. **Evidence coverage**: % of output artifacts carrying `EvidenceItem` with non-null confidence. Target: 100%.

---

## 10. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| LLM decompilation accuracy plateaus <80% re-executability | High | High | VRL refinement loop compensates — oracle-gated iteration raises effective quality regardless of single-shot ceiling |
| Firecracker/gVisor ops complexity users reject | Medium | Medium | Sandboxing opt-in for static analysis; mandatory only for dynamic + malware |
| Ghidra headless brittleness | Medium | High | Dual backend: Ghidra primary, Binary Ninja API fallback (commercial-friendly headless license) |
| IDA Pro users won't switch | High | Low | Not the target. VS Code/Cursor-embedded + MCP-driven analysts are the beachhead |
| Fine-tuning on user data raises privacy concerns | High | High | Local model path first (Ollama); explicit opt-in for cloud training; on-prem tier |
| Semantic equivalence formally undecidable | Certain | — | Scope honestly: differential fuzzing gives *statistical* equivalence; symbolic gives *bounded* formal. Claims scoped to the oracle that verified them |
| Over-claim "world's first" without receipts | High | Critical | Gate all claims behind the benchmark corpus + validation grades |

---

## 11. Architecture Changes Required

- **Real service boundaries** — extract `reveng-core`, `reveng-analyzers`, `reveng-adapters`, `reveng-ai`, `reveng-verify`, `reveng-sandbox`, `reveng-mcp`, `reveng-cli`, `reveng-web`. Monorepo via `uv workspace` or pyproject feature extras.
- **Python 3.9 → 3.12+ minimum** — unlocks `tomllib`, `@override`, exception groups, PEP 695, better `TypedDict`.
- **Adopt `uv`** — replaces pip/pip-tools/pytest discovery. 10× faster. Consolidates 5 requirements files into `pyproject.toml` extras. You currently have `requirements.txt`, `requirements-dev.txt`, `requirements-java.txt`, `requirements-optional.txt`, `requirements-security.txt` — that's a smell.
- **`logging` → `structlog` + OpenTelemetry** — structured traces with `run_id`, `binary_hash`, `function_addr`, `pipeline_stage`. OTel export → Grafana Tempo / Honeycomb.
- **IR as first-class artifact** — [x] DONE in Phase 1 (`src/reveng/ir.py` v2 with Provenance, NodeKind/EdgeKind, full graph API + JSON round-trip, backwards-compat aliases).
- **Clean up 100+ `analysis_*` dirs at root** — move to `.reveng/workspaces/`, update `.gitignore`, keep only `examples/` with reproducible samples. **Policy:** never delete untracked files without explicit permission.
- **Fix `reveng.py` root shadow** — the stray `reveng.py` at project root shadows `src/reveng/` for direct imports (pre-existing environmental bug, causes 4 CLI test failures). Fix by deleting the stray file or guarding with `if __name__ == "__main__":`.
- **`pytest-timeout` missing** — any CI script using `--timeout` flag currently fails. Install it as dev dep.
- **`pytest.ini` vs `pyproject.toml` conflict** — both define pytest config. `pytest.ini` wins, `[tool.pytest.ini_options]` is dead. Pick one.

---

## 12. Appendix: Top 20 Pain Points → Plan Resolution

| # | Pain Point | Resolved in |
|---|---|---|
| 1 | Every tool has different symbol/type format | Phase 1 IR + Phase 2 shared state store |
| 2 | No reliable verification that decompiled output runs | Phase 1 VRL |
| 3 | Function boundary recovery wrong on stripped binaries | Phase 1 whole-program context pass |
| 4 | Struct recovery is manual and tedious | Phase 1 AI-guided type reconstruction |
| 5 | Vtable/RTTI fragile on C++ | Phase 1.5 + Phase 2 decomp agent |
| 6 | Anti-analysis requires different tool per variant | Phase 2 deobf agent |
| 7 | No cross-arch comparison | Phase 4 cross-arch translation |
| 8 | YARA rules degrade as malware evolves | Phase 4 auto-YARA with atom quality |
| 9 | Context loss between sessions | Phase 2 session journal + Phase 3 knowledge graph |
| 10 | Decompiler output uses misleading fake variable names | Phase 1 iterative LLM refinement |
| 11 | No unified static+dynamic trace format | Phase 1 IR v2 + Phase 2 sandboxing |
| 12 | Instrumentation overhead changes timing | Phase 2 sandboxing (Intel PT integration deferred) |
| 13 | Binary patching is multi-tool | Phase 1 + Phase 4 semantic patch diff |
| 14 | No reproducible analysis environments | Phase 2 Firecracker/gVisor |
| 15 | Malware corpus management ad-hoc | Phase 3 knowledge graph + corpus manager |
| 16 | Exception handling code is black box | Phase 1.5 SEH/DWARF reconstruction |
| 17 | PDB/DWARF symbol recovery incomplete | Phase 1.5 symbol bridge |
| 18 | Multi-binary analysis (injection, proxying) no unified view | Phase 2 shared state store |
| 19 | Licensing constraints prevent automated pipelines | Ghidra/BinaryNinja-first (commercial-friendly) |
| 20 | No regression tests for RE tool outputs | Phase 1 benchmark corpus (DONE) + CI gating (Phase 1.5) |

---

**This document is the canonical reference for the revolution plan. Update it as phases close. Treat it as single source of truth for the VRL vision.**
