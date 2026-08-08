# REVENG Scope C Backlog

Ops index for the full roadmap clearance program. Update `status` when work lands.

**Scope C full index** — living ops file; phases sequential, honesty-first.
**Execution charter:** [`docs/architecture/scope-c-execution-charter.md`](docs/architecture/scope-c-execution-charter.md)
(not one clearance wave for phases 4–13; disposition ≠ capability `done`).

**CEO briefing (latest):** [`docs/architecture/ceo-update-2026-08-07-scope-c-charter.md`](docs/architecture/ceo-update-2026-08-07-scope-c-charter.md)  
**Prior CEO:** [`docs/architecture/ceo-update-2026-08-06-wave3.md`](docs/architecture/ceo-update-2026-08-06-wave3.md) · [`docs/architecture/ceo-update-2026-08-06-wave2.md`](docs/architecture/ceo-update-2026-08-06-wave2.md) · [`docs/architecture/ceo-update-2026-08-06.md`](docs/architecture/ceo-update-2026-08-06.md)  
**Wave B exit criteria:** [`docs/architecture/wave-b-exit-criteria.md`](docs/architecture/wave-b-exit-criteria.md)  
**Wave C exit criteria:** [`docs/architecture/wave-c-exit-criteria.md`](docs/architecture/wave-c-exit-criteria.md)  
**Lessons:** [`docs/architecture/lessons-learned-scope-c-2026-08.md`](docs/architecture/lessons-learned-scope-c-2026-08.md) (L1–L24)

Statuses: `open` · `in_progress` · `done` · `partial` · `parked` · `blocked` · `blocked_on_phase_4` · `mitigated` · `research` · `blocked_on_phase_4` · `deferred` · `wontfix`

`deferred` / `wontfix` / `parked` resolve roadmap decisions only — they never equal capability `done`.

---

## A. Release blockers / Phase 1–2 (shipped)

| id | title | status | notes |
| --- | --- | --- | --- |
| GA-HOLLOW-1 | Hollow native GA gate | done | evidence + success-floor gates |
| GAP-OLLAMA-1 | Ollama known_gap skips | done | real import paths patched |
| GAP-ML-1 | MalwareClassification API | done | alias → MLMalwareClassificationResult |
| SEC-EXP-1 | Exploit CLI watermark | done | EXPERIMENTAL / non-GA |
| NATIVE-EVID-1 | 0/5 analyze reports | done | detector + launcher fixes |
| CLI-PY39-1 | CLI `int \| None` on 3.9 | done | future annotations |
| BENCH-LAUNCH-1 | Dead `reveng.py` launcher | done | `python -m reveng` |
| PY39-FSTR-1 | spec_library f-string 3.9 | done | blocks all app RE imports |
| RECOMPILE-1 | Managed recompile needs Ghidra | done | app-adapter route |
| CLI-OUTDIR-1 | `--output-dir` lost on recompile | done | argv order in runner |

## B. Phase 3 JS behavior (mostly shipped)

| id | title | status | notes |
| --- | --- | --- | --- |
| P3-BP-1 | TS `main` behavior probe | done | optional `tsx` runner when present; else `tsx_not_found` |
| P3-BP-2 | npm pack/run probes | done | optional dry-run, default off |
| P3-BP-3 | Behavior promotes `validation.grade` | done | tier2+syntax → evidence_backed |
| P3-BP-4 | Size-scaled probe timeouts | done | by file_count |
| DF-2 | Lazy conftest heavy imports | done | fixtures import locally |
| LOG-PRINTF-1 | REVENGLogger %-args | done | stdlib-compatible *args |

## C. Open product / quality (active)

| id | title | phase | status | needs research? | notes |
| --- | --- | --- | --- | --- | --- |
| M1-NATIVE-FAM | ≥5 native / ≥3 families hermetic | 2 | open | see R-NATIVE-1 + fixtures | C+Go micro-CLIs landed (`test_samples/native/`); `required:false`/`fixture_only`. Close when analyze completes ≤120s on both without Ghidra + flip required true. Host C linker may skip hello_c. |
| RALPH-1 | Source-map path alias recall | 6 | partial | open (await Sol stop/go)| file overlap fixed |
| RALPH-2 | cli.js 0.8+ recall | 6 | open | **yes R-RALPH-2** | harness done; engine long pole |
| M5-PIPE | pipeline vs pipelines merge | 9 | partial | open (await Sol stop/go)| documented split freeze; Wave B merge optional |
| M0 | Baseline reporting discipline | exec | done | | preview reporting discipline: probe v1.2 + evidence hygiene (exact one stamp≡latest) + scoped git (DF-4); CI corpus gates remain **M4 residual** |
| M1 | Multi-codebase corpus gate | exec | open | see R-NATIVE-1 | overlaps M1-NATIVE-FAM |
| M2 | Hexyl frontier hardening | 4 | partial | no (R-HEX-1 measured) | Probe v1.3 semantic attribution + re-stamp done (Phase 4 Track A honesty); deeper hexyl analyze/recompile/behavior still open — world-class M2 not closed. See `phase-04-m2-hexyl-frontier.md`. No `required:true`; M1-NATIVE-FAM still open. |
| M3 | Validation/evidence unified contract | 3 | partial | | MCP top-level validation_grade + capability_report landed |
| M4 | CI/PR/nightly corpus gates | 5 | partial | | Wave B honesty + Phase 5 thin equivalence evidence gate (`.github/workflows/wave-c-phase5-honesty.yml` + `reports/equivalence_honesty/latest.json`); full nightly/corpus blocking still open (M4 residual) |
| M5 | Post-gate architecture extraction | 9–10 | open | after M0–M4 | workers/ports |

## D. Research queue (do before large builds)

| id | question | blocks |
| --- | --- | --- |
| R-NATIVE-1 | Linux-hermetic native CLI set for ≥5/≥3 families | **done** — `docs/architecture/research-r-native-1-linux-hermetic-candidates.md` |
| R-RALPH-2-BASELINE | Measure current cli.js recall (or label could_not_measure) | **done** — `docs/architecture/research-r-ralph-2-baseline.md` |
| R-RALPH-2 | Smallest engine wedge for 0.8+ recall (baseline first) | **open** — RALPH-2, Phase 6 |
| R-HEX-1 | Fresh hexyl timed run: still timeout-only? | **done** (measured) — `docs/architecture/research-r-hex-1-hexyl-timed-run.md` + `reports/native_analyze_probe/latest.json` (`hexyl_subject` status=`completed`, elapsed≈5.10s (R-HEX-1 historical ≈4.68s)); Phase 4 Track A honesty attribution evidenced (`phase-04-m2-hexyl-frontier.md`) — **not** world-class M2 closeout; M2 stays **partial**; VRL-LLM-1 done; Phase 4 honesty go |
| R-TSX-1 | Ship `tsx` probe vs keep smoke stub | **done** — optional tsx runner in behavior probe |
| R-PIPE-1 | Merge pipeline packages vs permanent split | **done** — decision: permanent documented split; see `docs/architecture/decision-r-pipe-1-pipeline-packages.md` |
| R-SEC-1 | Sandbox class before exploit expansion | **done** — decision: Docker-only preview; no exploit expansion; see `docs/architecture/decision-r-sec-1-sandbox-class.md` |
| R-VRL-1 | Min seeds + provider for honest VRL LLM gate | **done** — decision: `min_seeds: 3`, `provider: ollama`; see `docs/architecture/decision-r-vrl-1-seeds-and-provider.md` |

## E. Scope C phase catalog (program backlog)

| phase | focus | status |
| --- | --- | --- |
| 1 | Honesty + known_gaps + GA gate integrity | **done** |
| 2 | Managed recompile + GA report honesty (preview) | **done** (preview); native corpus still open |
| 3 | Behavior-backed JS validation | **done** (incl. optional tsx) |
| 4 | Hexyl frontier + VRL LLM round-trip honesty | **done (honesty go)** — waiver `decision-phase-04-honesty-go-waiver.md`; world-class M2 remains **partial**/separate |
| 5 | Equivalence product gates + CI corpus enforcement | **partial** — thin honesty authorized+landed (`decision-phase-05-thin-honesty-auth.md`); full nightly corpus / product equivalence service still open |
| 6 | JS close: RALPH-2 + bundler graph (P4) | open (await Sol stop/go; BP-2/3/4 done) |
| 7 | Native depth → partial_equivalence + multi-file | open (await Sol stop/go)|
| 8 | MCP + AI ops productization | open (await Sol stop/go)|
| 9 | Orchestration + modular monolith / ports | open (await Sol stop/go) |
| 10 | Workers + external-tool CI + SEC-1 sandbox | open (await Sol stop/go)|
| 11 | Analyst / governance / packaging (GA-P4) | open (await Sol stop/go)|
| 12 | Platform depth (IR, Ralph opt, RAG, KG start) | open (await Sol stop/go)|
| 13 | Blue-ocean / v6.1+ futures (post SEC-1 for exploits) | open (await Sol stop/go)|

## F. Capability hardening leftovers

| id | title | status |
| --- | --- | --- |
| P4-BUNDLER | Bundler-aware module / import-graph scoring | open |
| P5-NATIVE-EQ | Native entry→partial_equivalence | open |
| P6-PLATFORM | Single orchestration + MCP evidence uniformity | open |

## G. Parked (Tier 3 — do not claim)

| id | title | status |
| --- | --- | --- |
| T3-KERNEL | Kernel reverse engineering | parked |
| T3-PACKED | Packed/protected binaries depth | parked |
| T3-JIT | Self-modifying/JIT outside JS | parked |
| T3-ANTI | Malware anti-analysis depth | parked |
| T3-GUI | Large GUI-first without eval strategy | parked |

## H. Dogfood findings

| id | finding | status |
| --- | --- | --- |
| TG-AUDIT-2026-08-08 | tg-audit P0/P1 honesty fixups (plan+impl Sol APPROVE_WITH_NITS; `feat/tg-audit-fixups`; D1–D6 deferred) | done |
| DF-1 | Host python3.13 stdlib broken — use 3.9 | mitigated |
| DF-2 | Conftest heavy imports | done |
| DF-3 | Wrong analyze report filename in runner | done |
| DF-4 | Full `git status` hangs on dirty `reports/` (DrvFS) | done |
| DF-5 | hello_go analyze can process-exit 0 / probe `completed` with partial_success / empty native fallback — not native GA | done | documented+tested (`test_df5_process_completed_honesty.py`); process `completed` ≠ native GA |

## I. Decisions / waivers

| date | decision |
| --- | --- |
| 2026-08-06 | Scope C over thinktank B; honesty still first |
| 2026-08-06 | GA floor may accept analyze-ok / recompile-failed styles when evidence is real |
| 2026-08-06 | Public preview: CLI + app RE supported; native limited; exploits experimental |
| 2026-08-06 | Wave B honesty slice: thin PR gate (`.github/workflows/wave-b-honesty.yml`); M0/DF-5 done (reporting discipline); M4 **partial** (corpus residual); R-HEX-1 **done** (measured) via hexyl-subject probe (`completed` ≈5.10s); M2 remains open; see `docs/architecture/wave-c-exit-criteria.md` |
| 2026-08-07 | Phase 4 **honesty go** (Sol APPROVE_WITH_NITS waiver: M2 split). Phase 4 Track A: probe v1.3 re-stamp + honesty attribution doc (not world-class M2 closeout — M2 **partial**); Track B: Sol REJECT hollow ACK-ping → forgeable `candidate_hash_changed` → corpus registration of `vrl_llm_micro_go` + gate SHA/applied-source harden; dogfood loads seeds from corpus; VRL-LLM-1 **done** (load-bearing, Sol-ready evidence); Phase 4 **honesty go** recorded (M2 world-class still open/partial; hexyl C refine `vrl_compile_toolchain_broken`). See `docs/architecture/phase-04-m2-hexyl-frontier.md`, `docs/architecture/evidence-vrl-llm-honesty-phase-04.md`. |
| 2026-08-07 | Phase 5 **thin honesty** Sol APPROVE (`decision-phase-05-thin-honesty-auth.md`): `wave-c-phase5-honesty.yml` + `scripts/verify_equivalence_honesty.py` + `reports/equivalence_honesty/latest.json`; M4/EPIC-7/FEAT-2/REV-P1-CI-CORPUS **partial**; full nightly corpus open; M2 remains entry dep; no native `required:true`; no exploit expansion. |

---

## J. Scope C full roadmap index (source ingest)

One row per distinct open checkbox / epic / milestone leftover from roadmap sources.
Statuses for items already closed in sections A–I stay `done` / `partial` / `parked` — not reopened.
Tier-3 rows are `parked` (honesty non-goals). Phase column uses Scope C catalog 1–13, or `parked`.

| id | title | source_doc | phase | status | notes |
| --- | --- | --- | --- | --- | --- |
| M0 | Baseline and reporting discipline | reveng-world-class-execution-backlog.md | 1 | done | Probe v1.2 + evidence hygiene + scoped git (DF-4); CI corpus residual tracked under M4 |
| M1 | Multiple-codebase corpus gate | reveng-world-class-execution-backlog.md | 2 | open | ≥5 native / ≥3 families; overlaps M1-NATIVE-FAM; Bun 2 live already measured |
| M1-NATIVE-FAM | ≥5 native / ≥3 families hermetic analyze | reveng-world-class-execution-backlog.md | 2 | open | Fixtures landed required:false; flip true only after analyze ≤120s without Ghidra |
| M2 | Hexyl frontier hardening beyond timed probe | reveng-world-class-execution-backlog.md | 4 | partial | Probe v1.3 semantic attribution + re-stamp done; deeper hexyl analyze/recompile/behavior still open (world-class M2 acceptance unmet); see phase-04-m2-hexyl-frontier.md; M1-NATIVE-FAM still open |
| M3 | Validation and evidence grade lift | reveng-world-class-execution-backlog.md | 3 | partial | MCP top-level validation_grade + capability_report landed; unified benchmark contract residual |
| M4 | CI/PR/nightly corpus gate enforcement | reveng-world-class-execution-backlog.md | 5 | partial | wave-b-honesty + wave-c-phase5-honesty thin evidence gate; full corpus/nightly blocking still open |
| M5 | Post-gate architecture extraction | reveng-world-class-execution-backlog.md | 9 | open | After M0–M4 stable; workers/ports |
| M5-PIPE | pipeline vs pipelines reconciliation | reveng-world-class-execution-backlog.md | 9 | partial | R-PIPE-1 permanent documented split freeze; optional merge later |
| EPIC-0 | Establish trustworthy baseline | reveng-tdd-implementation-backlog.md | 1 | partial | M0 reporting discipline done; residual suite/characterization isolation |
| EPIC-1 | Define canonical result schemas | reveng-tdd-implementation-backlog.md | 3 | open | Versioned analysis/reconstruction/validation/MCP schemas |
| EPIC-2 | Introduce evidence and provenance | reveng-tdd-implementation-backlog.md | 3 | open | First-class evidence graph + provenance across analyzer/API/MCP |
| EPIC-3 | Split bounded contexts inside monolith | reveng-tdd-implementation-backlog.md | 9 | open | Ports for analyze/decomp/AI/recon/validate/report |
| EPIC-4 | Reconcile orchestration layers | reveng-tdd-implementation-backlog.md | 9 | open | Unify or permanently separate pipeline/ vs pipelines/ |
| EPIC-5 | Stabilize MCP as product surface | reveng-tdd-implementation-backlog.md | 8 | open | Stable schemas, auth, rate, audit; overlaps REV-MCP |
| EPIC-6 | Harden Ollama and AI routing | reveng-tdd-implementation-backlog.md | 8 | open | Model profiles, fallback routing, latency accounting |
| EPIC-7 | Elevate reconstruction and validation | reveng-tdd-implementation-backlog.md | 5 | partial | Thin equivalence honesty helper+report+CI landed; full product validation service + LibAFL/angr opt-in still open |
| EPIC-8 | Extract heavy workers | reveng-tdd-implementation-backlog.md | 10 | open | Ghidra/dynamic/compile workers; retries/timeouts/retention |
| EPIC-9 | Analyst review and governance | reveng-tdd-implementation-backlog.md | 11 | open | Review workspace, policy, case export |
| P3-BP-1 | TS main behavior probe (tsx optional) | reveng-capability-hardening-plan.md | 3 | done | Already in section B; do not reopen |
| P3-BP-2 | npm pack/run lifecycle probes | reveng-capability-hardening-plan.md | 3 | done | Already in section B; do not reopen |
| P3-BP-3 | Behavior promotes validation.grade | reveng-capability-hardening-plan.md | 3 | done | Already in section B; do not reopen |
| P3-BP-4 | Size-scaled probe timeouts | reveng-capability-hardening-plan.md | 3 | done | Already in section B; do not reopen |
| RALPH-1 | Source-map path alias recall | reveng-capability-hardening-plan.md | 6 | partial | File overlap fixed; domain recall separate |
| RALPH-2 | cli.js 0.8+ engine recall | reveng-capability-hardening-plan.md | 6 | open | Harness done; engine long pole; see R-RALPH-2 |
| P4-BUNDLER | Bundler-aware module / import-graph scoring | reveng-capability-hardening-plan.md | 6 | open | Chunk graph + import-graph precision/recall |
| P5-NATIVE-EQ | Native entry→partial_equivalence | reveng-capability-hardening-plan.md | 7 | open | Entry-reachable helper chains + multi-file synthesis |
| P6-PLATFORM | Single orchestration + MCP evidence uniformity | reveng-capability-hardening-plan.md | 9 | open | Thread result_contracts uniformly through MCP |
| T3-KERNEL | Kernel reverse engineering | reverse-compilation-master-roadmap.md | parked | parked | Tier 3 honesty non-goal |
| T3-PACKED | Packed/protected binaries depth | reverse-compilation-master-roadmap.md | parked | parked | Tier 3 honesty non-goal |
| T3-JIT | Self-modifying/JIT outside JS | reverse-compilation-master-roadmap.md | parked | parked | Tier 3 honesty non-goal |
| T3-ANTI | Malware anti-analysis depth | reverse-compilation-master-roadmap.md | parked | parked | Tier 3 honesty non-goal |
| T3-GUI | Large GUI-first without eval strategy | reverse-compilation-master-roadmap.md | parked | parked | Tier 3 honesty non-goal |
| GA-P0 | Freeze supported surface; non-GA watermarks | reveng-ga-master-plan.md | 1 | done | Exploits/symbolic/equivalence experimental; section A SEC-EXP-1 |
| GA-P1 | Baseline release gates (hollow-proof) | reveng-ga-master-plan.md | 1 | done | native-analyze-evidence + success-floor; section A GA-HOLLOW-1 |
| GA-P2 | GA target corpus gates (5 native / Bun / app) | reveng-ga-master-plan.md | 2 | open | provision_ga_assets + fresh .ga.json; overlaps M1 |
| GA-P3 | Operational hardening (external-tool CI lanes) | reveng-ga-master-plan.md | 10 | open | ilspycmd/pyi/Java/Ghidra CI where supported |
| GA-P4 | Customer packaging (matrix, notes, checklist) | reveng-ga-master-plan.md | 11 | open | Support matrix + troubleshooting + RELEASE_CHECKLIST live |
| FEAT-1 | Evidence graph and provenance ledger | reveng-feature-roadmap.md | 3 | open | Overlaps EPIC-2 / M3 |
| FEAT-2 | Equivalence validation service | reveng-feature-roadmap.md | 5 | partial | Overlaps EPIC-7; thin honesty path landed; full service open |
| FEAT-3 | Retrieval-augmented binary context for AI | reveng-feature-roadmap.md | 12 | open | CFG/strings/signatures before LLM stages |
| FEAT-4 | Service-level Ghidra/dynamic/validation workers | reveng-feature-roadmap.md | 10 | open | Overlaps EPIC-8 |
| FEAT-5 | Analyst review workspace | reveng-feature-roadmap.md | 11 | open | Overlaps EPIC-9 |
| FEAT-6 | Corpus and benchmark management | reveng-feature-roadmap.md | 2 | open | Overlaps M1 / GA-P2 |
| FEAT-7 | Policy and safety guardrails | reveng-feature-roadmap.md | 11 | open | Exploit auth gates, egress, retention |
| FEAT-8 | Better MCP productization | reveng-feature-roadmap.md | 8 | open | Schemas, streaming, approval hooks; overlaps EPIC-5 |
| FEAT-9 | Stronger local-model orchestration | reveng-feature-roadmap.md | 8 | open | Ollama profiles/routing; overlaps EPIC-6 |
| FEAT-10 | Recompilation developer kit | reveng-feature-roadmap.md | 12 | open | Compiler profiles, shims, artifact comparison |
| REV-P0-INSTALLERS | Finish or deprecate dependency-manager installer stubs | REVOLUTION_PLAN.md | 1 | open | dnSpy/uncompyle6/exeinfo_pe/x64dbg/imhex/lordpe |
| REV-P0-EVIDENCE-AUDIT | Evidence propagation adoption-matrix audit | REVOLUTION_PLAN.md | 1 | open | Read-only audit incomplete in prior session |
| REV-P0-ANALYSIS-CLEANUP | Cleanup policy for analysis_* dirs at repo root | REVOLUTION_PLAN.md | 1 | open | Policy: no untracked deletes without permission |
| REV-P1-LLM-REFINER | Iterative LLM refiner on oracle divergence | REVOLUTION_PLAN.md | 4 | open | Phase 1.5; feeds failing I/O + source to Claude/GPT |
| REV-P1-WHOLE-PROGRAM | Whole-program context / type propagation | REVOLUTION_PLAN.md | 12 | open | Cross-function types before LLM decomp |
| REV-P1-CI-CORPUS | Regression-gated CI on benchmark corpus | REVOLUTION_PLAN.md | 5 | partial | Thin equivalence evidence CI landed; full corpus residual overlaps M4 |
| REV-P2-GATE-LLM-RT | Proven LLM round-trip improves grade | REVOLUTION_PLAN.md | 4 | open | Phase 2 gate: divergence→fix→recompile→grade↑ |
| REV-P2-GATE-BM3 | 3 binaries reach behavior_matched via VRL | REVOLUTION_PLAN.md | 4 | open | Phase 2 gate; R-VRL-1 says min_seeds=3 / ollama |
| REV-P2-GATE-SEEDS | ≥5 non-trivial seeds per binary | REVOLUTION_PLAN.md | 4 | open | No --help-only convergence; decision min_seeds=3 for honesty gate |
| REV-MCP | MCP server first-class installable product | REVOLUTION_PLAN.md | 8 | open | pip install reveng-mcp; OIDC/API-key; rate; audit |
| REV-SUBAGENTS | Specialized MCP sub-agent tool bundles | REVOLUTION_PLAN.md | 8 | open | Triage/deobf/decomp/recomp/verify/report/hunt |
| REV-STATE | Shared state store (SQLite + LanceDB) | REVOLUTION_PLAN.md | 12 | open | .reveng/state/ embeddings |
| REV-JOURNAL | Session journal append-only audit log | REVOLUTION_PLAN.md | 8 | open | Agent calls/decisions/confidence |
| REV-SANDBOX | Firecracker/gVisor sandbox for binary exec | REVOLUTION_PLAN.md | 10 | open | Post R-SEC-1 Docker-only preview; no exploit expansion |
| REV-FINGERPRINT | Function fingerprint DB | REVOLUTION_PLAN.md | 12 | open | BinaryAI/rev.ng/Lumina/self-hosted ANN |
| REV-KG | Knowledge graph (Neo4j/Kuzu) | REVOLUTION_PLAN.md | 12 | open | Samples/families/CVE/ATT&CK annotations |
| REV-ANNOTATE | Collaborative annotation merge | REVOLUTION_PLAN.md | 11 | open | Git/CRDT-backed multi-analyst |
| REV-VARIANT | Cross-binary variant hunting | REVOLUTION_PLAN.md | 12 | open | CVE+patch_diff semantic sweep |
| REV-SELF-IMPROVE | Self-improving rename/type training loop | REVOLUTION_PLAN.md | 12 | open | Human corrections → fine-tune corpus |
| REV-COMPILER-ARCH | Compiler archaeology classifier | REVOLUTION_PLAN.md | 13 | open | Blue-ocean Phase 4 |
| REV-XARCH | Cross-architecture binary translation | REVOLUTION_PLAN.md | 13 | open | x86→ARM64 via VRL prerequisite |
| REV-SEMDIFF | Semantic patch diff reporter | REVOLUTION_PLAN.md | 13 | open | v1/v2 binary CWE-oriented report |
| REV-NLQ | Natural-language binary queries | REVOLUTION_PLAN.md | 13 | open | LLM→IR+KG query |
| REV-YARA | Auto-generated YARA/Sigma with atom quality | REVOLUTION_PLAN.md | 13 | open | malicious/benign set rule gen |
| REV-ARCH-OWN | eBPF / WASM / RISC-V ownership | REVOLUTION_PLAN.md | 13 | open | Underserved arch blue ocean |
| REV-SPA | Browser-based report viewer SPA | REVOLUTION_PLAN.md | 13 | open | Static SPA over analysis_* dirs |
| REV-IDE | VS Code + Cursor extension | REVOLUTION_PLAN.md | 13 | open | Refine/verify/variants/YARA actions |
| V6-TS-INFER | TypeScript type inference | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-REACT-VUE | React/Vue component detection | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-NPM | npm package analysis | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-SUPPLY | Supply chain security scanning | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-BROWSER-EXT | Browser extension on-the-fly deobfuscation | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-WEB-UI | Web UI dashboard | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-REST | REST API endpoints | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-DOCKER | Docker container | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-K8S | Kubernetes deployment | changelogs/v6.0.md | 13 | open | v6.1+ future |
| V6-GHA | GitHub Actions integration | changelogs/v6.0.md | 13 | open | v6.1+ future |
| PROF-SHIM-4 | Phase-4 shim removal + back-compat policy | 2026-06-03-reveng-professionalization-design.md | 11 | open | Shims remain; decide public API before retirement |
| VRL-LLM-1 | Measured VRL LLM round-trip honesty gate | decision-r-vrl-1-seeds-and-provider.md | 4 | done | Corpus entry `vrl_llm_micro_go` registered (seed_inputs ×3 + build_recipe); dogfood loads seeds from corpus; gate derives `candidate_hash_changed` from control/treatment sha256 (forgeable boolean rejected) and requires applied_source receipt when `llm_influenced`. Load-bearing `measured` via Go micro (`CGO_ENABLED=0`). Hexyl/PE C `run_vrl` still `vrl_compile_toolchain_broken`. Phase 4 honesty go (M2 separate). See evidence-vrl-llm-honesty-phase-04.md + decision-phase-04-honesty-go-waiver.md. |

### Source docs ingested

- `docs/architecture/reveng-world-class-execution-backlog.md`
- `docs/architecture/reveng-tdd-implementation-backlog.md`
- `docs/architecture/reveng-capability-hardening-plan.md`
- `docs/architecture/reverse-compilation-master-roadmap.md`
- `docs/architecture/reveng-ga-master-plan.md`
- `docs/architecture/reveng-feature-roadmap.md`
- `docs/architecture/2026-06-03-reveng-professionalization-design.md`
- `docs/architecture/decision-r-vrl-1-seeds-and-provider.md`
- `docs/REVOLUTION_PLAN.md`
- `docs/changelogs/v6.0.md`


## K. Phase 4 honesty go

Phase 4 honesty go recorded (`decision-phase-04-honesty-go-waiver.md`). Phases 5–13 are no longer `blocked_on_phase_4` for *authorization*, but still need per-phase Sol stop/go before product work. M2 world-class remains open.
