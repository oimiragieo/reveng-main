# REVENG Scope C Backlog

Ops index for the full roadmap clearance program. Update `status` when work lands.

**Scope C full index** — living ops file; phases sequential, honesty-first.
**Execution charter:** [`docs/architecture/scope-c-execution-charter.md`](docs/architecture/scope-c-execution-charter.md)
(not one clearance wave for phases 4–13; disposition ≠ capability `done`).

**CEO briefing (latest):** [`docs/architecture/ceo-update-2026-08-10-wave10.md`](docs/architecture/ceo-update-2026-08-10-wave10.md)  
**Prior CEO:** [`ceo-update-2026-08-10-wave9b.md`](docs/architecture/ceo-update-2026-08-10-wave9b.md) · [`ceo-update-2026-08-10-wave9.md`](docs/architecture/ceo-update-2026-08-10-wave9.md) · [`ceo-update-2026-08-10-wave85.md`](docs/architecture/ceo-update-2026-08-10-wave85.md) · [`ceo-update-2026-08-09-wave8.md`](docs/architecture/ceo-update-2026-08-09-wave8.md) · charter · wave2 · wave1  
**Wave 0 closeout plan:** [`docs/superpowers/plans/2026-08-09-backlog-closeout-program.md`](docs/superpowers/plans/2026-08-09-backlog-closeout-program.md) (Thinktank **APPROVE Wave 0**; PR #131 merged)  
**Wave 1 plan:** [`docs/superpowers/plans/2026-08-09-wave1-honesty-deep-dive.md`](docs/superpowers/plans/2026-08-09-wave1-honesty-deep-dive.md) (PR **#132** merged)  
**Wave 2 plan:** [`docs/superpowers/plans/2026-08-09-wave2-honesty-deep-dive.md`](docs/superpowers/plans/2026-08-09-wave2-honesty-deep-dive.md) (PR **#133** merged `1eff22f8`)  
**Wave 2 closeout plan:** [`docs/superpowers/plans/2026-08-09-wave2-closeout.md`](docs/superpowers/plans/2026-08-09-wave2-closeout.md) (Thinktank **APPROVE_WITH_NITS**; Sol **PASS_WITH_NITS** tip `34d5b99d`)  
**Wave 3 plan:** [`docs/superpowers/plans/2026-08-09-wave3-r-ralph-2-rebaseline.md`](docs/superpowers/plans/2026-08-09-wave3-r-ralph-2-rebaseline.md) (Thinktank **APPROVE Wave3=A**; R-RALPH-2 re-baseline — not all-backlog)  
**Wave 4 plan:** [`docs/superpowers/plans/2026-08-09-wave4-js-recovered-root-naming.md`](docs/superpowers/plans/2026-08-09-wave4-js-recovered-root-naming.md) (recovered-root + hints; R-RALPH-2 stays **open**)  
**Wave 7 plan:** [`docs/architecture/research-js-recovery-toolkit-2026-08-09.md`](docs/architecture/research-js-recovery-toolkit-2026-08-09.md) (toolkit + ensemble)  
**Wave 10 plan:** [`docs/architecture/research-wave10-soft-assignment-2026-08-10.md`](docs/architecture/research-wave10-soft-assignment-2026-08-10.md) (Hungarian soft-assign + tombstones)  
**Wave 8 plan:** [`docs/architecture/research-wave8-structural-bun-100-2026-08-09.md`](docs/architecture/research-wave8-structural-bun-100-2026-08-09.md) (structural + SerializedSourceMap + coverage union)  
**Wave 5 plan:** [`docs/superpowers/plans/2026-08-09-wave5-stale-map-fingerprint.md`](docs/superpowers/plans/2026-08-09-wave5-stale-map-fingerprint.md) (Thinktank **APPROVE_WITH_NITS**; fingerprint attribution — not exe decode)  
**Wave B exit criteria:** [`docs/architecture/wave-b-exit-criteria.md`](docs/architecture/wave-b-exit-criteria.md)  
**Wave C exit criteria:** [`docs/architecture/wave-c-exit-criteria.md`](docs/architecture/wave-c-exit-criteria.md)  
**Lessons:** [`docs/architecture/lessons-learned-scope-c-2026-08.md`](docs/architecture/lessons-learned-scope-c-2026-08.md) (**L1–L48**)

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
| RALPH-2 | cli.js 0.8+ recall | 6 | open | **yes R-RALPH-2** | harness done; npm `cli.js` obsolete (Wave 3); Wave 4 tracked recall **0.4** via source_map materialize (not 0.8); engine long pole |
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
| R-RALPH-2 | Smallest engine wedge for 0.8+ recall (baseline first) | **open** — Wave 6-A wire landed; tracked recall still **0.4** (fp 0 on micro-bundle); operator-local stale→Bun confirms 232; Phase 6 |
| R-HEX-1 | Fresh hexyl timed run: still timeout-only? | **done** (measured) — `docs/architecture/research-r-hex-1-hexyl-timed-run.md` + `reports/native_analyze_probe/latest.json` (`hexyl_subject` status=`completed`, elapsed≈5.10s (R-HEX-1 historical ≈4.68s)); Phase 4 Track A honesty attribution evidenced (`phase-04-m2-hexyl-frontier.md`) — **not** world-class M2 closeout; M2 stays **partial**; VRL-LLM-1 done; Phase 4 honesty go |
| R-TSX-1 | Ship `tsx` probe vs keep smoke stub | **done** — optional tsx runner in behavior probe |
| R-PIPE-1 | Merge pipeline packages vs permanent split | **done** — decision: permanent documented split; see `docs/architecture/decision-r-pipe-1-pipeline-packages.md` |
| R-SEC-1 | Sandbox class before exploit expansion | **done** — decision: Docker-only preview; no exploit expansion; see `docs/architecture/decision-r-sec-1-sandbox-class.md` |
| R-VRL-1 | Min seeds + provider for honest VRL LLM gate | **done** — decision: `min_seeds: 3`, `provider: ollama`; see `docs/architecture/decision-r-vrl-1-seeds-and-provider.md` |

## E. Scope C phase catalog (program backlog)

| phase | focus | status |
| --- | --- | --- |
| 1 | Honesty + known_gaps + GA gate integrity | done |
| 2 | Managed recompile + GA report honesty (preview); native corpus still open | done |
| 3 | Behavior-backed JS validation (incl. optional tsx) | done |
| 4 | Hexyl frontier + VRL LLM round-trip; honesty go via `decision-phase-04-honesty-go-waiver.md`; world-class M2 remains separate/partial | partial |
| 5 | Equivalence product gates + CI corpus; thin honesty via `decision-phase-05-thin-honesty-auth.md`; full nightly corpus / product equivalence still open | partial |
| 6 | JS close: RALPH-2 + bundler graph (P4); Wave 3 research honesty landed — Sol **NO-GO** cli.js 0.8 until recovered-root wedge; await engine wave; BP-2/3/4 done | open |
| 7 | Native depth → partial_equivalence + multi-file; await Sol stop/go | open |
| 8 | MCP + AI ops productization; await Sol stop/go | open |
| 9 | Orchestration + modular monolith / ports; await Sol stop/go | open |
| 10 | Workers + external-tool CI + SEC-1 sandbox; await Sol stop/go | open |
| 11 | Analyst / governance / packaging (GA-P4); await Sol stop/go | open |
| 12 | Platform depth (IR, Ralph opt, RAG, KG start); await Sol stop/go | open |
| 13 | Blue-ocean / v6.1+ futures (post SEC-1 for exploits); await Sol stop/go | open |

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
| CI-HONESTY-SLIM-1 | Wave B/C honesty CI: slim `requirements-honesty.txt` (avoid resolution-too-deep) | done |
| GHIDRAMCP-PIN-1 | Remove fictional `ghidramcp>=0.1.0` from java/security requirements | done |
| DF-1 | Host python3.13 stdlib broken — use 3.9 | mitigated |
| DF-2 | Conftest heavy imports | done |
| DF-3 | Wrong analyze report filename in runner | done |
| DF-4 | Full `git status` hangs on dirty `reports/` (DrvFS) | done |
| DF-5 | hello_go analyze can process-exit 0 / probe `completed` with partial_success / empty native fallback — not native GA | done | documented+tested (`test_df5_process_completed_honesty.py`); process `completed` ≠ native GA |
| WIRING-2026-08-09 | World-class MCP/CLI wiring honesty Top-8 | done | Wave 0 land |
| DOCS-DUALDOOR-2026-08-09 | Junior Diátaxis dual-door docs | done | Wave 0 land |
| ISSUE-101-DISP | #101 rich Capstone renderer — 43 xfails dispositioned blocked | blocked | See section L; issue remains open |
| CI-HONESTY-NOCOV-1 | Wave B/C honesty CI: `--no-cov` needs pytest-cov on slim install | done | add pytest-cov to requirements-honesty.txt |
| CI-PHASE5-PY39-PATH-1 | Wave C used hardcoded `/usr/bin/python3.9` (absent on GHA) | done | use setup-python `python` |
| CI-DOCS-LINK-1 | docs-link-check fails on main (215 errors; Windows abs paths in thinktank HTML) | partial | soft-fail via docs.yml continue-on-error; root cause open; Wave 1 disposition |
| CI-UNICORN-BUILD-1 | Tests matrix: angr/unicorn wheel build fails (cmake_minimum_required) | mitigated | macos slim install (`requirements-ci-macos-slim*.txt`) in test.yml+tests.yml; unicorn#2263; angr capability still not green |
| LINT-IMPORTS-HOST-1 | Host `/usr/bin/python3.9` lacks importlinter for local lint-imports | open | could_not_measure locally; CI Code Quality still owns import contracts |
| R-MCP-ANNOTATION-1 | Research: actlint-style declared-vs-derived MCP annotation honesty | partial | Wave 2 denylist dual-label (`generate_exploit`/`recompile_binary`); [policy-mcp-annotation-honesty-wave2.md](docs/architecture/policy-mcp-annotation-honesty-wave2.md); not actlint CI / not GA |
| EDGE-RECOMPILE-DIFF-1 | Research: competitor recompile-diff parity vs VRL | open | could_not_measure; cite https://github.com/kidoz/sleuthre (accessed 2026-08-09); no parity claim |

## I. Decisions / waivers

| date | decision |
| --- | --- |
| 2026-08-06 | Scope C over thinktank B; honesty still first |
| 2026-08-06 | GA floor may accept analyze-ok / recompile-failed styles when evidence is real |
| 2026-08-06 | Public preview: CLI + app RE supported; native limited; exploits experimental |
| 2026-08-06 | Wave B honesty slice: thin PR gate (`.github/workflows/wave-b-honesty.yml`); M0/DF-5 done (reporting discipline); M4 **partial** (corpus residual); R-HEX-1 **done** (measured) via hexyl-subject probe (`completed` ≈5.10s); M2 remains open; see `docs/architecture/wave-c-exit-criteria.md` |
| 2026-08-07 | Phase 4 **honesty go** (Sol APPROVE_WITH_NITS waiver: M2 split). Phase 4 Track A: probe v1.3 re-stamp + honesty attribution doc (not world-class M2 closeout — M2 **partial**); Track B: Sol REJECT hollow ACK-ping → forgeable `candidate_hash_changed` → corpus registration of `vrl_llm_micro_go` + gate SHA/applied-source harden; dogfood loads seeds from corpus; VRL-LLM-1 **done** (load-bearing, Sol-ready evidence); Phase 4 **honesty go** recorded (M2 world-class still open/partial; hexyl C refine `vrl_compile_toolchain_broken`). See `docs/architecture/phase-04-m2-hexyl-frontier.md`, `docs/architecture/evidence-vrl-llm-honesty-phase-04.md`. |
| 2026-08-08 | PR #119 merge (tg-audit + Scope C history). Follow-up: honesty slim install + drop ghidramcp PyPI fiction; CEO `ceo-update-2026-08-08-tg-audit-merge.md`; lessons L25–L32. |
| 2026-08-21 | Wave 10 closeout **merged** PR #150 (`82bc0ec3`); Sol **PASS** on tip2 `accf553a` (tip1 `fbc86c6e`); honesty-unit+lint-python green; matrix soft-red L42. Thinktank Option 1. **Not** all-backlog / enterprise GA / R-RALPH-2 close. |
| 2026-08-21 | Wave 10 closeout **candidate** (PR #150): Sol frozen-tip stub + packet; merge **pending Sol** on tip2. Thinktank 6/7 → Option 1 (close Wave 10). **REJECT** all-backlog / enterprise-GA “100% product” loop (L33). Hermetic wave10 tests 5 passed. |
| 2026-08-11 | Ceiling honesty capture: unlockable 100% ≠ full-oracle 100%; SEA tombstones hard ceiling; extend `reveng-js-recovery-climb` pins/skill + AGENTS/MEMORY/CEO/workflows (no new skill). |
| 2026-08-11 | Docs/skills capture: new project skill `reveng-js-recovery-climb` + workflow; refresh AGENTS/MEMORY/CLAUDE/ops/INDEX/release-honesty for Wave 10 Option C; triple-check Sol/named-path/MCP skills ACCURATE. |
| 2026-08-10 | Wave 10: Hungarian soft-assign + unique-token tombstones (Exa→arXiv Sinkhorn/unsupervised clones); hermetic 5 passed; Claude dogfood **1053→1087 (~57% oracle)**, recoverable **~82%** of unique-residue set; R-RALPH-2 open. CEO `ceo-update-2026-08-10-wave10.md`. |
| 2026-08-10 | Wave 9b: full Bun `cli.js` webcrack EXIT0 (35.8MB unminify, no string-array); real gpt-oss-20b digests 40/40; tag-boost **993→1053 (~55% oracle)** survivor 1.0; R-RALPH-2 open. CEO `ceo-update-2026-08-10-wave9b.md`. |
| 2026-08-10 | Wave 9 readable-normalize + semantic digest + optional AST-chunked LLM digest; webcrack→wakaru external chain; hermetic green; Claude still ~52% oracle (semantic +5); R-RALPH-2 open. Research `research-wave9-readable-semantic-llm-2026-08-10.md`. |
| 2026-08-10 | Wave 8.5 iterative defrag + TF-IDF word-map (option C): hermetic 100%; Claude unlockable **1.0**, oracle **990/1902 (~52%)** (+369 vs seed); R-RALPH-2 open. Research `research-wave85-iterative-defrag-wordmap-2026-08-10.md`. |
| 2026-08-09 | Wave 8 structural + Bun SerializedSourceMap decoder + coverage union: hermetic oracle/survivor **100%**; Claude stale→Bun union **621/1902 (~33%)** with survivor **1.0**; Claude SEA sourcemaps **0**; structural adds **0**; R-RALPH-2 open. Research `research-wave8-structural-bun-100-2026-08-09.md`. |
| 2026-08-09 | Wave 7 JS recovery toolkit: ensemble fingerprint **232→553** Bun confirms (~29% oracle src); wakaru/webcrack adapters; in-tree Bun extract; R-RALPH-2 open. Research `research-js-recovery-toolkit-2026-08-09.md`. |
| 2026-08-09 | Wave 6 Thinktank **APPROVE_W6A**: fingerprint wired in JS adapter; tracked Ralph still **0.4** (fp confirmed 0 on micro-bundle); mismatch 0.0; operator-local dogfood 232 confirms / map rebuild 1.0; M1 flip **blocked** (`native_fallback_empty`); R-RALPH-2 open. |
| 2026-08-09 | Operator-local map rebuild dogfood: materialize src_recall **1.0**; stale-map→Bun fingerprint confirms **232** (hashed, under src/); not exe decode; R-RALPH-2 open. Receipt `operator-local-map-rebuild-dogfood-2026-08-09.md`. |
| 2026-08-09 | Wave 5 Thinktank **APPROVE_WITH_NITS** stale-map fingerprint Tier A (hashed index, dual controls); Bun Tier B demoted to spike; R-RALPH-2 / Phase 6 stay **open**. Not exe decode. |
| 2026-08-09 | Wave 4 recovered-root: tracked Ralph recall **0.4** via sibling `.map` `sourcesContent` (`source_map`); mismatch arm 0.0; R-RALPH-2 / Phase 6 stay **open**. Plan `2026-08-09-wave4-js-recovered-root-naming.md`. |
| 2026-08-09 | Thinktank **APPROVE Wave3=A** R-RALPH-2 packaging re-baseline (REJECT close-all). Interim tracked-bundle Ralph score 0.0 (`no_recovered_root`); npm `cli.js` obsolete; R-RALPH-2 stays **open**. |
| 2026-08-09 | Wave 2 closeout **merged** PR #133 (`1eff22f8`); Sol PASS_WITH_NITS on tip `34d5b99d`; honesty-unit+lint-python green; matrix soft-red L42. Not all-backlog. |
| 2026-08-09 | Thinktank **APPROVE_WITH_NITS Wave 2** honesty (MCP denylist + path-sep + macos slim); not all-backlog. |
| 2026-08-09 | Thinktank **APPROVE Wave 1** honesty deep-dive (plan R3); installer deprecate + section-E L40 + CI partial disposition; not all-backlog.
| 2026-08-09 | Thinktank **APPROVE Wave 0** backlog closeout (not all-85-done). Land wiring honesty + dual-door docs; #101 dispositioned blocked with per-xfail table (section L); later waves Sol-gated. PR **#131** merged (`047cb81f`). |

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
| REV-P0-INSTALLERS | Finish or deprecate dependency-manager installer stubs | REVOLUTION_PLAN.md | 1 | partial | Wave 1 deprecate stubs (`deprecated_stub`); finish installers future Sol; see [policy-rev-p0-installers.md](docs/architecture/policy-rev-p0-installers.md) |
| REV-P0-EVIDENCE-AUDIT | Evidence propagation adoption-matrix audit | REVOLUTION_PLAN.md | 1 | open | Read-only audit incomplete in prior session |
| REV-P0-ANALYSIS-CLEANUP | Cleanup policy for analysis_* dirs at repo root | REVOLUTION_PLAN.md | 1 | partial | Policy landed [policy-rev-p0-analysis-cleanup.md](docs/architecture/policy-rev-p0-analysis-cleanup.md); automated enforcement open |
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

## L. Wave 0 closeout (2026-08-09)

Program plan: [`docs/superpowers/plans/2026-08-09-backlog-closeout-program.md`](docs/superpowers/plans/2026-08-09-backlog-closeout-program.md)  
Thinktank: Round 1 `APPROVE_WITH_NITS` → Round 2 Sol **`APPROVE Wave 0`** (`docs/architecture/thinktank-backlog-closeout-wave0-r2.txt`).

| id | finding | status | notes |
| --- | --- | --- | --- |
| WIRING-2026-08-09 | MCP/CLI Top-8 wiring honesty (W-01..W-07,W-04,W-06,W-09) | done | tests in `tests/unit/test_world_class_wiring_honesty_2026_08_09.py` |
| DOCS-DUALDOOR-2026-08-09 | Diátaxis dual-door junior docs ecosystem | done | `docs/support|tutorials|how-to|explanation|reference|ops` |
| ISSUE-101 | Rich local Capstone pseudocode renderer | blocked | Wave 0 path (2): disposition table below; issue stays **open**; do not claim closed |
| CLOSEOUT-W0 | Land honesty+docs; #101 disposition; dogfood | done | Merged PR #131 → `047cb81f`. Thinktank APPROVE Wave 0; Sol PASS_WITH_NITS then merge. Dogfood: 22 honesty / 1+43 xfail disasm / app RE evidence_backed. #101 remains open (section L). |

### ISSUE-101 xfail disposition (Wave 0 acceptance path 2)

Source: `tests/unit/test_local_disassembler.py` — all `test_*` except `_PASSING_AGAINST_MINIMAL_FALLBACK`. Count: **43** blocked / **1** pass unmarked.

| test | disposition | reason |
| --- | --- | --- |
| `test_to_ghidra_format_only_emits_continuations_for_generated_functions` | pass | passes against shipped minimal fallback |
| `test_to_ghidra_format_includes_local_pseudocode_functions` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_resolve_call_target_uses_sub_prefix_for_local_targets` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_resolve_call_target_prefers_indirect_local_code_targets` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_to_ghidra_format_prioritizes_direct_call_targets_from_entry_point` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_to_ghidra_format_prioritizes_indirect_local_targets_from_entry_point` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_bounded_section_data_uses_wider_but_still_bounded_window` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_instruction_to_pseudocode_resolves_rip_relative_import_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_instruction_to_pseudocode_resolves_rip_relative_local_code_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_resolves_register_loaded_import_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_preserves_windows_x64_register_args_for_import_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_emits_local_cmp_jump_labels_and_gotos` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_emits_local_test_jump_labels_and_gotos` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_emits_setcc_assignments_from_cmp_state` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_rbp_relative_local_buffers` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_indexed_frame_pointers_for_lea` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_indexed_frame_reads` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_register_relative_reads_and_stores` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_register_relative_lea` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_scaled_register_relative_lea` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_preserves_arithmetic_state_updates` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_does_not_double_add_rbp_to_frame_pointers` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_preserves_multibytetowidechar_arguments` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_uses_live_register_vars_for_overwritten_args` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_preserves_register_aliases_as_live_runtime_vars` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_materializes_rip_relative_addressed_strings` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_preserves_shadow_space_args_for_windows_x64_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_clears_volatile_arg_state_after_call` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_render_pseudocode_function_resolves_register_loaded_local_code_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_to_ghidra_format_stitches_bounded_fallthrough_continuations` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_to_ghidra_format_uses_on_demand_window_for_out_of_slice_local_targets` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_prefers_import_referencing_regions` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_prioritizes_output_regions_over_handle_setup` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_includes_local_callers_of_behavior_regions` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_includes_pe_wide_callers_of_behavior_regions` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_expand_behavioral_predecessor_targets_walks_multiple_local_hops` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_includes_multi_hop_pe_wide_callers` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_includes_neighbor_windows_for_behavior_regions` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_find_pe_behavioral_call_targets_promotes_direct_thunk_calls_to_enclosing_start` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_to_ghidra_format_prioritizes_behavioral_import_regions_over_chunk_sweep` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_to_ghidra_format_records_orphan_behavioral_seed_reachability_metadata` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_uses_pe_scan_for_out_of_slice_import_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_behavioral_seed_targets_prioritizes_pe_scan_output_imports_when_scan_order_is_noisy` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |
| `test_collect_register_behavioral_call_targets_finds_register_loaded_import_calls` | blocked | rich Capstone pseudocode renderer not implemented; shipped module is minimal fallback (#101) |

**Close #101 only when every `blocked` row above is `pass` (zero renderer xfails).**
