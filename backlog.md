# REVENG Scope C Backlog

Ops index for the full roadmap clearance program. Update `status` when work lands.

**CEO briefing:** [`docs/architecture/ceo-update-2026-08-06.md`](docs/architecture/ceo-update-2026-08-06.md)  
**Lessons:** [`docs/architecture/lessons-learned-scope-c-2026-08.md`](docs/architecture/lessons-learned-scope-c-2026-08.md)

Statuses: `open` · `in_progress` · `done` · `partial` · `parked` · `blocked` · `research`

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
| M1-NATIVE-FAM | ≥5 native / ≥3 families hermetic | 2 | open | see R-NATIVE-1 doc | Inventory done; still need C/Go fixtures + Linux pins |
| RALPH-1 | Source-map path alias recall | 6 | partial | domain recall separate | file overlap fixed |
| RALPH-2 | cli.js 0.8+ recall | 6 | open | **yes R-RALPH-2** | harness done; engine long pole |
| M5-PIPE | pipeline vs pipelines merge | 9 | partial | **yes R-PIPE-1** | documented split; merge deferred |
| M0 | Baseline reporting discipline | exec | open | | hexyl report-always / doc sync |
| M1 | Multi-codebase corpus gate | exec | open | see R-NATIVE-1 | overlaps M1-NATIVE-FAM |
| M2 | Hexyl frontier hardening | 4 | open | **yes R-HEX-1** | beyond timeout |
| M3 | Validation/evidence unified contract | 3 | partial | | MCP top-level validation_grade + capability_report landed |
| M4 | CI/PR/nightly corpus gates | 5 | open | | workflows lack bench jobs |
| M5 | Post-gate architecture extraction | 9–10 | open | after M0–M4 | workers/ports |

## D. Research queue (do before large builds)

| id | question | blocks |
| --- | --- | --- |
| R-NATIVE-1 | Linux-hermetic native CLI set for ≥5/≥3 families | **done** — `docs/architecture/research-r-native-1-linux-hermetic-candidates.md` |
| R-RALPH-2 | Smallest engine wedge for 0.8+ recall (baseline first) | RALPH-2, Phase 6 |
| R-HEX-1 | Fresh hexyl timed run: still timeout-only? | M2, Phase 4 |
| R-TSX-1 | Ship `tsx` probe vs keep smoke stub | **done** — optional tsx runner in behavior probe |
| R-PIPE-1 | Merge pipeline packages vs permanent split | M5-PIPE |
| R-SEC-1 | Sandbox class before exploit expansion | Phase 10, Track J |
| R-VRL-1 | Min seeds + provider for honest VRL LLM gate | Phase 4 |

## E. Scope C phase catalog (program backlog)

| phase | focus | status |
| --- | --- | --- |
| 1 | Honesty + known_gaps + GA gate integrity | **done** |
| 2 | Managed recompile + GA report honesty (preview) | **done (preview)**; native corpus still open |
| 3 | Behavior-backed JS validation | **done** (incl. optional tsx) |
| 4 | Hexyl frontier + VRL LLM round-trip honesty | open |
| 5 | Equivalence product gates + CI corpus enforcement | open |
| 6 | JS close: RALPH-2 + bundler graph (P4) | open (BP-2/3/4 done) |
| 7 | Native depth → partial_equivalence + multi-file | open |
| 8 | MCP + AI ops productization | open |
| 9 | Orchestration + modular monolith / ports | open |
| 10 | Workers + external-tool CI + SEC-1 sandbox | open |
| 11 | Analyst / governance / packaging (GA-P4) | open |
| 12 | Platform depth (IR, Ralph opt, RAG, KG start) | open |
| 13 | Blue-ocean / v6.1+ futures (post SEC-1 for exploits) | open |

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
| DF-1 | Host python3.13 stdlib broken — use 3.9 | open (env) |
| DF-2 | Conftest heavy imports | done |
| DF-3 | Wrong analyze report filename in runner | done |
| DF-4 | Full `git status` hangs on dirty `reports/` (DrvFS) | open (ops) |

## I. Decisions / waivers

| date | decision |
| --- | --- |
| 2026-08-06 | Scope C over thinktank B; honesty still first |
| 2026-08-06 | GA floor may accept analyze-ok / recompile-failed styles when evidence is real |
| 2026-08-06 | Public preview: CLI + app RE supported; native limited; exploits experimental |
