# CEO update — 2026-08-09 (Wave 0 closeout)

Plain English. Prior CEO: [`ceo-update-2026-08-08-tg-audit-merge.md`](ceo-update-2026-08-08-tg-audit-merge.md).

## One sentence

We **did not** finish the whole roadmap. Thinktank approved **Wave 0 only**: ship honesty wiring + junior docs, honestly park GitHub **#101**, fix honesty CI, merge **PR #131**. Most product work still waits for Sol stop/go.

## What worked

- **Thinktank said no to “close all backlog in one PR”** — then approved a tight Wave 0. That saved us from a fake “done” ship.
- **PR #131 merged** to `main` (`047cb81f`; closeout docs `a34e08af`):
  - MCP/CLI Top-8 wiring honesty (AI off means off; no fake % claims; health probes real; etc.)
  - Diátaxis **junior docs** (analyst + engineer doors under `docs/support|tutorials|how-to|explanation|reference|ops`)
  - Slim honesty CI: `pytest-cov` in `requirements-honesty.txt`; Phase 5 uses setup-python `python` (not a missing `/usr/bin/python3.9`)
  - Backlog tests allow Phase 5 **`partial`** (thin honesty is real, not “still open forever”)
- **Dogfood on main:** 22 wiring honesty tests + 35 backlog invariants green; `reveng --help` OK; sample app RE → `evidence_backed`.
- **#101 handled honestly:** 43 renderer tests stay `xfail`; per-test table in `backlog.md` §L; issue **stays open** (not closed as “done”).

## Research still needed

| ID | Plain question | Blocks |
| --- | --- | --- |
| **R-RALPH-2** | What’s the smallest engine change to get cli.js recall ≥ 0.8? (baseline already measured) | RALPH-2 / Phase 6 |

**Closed research (do not reopen):** R-NATIVE-1, R-RALPH-2-BASELINE, R-HEX-1, R-TSX-1, R-PIPE-1, R-SEC-1, R-VRL-1.

**Optional later (ops / packaging, not formal research rows):** real Ghidra MCP package vs forever-fallback; Docker Hub secrets; docs DNS / linkcheck debt (`CI-DOCS-LINK-1`); angr/unicorn matrix builds (`CI-UNICORN-BUILD-1`).

## Lessons since last CEO (L33–L40)

Full writeups: [`lessons-learned-scope-c-2026-08.md`](lessons-learned-scope-c-2026-08.md). Short:

1. **L33** — “Close all backlog” plans get **REJECT**; Wave-scoped plans get **APPROVE**.
2. **L34** — A disposition table + open issue ≠ shipped capability (#101).
3. **L35** — Slim CI must still install plugins your flags need (`--no-cov` ⇒ `pytest-cov`).
4. **L36** — Never hardcode `/usr/bin/python3.9` on GitHub Actions; use setup-python’s `python`.
5. **L37** — Codex mid-loop **FAIL** for missing verdict artifacts is process debt — write the SHA file, re-audit, then merge.
6. **L38** — `git reset` / full status on a dirty DrvFS tree (esp. `external/`) hangs and fights `index.lock`; named paths only.
7. **L39** — Early CI-watcher FAIL is a snapshot; fix, push, re-poll the **new** run before declaring blocked forever.
8. **L40** — Pre-existing red (docs-link, unicorn) ≠ your PR’s regression — label in backlog; don’t stall Wave 0 honesty on them.

## Ask of the CEO

1. Accept Wave 0 as **honesty land**, not roadmap clearance.
2. Sol **stop/go** before Phase 6+ product (RALPH-2 engine first research).
3. Priority call: fix `CI-DOCS-LINK-1` / `CI-UNICORN-BUILD-1` this week, or leave as known noise.

---

## ALL backlog (full inventory)

Living file: root [`backlog.md`](../../backlog.md). Status legend: `done` · `partial` · `open` · `blocked` · `parked` · `mitigated` · `in_progress` · `deferred`.  
`partial` / `parked` / `deferred` ≠ capability shipped as GA.

### A — Release blockers / Phase 1–2 (shipped)

| id | status |
| --- | --- |
| GA-HOLLOW-1 | done |
| GAP-OLLAMA-1 | done |
| GAP-ML-1 | done |
| SEC-EXP-1 | done |
| NATIVE-EVID-1 | done |
| CLI-PY39-1 | done |
| BENCH-LAUNCH-1 | done |
| PY39-FSTR-1 | done |
| RECOMPILE-1 | done |
| CLI-OUTDIR-1 | done |

### B — Phase 3 JS behavior

| id | status |
| --- | --- |
| P3-BP-1 | done |
| P3-BP-2 | done |
| P3-BP-3 | done |
| P3-BP-4 | done |
| DF-2 | done |
| LOG-PRINTF-1 | done |

### C — Open product / quality (active)

| id | status | needs research? |
| --- | --- | --- |
| M1-NATIVE-FAM | open | fixtures measured; flip `required:true` later |
| RALPH-1 | partial | await Sol |
| RALPH-2 | open | **yes — R-RALPH-2** |
| M5-PIPE | partial | await Sol (split freeze) |
| M0 | done | |
| M1 | open | overlaps M1-NATIVE-FAM |
| M2 | partial | world-class hexyl still open |
| M3 | partial | |
| M4 | partial | thin honesty in; full corpus residual |
| M5 | open | after M0–M4 |

### D — Research queue

| id | status |
| --- | --- |
| R-NATIVE-1 | done |
| R-RALPH-2-BASELINE | done |
| **R-RALPH-2** | **open** |
| R-HEX-1 | done (measured) |
| R-TSX-1 | done |
| R-PIPE-1 | done |
| R-SEC-1 | done |
| R-VRL-1 | done |

### E — Scope C phases 1–13

| phase | status |
| --- | --- |
| 1 | done |
| 2 | done (preview); native corpus open |
| 3 | done |
| 4 | done (honesty go); M2 world-class separate/partial |
| 5 | partial (thin honesty); full corpus open |
| 6 | open (await Sol) |
| 7 | open (await Sol) |
| 8 | open (await Sol) |
| 9 | open (await Sol) |
| 10 | open (await Sol) |
| 11 | open (await Sol) |
| 12 | open (await Sol) |
| 13 | open (await Sol) |

### F — Capability hardening leftovers

| id | status |
| --- | --- |
| P4-BUNDLER | open |
| P5-NATIVE-EQ | open |
| P6-PLATFORM | open |

### G — Parked (Tier 3 — do not claim)

| id | status |
| --- | --- |
| T3-KERNEL | parked |
| T3-PACKED | parked |
| T3-JIT | parked |
| T3-ANTI | parked |
| T3-GUI | parked |

### H — Dogfood / CI findings

| id | status |
| --- | --- |
| TG-AUDIT-2026-08-08 | done |
| CI-HONESTY-SLIM-1 | done |
| GHIDRAMCP-PIN-1 | done |
| DF-1 | mitigated |
| DF-2 | done |
| DF-3 | done |
| DF-4 | done |
| DF-5 | done |
| WIRING-2026-08-09 | done |
| DOCS-DUALDOOR-2026-08-09 | done |
| ISSUE-101-DISP | blocked (#101 open) |
| CI-HONESTY-NOCOV-1 | done |
| CI-PHASE5-PY39-PATH-1 | done |
| CI-DOCS-LINK-1 | open |
| CI-UNICORN-BUILD-1 | open |
| LINT-IMPORTS-HOST-1 | open |

### I — Decisions (dates)

2026-08-06 Scope C / preview / Wave B · 2026-08-07 Phase 4 honesty go · 2026-08-08 PR #119 + L25–L32 · 2026-08-09 Wave 0 APPROVE + PR #131.

### J — Full roadmap index (every ingested ID)

Duplicates of C/F/G are intentional (source ingest). Status is SoT here when it differs from prose elsewhere.

| id | status |
| --- | --- |
| M0 | done |
| M1 | open |
| M1-NATIVE-FAM | open |
| M2 | partial |
| M3 | partial |
| M4 | partial |
| M5 | open |
| M5-PIPE | partial |
| EPIC-0 | partial |
| EPIC-1 | open |
| EPIC-2 | open |
| EPIC-3 | open |
| EPIC-4 | open |
| EPIC-5 | open |
| EPIC-6 | open |
| EPIC-7 | partial |
| EPIC-8 | open |
| EPIC-9 | open |
| P3-BP-1 | done |
| P3-BP-2 | done |
| P3-BP-3 | done |
| P3-BP-4 | done |
| RALPH-1 | partial |
| RALPH-2 | open |
| P4-BUNDLER | open |
| P5-NATIVE-EQ | open |
| P6-PLATFORM | open |
| T3-KERNEL | parked |
| T3-PACKED | parked |
| T3-JIT | parked |
| T3-ANTI | parked |
| T3-GUI | parked |
| GA-P0 | done |
| GA-P1 | done |
| GA-P2 | open |
| GA-P3 | open |
| GA-P4 | open |
| FEAT-1 | open |
| FEAT-2 | partial |
| FEAT-3 | open |
| FEAT-4 | open |
| FEAT-5 | open |
| FEAT-6 | open |
| FEAT-7 | open |
| FEAT-8 | open |
| FEAT-9 | open |
| FEAT-10 | open |
| REV-P0-INSTALLERS | open |
| REV-P0-EVIDENCE-AUDIT | open |
| REV-P0-ANALYSIS-CLEANUP | open |
| REV-P1-LLM-REFINER | open |
| REV-P1-WHOLE-PROGRAM | open |
| REV-P1-CI-CORPUS | partial |
| REV-P2-GATE-LLM-RT | open |
| REV-P2-GATE-BM3 | open |
| REV-P2-GATE-SEEDS | open |
| REV-MCP | open |
| REV-SUBAGENTS | open |
| REV-STATE | open |
| REV-JOURNAL | open |
| REV-SANDBOX | open |
| REV-FINGERPRINT | open |
| REV-KG | open |
| REV-ANNOTATE | open |
| REV-VARIANT | open |
| REV-SELF-IMPROVE | open |
| REV-COMPILER-ARCH | open |
| REV-XARCH | open |
| REV-SEMDIFF | open |
| REV-NLQ | open |
| REV-YARA | open |
| REV-ARCH-OWN | open |
| REV-SPA | open |
| REV-IDE | open |
| V6-TS-INFER | open |
| V6-REACT-VUE | open |
| V6-NPM | open |
| V6-SUPPLY | open |
| V6-BROWSER-EXT | open |
| V6-WEB-UI | open |
| V6-REST | open |
| V6-DOCKER | open |
| V6-K8S | open |
| V6-GHA | open |
| PROF-SHIM-4 | open |
| VRL-LLM-1 | done |

### K — Phase 4 honesty go

Recorded. Phases 5–13 authorized for *planning* but need Sol stop/go before product builds. M2 world-class still open.

### L — Wave 0 closeout

| id | status |
| --- | --- |
| WIRING-2026-08-09 | done |
| DOCS-DUALDOOR-2026-08-09 | done |
| ISSUE-101 | blocked (43 xfails; issue open) |
| CLOSEOUT-W0 | done (PR #131) |

Plus **43** `#101` test rows dispositioned `blocked` (and 1 `pass`) — full table in `backlog.md` §L.

### GitHub

| item | status |
| --- | --- |
| Issue **#101** rich Capstone pseudocode | **OPEN** |
| PR **#131** Wave 0 | **MERGED** |

### Deferred from tg-audit (still not Wave 0)

D1–D6: LibAFL, mega splits, full CFG/fold/DCE, DnSpy installer, java AI cloud NI, hollow native rows — **deferred**, not done.
