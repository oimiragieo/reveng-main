# CEO update — 2026-08-09 (Waves 1–2 honesty)

Plain English. Prior CEO: [`ceo-update-2026-08-09-wave0.md`](ceo-update-2026-08-09-wave0.md).

## One sentence

We still **did not** finish the roadmap. After Wave 0, we shipped **Wave 1** (merged) and opened **Wave 2** (PR #133 — **not merged yet**). Product phases 6–13 and RALPH-2 still wait for Sol stop/go.

## What worked

- **Wave 1 merged** — PR [#132](https://github.com/oimiragieo/reveng-main/pull/132) → `41add7d1`:
  - Installer stubs fail closed with a real `deprecated_stub` token (TDD was red first)
  - Section E statuses are machine-readable (Phase 4 stays **`partial`**; honesty-go lives in notes)
  - CI unicorn/docs labeled honestly (then Wave 2 tightened unicorn)
  - Competitive research banked (actlint / Sleuthre) with pinned URLs
- **Wave 2 built** — branch `feat/wave2-honesty-deep-dive` / PR [#133](https://github.com/oimiragieo/reveng-main/pull/133) (**OPEN**):
  - MCP denylist dual-labels (`generate_exploit`, `recompile_binary`) — spec hints + proprietary risk
  - Path-separator test hygiene (Linux CI no longer fails on `\\` asserts)
  - macOS CI slim install (no angr/unicorn) — matrix **kept**; unicorn noise → **mitigated** (not “angr green”)
- **Thinktank discipline held** — Wave-scoped APPROVE only; “close all backlog” still REJECT (L33).
- **Honesty CI gates** stayed the merge bar for Wave 1 (broad matrix soft-red ≠ Wave blockers).

## What did *not* fully work

- **Wave 2 not on main yet** — Sol impl re-audit still **FAIL** (after remediations; R2 cited little). Don’t merge on a self-written “PASS” alone.
- **Exa MCP unavailable** this session — research used WebSearch/WebFetch; re-verify when Exa is up.
- **Cursor Pro Task seats** hit usage limits mid-audit — parent continued with tg/codex (don’t wait forever on dead seats).
- **Broad CI** still noisy (docs-link, some unit fixtures) — honesty lanes ≠ whole matrix green.

## Research still needed

| ID | Plain question | Status | Blocks |
| --- | --- | --- | --- |
| **R-RALPH-2** | Smallest engine change for cli.js recall ≥ 0.8? | **open** | RALPH-2 / Phase 6 |
| **R-MCP-ANNOTATION-1** | Full declared-vs-derived MCP honesty (actlint-class)? | **partial** (denylist only) | more MCP tools / optional CI gate |
| **EDGE-RECOMPILE-DIFF-1** | Honest VRL vs Sleuthre-style recompile-diff parity? | **open** / could_not_measure | marketing claims |

**Closed research (do not reopen):** R-NATIVE-1, R-RALPH-2-BASELINE, R-HEX-1, R-TSX-1, R-PIPE-1, R-SEC-1, R-VRL-1.

**Ops / not formal research rows:** `CI-DOCS-LINK-1` (root cause still open); angr wheels **done** only when a matrix leg installs angr green (today = mitigated noise only); Ghidra MCP real package; Docker Hub secrets; docs DNS.

## Lessons since last CEO (L41–L48)

Full writeups: [`lessons-learned-scope-c-2026-08.md`](lessons-learned-scope-c-2026-08.md). Short:

1. **L41** — Fail-first TDD must assert a token that is **red today** (e.g. `deprecated_stub`), not a property already true (`success=False`).
2. **L42** — `continue-on-error` / soft-fail ≠ **mitigated** or **done**.
3. **L43** — Phase 4 honesty-go stays status **`partial`**; waiver prose in focus/notes — never hollow `done` while M2 world-class is open.
4. **L44** — Competitive / CI research needs **pinned URLs + access dates** (even when Exa is down).
5. **L45** — MCP hints: **explicit denylist** only — do not auto-map every `risk_level=high`.
6. **L46** — macOS slim install: **keep** matrix legs; no `matrix.exclude` that drops coverage; pin tools for oldest Python (black &lt;25 for 3.9).
7. **L47** — Sol **FAIL** with no blockers + verdict SHA on parent tip is process debt — fix SHA/evidence or leave PR open; never merge on self-attested PASS alone.
8. **L48** — Path-sep CI: fix **asserts** with `as_posix`; don’t claim recovery/GA fixed. Dead Task seats (quota) ≠ “research done” — parent must finish.

## Ask of the CEO

1. Accept Waves 1–2 as **honesty / CI hygiene**, not roadmap clearance.
2. Decide: **merge #133 after Sol PASS**, or hold / slim further.
3. Priority next: Sol stop/go for **R-RALPH-2**, more MCP annotations, or `CI-DOCS-LINK-1` root cause.

---

## ALL backlog (full inventory)

Living file: root [`backlog.md`](../../backlog.md).  
Legend: `done` · `partial` · `open` · `blocked` · `parked` · `mitigated` · `deferred`.  
`partial` / `parked` / `mitigated` / `deferred` ≠ GA capability shipped.

### A — Release blockers / Phase 1–2

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

### C — Open product / quality

| id | status | needs research? |
| --- | --- | --- |
| M1-NATIVE-FAM | open | fixtures; flip `required:true` later |
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
| 4 | **partial** (honesty go in notes; M2 separate) |
| 5 | partial (thin honesty); full corpus open |
| 6–13 | open (await Sol) |

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
| CI-DOCS-LINK-1 | partial |
| CI-UNICORN-BUILD-1 | **mitigated** (macos slim; angr not green) |
| LINT-IMPORTS-HOST-1 | open |
| R-MCP-ANNOTATION-1 | **partial** (Wave 2 denylist) |
| EDGE-RECOMPILE-DIFF-1 | **open** / could_not_measure |

### I — Decisions (dates)

2026-08-06 Scope C / preview / Wave B · 2026-08-07 Phase 4 honesty go · 2026-08-08 PR #119 + L25–L32 · 2026-08-09 Wave 0 + PR #131 · Wave 1 APPROVE + PR #132 · Wave 2 APPROVE_WITH_NITS + PR #133 open.

### J — Full roadmap index (every ingested ID)

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
| REV-P0-INSTALLERS | **partial** (deprecate stubs Wave 1) |
| REV-P0-EVIDENCE-AUDIT | open |
| REV-P0-ANALYSIS-CLEANUP | **partial** (policy only) |
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

Recorded. Phases 5–13 need Sol stop/go before product builds. M2 world-class still open. Section E phase 4 status = **partial**.

### L — Wave 0 closeout (+ Wave 1/2 pointers)

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
| Issue **#101** rich Capstone | **OPEN** |
| PR **#131** Wave 0 | **MERGED** |
| PR **#132** Wave 1 | **MERGED** (`41add7d1`) |
| PR **#133** Wave 2 | **OPEN** (Sol gate) |

### Deferred from tg-audit (still not done)

D1–D6: LibAFL, mega splits, full CFG/fold/DCE, DnSpy installer finish, java AI cloud NI, hollow native rows — **deferred**.
