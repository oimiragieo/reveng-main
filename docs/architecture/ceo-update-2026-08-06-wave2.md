# CEO update — REVENG (2026-08-06, wave 2)

Plain English. **Previous briefing:** [`ceo-update-2026-08-06.md`](ceo-update-2026-08-06.md) (Phases 1–3 honesty + JS behavior).

**Superseded for “what’s next” by:** [`ceo-update-2026-08-06-wave3.md`](ceo-update-2026-08-06-wave3.md) (Wave A clearance on main). Keep this file as the native-fixtures snapshot.

## Bottom line (one sentence)

We built tiny real C/Go test programs and a stopwatch for “does analyze finish?”, measured that analyze **fails fast** (does not hang forever on our Go fixture), and we still **must not** say native reverse-engineering is ready.

## What worked (since last CEO update)

1. **Tiny native toys** — `hello_c` / `hello_go` under `test_samples/native/` with fixed `--help` / `--version` text (so tests don’t flake).
2. **Honest labels** — those toys are registered as `fixture_only` / `required: false`. Building them ≠ analyzing them.
3. **Stopwatch script (v1.1)** — `scripts/probe_native_analyze_timeout.py` records three different outcomes and refuses to mix them up:
   - finished OK → `completed`
   - ran too long → `timeout`
   - missing binary / crashed / nonzero exit → `could_not_measure`
4. **Real measurement** — on this machine, Go fixture + `reveng analyze` → exit 1 in ~0.03s (`could_not_measure` / `nonzero_exit:1`). Not a hang; also not success.
5. **MCP honesty leftovers from prior slice** — top-level `validation_grade` + `capability_report` on simple/enterprise MCP paths; optional `tsx` when present.
6. **Validator loop** — Codex Sol **REJECT → fix → REJECT → fix → APPROVE** on branch `feat/scope-c-phase-next` (tip includes `029627d4`).

## What “ship” means today (same honesty)

| Surface | Claim |
| --- | --- |
| CLI + app RE (JS / JVM / Python managed) | Supported **preview** |
| Native PE/ELF deep rebuild | **Limited** — fixtures exist; analyze not proven hermetic |
| Exploits | Experimental / non-GA |
| Full Scope C (phases 4–13) | **Not done** |

## Needs research (before big builds)

| ID | Still open? | Plain question |
| --- | --- | --- |
| R-RALPH-2 | **yes** | Smallest engine change to push tracked `cli.js` recall toward 0.8+ (measure baseline first)? |
| R-HEX-1 | **hexyl part yes** | Probe exists; **hexyl binary missing here** — still need a timed hexyl run before calling M2 done |
| R-PIPE-1 | **yes** | Merge `pipeline/` + `pipelines/` or keep the split forever? |
| R-SEC-1 | **yes** | What sandbox class before any exploit expansion? |
| R-VRL-1 | **yes** | Min seeds + provider for an honest VRL LLM gate? |
| R-NATIVE-1 | done | Candidate list written |
| R-TSX-1 | done | Optional `tsx` runner shipped |

## Full backlog (everything in `backlog.md`)

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

### B — Phase 3 JS behavior (mostly shipped)

| id | status |
| --- | --- |
| P3-BP-1 | done |
| P3-BP-2 | done |
| P3-BP-3 | done |
| P3-BP-4 | done |
| DF-2 | done |
| LOG-PRINTF-1 | done |

### C — Open product / quality (active)

| id | status | research? |
| --- | --- | --- |
| M1-NATIVE-FAM | open | fixtures landed; close only when analyze ≤120s on both + flip `required` |
| RALPH-1 | partial | domain recall separate |
| RALPH-2 | open | **R-RALPH-2** |
| M5-PIPE | partial | **R-PIPE-1** |
| M0 | open | reporting discipline (incl. native probe folder) |
| M1 | open | overlaps M1-NATIVE-FAM |
| M2 | open | **R-HEX-1** (hexyl still unmeasured here) |
| M3 | partial | MCP grade fields landed |
| M4 | open | CI/PR/nightly corpus jobs missing |
| M5 | open | after M0–M4 |

### D — Research queue

| id | status |
| --- | --- |
| R-NATIVE-1 | **done** |
| R-RALPH-2 | **open** |
| R-HEX-1 | probe shipped; **hexyl timed run still open** |
| R-TSX-1 | **done** |
| R-PIPE-1 | **open** |
| R-SEC-1 | **open** |
| R-VRL-1 | **open** |

### E — Scope C phases

| phase | status |
| --- | --- |
| 1 Honesty + GA integrity | **done** |
| 2 Managed recompile + GA honesty | **done (preview)**; native corpus open |
| 3 Behavior-backed JS validation | **done** |
| 4 Hexyl frontier + VRL LLM honesty | open |
| 5 Equivalence gates + CI corpus | open |
| 6 JS close: RALPH-2 + bundler graph | open |
| 7 Native depth → partial_equivalence | open |
| 8 MCP + AI ops productization | open |
| 9 Orchestration / ports | open |
| 10 Workers + tool CI + SEC-1 | open |
| 11 Analyst / governance / packaging | open |
| 12 Platform depth | open |
| 13 Blue-ocean / v6.1+ futures | open |

### F — Capability hardening leftovers

| id | status |
| --- | --- |
| P4-BUNDLER | open |
| P5-NATIVE-EQ | open |
| P6-PLATFORM | open |

### G — Parked (do not claim)

| id | status |
| --- | --- |
| T3-KERNEL | parked |
| T3-PACKED | parked |
| T3-JIT | parked |
| T3-ANTI | parked |
| T3-GUI | parked |

### H — Dogfood findings

| id | status |
| --- | --- |
| DF-1 | open (env) — use python3.9 |
| DF-2 | done |
| DF-3 | done |
| DF-4 | open (ops) — full `git status` hangs on dirty `reports/` |

### I — Decisions / waivers

- Scope C over thinktank B; honesty still first
- GA floor may accept analyze-ok / recompile-failed when evidence is real
- Public preview: CLI + app RE supported; native limited; exploits experimental

## Lessons since last CEO update (retain)

New durable rules **L12–L18** (plus restored L11 in the lessons file). Short versions:

1. **Fixture ≠ product** — a binary that builds is not “native RE works.”
2. **Nonzero ≠ completed** — stopwatch statuses must not lie.
3. **Latest.json is not enough** — every tracked evidence file must be honest, or delete it.
4. **Cursor Pro ≠ Fable** — use `claude -p --model claude-fable-5` / `codex exec --model gpt-5.6-sol`.
5. **Alive ≠ working** — check CPU + log growth on background agents.
6. **Inline Sol evidence** when the sandbox blocks PowerShell greps.
7. **This host’s C linker is broken** — Go with `CGO_ENABLED=0` works; skips must be loud.

Full write-ups: [`lessons-learned-scope-c-2026-08.md`](lessons-learned-scope-c-2026-08.md).

## Pointers

- Ops index: [`backlog.md`](../../backlog.md) (root — **not** `docs/BACKLOG.md`)
- Branch / worktree: `feat/scope-c-phase-next` · `.worktrees/scope-c-phase-next`
- Sol ledger: `.superpowers/sdd/sol-audit-native-fixtures.md`
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
