# CEO update — REVENG (2026-08-06, wave 3)

Plain English. **Previous briefing:** [`ceo-update-2026-08-06-wave2.md`](ceo-update-2026-08-06-wave2.md) (native fixtures + probe v1.1).

## Bottom line (one sentence)

We finished an honesty-first **Wave A**: better stopwatch, research *decisions* written down, backlog cleaned up — and we still **have not** finished native reverse-engineering, Ralph recall, hexyl, or most of Scope C.

## What worked (since wave 2)

1. **Thinktank + Sol plan loop** — “close everything” was rejected as dishonest; **Wave A v2** got Sol **APPROVE_WITH_NITS**, then implement, then Sol **APPROVE**.
2. **Probe v1.2** — missing tool ≠ failed analyze (`tool_absent` vs `input_absent`); stdout/stderr tails sanitized before truncate; semantic fields; multi-result `--job` file; exactly one stamp + `latest.json`.
3. **Measured evidence** — hello_go analyze can show process `completed` (exit 0) **and** still not be native GA (**DF-5**). Hexyl recorded as `tool_absent:hexyl` → **R-HEX-1 = blocked** (not “done”).
4. **Research decisions shipped as docs** — PIPE = keep split; SEC = Docker-only preview, no exploit expansion; VRL = `min_seeds: 3`, provider `ollama`.
5. **R-RALPH-2-BASELINE** — measured attempt labelled `could_not_measure` (no fake recall `0`); product **RALPH-2** stays open.
6. **DF-4** — `scripts/git_status_scoped.sh` so DrvFS doesn’t hang on `reports/`.
7. **Merged to `main`** — `20a5e201` (+ hygiene/format). Dogfood: Wave A unit suite green; `verify_ga_readiness` baseline + ga both pass (still ≠ native GA).

## What “ship” means today

| Surface | Claim |
| --- | --- |
| CLI + app RE (JS / JVM / Python managed) | Supported **preview** |
| Native PE/ELF deep rebuild | **Limited** — fixtures + probe; not hermetic GA |
| Exploits | Experimental / non-GA (Docker-only decision; no expansion) |
| Full Scope C (phases 4–13) | **Not done** — see Wave B exit criteria |

## Needs research / still blocked (before big builds)

| ID | Status | Plain question |
| --- | --- | --- |
| **R-RALPH-2** | **open** | Smallest engine wedge for cli.js recall → 0.8+? (baseline doc exists; wedge not chosen/built) |
| **R-HEX-1** | **blocked** | Obtain hexyl (or Linux musl binary) and run a **timed** probe — `tool_absent` is not a timed run |
| R-NATIVE-1 | done | Candidate list |
| R-RALPH-2-BASELINE | done | Baseline / could_not_measure recorded |
| R-TSX-1 | done | Optional tsx |
| R-PIPE-1 | done | Permanent split (decision) |
| R-SEC-1 | done | Docker-only preview (decision) |
| R-VRL-1 | done | min_seeds 3 + ollama (decision; runtime may still be unmeasured) |

## Full backlog (everything in `backlog.md`)

### A — shipped
GA-HOLLOW-1, GAP-OLLAMA-1, GAP-ML-1, SEC-EXP-1, NATIVE-EVID-1, CLI-PY39-1, BENCH-LAUNCH-1, PY39-FSTR-1, RECOMPILE-1, CLI-OUTDIR-1 → **done**

### B — shipped
P3-BP-1..4, DF-2, LOG-PRINTF-1 → **done**

### C — active
| id | status |
| --- | --- |
| M1-NATIVE-FAM | open |
| RALPH-1 | partial |
| RALPH-2 | open |
| M5-PIPE | partial (split freeze; merge optional Wave B) |
| M0 | partial |
| M1 | open |
| M2 | open |
| M3 | partial |
| M4 | open |
| M5 | open |

### D — research queue
| id | status |
| --- | --- |
| R-NATIVE-1 | done |
| R-RALPH-2-BASELINE | done |
| R-RALPH-2 | **open** |
| R-HEX-1 | **blocked** |
| R-TSX-1 | done |
| R-PIPE-1 | done |
| R-SEC-1 | done |
| R-VRL-1 | done |

### E — Scope C phases
1–3 **done** (2 = preview) · **4–13 open**

### F — hardening leftovers
P4-BUNDLER, P5-NATIVE-EQ, P6-PLATFORM → **open**

### G — parked
T3-KERNEL, T3-PACKED, T3-JIT, T3-ANTI, T3-GUI → **parked**

### H — dogfood
| id | status |
| --- | --- |
| DF-1 | mitigated (use py3.9) |
| DF-2 | done |
| DF-3 | done |
| DF-4 | done |
| DF-5 | open (honesty) — process completed ≠ native GA |

### I — decisions
Scope C + honesty first; preview claims as above; Wave A research/ops closures recorded; Wave B exit criteria published.

## Lessons since last CEO update (wave 2 → 3) — retain L19–L24

1. **“Close all backlog” plans must be Wave-scoped** — Sol rejects plans that mark research `done` without the measurement the row asks for.
2. **`tool_absent` ≠ timed frontier** — missing hexyl is **blocked**, not research-complete.
3. **Split baseline rows from engine rows** — `R-RALPH-2-BASELINE` can close; `R-RALPH-2` stays open.
4. **Process `completed` ≠ capability** — DF-5 / semantic fields required.
5. **Evidence hygiene is fail-closed** — exactly one stamp matching `latest.json`; merge can reintroduce stale stamps — re-check on main.
6. **Thinktank plans need Windows-reachable paths + inline Sol packets** — `/tmp` and PowerShell greps break seats.
7. **Merge needs explicit `git -c user.name/email`** — empty ident aborts; dirty main sync copies block merge (discard, don’t stash across worktrees).

Full write-ups: [`lessons-learned-scope-c-2026-08.md`](lessons-learned-scope-c-2026-08.md) (L1–L24).

## Pointers

- Ops: [`backlog.md`](../../backlog.md)
- Wave B gates: [`wave-b-exit-criteria.md`](wave-b-exit-criteria.md)
- Plan: `docs/superpowers/plans/2026-08-06-reveng-backlog-clearance-wave-a-v2.md`
- Sol impl: [`sol-audit-wave-a-impl.md`](sol-audit-wave-a-impl.md)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
- `main` tip at briefing time: includes `35ae5b8e` / merge `20a5e201`
