# REVENG Phase 4 — Hexyl frontier + VRL LLM honesty (2026-08-07)

> **Authorization scope:** Phase 4 only. Not phases 5–13.
> **Charter:** [`docs/architecture/scope-c-execution-charter.md`](../../architecture/scope-c-execution-charter.md)
> **For agentic workers:** TDD + named-path commits. Checkboxes track progress.

**Goal:** Close Phase 4 product exits for (A) M2 hexyl frontier hardening beyond a
single timed probe and (B) VRL LLM round-trip honesty under `min_seeds: 3` /
`provider: ollama` — without hollow `required: true` flips or Scope C blanket claims.

**Tech stack:** `/usr/bin/python3.9`, pytest, probe v1.3+, `scripts/run_vrl.py`,
local Ollama, backlog.md.

## Entry dependencies

| Dep | Required state | Source |
| --- | --- | --- |
| Phases 1–3 | done / preview on `main` | backlog section E |
| R-HEX-1 | **done (measured)** — timed hexyl subject probe | `research-r-hex-1-hexyl-timed-run.md` + `reports/native_analyze_probe/latest.json` |
| R-VRL-1 | **done (decision)** — `min_seeds: 3`, `provider: ollama` | `decision-r-vrl-1-seeds-and-provider.md` |
| DF-5 | **done** — process `completed` ≠ native GA | backlog H + honesty tests |
| Probe stream attribution | **done** in this wave (v1.3) | `scripts/probe_native_analyze_timeout.py` |
| Charter stop/go | approved for Phase 4 only | `scope-c-execution-charter.md` |
| R-SEC-1 | decision stands; **no exploit expansion** | `decision-r-sec-1-sandbox-class.md` |

## Measured vs open (today)

| Item | State |
| --- | --- |
| Hexyl subject timed analyze (`hexyl_subject` ≈4.68s `completed`) | **Measured** (R-HEX-1) |
| Probe semantic stream attribution (partial_success / empty fallback) | **Measured** — unit tests + Phase 4 live `latest.json` (`probe_version: "1.3"`) |
| M2 frontier hardening beyond timed probe | **Partial** — Track A honesty attribution (v1.3 + re-stamp) evidenced; world-class analyze/recompile/behavior still open |
| VRL policy integers (`min_seeds: 3`, `ollama`) | **Decision recorded** |
| VRL honesty gate (bidirectional / min_seeds / grades) | **Shipped** — `scripts/verify_vrl_llm_honesty.py` + unit tests |
| VRL `runtime_status: measured` on host | **Open** (`could_not_measure` — Ollama unreachable) |
| Native fixture `required: true` | **Forbidden** this phase (hollow gate) |

## Exit criteria (both halves required for Phase 4 stop/go = go)

### A — M2 hexyl frontier

- [x] Tracked probe job includes hexyl **subject** ELF with `analyze_cmd` =
      `/usr/bin/python3.9 -m reveng analyze` (not `tool_absent` on hexyl CLI).
- [x] Positive evidence: at least one completed run with semantic fields populated
      when stdout/stderr show `partial_success` / empty native fallback (v1.3).
- [x] Negative / control: process `completed` alone must **not** flip any native
      `required: true` or close M1-NATIVE-FAM.
- [x] Frontier honesty attribution documented: what improved beyond the R-HEX-1 timed
      measurement (stream attribution / DF-5 fields) with tracked artifact paths —
      **not** world-class M2 closeout.
- [x] M2 backlog row → stay `partial` (honesty attribution done; analyze/recompile/
      behavior still open). Never mark M2 `done` from probe attribution alone.

### B — VRL LLM honesty

- [ ] At least `min_seeds: 3` seeds × tracked corpus under `REVENG_AI_PROVIDER=ollama`.
- [x] Gate enforces: every scored run must record a real `ValidationGrade` (no grade →
      `could_not_measure`, never pass) — **measured grades not yet written** (Ollama CNM).
- [x] No-LLM control arm **fails** the gate (bidirectional) — unit-proven.
- [ ] Provider identity recorded per run; `runtime_status: measured` — policy + gate
      fields exist; live status remains `could_not_measure`.
- [x] Customer-path wiring: exercise `scripts/run_vrl.py` (not a unit-only stub) —
      dogfood attempted; exit 1 (corpus PE binary absent + Ollama down).

## Evidence predicates (exact)

| Artifact | Fields / checks |
| --- | --- |
| `reports/native_analyze_probe/latest.json` | `probe_version` ≥ 1.3 after dogfood re-stamp; exactly one `20*.json` stamp ≡ latest; hexyl + hello_go arms present |
| Result `semantic` | `process_status`, `native_fallback_empty`, `semantic_reason` honest under DF-5 markers |
| `.reveng/benchmarks/corpus.yaml` | grades written; seed argv contract unchanged |
| Native GA manifest | `required: false` / `fixture_only` for native fixtures — **no hollow `required: true`** |
| Backlog | M2 **partial** / VRL-LLM-1 rows match measured state; Phase 4 status **partial** until VRL measured **and** world-class M2 still incomplete |

## Permitted release claim after Phase 4 go

- “Phase 4 hexyl frontier + VRL LLM honesty **measured** under ollama / min_seeds 3.”
- Native PE/ELF deep rebuild remains **limited / preview** unless separate exits close.
- Exploits remain **EXPERIMENTAL / non-GA**; no expansion.
- **Not permitted:** “Scope C complete”, phases 5–13 done, native GA from process green.
- **Current honest claim:** Phase 4 **partial** — Track A honesty attribution evidenced; world-class M2 still open/partial; VRL half `could_not_measure`.

## Kill / park / rollback

| Condition | Action |
| --- | --- |
| Ollama unreachable after reasonable dogfood window | Keep VRL half `could_not_measure`; do not fake grades; Phase 4 stay open |
| Hexyl ELF absent in CI | Loud skip / local-only evidence; never claim CI measured hexyl binary |
| Hardening slice cannot be evidenced | Leave M2 `open`; do not close Phase 4 |
| Any exploit-surface PR appears | **Kill** — cite R-SEC-1; revert |
| Wrong claim lands in CEO/backlog | Rollback claim text; restore prior honest status |

## Explicit non-goals

RALPH-2 → 0.8; M1-NATIVE-FAM `required: true`; full M4 nightly corpus; M5-PIPE merge;
phases 5–13 product work; SEC sandbox proof builds; T3-* unpark.

## Lifecycle checklist

- [x] Plan (this doc) stop/go authorized
- [x] TDD red→green for each exit predicate (Track A + gate; VRL measured pending Ollama)
- [ ] Sol audit APPROVE (or APPROVE_WITH_NITS folded)
- [ ] Fix / re-audit
- [ ] Merge (named paths; author from `git log -1`)
- [ ] Dogfood on `main` (`python3.9` probe + VRL + verify_ga baseline **and** ga)
- [x] Evidence integrity (stamp ≡ latest; open tracked JSON) — probe dir + VRL CNM JSON
- [x] Backlog + CEO update — backlog updated; CEO optional until Sol
- [ ] Phase 4 stop/go recorded — **partial / stay open** (VRL CNM)

## Self-check before claiming Phase 4 done

- [x] No hollow `required: true`
- [x] Disposition statuses never used as capability `done`
- [x] Phases 5–13 still unauthorized
- [x] T3-* parked; no exploit expansion
