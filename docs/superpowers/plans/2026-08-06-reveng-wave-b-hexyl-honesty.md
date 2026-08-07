# REVENG Wave B — Hexyl unblock + thin honesty gates

> **For agentic workers:** TDD + named-path commits. Checkboxes track progress.
> **Sol plan audit:** APPROVE_WITH_NITS — fold: exact M0/DF-5 predicates; executable backlog invariants; DF-5 proves reporting contract only; pin sha256 in probe result; timeout semantics explicit; CI loud-skip for missing ELF.

**Goal:** Unblock R-HEX-1 with a real timed hexyl analyze probe; add a thin PR honesty gate (M4 slice); close DF-5 / M0 honesty rows where evidence exists — without claiming native GA, RALPH-2 0.8, or phases 4–13.

**Architecture:** Build/use local hexyl ELF (gitignored artifact); extend probe job; CI workflow step runs fixture/probe contract tests only; backlog reconcile. Minimal or zero `src/reveng/**` unless a one-line probe/CLI argv fix is required for attribution.

**Tech Stack:** `/usr/bin/python3.9`, pytest, cargo-built hexyl, GitHub Actions YAML, backlog.md.

## Global Constraints

- Python 3.9; named-path git; `git -c user.name/email` from log-1; no stash across worktrees.
- Fixture/build ≠ capability; process `completed` ≠ native GA (DF-5).
- Exactly one probe stamp ≡ `latest.json` after runs.
- T3-* stay parked; no exploit expansion.
- Do **not** flip native `required: true` or close M1-NATIVE-FAM / RALPH-2 / phases 4–13.

## Explicit non-goals

RALPH-2 engine to 0.8; M1-NATIVE-FAM required:true; full M5-PIPE merge; VRL runtime measured gate; phases 5–13 product work; SEC sandbox proofs beyond decision.

---

### Task 1 — Record hexyl binary provenance (TDD)

- [ ] Script or Makefile target `scripts/build_hexyl_fixture.sh` builds `external/hexyl-benchmark/hexyl` release and copies to `test_samples/native/hexyl/build/hexyl` (gitignored `build/`).
- [ ] Write `docs/architecture/research-r-hex-1-hexyl-timed-run.md` with version, sha256, path.
- [ ] Test: if binary present, sha256 file exists and matches; if absent, skip with loud reason (not silent pass).
- [ ] Commit sources/docs/tests only — **not** the ELF.

### Task 2 — Timed probe job including hexyl as **subject binary**

Job arm: `analyze_cmd` = `/usr/bin/python3.9 -m reveng analyze`, `binary` = hexyl ELF (not `tool_absent` on hexyl CLI).

- [ ] Update `wave_b_job.json` (or extend wave_a job) with hello_go + hexyl_subject.
- [ ] Run probe budget ≤120s; commit latest + one stamp + README.
- [ ] Update R-HEX-1 backlog: **done (measured)** or keep open if timeout — status must match JSON (`completed`/`timeout`/`could_not_measure`). Never claim M2 “fixed.”
- [ ] M2 stays open unless frontier hardening beyond timeout is proven (it won’t be this wave).

### Task 3 — M4 thin PR gate (TDD)

- [ ] Add `.github/workflows/wave-b-honesty.yml` (or job in existing) running:
  - `pytest --no-cov` for probe/evidence/backlog invariant / native fixture visibility tests
  - Does **not** require Ghidra/hexyl binary in CI (skip or tool_absent OK)
- [ ] Test or actionlint-friendly YAML; document that full corpus gates remain Wave B+ / M4 residual.
- [ ] Backlog M4 → **partial** (thin honesty gate landed; corpus blocking still open).

### Task 4 — Close DF-5 + M0 honesty rows

- [ ] DF-5: unit test that `latest.json` hello_go (or fixture) with `status=completed` must include semantic keys and backlog/CEO language forbids treating it as native GA; mark DF-5 **done (documented+tested)**.
- [ ] M0 → **done** for preview reporting discipline (probe v1.2 + hygiene + scoped git) — note CI corpus still M4 residual.

### Task 5 — Backlog + Wave C exit criteria

- [ ] Reconcile backlog rows touched above.
- [ ] Write `docs/architecture/wave-c-exit-criteria.md` for remaining: RALPH-2, M1-NATIVE-FAM, M2 hardening, M4 corpus, VRL measured, phases 4–13, P4–P6, T3 parked.
- [ ] Invariant tests updated for new statuses.
- [ ] Dogfood verify_ga baseline+ga; pytest wave modules.

### Task 6 — Sol audit + merge

- [ ] Sol APPROVE on branch; merge to main with author identity; post-merge stamp hygiene.

## Self-check

- [ ] RALPH-2 / M1-NATIVE-FAM / phases 4–13 / T3 still open/parked
- [ ] No required:true native flips
- [ ] Hexyl timed evidence committed (status honest)
- [ ] ELF not committed
