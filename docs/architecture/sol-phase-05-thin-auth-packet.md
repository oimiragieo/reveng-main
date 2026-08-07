# Sol authorization packet — Phase 5 THIN honesty slice (2026-08-07)

## Role
You are Sol (gpt-5.6-sol). Authorize or reject a **thin** Phase 5 honesty slice only.
Do NOT authorize full Phase 5 (nightly corpus, native required:true, exploit expansion, M2 closeout).

## Prior context (facts — prefer this packet over sandbox greps)
- Phase 4 honesty go MERGED at `5b59db8e`: `docs/architecture/decision-phase-04-honesty-go-waiver.md`
  (APPROVE honesty exits; M2 remains partial; Phase 5 needs its own Sol stop/go).
- Phase 5 plan: `docs/superpowers/plans/2026-08-07-reveng-phase-05-equiv-ci.md`
- Prior Sol guidance: Phase 5 may be submitted for authorization; preserve M2 as entry dep
  for hexyl/native-equivalence; no blanket Scope C claims.
- M4 today: **partial** — thin `.github/workflows/wave-b-honesty.yml` only; full corpus/nightly open.
- EPIC-7 / FEAT-2 / REV-P1-CI-CORPUS: **open**.
- Native fixtures stay `required: false` / fixture_only until measured (DF-5).
- Exploits: R-SEC-1 Docker-only preview; no expansion.

## Proposed thin slice (APPROVE only if ALL of A–E are acceptable)

**A)** Extend CI beyond wave-b-honesty with a fail-closed corpus/evidence check:
   - new workflow OR job (e.g. `.github/workflows/wave-c-phase5-honesty.yml`) that fails when
     equivalence report is missing/empty
   - empty fixture MUST fail (bidirectional oracle); valid tracked report passes

**B)** Equivalence helper writes a real ValidationGrade-ish grade/status into tracked
   `reports/equivalence_honesty/latest.json`; empty/missing evidence fails the gate

**C)** Wire helper from a customer path: CLI enrich OR `scripts/verify_equivalence_honesty.py`
   invoked by Makefile and/or CI (not a unit-test-only stub)

**D)** Explicit NON-GOALS for this slice:
   - Do NOT flip native `required: true`
   - Do NOT claim M2 done / world-class hexyl closed
   - Do NOT expand exploits
   - Do NOT claim full nightly corpus / M4 done
   - Do NOT claim Scope C complete or phases 6–13 done
   - Do NOT claim Phase 5 full exit criteria met

**E)** Honesty of backlog after landing:
   - M4 may stay **partial** (or note “closer”) with Phase 5 thin evidence gate; full nightly open
   - EPIC-7 / FEAT-2 may become **partial** if helper+report+CI land; full product service open
   - Phase 5 overall **partial** (not full exit)
   - Preserve M2 as entry dep for any hexyl/native-equivalence depth work

## Verdict format (REQUIRED)
Respond with brief cited reasoning, then exactly one final line that is one of:
RECOMMENDED: APPROVE
or
RECOMMENDED: APPROVE_WITH_NITS
or
RECOMMENDED: REJECT

If APPROVE_WITH_NITS, list nits that must land in the same PR.
If REJECT, state the blocking condition clearly (implementer will stop and document).
