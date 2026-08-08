# Decision: Phase 5 thin honesty slice — authorized (2026-08-07)

## Decision
**APPROVE** a **thin** Phase 5 honesty slice only (not full Phase 5 exit criteria).

Sol: `APPROVE` (inline packet `sol-phase-05-thin-auth-packet.md`, 2026-08-07).

## Authorized scope
| Item | Allowed |
| --- | --- |
| A — CI fail-closed evidence check beyond wave-b-honesty | yes |
| B — Equivalence helper → `reports/equivalence_honesty/latest.json` (empty fails) | yes |
| C — Customer path: `scripts/verify_equivalence_honesty.py` via Makefile/CI | yes |
| D — Flip native `required: true` / claim M2 done / expand exploits / full nightly | **no** |
| E — Backlog honesty: Phase 5 / M4 / EPIC-7 / FEAT-2 may be **partial**; nightly corpus remains open | yes |

## Permitted claim
“Phase 5 thin equivalence honesty gate measured under named workflow/report.”

## Forbidden claims
- Phase 5 full exit / M4 nightly corpus done
- M2 done / native GA / Scope C complete
- Exploit expansion
- Hollow empty-evidence green

## Effects
- Phase 5 → **partial** (thin honesty landed; full corpus residual open)
- M2 remains entry dep for hexyl/native-equivalence depth
