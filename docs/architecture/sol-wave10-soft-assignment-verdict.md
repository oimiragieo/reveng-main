# Sol verdict — Wave 10 soft-assign + tombstones

**Reviewed HEAD SHA:** `TBD`  
**Plan / research:** `docs/architecture/research-wave10-soft-assignment-2026-08-10.md`  
**Packet:** `docs/architecture/sol-wave10-soft-assignment-packet.md`  
**PR:** #150

## Protocol note (L47)

- tip1: content under audit with stub `Reviewed HEAD SHA: TBD` (+ backlog pre-merge note).
- tip2: one commit that pins tip1’s SHA into **Reviewed HEAD SHA** above (pin only).
- Sol audits **tip2** SHA. Final PASS / PASS_WITH_NITS / FAIL lives in the **PR comment**.

## Dogfood (pre-Sol)

- `pytest tests/unit/test_wave10_soft_assignment.py -v --no-cov` → **5 passed** (2026-08-21 local).
- CI merge bar on tip `73603a0f…`: `honesty-unit` SUCCESS, `lint-python` SUCCESS (matrix soft-reds L42).
