# Thinktank — Wave 6 wedge (2026-08-09)

**Seats:** Codex `gpt-5.6-sol` (primary). `tt_quick` failed (agy STRUCTURED_INVALID / permission deny on dogfood path).  

**Verdict:** **APPROVE_W6A**

## Decision

Wire fingerprint confirmations through the JS **adapter** product path; only write recovered files when map `sourcesContent` backs them (no empty stubs; attribution ≠ source content). Measure tracked Ralph recall vs Wave 4 baseline **0.4**; mismatch must stay **0**. Keep **R-RALPH-2 open** unless ≥0.8. **Do not** flip M1-NATIVE-FAM `required:true` while `native_fallback_empty`.

## Must-fix nits (baked into Wave 6 plan / impl)

- Adapter path: `adapters/javascript.py` + `js_stale_map_transfer.apply_fingerprint_backed_missing`
- Preserve ≥2-signal / hashed / mismatch-zero contracts
- Fail-first unit tests for content-backed write + mismatch zero writes
- Regenerate tracked Ralph report after measure; do not close Phase 6 on partial lift
