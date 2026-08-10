# Thinktank + Fable synthesis — stale-map fingerprint transfer

**Date:** 2026-08-09  
**Question:** `/tmp/thinktank_stale_map_transfer/question.md`  
**Research bank:** [`research-stale-map-fingerprint-transfer-2026-08-09.md`](research-stale-map-fingerprint-transfer-2026-08-09.md)

## Verdict

**Unanimous `APPROVE_WITH_NITS`** among all verdict-bearing seats.

| Seat | Status | Verdict |
| --- | --- | --- |
| claude (council seat 1 / Fable-class) | OK | APPROVE_WITH_NITS |
| **Dedicated Fable headless** (`claude-fable-5`) | OK | APPROVE_WITH_NITS |
| codex (gpt-5.6-sol) | OK | APPROVE_WITH_NITS |
| agy (Gemini) | OK | APPROVE_WITH_NITS |
| copilot (MAI) | OK | APPROVE_WITH_NITS |
| tt_quick codex+agy | OK / OK | both APPROVE_WITH_NITS |
| droid kimi/minimax/glm | EMPTY (rc 127) | not votes |
| cursor | MISSING_CLI | not a vote |

Chairman reading: **4/4 Western+Google seats + dedicated Fable** agree — proceed as Wave 5 candidate **only after must-fix nits**. No seat recommended REJECT. No seat recommended bare APPROVE.

## Consensus steelman

Stale map is a **puzzle dictionary** (literals / export keys / paths), not a coordinate transform. VLQ application to the new Bun extract is a known false friend. Tier A fingerprint transfer is the right deterministic wedge; LLM is residual-only.

## Must-fix nits (folded — required before coding)

1. **Confidence model, not raw membership.** Unique-to-one-source on the *index* side **and** uniqueness/sparsity on the *target* side; length/IDF floor; exclude `node_modules`/vendor from first-party metrics; **≥2 independent signals** in the same AST scope for “confirmed.” Report first-party separately (Fable: ~29% export-name is the honest anchor, not blended ~69%).
2. **Salted/hashed fingerprint store** — do not commit raw Anthropic literals as an index artifact (claude council).
3. **Bidirectional controls (fail-first).** Positive: map-era index × map-era bundle → high precision. Mismatch: same index × unrelated bundle → ~0 first-party confirmations. Uniform scores = broken instrument.
4. **Split metrics:** `provenance_confidence` ≠ `name_recovery_confidence`; LLM must never upgrade deterministic confidence.
5. **Hermetic ship gate only** — LLM-disabled path complete; LLM flagged `suggested` / non-gating.
6. **Honesty tests (machine-checked):** materialize/`sourcesContent` ≠ “decoded new exe”; L33 — R-RALPH-2 / Phase 6 / enterprise GA stay open.
7. **Slice-0 Bun-unpack feasibility probe (time-boxed).** If multi-module boundaries unrecoverable, state Tier A = hints-only on exe surface and demote Tier B to spike (agy + Fable). Do not list B as ready.
8. **Precision-first** over recall; abstention beats wrong high-confidence path (codex).
9. **Attribution evidence output**, not recovered source modules, for Wave 5 ship claims.

## Wedge order (resolved)

- **Ship Wave 5 slice:** Tier A hermetic indexer/scanner + dual controls + honesty asserts.
- **Parallel/time-boxed:** Bun unpack feasibility (does not block Tier A start; does choose whether B is next).
- **Not first:** LLM rename; VLQ stale-map apply; claiming exe decode.

## Smallest shippable slice

`reveng` module (name TBD, e.g. `js_stale_map_transfer`):
1. Build fingerprint index from stale-map `sourcesContent` (unique long literals + export keys; vendor excluded).
2. Scan target bundle (AST-scoped when possible).
3. Emit ranked hits with confidence + abstentions.
4. Gates: positive high **and** mismatch ~0; deterministic repeat; honesty string forbids.

Tracked fixtures for hermetic CI; Claude dogfood operator-local only.

## Forbidden claims (ship in honesty tests)

- Materializing old `sourcesContent` = decoding / decompiling / recovering new `claude.exe`
- ~69% literal membership = recall / “decoded %”
- Closing R-RALPH-2 / Phase 6 / enterprise GA on fingerprint transfer
- Blended vendor+first-party as first-party recovery
- LLM names as verified / gating
- Anthropic trees in git
- Positive control alone without mismatch arm
