# Wave 6 — R-RALPH-2 fingerprint wire (W6-A)

> Thinktank: **APPROVE_W6A** (`docs/architecture/thinktank-wave6-fingerprint-wire-2026-08-09.md`). Codex Sol seat.

**Goal:** Wire fingerprint confirmations into the JS adapter product path; content-backed fills only; measure tracked Ralph recall vs Wave 4 **0.4**.

## Tasks

- [x] Thinktank APPROVE_W6A (+ M1 flip forbidden)
- [x] `apply_fingerprint_backed_missing` + adapter wire
- [x] Unit tests: content-backed write + mismatch writes 0
- [ ] Measure tracked Ralph + mismatch; update `reports/js_oracle_ralph_tracked/`
- [ ] Honesty tests / CEO / backlog
- [ ] Sol tip1/tip2 + PR

## Acceptance

- Fingerprint artifact written on adapter path when sibling `.map` exists
- No empty stubs; `decoded_exe_claim=false`
- Mismatch recall 0; treatment ≥ Wave 4 baseline (lift preferred, not required to close R-RALPH-2)
- R-RALPH-2 stays **open** unless recall ≥ 0.8
- M1-NATIVE-FAM `required:false` while `native_fallback_empty`
