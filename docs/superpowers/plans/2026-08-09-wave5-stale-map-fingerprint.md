# Wave 5 — Stale-map fingerprint transfer (Tier A)

> Thinktank + Fable: **APPROVE_WITH_NITS** (`docs/architecture/thinktank-stale-map-fingerprint-transfer-2026-08-09.md`).

**Goal:** Hermetic fingerprint index/scan from stale-map `sourcesContent` → attribution evidence on a target bundle. Dual controls. No exe-decode claims. R-RALPH-2 stays open.

## Must-fix nits (baked in)

- Hashed fingerprints only in serialized index
- Unique-to-one-source + length floor + vendor exclude + ≥2 signals for confirm
- Split provenance vs name_recovery (name always 0 on hermetic path)
- Positive + mismatch controls; fail-first mismatch
- Bun unpack = spike doc only (Tier B not ready)

## Tasks

- [x] `js_stale_map_transfer.py`
- [x] Synthetic fixtures under `test_samples/js_stale_map_transfer/`
- [x] Unit + honesty tests
- [x] Research / CEO / backlog / Bun spike note
- [ ] Sol tip1/tip2 + PR

## Acceptance

- [x] Mismatch confirms 0; positive confirms alpha (≥2 signals)
- [x] Serialized index omits raw fixture secrets
- [x] R-RALPH-2 open; no “decoded exe” product claim
