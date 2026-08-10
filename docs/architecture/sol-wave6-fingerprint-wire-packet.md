# Sol audit packet — Wave 6 fingerprint wire (W6-A)

**Branch:** `feat/wave6-fingerprint-wire`  
**Plan:** `docs/superpowers/plans/2026-08-09-wave6-r-ralph2-fingerprint-engine.md`  
**Thinktank:** APPROVE_W6A

## Must verify

1. Adapter calls `apply_fingerprint_backed_missing`; artifact `fingerprint_transfer.json` on tracked run.
2. Unit: mismatch writes 0; positive writes real map body (not empty stub).
3. Tracked Ralph `best_project_file_recall` still **0.4** (honest — no fake lift); mismatch **0.0**.
4. R-RALPH-2 backlog **open**; M1 native_hello_* remain `required:false` / `fixture_only`.
5. Forbidden: exe decode, Phase 6 complete, enterprise GA, M1 flip.
6. tip2 pin-only vs tip1.

## Verdict file

`docs/architecture/sol-wave6-fingerprint-wire-verdict.md`
