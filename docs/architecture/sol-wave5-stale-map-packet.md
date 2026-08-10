# Sol audit packet — Wave 5 stale-map fingerprint transfer

**Branch:** `feat/wave5-stale-map-fingerprint`  
**Plan:** `docs/superpowers/plans/2026-08-09-wave5-stale-map-fingerprint.md`  
**Thinktank:** APPROVE_WITH_NITS

## Must verify

1. Unit tests: mismatch confirms 0; positive confirms alpha with ≥2 signals.
2. Serialized index has **no** plaintext fixture secrets (hashed only).
3. `decoded_exe_claim` is false; `llm_used` false; name_recovery mean 0.
4. Bun Tier B is spike-only doc; R-RALPH-2 backlog status **open**.
5. Honesty tests green; no Anthropic recovered trees in tip file list.
6. Forbidden: claiming materialize/fingerprint = decoded new exe.

## Verdict file

`docs/architecture/sol-wave5-stale-map-verdict.md`
