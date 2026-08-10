# Sol verdict — Wave 4 JS recovered-root

**Reviewed HEAD SHA (tip1):** `8923ab7f45db5b4e26f130f0fd5c7565ee196b14`  
**Plan:** `docs/superpowers/plans/2026-08-09-wave4-js-recovered-root-naming.md`  
**Packet:** `docs/architecture/sol-wave4-recovered-root-packet.md`

## Tip1 verdict

`REJECT` (Codex `gpt-5.6-sol`, 2026-08-09)

### Checklist

- [x] Treatment recall > 0 + source_map
- [x] Wave 3 freeze intact
- [x] Mismatch discriminates (doc)
- [x] R-RALPH-2 open
- [ ] No Anthropic IP in diff — **UNVERIFIED** in tip1 (sandbox blocked `git show`; tip file list now pinned in `sol-wave4-tip1-name-status.txt`)
- [ ] Mismatch honesty test asserts numeric `treatment > mismatch` — **FAIL** tip1 (substring-only)

### Must-fix (tip2)

1. Parse Treatment/Mismatch floats in `test_mismatch_control_doc_discriminates` and assert `treatment > mismatch`.
2. Pin `git show --name-status` for tip1 SHA in-repo for Anthropic-tree gate.
3. Re-run focused pytest; re-audit tip2.
