# Sol verdict — Wave 4 JS recovered-root

**Reviewed HEAD SHA (tip1):** `8923ab7f45db5b4e26f130f0fd5c7565ee196b14` — **REJECT**  
**Reviewed HEAD SHA (tip2):** `b687e0d2c0009348adb2f896c2b051e9b7f45d7a` — **PASS**  
**Plan:** `docs/superpowers/plans/2026-08-09-wave4-js-recovered-root-naming.md`  
**Packet:** `docs/architecture/sol-wave4-recovered-root-packet.md`

## Tip1 (REJECT)

Must-fixes: numeric mismatch honesty assert; pin tip1 `git show --name-status`; re-audit.

## Tip2 (PASS)

Codex `gpt-5.6-sol` (2026-08-09): tip1 nits closed. Numeric `treatment > mismatch` gate + Anthropic-tree absence via pinned name-status. Focused pytest green locally (6/6); Sol sandbox blocked pytest execution (environment limit, not repo failure).

### Checklist

- [x] Treatment recall > 0 + source_map
- [x] Wave 3 freeze intact
- [x] Mismatch discriminates (doc + numeric test)
- [x] R-RALPH-2 open
- [x] No Anthropic IP in tip1 name-status pin
- [x] Sol PASS tip2
