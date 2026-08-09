---
name: reveng-sol-frozen-tip
description: >-
  Runs the Sol/Codex frozen-tip audit protocol for REVENG Wave closeout and
  honesty PRs (L47). Use when Sol or Codex must audit a closeout PR before
  merge, when writing or pinning a Sol verdict file, or when tempted to merge
  on self-PASS / amend after Sol / pin Sol to a parent SHA while HEAD moved.
---

# REVENG Sol frozen-tip (L47)

## Overview

Sol audits a **frozen tip SHA**, not a moving branch tip. The merge commit is
exactly the tip Sol passed. Post-merge docs that stamp the merge SHA are a
**separate** commit after merge.

## Protocol (ONLY)

1. **tip1** — Commit all closeout work + a verdict stub that still says
   `Reviewed HEAD SHA: TBD`, plus the backlog pre-merge note. tip1 is the
   content under audit, not the audited tip.
2. **tip2** — One commit that writes tip1’s SHA into the verdict file
   (`Reviewed HEAD SHA: <tip1>`). tip2’s tree is tip1 + that pin.
3. **Sol audits tip2 SHA** — Inline the audit packet (do **not** shell greps
   that hang in sandbox). Sol must cite **blocker/nit text** from real files
   (path + substance), not vibes.
4. **PASS or PASS_WITH_NITS** — Leave a PR comment naming **tip2 SHA**. Make
   **no further commit**. Merge **tip2** (that exact SHA).
5. **FAIL** — Fix on a new tip1 → tip2 loop. Do not amend tip2 after Sol saw it.
6. **Post-merge** — A merge-SHA docs/backlog stamp is a **separate** commit
   after the merge lands. Never fold it into tip2 before Sol.

## Checklist

```
- [ ] tip1 has stub Reviewed HEAD SHA: TBD (+ pre-merge backlog note)
- [ ] tip2 only pins tip1 SHA into the verdict
- [ ] Sol packet is tip2 SHA; inline packet; file cites for blockers/nits
- [ ] PASS/PASS_WITH_NITS → PR comment tip2 SHA → merge tip2 → no amend
- [ ] FAIL → new tip1/tip2 (no amend-after-Sol)
- [ ] merge-SHA docs commit only AFTER merge
```

## Anti-patterns (do not rationalize)

| Excuse | Reality |
|--------|---------|
| "I self-reviewed; Sol can rubber-stamp after merge" | Merge on self-PASS is forbidden (L47). |
| "Sol PASS_WITH_NITS — I'll just amend the nits" | Amend after Sol invalidates the tip. Merge tip2 or restart the loop. |
| "I'll pin Sol to tip1 / parent; tip2 is just bookkeeping" | Sol must audit **tip2**. Parent-SHA pin while HEAD moved is process debt. |
| "Sol FAIL but no file cites — close enough" | Bare FAIL without path+text cites is invalid; re-run Sol. |
| "Fold merge-SHA into tip2 so one commit ships" | Post-merge stamp is separate by design. |

## Red flags — STOP

- Merging a SHA Sol never named
- `git commit --amend` after Sol returned
- Verdict `Reviewed HEAD SHA` ≠ tip1 while claiming tip2 is audited
- Sol verdict with zero file citations on FAIL
- Docs claiming “Sol audited merge SHA X” before X exists

## Cross-refs

- Sibling: `reveng-release-honesty` (L37/L47 seating)
- Named-path commits on dirty trees: `reveng-named-path-commit`
- Research pins: [references/pins.md](references/pins.md)
