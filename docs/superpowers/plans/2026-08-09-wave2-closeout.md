# Wave 2 Closeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Checkbox steps for tracking.

**Goal:** Close Wave 2 honestly — land CEO/lesson retention, fix Wave-2-introduced CI (black + any honesty regressions we caused), get Sol **PASS / PASS_WITH_NITS** against the **final candidate tip SHA**, merge PR #133. Do **not** close all backlog or fix pre-existing matrix reds.

**Architecture:** Finish the open Wave 2 branch (`feat/wave2-honesty-deep-dive` / PR #133). Honesty gates + lint on touched files are the merge bar. Broad unit/docs soft-red stays dispositioned (L42).

**Tech Stack:** Python 3.9, black/isort 100, pytest, GitHub Actions, Codex `gpt-5.6-sol`.

**Thinktank:** Round 1 **REJECT** (verdict/SHA sequencing; backlog post-merge; L44 URLs). Round 2b **APPROVE_WITH_NITS** — C4 must use only the tip2 protocol below (no contradictory “edit SHA then Sol on parent” path).

**Research (accessed 2026-08-09; Exa MCP unavailable → WebSearch):**
| Topic | URL |
| --- | --- |
| MCP annotation testing / dual labels | https://sunpeak.ai/blogs/testing-mcp-tool-annotations/ |
| Closient MCP annotation CI pattern | https://docs.closient.com/guides/mcp-tool-annotations |
| Unicorn macos-15 cmake floor | https://github.com/unicorn-engine/unicorn/issues/2263 |
| actlint declared-vs-derived | https://github.com/formael/actlint |

Full actlint CI / annotate-every-tool remains Wave 3+ (L45). Slim macos mitigation remains correct per unicorn#2263.

## Global Constraints

- L33 wave-scope; L47: Sol reviews a **frozen tip**; final PASS published as PR comment (not a new commit after Sol)
- Named-path git; temp `GIT_INDEX_FILE` if DrvFS hangs
- Prefer `/usr/bin/python3.9`; GHA `python`
- Out of scope: RALPH-2, #101 renderer, docs-link root cause, missing fixtures, full actlint CI, phases 6–13 product

## PLAN SUMMARY

| ID | Task | Done when |
| --- | --- | --- |
| C0 | CEO update + L41–L48 retention + research URL bank | committed on branch |
| C1 | `black` format `test_bun_extractor.py` | `black --check` exit 0 |
| C2 | Wave-2-caused honesty/backlog fails only | targeted pytest green |
| C3 | Dogfood Wave 2 + honesty suites | N passed recorded in PR body / verdict draft |
| C4 | Build **final candidate tip** (includes preliminary verdict stub + pre-merge backlog note) → Sol audit that SHA | Sol PASS / PASS_WITH_NITS with explicit nits/blockers text; result posted as **PR comment** (no post-Sol commit) |
| C5 | Push tip; verify checks on **that SHA**; merge #133 | merged; merge SHA noted in follow-up docs commit **after** merge (out of Sol tip) |

---

### Task C0 — CEO / lesson retention

**Files:**
- `docs/architecture/ceo-update-2026-08-09-waves1-2.md`
- `docs/architecture/lessons-learned-scope-c-2026-08.md` (L41–L48)
- `docs/architecture/research-wave2-closeout-2026-08-09.md` (pin the URL table above)
- `AGENTS.md`, `.claude/MEMORY.md`, `.cursor/skills/reveng-release-honesty/SKILL.md`
- `backlog.md` CEO pointers, `docs/ops/README.md`
- this plan file

- [ ] Named-path commit `docs: CEO Waves 1–2 + L41–L48 + closeout research pins`

### Task C1 — Black format

- [ ] `python3.9 -m black --line-length 100 tests/unit/test_bun_extractor.py`
- [ ] `black --check` exit 0
- [ ] Commit `style: black format test_bun_extractor for Wave 2 CI`

### Task C2 — Wave-2 honesty regressions only

```bash
python3.9 -m pytest tests/unit/test_scope_c_phase_unauthorized_honesty.py \
  tests/unit/test_backlog_wave_a_invariants.py \
  tests/unit/test_mcp_annotation_honesty_wave2.py -q --no-cov
```

Fix only Wave-2-caused fails (e.g. restore `await Sol stop/go` in section E focus if needed). Do not weaken tests.

- [ ] Green → commit if fixes needed

### Task C3 — Dogfood

```bash
python3.9 -m pytest \
  tests/unit/test_mcp_annotation_honesty_wave2.py \
  tests/unit/test_generate_skip_inventory.py \
  tests/unit/test_bun_sample_matrix.py \
  tests/unit/test_bun_extractor.py \
  tests/unit/test_world_class_wiring_honesty_2026_08_09.py \
  tests/unit/test_backlog_wave_a_invariants.py \
  tests/unit/test_scope_c_phase_unauthorized_honesty.py \
  -q --no-cov
```

- [ ] Record N passed for Sol packet

### Task C4 — Frozen tip + Sol (L47 sequencing)

**Only this protocol (tip2):**
1. Land C0–C3 + backlog pre-merge note (“Wave 2 closeout candidate; merge pending Sol”) + preliminary verdict stub with dogfood counts and `Reviewed HEAD SHA: TBD` (commit = tip1).
2. `SHA=$(git rev-parse HEAD)` on tip1.
3. Write `Reviewed HEAD SHA: $SHA` into `docs/architecture/sol-wave2-closeout-verdict.md` and commit → **tip2**. (SHA line names tip1 parent content; Sol reviews tip2 as the merge candidate.)
4. Run Sol against **tip2** with plan + `git show tip2 --stat` inlined (tell Sol: do not shell; reviewed tip SHA is tip2).
5. On **PASS / PASS_WITH_NITS**: post full Sol verdict text as a **PR comment** citing tip2. **Do not commit** after Sol. Merge tip2 as-is.
6. On **FAIL**: fix blockers, new tip1→tip2, repeat from step 2.

Sol response must include explicit blockers or nits text (not token alone).

- [ ] Produce frozen tip2; Sol PASS/PASS_WITH_NITS; PR comment with tip2 SHA

### Task C5 — Push, CI on tip SHA, merge

- [ ] Push tip2
- [ ] Confirm **new** check runs for tip2 SHA (L39); honesty-unit + lint-python green enough for merge policy (pre-existing matrix soft-red OK per L42)
- [ ] `gh pr merge 133 --merge`
- [ ] **After merge** (separate follow-up commit on main, not part of Sol tip): record merge SHA in backlog decision row / CEO note

---

## Explicitly deferred

Pre-existing fixture/unit fails, docs-link root cause, angr green, RALPH-2, #101, MCP `write_file`/`query_db` annotations, EDGE-RECOMPILE-DIFF measurement, full actlint CI.
