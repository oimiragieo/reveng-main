# Wave 3 — R-RALPH-2 honesty + re-baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Checkbox steps for tracking.

**Goal:** Close the obsolete `cli.js` measurement assumption after Anthropic Claude Code’s npm packaging shift; produce an honest Phase-6 measurement surface + Sol stop/go. Do **not** close all backlog, flip native `required:true`, or ship a 0.8 engine rewrite.

**Architecture:** Research + evidence + docs/tests only. No `src/reveng/**` engine edits. Thinktank (2026-08-09) **4/4 APPROVE Wave3=A** (claude/codex/copilot/agy); droid/cursor seats absent (rc127 / MISSING_CLI) — noted, not votes.

**Tech Stack:** Python 3.9, Ralph JS oracle harness, pytest honesty gates, Codex `gpt-5.6-sol`.

**Thinktank:** `/tmp/thinktank_wave3_scope/synthesis.md` — `APPROVE Wave3=A | REJECT close-all`.

## Global Constraints

- L33 wave-scope; reject close-all
- Fixture ≠ capability; do not sell tracked micro-bundle as “cli.js GA”
- Numeric `0` recall is valid **only** when a scored `ralph_report.json` exists; never invent recall for absent input
- Bidirectional control: document when both arms fail before `recovered_root` (instrument limitation)
- Named-path git; merge bar = honesty-unit + lint-python + Sol PASS/PASS_WITH_NITS
- Out of scope: M1-NATIVE-FAM flips, M2 world-class, CI-DOCS-LINK-1, MCP/workers/packaging, phases 7–13, `bundle_reverse_engineer.py` changes

## PLAN SUMMARY

| ID | Task | Done when |
| --- | --- | --- |
| W3-0 | Branch + plan committed | plan on `feat/wave3-r-ralph-2-rebaseline` |
| W3-1 | Fail-first honesty test for packaging + research doc | red on main shape, then green |
| W3-2 | Packaging research + Phase-6 target redefinition | `research-r-ralph-2.md` + update baseline note |
| W3-3 | Commit tracked-bundle Ralph report + mismatch control notes | `reports/js_oracle_ralph_tracked/` |
| W3-4 | Ranked wedges (only because scored baseline exists) + Sol packet | research lists wedges; Sol stop/go **no** for cli.js 0.8 |
| W3-5 | Backlog + CEO Wave 3 update | R-RALPH-2 stays open/`research`; program Wave 4/5 labeled |
| W3-6 | Dogfood + tip1/tip2 + Sol frozen tip | PASS/PASS_WITH_NITS on tip2 |

---

### Task W3-1 — Fail-first test

**Files:**
- Create: `tests/unit/test_wave3_r_ralph2_rebaseline_honesty.py`
- Modify later: research docs under `docs/architecture/`

- [ ] **Step 1: Write failing test** asserting:
  1. `docs/architecture/research-r-ralph-2.md` exists
  2. Mentions `@anthropic-ai/claude-code` packaging / `cli.js` obsolete / native `claude.exe` (or equivalent tokens)
  3. Mentions interim surface `js_tracked_bundle_artifact`
  4. Does **not** claim RALPH-2 / Phase 6 complete
  5. `reports/js_oracle_ralph_tracked/ralph_report.json` exists with `best_project_file_recall` key (float)
  6. Backlog `R-RALPH-2` status is still `open` or `research` (exact-id match)

- [ ] **Step 2: Run to verify red**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_wave3_r_ralph2_rebaseline_honesty.py -q --no-cov
```

Expected: FAIL (missing research doc / report)

- [ ] **Step 3–4:** Implement docs+report (W3-2/W3-3) until green
- [ ] **Step 5:** Named-path commit

### Task W3-2 — Research docs

**Files:**
- Create: `docs/architecture/research-r-ralph-2.md`
- Create: `docs/architecture/research-wave3-r-ralph-2-2026-08-09.md` (URL pins + dogfood)
- Modify: `docs/architecture/research-r-ralph-2-baseline.md` (pointer: packaging obsolete; BASELINE row stays done)
- Modify: `examples/use-cases/js-oracle-ralph/README.md` (obsolete cli.js path note + tracked-bundle example)

Content must include:
- package version `2.1.226`, `bin.claude=bin/claude.exe`, no `cli.js` in `files` (accessed 2026-08-09)
- Interim Phase-6 **measurement** target: tracked bundle + `js_tracked_bundle_source` oracle
- Product RALPH-2 (large Anthropic `cli.js`-class) remains **blocked** until a legitimate large JS bundle input exists
- Measured: `best_project_file_recall=0.0`, notes `no_recovered_root` / `no_recovered_project_files`, exit 2, max_attempts=1
- Mismatch control also 0.0 — scorer not discriminatory until `project/` materializes; cite unit tests on `js_oracle_scorecard` as positive control for the math
- Ranked wedges (smallest first): (1) materialize `output_dir/project` from source-map / normalized artifacts; (2) path alias / RALPH-1 carry-through; (3) bundler graph P4
- Sol stop/go recommendation: **NO-GO** large Phase-6 engine PR for cli.js 0.8; **GO** only for a later wave that implements wedge (1) against the tracked surface with bidirectional proof

Pinned URLs (L44):
- https://www.npmjs.com/package/@anthropic-ai/claude-code (accessed 2026-08-09)
- Local package.json path as dogfood evidence

### Task W3-3 — Commit Ralph report

```bash
mkdir -p reports/js_oracle_ralph_tracked
# copy scored report from dogfood run; scrub absolute host paths to repo-relative in a notes sidecar if needed
```

Include `mismatch_control.md` stating both arms 0.0 and why.

### Task W3-4 — Sol packet stub

**Files:**
- Create: `docs/architecture/sol-wave3-r-ralph2-packet.md`
- Create: `docs/architecture/sol-wave3-r-ralph2-verdict.md` (tip1: `Reviewed HEAD SHA: TBD`)

### Task W3-5 — Backlog + CEO

**Files:**
- `backlog.md` — R-RALPH-2 notes updated; status stays `open`; Wave 3 plan pointer
- `docs/architecture/ceo-update-2026-08-09-wave3.md`
- skill / MEMORY pointers if needed

### Task W3-6 — Closeout

- Dogfood honesty tests
- tip1 → tip2 → Sol on tip2 → PR

## Program sequencing (not this PR)

- Wave 4: M1-NATIVE-FAM measure-and-maybe-flip
- Wave 5: CI-DOCS-LINK-1 + M4 residual
- Later Sol-gated: wedge (1) engine → MCP productization → workers → packaging
