# Wave 1 Honesty Deep-Dive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close honesty-safe Wave 1 items only — installer stub policy, CI unicorn/docs disposition, section-E parseability, competitive research banked — without claiming all backlog / RALPH-2 / #101 renderer / phases 6–13 done.

**Architecture:** Evidence-first Wave 1 after Wave 0 (PR #131). Prefer disposition + fail-closed messaging over hollow installs. Competitive edge cases from web research (Exa MCP unavailable → WebSearch/WebFetch) land as research/backlog rows, not fake GA.

**Tech Stack:** Python 3.9, pytest TDD, black/isort 100, tg for navigation, GitHub Actions YAML, root `backlog.md`.

**Thinktank:** Round 1 APPROVE_WITH_NITS; Round 2 REJECT (field name / fail-first / Phase-4 / research URLs). This revision addresses Round 2.

## Global Constraints

- Honesty SoT: release-honesty skill; lessons **L1–L40**; L33 forbids all-backlog PR
- Prefer `/usr/bin/python3.9` locally; GHA uses setup-python `python`
- Named-path commits; `git -c user.name/email` from `git log -1`; no stash across worktrees
- No exploit expansion; no native `required:true`; no #101 renderer epic
- Research file: `docs/architecture/research-wave1-deep-dive-2026-08-09.md`

## PLAN SUMMARY (Thinktank)

- **In scope:** REV-P0-INSTALLERS deprecate-or-finish policy + TDD requiring new `deprecated_stub` token (RED on main today); REV-P0-ANALYSIS-CLEANUP written policy → backlog `partial`; CI-UNICORN / CI-DOCS-LINK stay `partial` with pinned URLs; L40 section E status cells = single machine token + waiver-backed Phase 4 invariant (Phase 4 stays **`partial`**, never hollow `done`); bank competitive research rows with pinned URLs; lint/format touched Python.
- **Out of scope:** RALPH-2 engine, M1-NATIVE-FAM required flip, #101 rich renderer, phases 6–13 product, EPIC megarefactors, V6, LibAFL.
- **Success:** Thinktank APPROVE Wave 1; Codex PASS vs this plan; backlog rows updated; dogfood green for new tests.

---

## File Structure

| Path | Role |
| --- | --- |
| `src/reveng/core/dependency_manager.py` | Installer registry; None stubs |
| `tests/unit/test_wave1_installer_stub_honesty.py` | New TDD (fail-first on `deprecated_stub`) |
| `tests/unit/test_backlog_wave_a_invariants.py` | Waiver-backed Phase 4 / section E predicates |
| `docs/architecture/policy-rev-p0-analysis-cleanup.md` | analysis_* cleanup policy |
| `docs/architecture/policy-rev-p0-installers.md` | deprecate stubs policy |
| `docs/architecture/research-wave1-deep-dive-2026-08-09.md` | Competitive + unicorn research (pinned URLs) |
| `backlog.md` | Status updates |
| `.github/workflows/tests.yml` / `docs.yml` | Optional soft-fail comment citing sources |

---

### Task W1-1 — Branch + baseline

**Files:** none yet

- [ ] `git checkout -b feat/wave1-honesty-deep-dive` from current `main`
- [ ] Baseline: `python3.9 -m pytest tests/unit/test_world_class_wiring_honesty_2026_08_09.py -q --no-cov` → record **N passed**
- [ ] Named-path porcelain only (L38)

### Task W1-2 — Installer stub honesty (REV-P0-INSTALLERS)

**Files:**
- Modify: `src/reveng/core/dependency_manager.py`
- Create: `tests/unit/test_wave1_installer_stub_honesty.py`
- Create: `docs/architecture/policy-rev-p0-installers.md`

**Interfaces:**
- Field is `InstallationResult.error_message` (not `.error`)
- Consumes: `DependencyManager.tools`, `install_missing_tools`, `get_installation_status`
- Produces: stub tools’ install path never reports `success=True`; status `install_method == "deprecated_stub"`; `error_message` contains stable token **`deprecated_stub`**

**Why fail-first is real (Round 2 nit):** Today stubs already return `success=False` and message `"Tool … not supported"` with `install_method="not_supported"`. Asserting only those would be GREEN without a code change. Wave 1 requires the stronger token **`deprecated_stub`** on both `error_message` and `install_method` — that is RED on current main.

- [ ] **Step 1: Write failing test (must be RED before prod change)**

```python
STUBS = ("dnspy", "uncompyle6", "exeinfo_pe", "x64dbg", "imhex", "lordpe")

def test_stub_install_emits_deprecated_stub_token():
    dm = DependencyManager()
    results = dm.install_missing_tools(list(STUBS), auto_install=True)
    for name in STUBS:
        assert name in results
        assert results[name].success is False
        err = (results[name].error_message or "").lower()
        assert "deprecated_stub" in err, f"{name}: need deprecated_stub in error_message, got {err!r}"

def test_stub_install_method_is_deprecated_stub():
    dm = DependencyManager()
    status = dm.get_installation_status()
    for name in STUBS:
        assert status[name].install_method == "deprecated_stub"
```

- [ ] **Step 2:** Run tests — expect **FAIL** (current message is `"not supported"` / method `not_supported`).

- [ ] **Step 3:** Update `install_missing_tools` + `get_installation_status` None-branch to set `install_method="deprecated_stub"` and `error_message` containing `deprecated_stub`; write `policy-rev-p0-installers.md` (Wave 1 = deprecate; finish installers = future Sol).

- [ ] **Step 4:** Re-run → PASS. Do **not** assert `is_installed is False`.

- [ ] **Step 5:** Commit `fix(honesty): deprecate installer stubs with deprecated_stub status`

### Task W1-3 — analysis_* cleanup policy (REV-P0-ANALYSIS-CLEANUP)

**Files:**
- Create: `docs/architecture/policy-rev-p0-analysis-cleanup.md`
- Modify: `backlog.md` — REV-P0-ANALYSIS-CLEANUP → **`partial`** (policy landed; automated enforcement not claimed)

Policy must state:
1. Never `git clean` / mass-delete untracked `analysis_*` without operator permission
2. CI must not upload secrets from analysis dirs
3. Local dogfood: prefer `/tmp` or gitignored paths
4. Agents use named paths only

Acceptance: policy file exists + backlog `partial` with link. Do **not** mark `done`.

- [ ] Write policy + backlog `partial` + commit `docs: REV-P0 analysis_* cleanup policy (partial)`

### Task W1-4 — CI unicorn / docs-link disposition

**Files:**
- Modify: `backlog.md` (CI-UNICORN-BUILD-1, CI-DOCS-LINK-1) → status **`partial`**
- Optionally annotate workflow YAML with comment citing sources
- Update research doc with pinned URLs + access date **2026-08-09**

Pinned citations (required in research + backlog notes):

| Topic | URL | Accessed |
| --- | --- | --- |
| Unicorn cmake floor | https://github.com/unicorn-engine/unicorn/issues/2263 | 2026-08-09 |
| actlint declared-vs-derived | https://github.com/formael/actlint | 2026-08-09 |
| actlint DEV writeup | https://dev.to/formael/are-your-mcp-servers-safety-labels-honest-a-one-command-check-and-what-it-found-on-31-popular-1ml3 | 2026-08-09 |
| Sleuthre recompile-diff | https://github.com/kidoz/sleuthre | 2026-08-09 |
| docs-link soft-fail | `.github/workflows/docs.yml` `continue-on-error: true` on docs-link-check | repo |

Acceptance: both CI rows stay **`partial`** (soft-fail contains noise; root cause not fixed). **Forbidden:** `mitigated`/`done` or claiming angr matrix green.

- [ ] Update backlog + research citations + optional YAML comment + commit `docs(ci): partial disposition unicorn/docs soft-red`

### Task W1-5 — Section E machine-readable status (L40) + waiver-backed Phase 4

**Files:**
- Modify: `backlog.md` section E — **status column = single token only** (`done` / `partial` / `open`). Move waiver prose into the **focus** cell (or a notes clause after an em-dash outside the status cell).
- Modify: `tests/unit/test_backlog_wave_a_invariants.py` — **add** positive predicates; do **not** delete the “Phase 4 ≠ done” guard.

**Phase 4 contract (Round 2 nit — do not weaken):**

1. `_section_e_phase_status(4) == "partial"` (exact; not `done`)
2. Existing assert `!= "done"` remains
3. **New waiver-backed positive predicate:** section E phase-4 **row text** (focus/notes) must contain both:
   - `decision-phase-04-honesty-go-waiver.md`
   - and the string `honesty go` (case-insensitive)
4. `_backlog_status("M2") == "partial"` remains

**Do not** set Phase 4 status to `done` because of the honesty-go waiver — that conflicts with `test_section_e_phase_4_partial_until_both_exits` and world-class M2 still open.

Example row shape:

```markdown
| 4 | Hexyl frontier + VRL LLM; honesty go via `decision-phase-04-honesty-go-waiver.md`; world-class M2 separate | partial |
```

Phases 1–3 stay `done`; Phase 5 stays `partial`; 6–13 stay `open`.

- [ ] Fix status cells; add waiver-backed test; run `pytest tests/unit/test_backlog_wave_a_invariants.py -q --no-cov`
- [ ] Commit `fix(backlog): machine-readable section E statuses (L40)`

### Task W1-6 — Competitive edge cases → backlog

**Files:**
- Modify: `backlog.md` section H/D with new rows:
  - `R-MCP-ANNOTATION-1` — research open; cite https://github.com/formael/actlint (accessed 2026-08-09)
  - `EDGE-RECOMPILE-DIFF-1` — research / `could_not_measure` until measured; cite https://github.com/kidoz/sleuthre (accessed 2026-08-09); no VRL parity claim
- Keep research file linked with full URL table

- [ ] Commit `docs: bank Wave 1 competitive edge-case research rows`

### Task W1-7 — Codex impl audit + dogfood + PR

- [ ] Implement W1-1…W1-6 on branch
- [ ] `black`/`isort` touched Python; dogfood new tests + honesty suite; record exit codes
- [ ] Codex audit of **implementation** vs this plan; write `docs/architecture/sol-wave1-impl-verdict.md` with **reviewed HEAD SHA**; fix findings and re-run until PASS / PASS_WITH_NITS (merge-only nit OK)
- [ ] PR merge (no FF-only bypass)

**Note:** Plan Thinktank approval is separate from impl Codex PASS (do not “loop reviewers until APPROVE” as a substitute for fixing findings).

---

## Explicitly deferred (not Wave 1)

RALPH-2 / R-RALPH-2 engine wedge, M1-NATIVE-FAM `required:true`, world-class M2, #101 Capstone renderer (43 xfails), phases 6–13 product, EPIC-3–9, FEAT-3–10, REV-MCP installable product, V6-*, exploit sandbox expansion, REV-P0-EVIDENCE-AUDIT full matrix (optional light start only if time — default defer).
