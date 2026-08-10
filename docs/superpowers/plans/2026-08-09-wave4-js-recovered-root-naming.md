# Wave 4 — JS recovered-root + generic naming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Checkbox steps for tracking.

**Goal:** Materialize `output_dir/project/` on the tracked JS micro-bundle (prefer source-map `sourcesContent`), add generic structural identifier **hints** (no Anthropic tables, no regex rewrite), wire into app-RE, and measure before/after Ralph recall with a discriminating mismatch arm.

**Architecture:** `materialize_js_project_tree` (source_map → bun_vfs → absent/fallback). Expand project file suffixes to `.ts/.tsx/.jsx`. Adapter calls materialize before scorecard and records `materialization_mode`. Hints JSON only. Claude dogfood stays operator-local.

**Tech Stack:** Python 3.9, existing JS bundle RE + SourceMapRecoverer patterns, Ralph harness, pytest, Codex `gpt-5.6-sol`.

**Branch base:** `feat/wave3-r-ralph-2-rebaseline` tip `90de9d1c` (PR #134 open).

## Global Constraints

- L33; do not close Phase 6 / R-RALPH-2 / enterprise GA
- No Anthropic IP in git
- Tracked micro-bundle is ship-gating; Claude pair non-ship-gating
- Fail-first TDD (L41); named-path commits
- Out: LLM rename; wakaru/webcrack hard deps; M1-NATIVE-FAM; CI-DOCS-LINK-1; MCP productization; “any claude.exe → full codebase”

## Thinktank plan audit

- 3× APPROVE_PLAN_WITH_NITS; Codex **REJECT_PLAN** until hollow-fallback gate fixed — **nits below are mandatory**

## Codex must-fixes (folded in)

1. Collect `.ts/.tsx/.jsx` in recovered-root helpers  
2. Prefer sibling `.map` with `sourcesContent` (tracked fixture has it; no `sourceMappingURL` required)  
3. Ship gate = `source_map` + treatment recall **> 0** + mismatch recall **<** treatment — not “fallback cleared the note”  
4. Wipe stale `project/` before materialize  
5. Empty normalized → mode `absent`, `recovered_root=None`  
6. Hints JSON only (no rewrite)  
7. One Bun interface: adapter kwarg `bun_vfs_dir` (default `output_dir/bunfs` if exists)  
8. Propagate `materialization_mode` into metadata/scorecard notes  

## Issues → tasks

| ID | Issue | Task |
| --- | --- | --- |
| I1 | No `project/` | W4-1 |
| I2 | Source maps unused | W4-1/W4-2 |
| I3 | Bun VFS not fed to app-RE | W4-3 |
| I4 | No structural hints | W4-4 |
| I5 | Non-discriminating controls | W4-5 |
| I6 | No Claude provenance contract | W4-6 |
| I7 | Unwired product path | W4-1 adapter |
| I8 | Missing Exa pins | W4-0 done |
| I9 | Backlog/CEO | W4-8 |

---

### Task W4-1 — Materialize + adapter wire

**Files:**
- Create `src/reveng/app_reverse_engineering/js_project_materialize.py`
- Modify `adapters/javascript.py` (`_JS_SUFFIXES`, call materialize, metadata)
- Tests `tests/unit/test_js_project_materialize.py`

```python
@dataclass
class ProjectMaterializeResult:
    recovered_root: Optional[Path]
    mode: str  # source_map | bun_vfs | fallback_index | absent
    files_written: int
    notes: List[str]

def materialize_js_project_tree(
    *,
    output_dir: Path,
    normalized_bundle: Optional[Path] = None,
    input_path: Optional[Path] = None,
    bun_vfs_dir: Optional[Path] = None,
) -> ProjectMaterializeResult: ...
```

- [x] Fail-first: tracked `bundle.js`+`bundle.js.map` → `project/**/index.ts` and `greet.ts` bodies match map `sourcesContent`; mode `source_map`
- [x] Fail-first: empty normalized → absent
- [x] Fail-first: bun_vfs copy
- [x] Implement + wire; commit

### Task W4-2 — covered by W4-1 source_map path (sibling map without URL)

### Task W4-3 — Bun VFS via `bun_vfs_dir` kwarg / `output_dir/bunfs`

- [x] Unit covered in W4-1; adapter accepts `bun_vfs_dir`

### Task W4-4 — Structural hints JSON only

- [x] `js_structural_identifiers.py` → `artifacts/structural_identifier_hints.json`
- [x] Tests; commit

### Task W4-5 — Ralph dogfood

- [x] Treatment recall > 0; no `no_recovered_root`; mode `source_map`
- [x] Mismatch recall < treatment
- [x] Evidence doc; commit reports

### Task W4-6 — Operator-local provenance example + README

- [x] `operator_local_claude.md` + example JSON + README note

### Task W4-7 — `test_wave4_recovered_root_honesty.py`

- [x] Honesty tests

### Task W4-8 — CEO/backlog

- [x] CEO Wave 4 + backlog pointers; R-RALPH-2 open

### Task W4-9 — Sol tip1/tip2 + PR

- [x] Sol tip1 REJECT → tip2 PASS (`b687e0d2`); PR next

## Acceptance

- [x] Tracked Ralph: `source_map`, recall>0, mismatch lower, no Anthropic IP committed
- [x] R-RALPH-2 still open
- [x] Sol PASS tip2
