# REVENG tg-audit Fixups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every finding from the 2026-08-08 tensor-grep audit with honesty-first wiring — no silent MCP knobs, no Ralph `oracle_dir` TypeError/xfail, no fake “deobfuscation completed” when only placeholders ran — and leave true research deferred items as explicit `deferred` with refuse-overclaim tests.

**Architecture:** Thread missing kwargs through the app-RE framework → JS adapter → scorecard helper; wire or remove Enterprise MCP schema knobs; make malware / deobfuscator / LibAFL surfaces fail closed with `unsupported` / capability flags. Do **not** implement LibAFL, mega-file splits, or full CFG unflatten in this plan.

**Tech Stack:** Python 3.9 (`/usr/bin/python3.9`), pytest (`--no-cov` for local loops), existing `reveng.app_reverse_engineering` + MCP servers, tensor-grep optional for verification (`tg callers` / `tg find`).

## Revision history (Thinktank)

| Round | Seat | Verdict | Action |
| --- | --- | --- | --- |
| R1–R8 | Sol | **REJECT** | folded forward |
| R9 | Sol | **APPROVE_WITH_NITS** | Nits baked below; proceed to implement |

### APPROVE_WITH_NITS (must honor during impl)

1. Persist `no_recovered_project` inside `capability_report.dimensions` (not only metadata) when `reconstructed_project` absent.
2. LLM structured outcome requires keys `{status, code, reason}`; may also include `analysis` for `llm_analysis`.
3. `capabilities_run` exact dict: `{"cfg_unflatten": false, "constant_folding": false, "dead_code_removal": false, "reason": "placeholder"}`.
4. Create branch `feat/tg-audit-fixups` from main before Task 1.
5. Nonzero webcrack exit must not treat stale/partial output as success (`webcrack_failed`).

## Global Constraints

- Prefer `/usr/bin/python3.9`; never invent ValidationGrade / scorecard numbers beyond the documented filename-set formulas below.
- No hollow GA / native `required: true` flips; R-SEC-1 — no exploit expansion.
- Named-path commits; author from `git log -1`; no `git stash` across worktrees.
- Bidirectional tests: empty/missing oracle or unsupported path must fail or return explicit unsupported — never silent success. Missing `oracle_dir` / each MCP knob needs **positive and negative** behavioral tests.
- Scope C honesty: disposition `deferred` ≠ capability `done`.
- Branch: `feat/tg-audit-fixups` from current `main`.
- “Fully integrated / clean” for this wave = P0+P1 honesty wiring + deferred guards — **not** LibAFL, RALPH-2 0.8 engine, or mega refactors.

## Explicitly deferred (out of implementation; honesty only)

| ID | Item | Disposition |
| --- | --- | --- |
| D1 | LibAFL `fuzz_until_divergence` | Keep `NotImplementedError`; add unit test that documents Phase 1.5 |
| D2 | Split `recompilation_engine.py` / mega MCP file | Doc note only; no refactor this wave |
| D3 | Full CFG unflatten / constant-fold / DCE algorithms | Stages skipped + capability flags — not full engines |
| D4 | DnSpy installer in `dependency_manager` | Leave TODO; optional log once |
| D5 | `java_ai_analyzer` OpenAI/Anthropic | Keep `NotImplementedError` (honest) |
| D6 | Hollow native `analyze_report_exists` rows (pipeline failures under SUCCESS) | Measure in Task 8 receipt; do not flip GA gates this wave |

---

## File map

| File | Responsibility |
| --- | --- |
| `src/reveng/app_reverse_engineering/js_oracle_scorecard.py` | **Create** — compute `benchmark_scorecard` from oracle dir vs recovered paths |
| `src/reveng/app_reverse_engineering/framework.py` | Accept + forward `oracle_dir`, probe flags |
| `src/reveng/app_reverse_engineering/adapters/javascript.py` | Accept kwargs; attach scorecard to metadata (real producer) |
| Other adapters | **Unchanged signatures** — framework does **not** pass JS-only kwargs to them |
| `src/reveng/analysis/analyzer.py` | `enable_ai` whole-analyzer AI contract (steps 1+3 + preflight) |
| `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py` | Wire MCP knobs to analyzer / honest ignore |
| `src/reveng/agent_sdk/mcp/servers/reveng_server.py` | Binary malware → `unsupported` status |
| `src/reveng/javascript/deobfuscator.py` | Placeholder stages → `stages_skipped`; capability flags |
| `tests/unit/test_js_oracle_scorecard.py` | **Create** |
| `tests/unit/test_js_adapter_oracle_scorecard.py` | **Create** — real adapter + mocked bundle engine |
| `tests/unit/test_tracked_js_bundle_manifest.py` | Lift xfail when wiring works |
| `tests/unit/test_mcp_enterprise_knobs.py` | **Create** — every knob true/false |
| `tests/unit/test_js_deobfuscator_capabilities.py` | **Create** |
| `tests/unit/test_tg_audit_deferred_honesty.py` | **Create** |
| `docs/architecture/tg-audit-fixups-2026-08-08.md` | Receipt + deferred table |

---

### Task 1: JS oracle scorecard helper (foundation)

**Files:**
- Create: `src/reveng/app_reverse_engineering/js_oracle_scorecard.py`
- Create: `tests/unit/test_js_oracle_scorecard.py`

**Interfaces:**
- Produces: `compute_js_project_file_scorecard(oracle_dir: Path, recovered_paths: Sequence[Path], *, recovered_root: Optional[Path] = None) -> Dict[str, Any]`
- **`recovered_root` contract:** When provided, relative paths for recovered files are `Path(p).resolve().relative_to(Path(recovered_root).resolve())` (posix). When omitted, only basename matching is possible (`match_mode` will never be `relative_path`).
- **Required keys:**
  - `project_file_recall`, `project_file_precision`
  - `matched_oracle_file_count`, `oracle_file_count`, `recovered_file_count`
  - `reconstruction_mode` — always `"filename_set"`
  - `match_mode` — `"relative_path"` if ≥1 relative-path match; else `"basename"` if ≥1 basename match; else `"none"`
  - `overall_score` — `mean(recall, precision)`; `0.0` if empty oracle
  - `token_signal_score` — Jaccard over **all** oracle vs **all** recovered basename tokens (not matched-only; matched-only is degenerate):
    - tokens(path) = `{t for t in re.split(r'[^A-Za-z0-9]+', Path(path).name) if t}`
    - `O` = union of tokens over every oracle file; `R` = union over every recovered file (after dedupe)
    - `token_signal_score = |O ∩ R| / |O ∪ R|` if `|O ∪ R| > 0` else `0.0`
    - `token_signal_mode: "filename_set_basename_jaccard_all"`
  - Deduplicate recovered paths by `resolve()` before counting (`recovered_file_count` unique).
  - **Missing `oracle_dir` path (does not exist):** do not call scorecard from adapter; adapter adds warning `oracle_dir_missing`; no `benchmark_scorecard` key.
  - **Existing empty oracle directory:** scorecard with zeros + `notes` containing `empty_oracle`.
  - **`oracle_dir is None`:** no scorecard (negative control).

**Algorithm:**
1. Oracle files → set of relative posix paths under `oracle_dir` (ignore `node_modules`, `.git`).
2. For each existing recovered path: if `recovered_root` set and path is under it, compute rel path; else only basename available.
3. One-to-one matching: relative-path pass first, then basename pass on leftovers; **sort unmatched oracle paths lexicographically** before basename matching; collisions → at most one match + `basename_collision` note.
4. Metrics as above.

- [ ] **Step 1: Write failing tests** including:

```python
def test_relative_path_match_requires_recovered_root(tmp_path):
    oracle = tmp_path / "oracle"
    (oracle / "src").mkdir(); (oracle / "src" / "a.js").write_text("a")
    root = tmp_path / "recovered"; (root / "src").mkdir()
    (root / "src" / "a.js").write_text("x")
    sc = compute_js_project_file_scorecard(oracle, [root / "src" / "a.js"], recovered_root=root)
    assert sc["match_mode"] == "relative_path"
    assert sc["project_file_recall"] == 1.0

def test_without_recovered_root_falls_back_to_basename(tmp_path):
    oracle = tmp_path / "oracle"; (oracle / "a.js").write_text("a")
    other = tmp_path / "elsewhere"; other.mkdir(); (other / "a.js").write_text("x")
    sc = compute_js_project_file_scorecard(oracle, [other / "a.js"])  # no recovered_root
    assert sc["match_mode"] == "basename"
    assert "no_recovered_root" in str(sc.get("notes", ""))

def test_mixed_relative_and_basename(tmp_path):
    oracle = tmp_path / "oracle"
    (oracle / "src").mkdir(); (oracle / "src" / "a.js").write_text("a")
    (oracle / "b.js").write_text("b")
    root = tmp_path / "rec"; (root / "src").mkdir()
    (root / "src" / "a.js").write_text("x")
    loose = tmp_path / "loose"; loose.mkdir(); (loose / "b.js").write_text("y")
    sc = compute_js_project_file_scorecard(
        oracle, [root / "src" / "a.js", loose / "b.js"], recovered_root=root
    )
    # a.js relative; b.js only basename (outside root)
    assert sc["matched_oracle_file_count"] == 2
    assert sc["match_mode"] == "relative_path"  # at least one relative match dominates label
```

(Keep perfect basename, empty oracle, collision, partial-match tests from R3.)

- [ ] **Step 2: Run tests — expect FAIL** (module missing)

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_js_oracle_scorecard.py -q --no-cov
```

- [ ] **Step 3: Implement minimal `js_oracle_scorecard.py`**

- [ ] **Step 4: Run tests — expect PASS**

- [ ] **Step 5: Commit** `feat(app-re): add js_oracle_scorecard filename-set helper`

---

### Task 2: Wire `oracle_dir` + probe flags through framework → JS adapter

**Files:**
- Modify: `framework.py` (other adapters **unchanged**)
- Modify: `adapters/javascript.py` — accept `oracle_dir` + compute scorecard + ralph knobs
- Modify: `ralph_js_loop.py` — copy `metadata.get("ralph_knobs")` into each attempt record (both framework path and `attempt_runner` path)
- Create: `tests/unit/test_js_adapter_oracle_scorecard.py`
- Create: `tests/unit/test_framework_js_probe_forwarding.py`
- Extend: `tests/unit/test_ralph_js_loop.py` for ralph_knobs on attempts

**Forwarding policy (conditional JS):**
- Base `AppAdapter` Protocol **unchanged** (keeps mypy happy for other adapters).
- Framework JS branch: `js_adapter = cast(Any, adapter)` then call with JS-only kwargs; non-JS branch uses base kwargs only.
- Framework signature adds: `oracle_dir: Optional[str] = None`, Ralph keys default False, and probes with **exact defaults**:
  - `run_js_syntax_check: bool = True`
  - `run_js_behavior_probe: bool = True`
  - `run_js_npm_lifecycle_probe: bool = False`
- Always forward those three probe flags into `enrich_app_analysis_payload`.

**Ralph knob disposition (JS adapter → engine):**

| Kwarg | Behavior when True | When False |
| --- | --- | --- |
| `run_deobfuscator` | Pass to `JavaScriptBundleReverseEngineer(run_deobfuscator=True)` | default False |
| `run_js_deobfuscator` | **Alias** of `run_deobfuscator` (OR together) | — |
| `run_webcrack` / `run_restringer` / `run_wakaru` | If engine has no dedicated flag: append warning `unsupported_ralph_knob:<name>` to result.warnings; set `metadata["ralph_knobs"][name]="unsupported"`; **do not** claim tool ran. (If later engine grows support, wire then.) | `metadata["ralph_knobs"][name]="not_requested"` |

Never silently drop True knobs.

**Tests:** probe forwarding true/false; Ralph True unsupported warning; framework call with a built-in Ralph variant dict (from `ALLOWED_JS_RALPH_VARIANT_KEYS`) does not TypeError; real adapter scorecard tests. Ralph loop attempt records must include `ralph_knobs` (or equivalent) disposition from metadata — not only the variant label.

**JS adapter scorecard + probe wiring (exact):**
1. After engine returns, set `recovered_root = Path(output_dir) / "project"` if that directory exists and contains ≥1 `.js/.cjs/.mjs` file; else `recovered_root = None`.
2. `recovered_paths` = only files under that `project/` tree (rglob js/cjs/mjs). **Never** include `topic_files`, `domain_files`, `normalized_bundle`, or specs dirs.
3. If `recovered_root` is set: `primary_artifacts["reconstructed_project"] = recovered_root` (required for enrich probes).
4. If no `project/` tree: still compute scorecard when `oracle_dir` exists, with `recovered_paths=[]`, `notes` containing `no_recovered_project_files`. Enrich/`capability_report` must emit canonical skipped objects under `capability_report.dimensions` for syntax/behavior/npm (`status`/`reason` = `skipped_no_recovered_project`) — not `None` / silent omit. Metadata markers optional extras.
5. Missing `oracle_dir` path → warning `oracle_dir_missing`, no scorecard key.
6. Unit test: specs/topic files not counted; when `project/` present and probes True, capability_report shows probes ran (or attempted); when probes False, disposition skipped/disabled; when no project, explicit `skipped_no_recovered_project` — not silent absence.
7. Note: `ralph_js_loop` may pass `run_js_syntax_check=False` intentionally (override of framework default True).

- [ ] **Step 1: Write failing unit tests**
- [ ] **Step 2: Run — expect FAIL**
- [ ] **Step 3: Implement framework + JS adapter only**
- [ ] **Step 4: Run unit tests PASS**
- [ ] **Step 5: Commit** `feat(app-re): wire oracle_dir, Ralph knobs, and JS probe flags`


---

### Task 3: Lift tracked-bundle xfail (integration honesty)

**Files:**
- Modify: `tests/unit/test_tracked_js_bundle_manifest.py` — remove `@pytest.mark.xfail` only when Tasks 1–2 make the test green

- [ ] **Step 1: Run with `--runxfail`** (or temporarily remove xfail) to prove green:

```bash
/usr/bin/python3.9 -m pytest \
  tests/unit/test_tracked_js_bundle_manifest.py::test_tracked_bundle_corpus_benchmark_includes_capability \
  -q --no-cov --runxfail
```

- [ ] **Step 2: Remove `@pytest.mark.xfail`** only after Step 1 is a real pass (not xfail/xpass confusion)

- [ ] **Step 3: Commit** `test(app-re): lift tracked JS oracle_dir xfail after wiring`

---

### Task 4: Analyzer `enable_ai` whole-contract + Enterprise MCP knobs

**Files:**
- Modify: `src/reveng/analysis/analyzer.py`
- Modify: `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`
- Create: `tests/unit/test_analyzer_enable_ai.py`
- Create: `tests/unit/test_mcp_enterprise_knobs.py`

**`enable_ai=False` whole-analyzer contract:**
1. `__init__(..., enable_ai: bool = True)` stores `self.enable_ai`.
2. `effective_check_ollama = bool(enable_ai) and bool(check_ollama)` — never run preflight when `enable_ai=False`.
3. If `enable_ai=False`: set `self.enhanced_features.enable_enhanced_analysis = False` (master off → steps 9–13 gated off by existing `is_any_enhanced_enabled()` / enable flags). Prefer also setting the five module flags False for clarity.
4. In `analyze_binary`: skip calling `_step1_ai_analysis` and `_step3_ai_inspection` when `not enable_ai` (record skipped reasons).
5. Tests False: never construct `AIRecompilerConverter`, `AISourceInspector`, `OllamaPreflightChecker`; never call `_step9`…`_step13` (monkeypatch each). Logs/capability metadata must not claim AI-enhanced enabled.
6. Tests True: positive control that step1 attempts converter construction.

**Skipped AI step records (exact):**
- `results["step1"] = {"status": "skipped", "reason": "enable_ai_false"}`
- `results["step3"] = {"status": "skipped", "reason": "enable_ai_false"}`

**MCP `analyze_binary`:**
- Build `EnhancedAnalysisFeatures` with `enable_vulnerability_discovery=False` always on this tool path.
- **`quick_mode` truthful contract:** only affects Ollama preflight via `effective_check_ollama = enable_ai and not quick_mode`. It does **not** reduce analysis depth. Update the MCP tool schema description string to: `"Skip Ollama preflight check (faster startup; analysis steps unchanged)"`. Tests: with `quick_mode=True`, assert `check_ollama is False` **and** assert `_step2_disassembly` (or analyze_binary body after step1) is still invoked.
- `find_vulnerabilities=True` → deferral string in payload+text; `_step10` never called.
- `find_vulnerabilities=False` → key absent; `_step10` never called.
- `enable_ai` as whole-analyzer contract above; `knobs_applied` only for real flags.

**MCP `decompile_binary`:**
- Read knobs with **explicit defaults False** (do not use schema/default True): `use_ai_enhancement = bool(args.get("use_ai_enhancement", False))`, `reconstruct_types = bool(args.get("reconstruct_types", False))`. Omitted → not_requested.
- `use_ai_enhancement=True` → unsupported warning; `knobs_applied.use_ai_enhancement="unsupported"`.
- `use_ai_enhancement` omitted/False → no AI-enhancement claim; payload omits or `"not_requested"`.
- `reconstruct_types=True` → warning `"reconstruct_types requested but unsupported in this MCP decompile path"`; payload `reconstruct_types: "unsupported"`.
- `reconstruct_types` omitted/False → key absent.
- Bidirectional tests including omitted-args arm.
- Assert MCP schema description for `quick_mode` equals the truthful string from Task 4.

- [ ] **Step 1–4:** failing tests → implement → pass → commit `fix(mcp+analyzer): apply enterprise knobs; whole-analyzer enable_ai`

---

### Task 5: MCP binary malware — explicit unsupported

**Files:**
- Modify: `src/reveng/agent_sdk/mcp/servers/reveng_server.py` (`detect_malware` else branch)
- Check enterprise server for same stub; fix both if present
- Test: **Create** `tests/unit/test_mcp_binary_detect_malware_unsupported.py`

**Behavior:**

```python
return build_mcp_tool_response(
    tool_name="detect_malware",
    text="Binary malware detection unsupported in this MCP path; use JavaScript detect or security classifier CLI",
    payload={"supported": False, "reason": "binary_malware_mcp_unsupported"},
    status="unsupported",  # or "error" if status enum lacks unsupported — use existing contract
    error="binary_malware_mcp_unsupported",
)
```

Prefer calling existing `ml_malware_classifier` **only if** a one-liner path already exists and is tested; otherwise explicit unsupported (honesty > fake wiring).

- [ ] **Step 1: Test** asserts status/error code present and not empty success (positive unsupported + negative: JS path still works if already tested elsewhere)

- [ ] **Step 2: Implement**

- [ ] **Step 3: Commit** `fix(mcp): binary detect_malware returns explicit unsupported`

---

### Task 6: JS deobfuscator capability honesty

**Files:**
- Modify: `src/reveng/javascript/deobfuscator.py`
- Test: `tests/unit/test_js_deobfuscator_capabilities.py` (**create**)

**Concrete schemas:**
- `stages_skipped: List[Dict[str, str]]` items exactly `{"stage": <enum.value>, "reason": <str>}`
- `capabilities_run` exact keys: `cfg_unflatten`, `constant_folding`, `dead_code_removal` → False; `reason`: `"placeholder"`
- Placeholder CFG/fold/DCE: never in `stages_applied`; always skipped with `reason="placeholder_not_implemented"`

**Substantive stage outcomes (critical):**
- General rule: helpers return `{"status": "ok"|"error"|"skipped", "code": str, "reason": str}`. Append to `stages_applied` only if `status=="ok"` **and** `code != input_code`. Else `stages_skipped` with `reason`.
- Webcrack: on success append **only** `UNPACKING` (do not also append `UNBUNDLING` without separate evidence). Fail reasons: `webcrack_failed` | `webcrack_timeout` | `webcrack_empty` | `webcrack_absent` | `webcrack_unchanged`.
- `ML_RENAMING` / `LLM_ENHANCEMENT`: same structured outcome; tests for empty output and unchanged code.
- Placeholders (CFG/fold/DCE): always skipped `placeholder_not_implemented`.
- Tests: webcrack nonzero/timeout/empty; ML unchanged; LLM failure; DETECTION still applied.

**success fail-closed:**
- Substantive stages: UNPACKING, UNBUNDLING, CFG_UNFLATTENING, CONSTANT_FOLDING, DEAD_CODE_REMOVAL, ML_RENAMING, LLM_ENHANCEMENT (placeholders never count as applied).
- `success = True` only if ≥1 substantive stage in `stages_applied` **and** `confidence > 0.5` (pinned).
- Else `success=False` and `effectiveness_status="no_substantive_transform"` on **`DeobfuscationResult`**.
- Dataclass fields required: `stages_skipped`, `capabilities_run`, `effectiveness_status`.
- Narrow or delete any module docstring / log claiming unsupported "70–95% success rate".

- [ ] **Step 1: Tests** as above + positive DETECTION applied + capabilities_run shape
- [ ] **Step 2: Implement**
- [ ] **Step 3: Commit** `fix(js): honest deobfuscator stages_applied and fail-closed success`

### Task 7: Deferred-item honesty guards

**Files:**
- Create: `tests/unit/test_tg_audit_deferred_honesty.py`
- Create: `docs/architecture/tg-audit-fixups-2026-08-08.md`
- Modify: `backlog.md` — add short rows for fixed items + deferred

**Tests:**
1. `DifferentialOracle.fuzz_until_divergence` raises `NotImplementedError` (import and call).
2. Doc/backlog contains deferred table IDs D1–D6.
3. Re-grep guard: no `# noqa: F841` on the former silent enterprise knobs (assert via reading source or subprocess `rg`).

- [ ] **Step 1: Write tests + doc**

- [ ] **Step 2: Commit** `docs+test: tg-audit fixup receipt and deferred honesty guards`

---

### Task 8: Dogfood + Sol/Thinktank re-audit

- [ ] **Step 1: Run focused suite**

```bash
export PYTHONPATH=src
/usr/bin/python3.9 -m pytest \
  tests/unit/test_js_oracle_scorecard.py \
  tests/unit/test_js_adapter_oracle_scorecard.py \
  tests/unit/test_framework_js_probe_forwarding.py \
  tests/unit/test_tracked_js_bundle_manifest.py \
  tests/unit/test_ralph_js_loop.py \
  tests/unit/test_analyzer_enable_ai.py \
  tests/unit/test_mcp_enterprise_knobs.py \
  tests/unit/test_mcp_binary_detect_malware_unsupported.py \
  tests/unit/test_js_deobfuscator_capabilities.py \
  tests/unit/test_tg_audit_deferred_honesty.py \
  tests/unit/test_app_reverse_engineering.py \
  tests/unit/test_mcp_contracts.py \
  tests/unit/test_analyzer.py \
  -q --no-cov
lint-imports --no-cache
# targeted mypy on touched modules if available:
if command -v mypy >/dev/null 2>&1 || /usr/bin/python3.9 -m mypy --version >/dev/null 2>&1; then
  /usr/bin/python3.9 -m mypy src/reveng/app_reverse_engineering/framework.py \
    src/reveng/app_reverse_engineering/adapters/javascript.py \
    src/reveng/app_reverse_engineering/js_oracle_scorecard.py \
    --ignore-missing-imports
else
  echo "mypy not installed — SKIP with reason recorded in receipt (not a silent pass)"
fi
```

- [ ] **Step 2: GA readiness with separate outputs + executable JSON assertions**

```bash
BASE_OUT=reports/ga_readiness_tg_audit_baseline.json
GA_OUT=reports/ga_readiness_tg_audit_ga.json
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile baseline --output "$BASE_OUT"
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile ga --output "$GA_OUT"
# Do NOT claim pass from exit code alone — run the inspector below (fails hard).
/usr/bin/python3.9 - <<'PY'
import json
from pathlib import Path

BASELINE_GATES = {
    "documented-support-surface",
    "app-corpus-baseline",
    "native-benchmark-baseline",
    "native-analyze-evidence",
    "bun-matrix-baseline",
}
GA_EXTRA = {
    "strict-ga-input-provenance",
    "native-success-floor",
    "multi-codebase-validation-breadth",
    "bun-live-sample-depth",
    "app-corpus-non-synthetic",
}

def inspect(path: Path, profile: str, required_ids: set[str]) -> None:
    data = json.loads(path.read_text())
    assert data["profile"] == profile, (path, data.get("profile"))
    assert data["result_type"] == "ga_readiness_report"
    assert data["schema_version"]
    assert data["summary"]["overall_status"] in ("pass", "fail")
    assert isinstance(data["summary"]["failed_gate_count"], int)
    gates = {g["id"]: g for g in data["gates"]}
    missing = required_ids - set(gates)
    assert not missing, (path, missing)
    for gid, g in gates.items():
        assert g["status"] in ("pass", "fail", "warn", "skip"), g
        assert isinstance(g.get("details"), dict) and g["details"], f"empty details: {gid}"
        assert g.get("summary"), f"empty summary: {gid}"
    # Open every referenced input file; must exist and be non-empty (honesty: no hollow refs)
    for key, rel in data["inputs"].items():
        p = Path(rel)
        assert p.is_file() and p.stat().st_size > 0, (key, rel)
        # Spot-check JSON parse for report inputs
        if p.suffix == ".json":
            blob = json.loads(p.read_text())
            assert blob, (key, "empty json")
    # native-analyze-evidence must carry concrete detail keys (not empty {})
    nae = gates["native-analyze-evidence"]["details"]
    assert len(nae) >= 1
    # Open concrete analyze artifacts from source_report (never trust boolean alone)
    src = json.loads(Path(data["inputs"]["source_report"]).read_text())
    hollow = []
    missing_art = []
    for row in src.get("benchmarks") or []:
        if not row.get("analyze_report_exists"):
            continue
        # Derive unified report path from stdout_tail or conventional layout
        out_dir = None
        cmd = (row.get("analyze_command") or {}).get("command") or []
        if "--output-dir" in cmd:
            out_dir = Path(cmd[cmd.index("--output-dir") + 1])
        if out_dir is None:
            missing_art.append(row.get("name") or row.get("id") or "unknown")
            continue
        unified = out_dir / "reports" / "unified_analysis_report.json"
        if not unified.is_file() or unified.stat().st_size == 0:
            missing_art.append(str(unified))
            continue
        urep = json.loads(unified.read_text())
        assert urep, unified
        # Required non-empty structural fields (schema honesty)
        assert any(k in urep for k in ("result_type", "status", "pipeline_status", "schema_version", "validation")), list(urep)[:20]
        stderr = str((row.get("analyze_command") or {}).get("stderr_tail") or "")
        stdout = str((row.get("analyze_command") or {}).get("stdout_tail") or "")
        if "Pipeline failed" in stderr or "Pipeline failed" in stdout or "GhidraEngine not configured" in stderr:
            hollow.append(str(unified))
    assert not missing_art, ("missing/unreadable analyze artifacts", missing_art[:5])
    # D6: measure hollow; do not fail wave on hollow_count>0 — write to receipt
    receipt = Path("docs/architecture/tg-audit-fixups-2026-08-08.md")
    print(path, "OK", data["summary"]["overall_status"], "hollow_analyze_rows=", len(hollow))
    # Idempotent: replace section for this profile rather than append forever
    if receipt.exists():
        body = receipt.read_text()
        header = f"### GA hollow measure ({profile})"
        block = f"{header}\n\nhollow_analyze_rows={len(hollow)}\n"
        if header in body:
            import re as _re
            body = _re.sub(rf"{_re.escape(header)}\n\nhollow_analyze_rows=\d+\n", block, body, count=1)
        else:
            body = body.rstrip() + "\n\n" + block
        receipt.write_text(body)

inspect(Path("reports/ga_readiness_tg_audit_baseline.json"), "baseline", BASELINE_GATES)
inspect(Path("reports/ga_readiness_tg_audit_ga.json"), "ga", BASELINE_GATES | GA_EXTRA)
PY
```

If this wave does not touch probe stamp directories, still note: for any probe evidence dir under `.reveng/` / reports that ships `latest.json`, confirm exactly one `20*.json` stamp is byte-identical to `latest.json` (release-honesty DF). Skip only if no such dir is in the changed file set — document skip reason in the receipt doc.

- [ ] **Step 3: Optional tg verify** (path-first `tg find`)

```bash
tg callers src/reveng/app_reverse_engineering reverse_engineer --json --deadline 20
tg find "noqa: F841" src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py --json --deadline 20
```

- [ ] **Step 4: Sol/Thinktank audit packet** vs this plan + diff; fix REJECT until APPROVE/APPROVE_WITH_NITS

- [ ] **Step 5: Merge procedure (junior, noninteractive)**
  1. Ensure branch `feat/tg-audit-fixups` pushed; CI green or local Task 8 green.
  2. `git checkout main && git pull --ff-only`
  3. `git merge --no-ff feat/tg-audit-fixups -m "merge: tg-audit fixups wave"`
  4. Re-run Task 8 focused suite on main tip.
  5. Update `backlog.md` + receipt hollow measures; **named-path commit** `docs: tg-audit fixups receipt and backlog` before push.
  6. Do **not** force-push; do **not** `git stash`.

---

## Definition of done

- [ ] No xfail on tracked-bundle oracle wiring for the reason “oracle_dir not wired”
- [ ] Scorecard includes honest `overall_score` + `token_signal_score` with `reconstruction_mode=filename_set`
- [ ] Enterprise MCP knobs applied or explicitly warned (no `# noqa: F841` silent drops); every knob has true/false tests
- [ ] `enable_ai=False` behaviorally skips AI step1
- [ ] Binary MCP malware returns explicit unsupported/error code
- [ ] Deobfuscator placeholder stages not in `stages_applied`
- [ ] Deferred LibAFL/splits documented + guarded
- [ ] Baseline + GA reports written to **separate** paths and JSON evidence inspected
- [ ] Thinktank/Sol APPROVE on plan and APPROVE/APPROVE_WITH_NITS on implementation

## Non-goals (do not do in this plan)

- Achieving RALPH-2 0.8 recall engine quality (wiring + filename-set scorecard only)
- Implementing LibAFL / angr product depth
- Splitting 300KB modules
- Claiming Scope C phases 6–13 complete
