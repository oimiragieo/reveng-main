# REVENG Professionalization — Phase 0 + Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get the REVENG working tree clean and the test suite fully green (0 unaccounted failures), fixing every audited bug, *before* any structural file moves.

**Architecture:** Work on a dedicated branch. Phase 0 deletes regenerable cruft and hardens `.gitignore` with zero `src/` logic changes. Phase 1 fixes real bugs and retires stale tests/fixtures one cluster at a time, each with a regression test and TDD discipline (write failing test → verify red → fix → verify green → commit). Cycle-detection tooling (`import-linter`) is stood up in Phase 0 as a regression baseline. Ends with the four-gate sweep.

**Tech Stack:** Python 3.9+, pytest (+pytest-cov), black/isort/pylint/mypy, import-linter, git. Run from repo root `C:\dev\projects\reveng-main`; tests put `src/` on path via the editable install or `PYTHONPATH=src`.

**Source of truth:** the design spec `docs/architecture/2026-06-03-reveng-professionalization-design.md` (esp. §7 council amendments). Where this plan and the spec disagree, the spec §7 wins.

---

## Conventions (read once)

- **Baseline ledger:** the 46 pre-existing unit failures recorded in Task 0.1 are the regression bar. A task is "green" when its targeted tests pass AND no *previously-passing* test regressed.
- **Per-task gate (fast):** `python -m pytest <touched test files> -p no:cacheprovider -q --no-cov`
- **Phase gate (full):** see Task 1.20.
- **Commit style:** Conventional Commits (`fix:`, `test:`, `chore:`, `docs:`). Each task ends in a commit.
- **Editing files you haven't read:** every fix task starts by *reading the cited file around the cited line* to confirm the current code before editing — line numbers are from the 2026-06-03 audit and may drift.

---

## Phase 0 — Cleanup + gitignore + cycle baseline

### Task 0.1: Branch + baseline ledger

**Files:**
- Create: `docs/architecture/_baseline_failures_2026-06-03.txt` (ledger; can be git-ignored or committed)

- [ ] **Step 1: Create the working branch**

```bash
cd /c/dev/projects/reveng-main
git checkout -b refactor/professionalization
```

- [ ] **Step 2: Capture the baseline failing node IDs**

```bash
python -m pytest tests/unit -p no:cacheprovider -q --no-cov \
  -m "not requires_external_tools and not slow and not requires_network" \
  2>&1 | grep -E "^(FAILED|ERROR)" | sort > docs/architecture/_baseline_failures_2026-06-03.txt
wc -l docs/architecture/_baseline_failures_2026-06-03.txt
```

Expected: ~46 lines (the recorded failures). This file is the regression bar.

- [ ] **Step 3: Commit the ledger**

```bash
git add docs/architecture/_baseline_failures_2026-06-03.txt
git commit -m "chore: record pre-cleanup unit-test failure baseline (46 failures)"
```

### Task 0.2: Stand up import-linter cycle baseline (amendment §7.8)

**Files:**
- Modify: `pyproject.toml` (add `import-linter` to `[project.optional-dependencies].dev`)
- Create: `.importlinter` (contract config)
- Create: `tests/unit/test_import_contracts.py`

- [ ] **Step 1: Add the dev dependency**

In `pyproject.toml`, under `[project.optional-dependencies]` `dev = [...]`, add `"import-linter>=2.0",`. Install: `pip install "import-linter>=2.0"`.

- [ ] **Step 2: Write a baseline "forbidden cycle" contract**

Create `.importlinter`:

```ini
[importlinter]
root_package = reveng

[importlinter:contract:no-ai-security-cycle]
name = ai and security must not form an import cycle
type = independence
modules =
    reveng.ai
    reveng.security
```

- [ ] **Step 2b: Write a test that runs the contract**

Create `tests/unit/test_import_contracts.py`:

```python
import shutil
import subprocess
import pytest

@pytest.mark.skipif(shutil.which("lint-imports") is None, reason="import-linter not installed")
def test_import_contracts_documented_state():
    # Baseline: the ai<->security cycle EXISTS today (broken in Phase 3).
    # This test documents the current state so Phase 3 can flip it to a hard gate.
    result = subprocess.run(["lint-imports"], capture_output=True, text=True)
    # Record, do not yet enforce: cycle is expected to be reported now.
    assert "no-ai-security-cycle" in (result.stdout + result.stderr)
```

- [ ] **Step 3: Run it**

Run: `python -m pytest tests/unit/test_import_contracts.py -q --no-cov`
Expected: PASS (it asserts the contract is *evaluated*, not yet clean).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml .importlinter tests/unit/test_import_contracts.py
git commit -m "chore: add import-linter cycle baseline (ai<->security, enforced in Phase 3)"
```

### Task 0.3: Harden `.gitignore` and untrack VRL run logs

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Read the current `.gitignore`** to avoid duplicate patterns (it has dir-only `reports/...` rules that miss `.json` *files*).

- [ ] **Step 2: Append the file-level patterns** (amendment list, spec §4 Phase 0):

```gitignore
# --- professionalization cleanup (2026-06-03): regenerable run artifacts ---
reports/app_reverse_engineering_corpus_claude_*.json
reports/_tmp_*.json
reports/source_binary_benchmarks*
reports/ralph_tracked_bundle_*/
reports/app_reverse_engineering_tool_eval_*/
reports/app_reverse_engineering_corpus_js_oracle*.json
reports/cli_js_user_proof_run/
reports/tracked_js_bundle_benchmark/
reports/app_reverse_engineering_corpus_javascript_test/
external/ga_binaries/
external/ghidramcp/
.reveng/vrl-runs/*.json
```

- [ ] **Step 3: Untrack the VRL run logs** (decided: gitignore them):

```bash
git rm --cached -r .reveng/vrl-runs/ 2>/dev/null || true
git status --short | grep vrl-runs
```

Expected: `.reveng/vrl-runs/*.json` shown as deleted-from-index (still on disk).

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: gitignore regenerable run artifacts; untrack .reveng/vrl-runs"
```

### Task 0.4: Delete cruft (verify zero inbound readers first)

**Files (delete):** `_list_analysis.py`; `reports/_tmp_app_corpus_*.json`; `reports/app_reverse_engineering_corpus_claude_real_v*.json` + base/`_cli_real`/`_local`/`_loop`/`_loop_smoke` dumps; top-level `projects/`.

- [ ] **Step 1: Confirm no source reads the dump files** (amendment: zero *readers*, not just importers)

```bash
grep -rEl "app_reverse_engineering_corpus_claude_real_v|_tmp_app_corpus_|_list_analysis" \
  src/ scripts/ tests/ .reveng/ 2>/dev/null || echo "NO READERS FOUND"
```

Expected: `NO READERS FOUND` (or only matches inside the files being deleted). If a generator reads any, STOP and surface it.

- [ ] **Step 2: Delete the scratch files and dirs**

```bash
rm -f _list_analysis.py
rm -f reports/_tmp_app_corpus_*.json
rm -f reports/app_reverse_engineering_corpus_claude_real*.json
rm -f reports/app_reverse_engineering_corpus_claude_cli_real.json \
      reports/app_reverse_engineering_corpus_claude_local.json \
      reports/app_reverse_engineering_corpus_claude_loop.json \
      reports/app_reverse_engineering_corpus_claude_loop_smoke.json
rm -rf projects/
```

- [ ] **Step 3: Verify the package still imports and tests still collect**

Run: `python -c "import sys; sys.path.insert(0,'src'); import reveng; print(reveng.__version__)"`
Expected: `4.0.0`
Run: `python -m pytest tests/ -p no:cacheprovider --co -q --no-cov 2>&1 | tail -1`
Expected: `1171 tests collected` (or current count), no new collection errors.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove regenerable eval-loop dumps and stray projects/ scaffold"
```

---

## Phase 1 — Make the suite green + fix every bug

> Order: stale-test retirements first (fast green), then real bugs, then static bugs. Each fix = read file → write failing regression test → verify red → fix → verify green → commit.

### Task 1.1: Retire stale `local_disassembler` renderer tests (36 failures → xfail)

**Files:**
- Modify: `tests/unit/test_local_disassembler.py`
- Create: GitHub issue (tracked) — see Step 4.

- [ ] **Step 1: Confirm the gap** — read `src/reveng/integrations/local_disassembler.py`; confirm it lacks `_render_pseudocode_function`, `_collect_behavioral_seed_targets`, `_instruction_to_pseudocode`, etc. (the shipped module is the minimal fallback).

- [ ] **Step 2: Add a module-level xfail** at the top of `tests/unit/test_local_disassembler.py`:

```python
import pytest

pytestmark = pytest.mark.xfail(
    reason="rich local pseudocode renderer not yet implemented (tracking: REVENG-RENDERER); "
           "shipped local_disassembler is a deliberate minimal fallback",
    strict=False,
)
```

(If a handful of tests in this file currently PASS, scope the marker to the renderer tests instead — apply `@pytest.mark.xfail` to the specific classes/functions named in the audit so passing tests are not masked.)

- [ ] **Step 3: Run** — `python -m pytest tests/unit/test_local_disassembler.py -q --no-cov`
Expected: all xfailed (reported as `xfailed`), 0 failures.

- [ ] **Step 4: File the tracking issue** — `gh issue create --title "Implement rich local pseudocode renderer in local_disassembler" --body "36 xfailed tests in tests/unit/test_local_disassembler.py expect _render_pseudocode_function/_collect_behavioral_seed_targets/etc. Decide: implement renderer or delete tests. See docs/architecture/2026-06-03-reveng-professionalization-design.md §Decisions."` (record the issue number into the xfail reason if it differs from `REVENG-RENDERER`).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "test: xfail unimplemented local pseudocode renderer tests + track issue"`

### Task 1.2: Update stale `claude_cli_analyzer` test (`--bare` removed)

**Files:** Modify `tests/unit/test_claude_cli_analyzer.py::test_analyze_invokes_subprocess_with_shell_false`

- [ ] **Step 1: Read** the test and `src/reveng/agents/ai/claude_cli_analyzer.py` to confirm the current argv (no `--bare`; has `--no-session-persistence`, `--permission-mode bypassPermissions`).
- [ ] **Step 2: Replace** `assert "--bare" in argv` with:

```python
assert "--no-session-persistence" in argv
assert "--permission-mode" in argv and "bypassPermissions" in argv
```

Keep the existing `shell=False` / argv-is-list / prompt-is-last assertions.
- [ ] **Step 3: Run** — `python -m pytest tests/unit/test_claude_cli_analyzer.py -q --no-cov` → Expected: PASS.
- [ ] **Step 4: Commit** — `git commit -am "test: update claude_cli argv assertions (--bare intentionally dropped)"`

### Task 1.3: Fix `cli/reveng.py` sys.path (keep dedup guard) — 4 CLI tests (amendment §7.6)

**Files:** Modify `src/reveng/cli/reveng.py`; Test `tests/unit/test_cli.py::TestCLIIntegration`

- [ ] **Step 1: Read** `src/reveng/cli/reveng.py`. Current bug: it computes `SRC_ROOT` but only inserts it when `not in sys.path`, so the script-dir entry shadows the package.
- [ ] **Step 2: Replace** the path-setup block with (keep dedup; force `src/` to front; strip the script-dir entry):

```python
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2]  # src/
_SCRIPT_DIR = str(Path(__file__).resolve().parent)
sys.path[:] = [p for p in sys.path if p and Path(p).resolve() != Path(_SCRIPT_DIR).resolve()]
_src = str(SRC_ROOT)
if _src in sys.path:
    sys.path.remove(_src)
sys.path.insert(0, _src)

from reveng.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Verify the wrapper runs** — `python src/reveng/cli/reveng.py --version` → Expected: exit 0, prints version.
- [ ] **Step 4: Run the 4 CLI tests** — `python -m pytest tests/unit/test_cli.py::TestCLIIntegration -q --no-cov` → Expected: PASS (4).
- [ ] **Step 5: Commit** — `git commit -am "fix(cli): force src/ to front of sys.path in reveng.py wrapper, keep dedup guard"`

### Task 1.4: Fix source-map recoverer — 3 tests

**Files:** Modify `src/reveng/javascript/source_map_recoverer.py`; Test `tests/unit/test_source_map_recoverer.py`

- [ ] **Step 1: Read** `_find_sourcemaps_local` and `recover` + `_clean_filename`.
- [ ] **Step 2: Apply the three fixes** (from audit):
  - Open bundle with `encoding="utf-8", errors="replace"` (no UnicodeDecodeError on non-UTF8).
  - If the captured `sourceMappingURL` starts with `data:`, append it **verbatim** to maps (don't treat as a path).
  - Replace `Path(filepath).with_suffix(filepath + ".map")` with `Path(str(filepath) + ".map")`.
  - In `recover()`: if the url starts with `data:`, split on the first comma, base64-decode the payload, `json.loads` it (do not `open()` it).
  - Extend `_clean_filename` to strip `sourceRoot` prefix, leading `./`, and any `?...`/`#...` suffix, then dedupe.
- [ ] **Step 3: Run** — `python -m pytest tests/unit/test_source_map_recoverer.py -q --no-cov` → Expected: PASS (3 previously-failing now green).
- [ ] **Step 4: Commit** — `git commit -am "fix(js): source-map recoverer handles inline data: URLs, non-utf8 bundles, .map path"`

### Task 1.5: Wire JS→IR emission — 1 test

**Files:** Modify `src/reveng/javascript/bundle_reverse_engineer.py`; uses `reveng.ir`; Test `tests/unit/test_reverse_engineering_ir.py::test_js_bundle_workflow_emits_ir_artifact`

- [ ] **Step 1: Read** `BundleReverseEngineeringResult` and `reverse_engineer_bundle`, and `src/reveng/ir.py` (`REProjectIR`, node/edge API), and the passing `test_re_project_ir_serializes_nodes_edges_and_metadata` to match payload keys.
- [ ] **Step 2: Add** `ir_file: Optional[Path] = None` to `BundleReverseEngineeringResult`.
- [ ] **Step 3: In `reverse_engineer_bundle`**, near the end build a `REProjectIR(language="javascript", ...)` with a `cli` node for the bundle entry plus nodes/edges from recovered domains (`auth`, `mcp`, ...), serialize to `artifacts_dir / "project.re_project_ir.json"`, and set `result.ir_file` to that path.
- [ ] **Step 4: Run** — `python -m pytest tests/unit/test_reverse_engineering_ir.py -q --no-cov` → Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(js): emit shared REProjectIR artifact from bundle reverse-engineer"`

### Task 1.6: Add missing corpus fixture row — 1 test

**Files:** Modify `.reveng/app_reverse_engineering_corpus.json` and `.reveng/app_reverse_engineering_corpus.ga.json`; Test `tests/unit/test_tracked_js_bundle_manifest.py::test_corpus_configs_reference_tracked_bundle_row`

- [ ] **Step 1: Read** the existing `javascript-sample-app` entry in both files to mirror its shape.
- [ ] **Step 2: Add** a `javascript-tracked-bundle` entry to the `entries[]` of both files, pointing at `test_samples/js_tracked_bundle_artifact/bundle.js` with oracle dir `test_samples/js_tracked_bundle_source`, `language: "javascript"`, plus any required GA fields the `.ga.json` row uses.
- [ ] **Step 3: Run** — `python -m pytest tests/unit/test_tracked_js_bundle_manifest.py -q --no-cov` → Expected: PASS.
- [ ] **Step 4: Commit** — `git commit -am "fix(corpus): add javascript-tracked-bundle row to corpus configs"`

### Task 1.7: VRL argv + seed contract (CRITICAL) (amendments §7.5, §7.1)

**Files:** Modify `src/reveng/verification/differential/harness.py`, `src/reveng/verification/differential/oracle.py`, `scripts/run_vrl.py`; Create `tests/unit/test_vrl_harness_argv.py`

- [ ] **Step 1: Write the failing deterministic unit test** (this becomes the per-move VRL gate). Create `tests/unit/test_vrl_harness_argv.py`:

```python
import sys
from pathlib import Path
from reveng.verification.differential.harness import ExecutionHarness

def test_run_passes_argv_not_stdin(tmp_path):
    # A tiny python "binary" that echoes argv so we can prove args reach argv.
    prog = tmp_path / "echo_argv.py"
    prog.write_text("import sys; print('ARGV:' + ' '.join(sys.argv[1:]))")
    h = ExecutionHarness(binary_path=prog, runner=[sys.executable])  # runner shim if supported
    result = h.run(argv=["--help", "--version"], input_bytes=b"")
    assert "ARGV:--help --version" in result.stdout
```

(If `ExecutionHarness` runs the binary directly without a `runner`, adapt the test to a platform script the harness can execute; the *assertion* — argv tokens reach `sys.argv`, not stdin — is the point.)

- [ ] **Step 2: Run → red** — `python -m pytest tests/unit/test_vrl_harness_argv.py -q --no-cov` → Expected: FAIL (`run()` has no `argv` param).
- [ ] **Step 3: Implement** `ExecutionHarness.run(argv: Optional[List[str]] = None, input_bytes: bytes = b"")`: build `cmd = [str(self._binary_path), *(argv or [])]`, call `subprocess.run(cmd, input=input_bytes, ...)`, keep stdin distinct. Thread an optional `argv` through `DifferentialOracle.verify(...)`.
- [ ] **Step 4: Define the seed contract in `run_vrl.py`** — extend `_get_seed_inputs`/corpus parsing so each seed declares argv vs stdin: treat tokens beginning `-` or resolving to an existing file as **argv** (`shlex.split` multi-token strings), explicit stdin payloads via a separate key. Pass argv through to `verify`. Ensure file-path seeds exist relative to cwd.
- [ ] **Step 5: Run → green** — `python -m pytest tests/unit/test_vrl_harness_argv.py -q --no-cov` → Expected: PASS.
- [ ] **Step 6: Commit** — `git commit -am "fix(vrl): pass seed args as argv not stdin; add seed argv/stdin contract"`

### Task 1.8: ValidationGrade type + oracle populates grade + run_vrl write + null-guard (amendment §7.3)

**Files:** Modify `src/reveng/verification/models.py` (`ValidationGrade = Any` → real vocabulary), `src/reveng/verification/differential/oracle.py` (populate `DivergenceReport.grade`), `scripts/run_vrl.py` (`_update_corpus_grade` write + exact-name match); Create `tests/unit/test_vrl_grade.py`

- [ ] **Step 1: Write failing tests** in `tests/unit/test_vrl_grade.py`: (a) a converged result writes a member of the grade ladder (e.g. `behavior_matched`) into corpus `current_grade`; (b) an LLM_ERROR result (where `final_divergence is None`) writes a valid fallback grade (e.g. `unknown`/`analysis_only`), never `None`; (c) `_update_corpus_grade` matches `- name: hexyl` exactly and does not match a substring like `hex`.
- [ ] **Step 2: Run → red.**
- [ ] **Step 3: Implement** — define `ValidationGrade` as an ordered vocabulary (`unknown < analysis_only < ... < behavior_matched < evidence_backed`) in `verification/models.py`; have `DifferentialOracle.verify()` compute+assign `DivergenceReport.grade`; in `run_vrl._update_corpus_grade` write `result.final_divergence.grade` guarded by `getattr(result.final_divergence, "grade", None) or <fallback>`; replace `binary_name in line` with exact name parse/compare.
- [ ] **Step 4: Run → green.**
- [ ] **Step 5: Commit** — `git commit -am "fix(vrl): write ValidationGrade (not status) into corpus, null-guarded, exact-name match"`

### Task 1.9: `agent_sdk` ToolError arity + non-raising registry lookup

**Files:** Modify `src/reveng/agent_sdk/client.py` (lines ~184/189/193, 188/220-224), maybe `src/reveng/agent_sdk/tools/registry.py`; Test `tests/unit/` (new `test_agent_sdk_client.py`)

- [ ] **Step 1: Write failing tests** — (a) a permission-denied tool raises `ToolError` (not `TypeError`); (b) `query(tools=["does-not-exist"])` skips the unknown tool instead of raising.
- [ ] **Step 2: Run → red.**
- [ ] **Step 3: Implement** — change the three `ToolError(f"...")` calls to `ToolError(tool_name, "Permission denied")` / `ToolError(tool_name, "Tool not found")` / `ToolError(tool_name, "Pre-hook blocked execution")`; add `ToolRegistry.try_get(name) -> Optional[BaseTool]` (returns None on miss) and use it in the `if not tool` / `_get_available_tools` sites.
- [ ] **Step 4: Run → green. Step 5: Commit** — `git commit -am "fix(agent_sdk): ToolError 2-arg calls + non-raising registry lookup"`

### Task 1.10: `BinaryAnalysisTool` calls correct analyzer API

**Files:** Modify `src/reveng/agent_sdk/tools/reveng/binary_analysis_tool.py:62-66`; Test new `tests/unit/test_binary_analysis_tool.py`

- [ ] **Step 1: Failing test** — `execute()` on a sample binary returns success (not "object has no attribute 'analyze'").
- [ ] **Step 2: red. Step 3:** construct `REVENGAnalyzer(binary_path=path)` and call `analyzer.analyze_binary` with no positional path: `await loop.run_in_executor(None, analyzer.analyze_binary)`.
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(agent_sdk): BinaryAnalysisTool uses REVENGAnalyzer(binary_path=...).analyze_binary()"`

### Task 1.11: `SecurityAuditSkill` reads existing ToolResult field

**Files:** Modify `src/reveng/agent_sdk/skills/builtin/security_audit.py:69`; Test new test.

- [ ] **Step 1: Failing test** — a successful audit returns a report (not "ToolResult has no attribute 'data'").
- [ ] **Step 2: red. Step 3:** replace `analysis_result.data` with `analysis_result.content` (confirm field on `ToolResult` in `agent_sdk/tools/base.py`).
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(agent_sdk): SecurityAuditSkill reads ToolResult.content not .data"`

### Task 1.12: `babel_transformer` re.sub replacement injection (verify real method) (amendment §7.7)

**Files:** Modify `src/reveng/javascript/babel_transformer.py`; Test new test.

- [ ] **Step 1: Locate the actual unsafe site** — grep for `re.sub(` in the file; confirm which method builds `replacement = f"'{string}'"` from decoded array elements (candidates: `_replace_accessors`, `_remove_opaque_predicates`, `_simplify_strings`; `_constant_folding` is already a safe lambda — do not touch).
- [ ] **Step 2: Failing test** — deobfuscating a string-array element containing `\x41` or `\1` does not raise `re.error` and does not mangle output.
- [ ] **Step 3: red. Step 4:** replace the string replacement with a **callable**: `re.sub(pattern, lambda m, s=string: "'" + s + "'", code)`.
- [ ] **Step 5: green. Step 6: Commit** — `git commit -am "fix(js): use callable re.sub replacement to avoid backslash/group-ref injection"`

### Task 1.13: `python_bytecode_analyzer` numeric version compare

**Files:** Modify `src/reveng/tools/languages/python_bytecode_analyzer.py` (~329/333); Test new test.

- [ ] **Step 1: Failing test** — `"3.10"` routes to the 3.10+ path, not uncompyle6 (assert via the selected decompiler).
- [ ] **Step 2: red. Step 3:** parse to a tuple `tuple(int(p) for p in python_version.split(".")[:2])` and compare numerically against `(3,8)`/`(3,7)`/`(3,9)`.
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(tools): numeric (major,minor) python version comparison for decompiler routing"`

### Task 1.14: VirusTotal `enrich_analysis` KeyError on not-found

**Files:** Modify `src/reveng/tools/threat_intel/virustotal_connector.py:~339,371`; Test new test.

- [ ] **Step 1: Failing test** — `enrich_analysis({})` with a hash not on VT does not raise `KeyError: 'threat_intel'`.
- [ ] **Step 2: red. Step 3:** hoist `enriched.setdefault("threat_intel", {})` above the `if vt_intel:`/`else` so both branches can index it.
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(threat_intel): setdefault threat_intel before VT found/not-found branches"`

### Task 1.15: `deobfuscator` temp-file finally-guard

**Files:** Modify `src/reveng/javascript/deobfuscator.py:380-408`; Test new test.

- [ ] **Step 1: Failing test** — if `NamedTemporaryFile` is patched to raise, the original exception propagates (not `NameError: input_file`).
- [ ] **Step 2: red. Step 3:** init `input_file = None` before the try; guard `finally` with `if input_file is not None`; catch `(OSError, FileNotFoundError)` around `os.unlink`.
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(js): guard deobfuscator temp-file cleanup against NameError/unlink errors"`

### Task 1.16: `bun_extractor` temp-dir leak

**Files:** Modify `src/reveng/tools/anti_analysis/bun_extractor.py:3036-3075`; Test new test (assert temp dir removed).

- [ ] **Step 1: Failing test → red. Step 2:** wrap the `_probe_standalone_output` body in `try/finally` and `shutil.rmtree(probe_dir, ignore_errors=True)` in `finally`.
- [ ] **Step 3: green. Step 4: Commit** — `git commit -am "fix(tools): clean up bun SEA probe temp dir in finally"`

### Task 1.17: filesystem MCP path-containment bypass

**Files:** Modify `src/reveng/agent_sdk/mcp/servers/filesystem.py:102-110`; Test new test.

- [ ] **Step 1: Failing test** — a sibling path like `<root>_secret/x` is rejected (currently passes the `startswith` check).
- [ ] **Step 2: red. Step 3:** replace `str(full_path).startswith(str(self.root_path))` with containment via `full_path.relative_to(self.root_path)` in `try/except ValueError` (or `os.path.commonpath`).
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(mcp): proper path containment in filesystem server (relative_to, not startswith)"`

### Task 1.18: refiner telemetry + compile_adapter freshness (LOW)

**Files:** Modify `src/reveng/verification/refinement/refiner.py:157-184`, `src/reveng/verification/refinement/compile_adapter.py:62-107`; Tests new.

- [ ] **Step 1: Failing tests** — (a) LLM_ERROR round records computed `response_text`/tokens when available; (b) `compile_fn` asserts `binary_path.exists()` and is newer than source write after returncode 0.
- [ ] **Step 2: red. Step 3:** bind `llm_result`/`response_text` outside the try and reuse; after returncode 0, `assert binary_path.exists()` and unlink any stale pre-existing binary before compile.
- [ ] **Step 4: green. Step 5: Commit** — `git commit -am "fix(vrl): preserve LLM_ERROR telemetry; assert fresh compiled binary"`

### Task 1.19 (Phase 1.5): VRL re-baseline after argv fix (amendment §7.10)

- [ ] **Step 1:** Re-run `scripts/run_vrl.py --binary hexyl` (with `REVENG_AI_PROVIDER` set, or `--mock-oracle` if implemented) and record the genuine argv-driven grade.
- [ ] **Step 2:** Audit any VRL test that asserted convergence/EQUIVALENT to confirm it did not pass *because of* the old stdin behavior; update expectations to the genuine grade.
- [ ] **Step 3: Commit** — `git commit -am "chore(vrl): re-baseline hexyl corpus grade against argv-driven runs"`

### Task 1.20: Phase 1 four-gate sweep

- [ ] **Gate 1 — tests:** `python -m pytest tests/unit tests/integration -p no:cacheprovider -q --no-cov -m "not requires_external_tools and not slow and not requires_network"`
  Expected: 0 failures; the only non-passing are the `local_disassembler` **xfailed** items. Compare against `_baseline_failures_2026-06-03.txt` — every formerly-failing node now passes or is xfailed; no new failures.
- [ ] **Gate 2 — CLI smoke:** `reveng --version && reveng --help >/dev/null && reveng-app --help >/dev/null && reveng-js --help >/dev/null && python src/reveng/cli/reveng.py --version` → all exit 0.
- [ ] **Gate 3 — VRL (deterministic):** `python -m pytest tests/unit/test_vrl_harness_argv.py tests/unit/test_vrl_grade.py -q --no-cov` → PASS. (Full network convergence is a phase-boundary smoke, not required here.)
- [ ] **Gate 4 — lint/type:** `black --check src/ tests/ && isort --check-only src/ tests/ && pylint src/reveng/verification src/reveng/agent_sdk src/reveng/javascript && mypy src/reveng/verification` (scope to touched packages; fix fallout).
- [ ] **Final commit / PR:** push branch; open PR titled "Phase 0+1: cleanup + green suite + bug fixes"; paste the four-gate results into the PR body.

---

## Self-review notes

- **Spec coverage:** Phase 0 (§4 Phase 0) and Phase 1 (§4 Phase 1 + §7 amendments 1–10) are each mapped to tasks. Phase 1.5 = Task 1.19. Amendment §7.2 (expanded gates: clean-install/`__file__`/dynamic-loader/pickling) and §7.4/§7.9/§7.11 (cli namespace flip, CI wiring, domain refinements, tools/ end-state) belong to the **Phase 2–4 plan** and are intentionally deferred there.
- **Deferred to Phase 2–4 plan:** all file moves, shims, the `cli.py→cli/` atomic flip, breaking the `ai↔security` cycle (flips Task 0.2's contract to enforcing), domain grouping, CI workflow gate wiring, back-compat policy.
- **Known unread files:** every fix task Step 1 mandates reading the cited file first; audit line numbers are hints, not contracts.
