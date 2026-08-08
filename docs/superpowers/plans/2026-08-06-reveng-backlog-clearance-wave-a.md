# REVENG Backlog Clearance — Wave A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close or honestly reclassify every REVENG backlog row that can be closed *without* new engine work, by shipping measurement-honest probe upgrades, five research/decision docs, two ops fixes, and a reconciled `backlog.md` — while explicitly refusing to claim native GA, exploit GA, or phases 4–13.

**Architecture:** Wave A touches three surfaces only: (1) `scripts/` — the bounded native-analyze probe gains a tool-absence status and a stderr tail so a nonzero exit is diagnosable instead of merely recorded; (2) `docs/architecture/` — research and decision docs (R-HEX-1, R-RALPH-2, R-PIPE-1, R-SEC-1, R-VRL-1) that each state a *measured* baseline or an explicit `could_not_measure` with a reason; (3) `backlog.md` — the final reconciliation. `src/reveng/**` is **not** modified in Wave A (Sol R1). Probe/script/docs/tests/backlog only. Product analyze fixes are Wave B. Code/script changes are fail-first TDD; research docs use fail-first shape/invariant tests where listed; pure decision docs use checklist verification (Sol R1 — no blanket TDD claim).

**Tech Stack:** Python 3.9 (`/usr/bin/python3.9` is the dogfood interpreter), pytest, `scripts/probe_native_analyze_timeout.py` (probe v1.1 → v1.2), `scripts/verify_ga_readiness.py`, Markdown docs under `docs/architecture/`, Git.


## Thinktank amendment (2026-08-06)

Sol R1 **REJECT** (`.superpowers/sdd/thinktank-wave-a-plan-r1-sol.md`) applied before any implementation:

1. Process `completed` ≠ native capability — Tasks 2–4 must capture/record semantic evidence (stdout/stderr tails + empty-fallback / analyze report presence when exit 0).
2. Hexyl `tool_absent` evidence lives in `reports/native_analyze_probe/` (multi-result `latest.json` + stamped sibling + README), not a side folder alone.
3. **R-HEX-1 stays `open`/`blocked`** until a real timed hexyl binary run exists. Do **not** mark research done from `tool_absent` alone.
4. Split **R-RALPH-2-BASELINE** (closeable after measured baseline doc) from **R-RALPH-2** (stays open until smallest 0.8+ wedge identified *and* implemented).
5. Soften TDD claim: code/script changes are fail-first TDD; research docs use fail-first *shape/invariant* tests where listed; pure decision docs use checklist verification — no blanket "Everything is TDD".
6. Task 4 = diagnosis doc only — **no** `src/reveng/**` authorization in Wave A. Reconcile exit-1 *and* exit-0 observations; do not assert root cause before stderr/evidence.
7. Task 9 evidence hygiene **fails** (not skips) when required evidence absent; scoped-git test uses a temporary repo behaviorally.
8. Task 10 dogfoods `--profile baseline` **and** `--profile ga`; neither proves native capability.
9. `stderr_tail` / stdout tails: redaction note in probe README (no secrets in tracked reports).
10. Fail-first backlog invariant test: M1-NATIVE-FAM open, ≥5 T3 parked, R-HEX-1 not `done` without hexyl timed evidence.

## Global Constraints

- **Python 3.9 is the dogfood interpreter.** Every dogfood/probe invocation in this plan uses `/usr/bin/python3.9`, never the host `python3.13`/`3.14`. No syntax above 3.9 (no `int | None` in annotations without `from __future__ import annotations`; no `match`). Ref DF-1, CLI-PY39-1, PY39-FSTR-1.
- **Named-path git only.** Every commit stages an explicit list of files: `git add <path> <path>`. Never `git add -A`, never `git add .`, never `git stash` (this repo has live `.worktrees/`; stash refs are shared). Never run a repo-wide `git status` — `reports/` on DrvFS hangs it (DF-4).
- **Fixture build ≠ analyze capability.** A binary that compiles proves the fixture builds. It does not prove REVENG can analyze it. No task may claim a capability from a successful `make` alone.
- **Probe status contract is three-valued and must stay that way:** `completed` (returncode 0), `timeout` (wall-clock budget exceeded), `could_not_measure` (everything else, always with a non-null `reason`). A nonzero exit is **never** `completed`. A zero must be labelled at the point of reporting: a report that says nothing must say *why* it says nothing.
- **No hollow GA.** Wave A may not flip any `required: false` fixture to `required: true`, may not mark `M1-NATIVE-FAM` closed, may not claim native GA, exploit GA, or completion of phases 4–13. A green `verify_ga_readiness` run is evidence of a gate passing, not proof of capability — record the tracked evidence fields alongside it.
- **Parked stays parked.** `T3-KERNEL`, `T3-PACKED`, `T3-JIT`, `T3-ANTI`, `T3-GUI` are untouched by this plan and must remain `parked` in `backlog.md`.
- **No exploit-surface expansion.** `R-SEC-1` produces a decision document only. No new exploit code, no watermark relaxation, no status change to `SEC-EXP-1`.
- Line length 100; `black`/`isort` before commit on any touched Python.

**Explicit non-goals for Wave A (do not do these, do not claim these):**
- Merging phases 7–13, or any phase-catalog status change from `open` to `done`.
- Closing `M1-NATIVE-FAM` or flipping native fixtures to `required: true`.
- The RALPH-2 0.8-recall engine rewrite. Wave A records a *baseline*, nothing more.
- Building or vendoring hexyl to manufacture an `M2` result.
- Any `src/reveng/**` change unless a task below explicitly authorizes one (none currently do).

---

## File Structure

| Path | Created/Modified | Responsibility |
| --- | --- | --- |
| `scripts/probe_native_analyze_timeout.py` | Modify | Probe v1.2: add `tool_absent:<name>` status reason and `stderr_tail` capture |
| `tests/unit/test_probe_native_analyze_timeout.py` | Modify | Regression tests for the two new probe behaviours |
| `scripts/git_status_scoped.sh` | Create | DF-4 ops fix: pathspec-scoped status that cannot hang on `reports/` |
| `tests/unit/test_git_status_scoped.py` | Create | Asserts the script excludes `reports/` and never runs a bare `git status` |
| `tests/unit/test_evidence_dir_hygiene.py` | Create | M0: `latest.json` must match a stamped sibling; no orphan/stale stamps |
| `docs/architecture/research-r-hex-1-hexyl-frontier-measurement.md` | Create | R-HEX-1 / M2: measured probe run + honest `tool_absent` record for hexyl |
| `docs/architecture/diagnosis-hello-go-analyze-exit1.md` | Create | Root cause of the 0.03s `nonzero_exit:1` on `hello_go` |
| `docs/architecture/research-r-ralph-2-recall-baseline.md` | Create | R-RALPH-2: measured current recall baseline + smallest-wedge options |
| `docs/architecture/decision-r-pipe-1-pipeline-packages.md` | Create | R-PIPE-1: merge vs permanent split decision |
| `docs/architecture/decision-r-sec-1-sandbox-class.md` | Create | R-SEC-1: sandbox class required before any exploit expansion |
| `docs/architecture/decision-r-vrl-1-seeds-and-provider.md` | Create | R-VRL-1: minimum seeds + provider for an honest VRL LLM gate |
| `docs/architecture/dogfood-verify-ga-readiness-2026-08-06.md` | Create | Dogfood record of `verify_ga_readiness` under 3.9 with tracked evidence fields |
| `docs/architecture/wave-b-exit-criteria.md` | Create | Wave B research-gated queue with explicit exit criteria |
| `backlog.md` | Modify | Final reconciliation of every row this wave touched |
| `reports/native_analyze_probe/` | Regenerated | Probe artifacts (stamped + `latest.json`) |
| `reports/native_analyze_probe/README.md` | Modify | Multi-result contract + tool_absent + stderr/stdout redaction (no secrets) |

---

### Task 1: Probe v1.2 — a missing tool must not read as a failed analyze

Today `probe_one` maps a missing analyze executable onto `os_error:FileNotFoundError`, which is indistinguishable from a real OS-level failure of a tool that *is* installed. `hexyl` is absent on this host (`command -v hexyl` → nothing), so M2 needs a status that says *the instrument was never present* rather than *the measurement failed*.

**Files:**
- Modify: `scripts/probe_native_analyze_timeout.py` (`PROBE_VERSION`, `probe_one`)
- Test: `tests/unit/test_probe_native_analyze_timeout.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `probe_one(binary_path: Path, analyze_cmd: Sequence[str], timeout_s: float, now_iso: str) -> Dict[str, Any]` now returns `status="could_not_measure"`, `measured=False`, `reason=f"tool_absent:{analyze_cmd[0]}"` when `shutil.which(analyze_cmd[0])` is `None` and `analyze_cmd[0]` is not an existing file. `PROBE_VERSION == "1.2"`. Task 2 adds `stderr_tail` and (on executed runs) bounded `stdout_tail`; Task 3–4 consume both. Process `completed` still ≠ native GA.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_probe_native_analyze_timeout.py`:

```python
def test_probe_reports_tool_absent_when_analyze_executable_missing(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        ["definitely-not-a-real-tool-xyz"],
        timeout_s=5.0,
        now_iso="2026-08-06T00:00:00Z",
    )
    assert out["status"] == "could_not_measure"
    assert out["measured"] is False
    assert out["reason"] == "tool_absent:definitely-not-a-real-tool-xyz"


def test_probe_tool_absent_is_distinguishable_from_nonzero_exit(tmp_path: Path):
    """Positive control: a tool that EXISTS and fails must not read as absent."""
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    present = probe_one(binary, [sys.executable, "-c", "raise SystemExit(1)"],
                        timeout_s=10.0, now_iso="2026-08-06T00:00:00Z")
    assert present["reason"] == "nonzero_exit:1"
    assert present["measured"] is True


def test_probe_version_is_1_2():
    from scripts.probe_native_analyze_timeout import PROBE_VERSION

    assert PROBE_VERSION == "1.2"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -v --no-cov
```

Expected: `test_probe_reports_tool_absent_when_analyze_executable_missing` FAILS with `reason == 'os_error:FileNotFoundError'`; `test_probe_version_is_1_2` FAILS with `'1.1' != '1.2'`. The positive-control test must **pass already** — if it fails, stop and fix the harness before changing the probe.

- [ ] **Step 3: Implement the minimal change**

In `scripts/probe_native_analyze_timeout.py`, add `import shutil` to the imports, bump the constant, and insert the guard immediately after the `binary_path.is_file()` check:

```python
PROBE_VERSION = "1.2"
```

```python
    tool = analyze_cmd[0] if analyze_cmd else ""
    if not tool or (shutil.which(tool) is None and not Path(tool).is_file()):
        result["reason"] = f"tool_absent:{tool}"
        return result
```

(`measured` stays `False` and `status` stays `could_not_measure` from the initialiser — the tool was never run, so nothing was measured.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -v --no-cov
```

Expected: PASS, including all four pre-existing tests.

- [ ] **Step 5: Format and commit**

```bash
black --line-length=100 scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py
isort scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py
git add scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py
git commit -m "feat(probe): distinguish tool_absent from analyze failure (probe v1.2)"
```

---

### Task 2: Probe v1.2 — capture a stderr tail so a nonzero exit is diagnosable

`hello_go` currently records `nonzero_exit:1` at ~0.03s. Thirty milliseconds is far too fast for analysis; it is an import/startup failure. The report keeps no evidence of *what* failed, so the number cannot be acted on. Capture a bounded tail.

**Files:**
- Modify: `scripts/probe_native_analyze_timeout.py` (`probe_one`)
- Test: `tests/unit/test_probe_native_analyze_timeout.py`

**Interfaces:**
- Consumes: `probe_one` from Task 1.
- Produces: every `probe_one` result dict carries key `stderr_tail: Optional[str]` — the last 2000 characters of the child's stderr on any executed run, `None` when the child never ran (`binary_absent`, `tool_absent`). Task 3 and Task 4 read this field.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_probe_native_analyze_timeout.py`:

```python
def test_probe_captures_stderr_tail_on_nonzero_exit(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        [sys.executable, "-c", "import sys; sys.stderr.write('BOOM-marker\\n'); raise SystemExit(1)"],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
    )
    assert out["status"] == "could_not_measure"
    assert "BOOM-marker" in (out["stderr_tail"] or "")


def test_probe_stderr_tail_is_none_when_child_never_ran(tmp_path: Path):
    out = probe_one(tmp_path / "nope", ["true"], timeout_s=1.0, now_iso="2026-08-06T00:00:00Z")
    assert out["stderr_tail"] is None
    assert out["reason"].startswith("binary_absent:")


def test_probe_stderr_tail_is_bounded(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        [sys.executable, "-c", "import sys; sys.stderr.write('z' * 50000); raise SystemExit(3)"],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
    )
    assert len(out["stderr_tail"]) == 2000
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -k stderr -v --no-cov
```

Expected: FAIL with `KeyError: 'stderr_tail'`.

- [ ] **Step 3: Implement the minimal change**

Add `"stderr_tail": None` to the `result` initialiser dict in `probe_one`, then after the `subprocess.run(...)` call assign it:

```python
        result["stderr_tail"] = (proc.stderr or "")[-2000:]
```

and inside the `except subprocess.TimeoutExpired as exc:` branch (widen the `except` to bind `exc`):

```python
        raw = exc.stderr or b""
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        result["stderr_tail"] = text[-2000:]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -v --no-cov
```

Expected: PASS, all tests including the Task 1 set.

- [ ] **Step 5: Format and commit**

```bash
black --line-length=100 scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py
isort scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py
git add scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py
git commit -m "feat(probe): capture bounded stderr tail so a nonzero exit is diagnosable"
```

---

### Task 3: R-HEX-1 / M2 — measured run, and an honest `tool_absent` record for hexyl

`hexyl` is not installed on this host. Wave A does **not** invent a hexyl result. It records the measurement it *can* make (the native fixtures) and records hexyl as `tool_absent` with the reason, so the M2 row stops reading as "unmeasured because nobody looked."

**Files:**
- Create: `docs/architecture/research-r-hex-1-hexyl-frontier-measurement.md`
- Regenerate: `reports/native_analyze_probe/latest.json` + one stamped sibling
- Test: `tests/unit/test_probe_native_analyze_timeout.py` (report-shape assertion)

**Interfaces:**
- Consumes: `probe_one` v1.2 (`tool_absent` reason, `stderr_tail`) from Tasks 1–2; `write_report(results, out_dir, now_iso) -> Path`.
- Produces: a report whose every entry carries `probe_version == "1.2"`; the doc `docs/architecture/research-r-hex-1-hexyl-frontier-measurement.md` cited by `backlog.md` in Task 10.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_probe_native_analyze_timeout.py`:

```python
def test_write_report_stamps_probe_version_1_2(tmp_path: Path):
    from scripts.probe_native_analyze_timeout import write_report
    import json as _json

    results = [probe_one(tmp_path / "nope", ["true"], 1.0, "2026-08-06T00:00:00Z")]
    latest = write_report(results, tmp_path / "out", "2026-08-06T00:00:00Z")
    payload = _json.loads(latest.read_text(encoding="utf-8"))
    assert payload["probe_version"] == "1.2"
    assert payload["results"][0]["probe_version"] == "1.2"
```

- [ ] **Step 2: Run the test to verify it fails, then passes**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -k probe_version -v --no-cov
```

Expected: PASS immediately (Task 1 bumped the constant; both call sites read `PROBE_VERSION`). If it FAILS, one call site hardcodes `"1.1"` — fix that literal, re-run, and note it in the doc.

- [ ] **Step 3: Run the real probe and the hexyl arm**

```bash
/usr/bin/python3.9 scripts/probe_native_analyze_timeout.py \
  --binary test_samples/native/hello_go/build/hello_go \
  --analyze-cmd "/usr/bin/python3.9 -m reveng analyze" \
  --timeout-s 120 ; echo "probe_rc=$?"

command -v hexyl || echo "hexyl-absent"

/usr/bin/python3.9 scripts/probe_native_analyze_timeout.py \
  --binary test_samples/native/hello_go/build/hello_go \
  --analyze-cmd "hexyl" \
  --timeout-s 120 \
  --out-dir reports/native_analyze_probe ; echo "hexyl_rc=$?"
# Prefer ONE multi-result invocation that includes hello_go + a hexyl tool_absent arm
# so latest.json holds both; commit latest.json + stamped sibling + README.
```

Expected: the first run exits 2 (`could_not_measure` present) and now carries a `stderr_tail`. The second records `reason: "tool_absent:hexyl"`, `measured: false`.

- [ ] **Step 4: Write the research doc**

Create `docs/architecture/research-r-hex-1-hexyl-frontier-measurement.md`:

```markdown
# R-HEX-1 — Hexyl frontier: what was actually measured (2026-08-06)

**Question:** Is the hexyl frontier still timeout-only?

**Answer: NOT MEASURED. `hexyl` is not installed on this host.** `command -v hexyl`
returns nothing; the probe records `status: could_not_measure`, `measured: false`,
`reason: tool_absent:hexyl`. This is a labelled zero, not a clean bill: it means the
instrument was never present, NOT that hexyl analysed fast, NOT that it timed out.

## What WAS measured

Probe v1.2, budget 120s, interpreter `/usr/bin/python3.9`:

| binary | status | reason | elapsed_s |
| --- | --- | --- | --- |
| `test_samples/native/hello_go/build/hello_go` | `could_not_measure` | `nonzero_exit:1` | <paste> |

Artifacts: `reports/native_analyze_probe/latest.json` (+ stamped sibling).
Root cause of the nonzero exit: see `diagnosis-hello-go-analyze-exit1.md`.

## Positive control

The probe's ability to return a non-`could_not_measure` verdict is proven by
`test_probe_records_completed_when_command_exits_zero` and
`test_probe_records_timeout_when_command_exceeds_budget`. Without those, an
all-`could_not_measure` report would be indistinguishable from a probe that never ran.

## Wave B exit criterion for M2

M2 stays `open`. It closes only when: hexyl is obtained (distro package or
`cargo install hexyl`, recorded with version + sha256), the probe records a
`completed` or `timeout` status for it at a stated budget, and the result is written
into a tracked report. Building hexyl is NOT authorized in Wave A.
```

Paste the real numbers from Step 3 into the table — no placeholders survive the commit.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/research-r-hex-1-hexyl-frontier-measurement.md \
        tests/unit/test_probe_native_analyze_timeout.py \
        reports/native_analyze_probe/latest.json \
        reports/native_analyze_probe/*.json \
        reports/native_analyze_probe/README.md
git commit -m "docs(r-hex-1): multi-result probe evidence incl. tool_absent:hexyl (R-HEX-1 stays open)"
```

---

### Task 4: Diagnose the `hello_go` analyze exit-1 (root-cause doc; fix only if trivial)

A 0.03s nonzero exit is a startup failure, not an analysis failure. This task finds out which, and writes it down. **Wave A is diagnosis-doc only — no `src/reveng/**` changes.** Any product fix is Wave B. Reconcile both historical exit-1 and later exit-0/`partial_success` observations; do not assert “startup failure” until stderr/semantic evidence says so.

**Files:**
- Create: `docs/architecture/diagnosis-hello-go-analyze-exit1.md`
- Modify (conditional, only if the root cause is trivial): the single file the diagnosis names
- Test (conditional): a regression test named in the doc

**Interfaces:**
- Consumes: `stderr_tail` from Task 2, the report from Task 3.
- Produces: a documented root cause consumed by `backlog.md` (Task 10) to reclassify `M1-NATIVE-FAM`'s blocking reason.

- [ ] **Step 1: Reproduce and capture the failure directly**

```bash
/usr/bin/python3.9 -m reveng analyze test_samples/native/hello_go/build/hello_go; echo "rc=$?"
/usr/bin/python3.9 -c "import reveng, sys; print(reveng.__file__, sys.version)"
```

Record both outputs verbatim. The second command discriminates the two leading hypotheses: **(a)** `reveng` is not importable by `/usr/bin/python3.9` at all (an environment gap — the package is installed for a different interpreter), versus **(b)** `reveng` imports fine and the CLI itself exits 1 (a product defect).

- [ ] **Step 2: Run the discriminating control**

```bash
/usr/bin/python3.9 -m reveng --help; echo "help_rc=$?"
```

If `--help` also exits nonzero in ~0.03s, the failure is at import/entry, not in `analyze`. If `--help` exits 0, the failure is inside the `analyze` path and the `stderr_tail` names it.

- [ ] **Step 3: Write the diagnosis doc**

Create `docs/architecture/diagnosis-hello-go-analyze-exit1.md` with these sections, all filled from Steps 1–2 (no hypotheses stated as fact):

```markdown
# Diagnosis — `hello_go` analyze exits 1 in ~0.03s (2026-08-06)

## Symptom
Probe v1.1 recorded `status: could_not_measure`, `reason: nonzero_exit:1`,
`elapsed_s: 0.0288` on `test_samples/native/hello_go/build/hello_go` under
`/usr/bin/python3.9 -m reveng analyze`.

## Evidence
- `python3.9 -m reveng analyze <bin>` → rc=<paste>, stderr:
  ```
  <paste verbatim>
  ```
- `python3.9 -c "import reveng"` → <paste>
- `python3.9 -m reveng --help` → rc=<paste>   ← the discriminating control

## Root cause
<one of: ENVIRONMENT (reveng not importable by the 3.9 dogfood interpreter) |
PRODUCT (named module/function, file:line)>

## Disposition
<either: "Environment — no product change. `M1-NATIVE-FAM` is blocked on an
install step, not on analyze capability; recorded in backlog.md." OR
"Product, trivial — one-line fix in <file:line>, regression test
<tests/unit/test_x.py::test_y>." OR "Product, non-trivial — Wave B row with exit
criterion: <criterion>.">

## What this does NOT establish
This diagnosis does not show that REVENG can analyze a Go binary. Even after the
exit-1 is resolved, `M1-NATIVE-FAM` requires a `completed` probe status within the
120s budget on ≥5 binaries across ≥3 families, without Ghidra. Fixture builds are
not analyze capability.
```

- [ ] **Step 4: If and only if the root cause is a trivial product defect — TDD the fix**

Write the failing regression test first at the path named in the doc, run it to confirm it fails for the documented reason, make the minimal change, re-run. If the root cause is environmental, or the fix exceeds two lines, **skip this step** and record the Wave B exit criterion in the doc instead. Do not open `src/reveng/**` otherwise.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/diagnosis-hello-go-analyze-exit1.md
# plus the fix + test paths ONLY if Step 4 ran:
# git add src/reveng/<named-file>.py tests/unit/<named-test>.py
git commit -m "docs(native): root-cause hello_go analyze exit-1 with discriminating control"
```

---

### Task 5: R-RALPH-2 — measure the current recall baseline before proposing any wedge

The backlog says "engine long pole." Wave A does not touch the engine. It measures where recall actually sits today, so Wave B's target is a delta from a number rather than from a guess.

**Files:**
- Create: `docs/architecture/research-r-ralph-2-recall-baseline.md`
- Reads: `scripts/ralph_js_oracle_loop.py`, `examples/use-cases/js-oracle-ralph/`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: a stated baseline recall figure (or a labelled `could_not_measure`) cited by `backlog.md` (Task 10) and by `wave-b-exit-criteria.md` (Task 10).

- [ ] **Step 1: Locate the harness entry point and its scoring function**

```bash
/usr/bin/python3.9 scripts/ralph_js_oracle_loop.py --help; echo "rc=$?"
grep -rn "recall" scripts/ralph_js_oracle_loop.py | head -30
```

Record the exact flag names and the function that computes recall. Do not guess flags — a plan that names a flag the CLI does not have produces a false red.

- [ ] **Step 2: Run the baseline measurement**

Using the flags discovered in Step 1, run the harness against the tracked `cli.js` case and capture the recall number, the corpus size, and the wall clock. If the run cannot complete (missing corpus, missing dependency, nonzero exit), record `could_not_measure` **with the reason and the command** — that is a valid Wave A outcome and it is the honest one.

- [ ] **Step 3: Write the research doc**

Create `docs/architecture/research-r-ralph-2-recall-baseline.md`:

```markdown
# R-RALPH-2 — Recall baseline before any engine wedge (2026-08-06)

**Question:** What is the smallest engine wedge that reaches 0.8+ recall on `cli.js`?
**Wave A answer:** Not decidable without a baseline. This doc supplies the baseline only.

## Measured baseline
- Command: `<verbatim from Step 2>`
- Corpus / target: `<path>`
- Recall: `<number>` OR `could_not_measure` — reason: `<verbatim>`
- Wall clock: `<s>`
- Interpreter: `/usr/bin/python3.9`

## Gap to target
0.8 − <baseline> = <delta>. If the baseline is `could_not_measure`, the gap is
UNKNOWN and no wedge may be scoped against it.

## Candidate wedges (unranked, unbuilt)
1. <candidate>, expected to move <which recall component>, evidence: <file:line>
2. <candidate>, ...
3. <candidate>, ...
Each candidate names the file it would touch. None is authorized in Wave A.

## Wave B exit criterion for RALPH-2
RALPH-2 closes only when the harness reports recall ≥ 0.8 on the tracked `cli.js`
case in a committed report, produced by the same command recorded above.
The 0.8 engine rewrite is explicitly NOT in Wave A.
```

- [ ] **Step 4: Verify the doc contains no unfilled placeholder**

```bash
grep -nE "<paste>|<number>|TBD|TODO" docs/architecture/research-r-ralph-2-recall-baseline.md; echo "rc=$?"
```

Expected: no matches (grep rc=1). A match means the doc still carries a template hole — fill it.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/research-r-ralph-2-recall-baseline.md
git commit -m "docs(r-ralph-2): record measured recall baseline and unbuilt wedge candidates"
```

---

### Task 6: R-PIPE-1 — decide `pipeline` vs `pipelines`

**Files:**
- Create: `docs/architecture/decision-r-pipe-1-pipeline-packages.md`
- Reads: `src/reveng/pipeline/`, `src/reveng/pipelines/`, `.importlinter`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: a `MERGE` or `PERMANENT SPLIT` verdict cited by `backlog.md` (Task 10) for the `M5-PIPE` row.

- [ ] **Step 1: Measure the two packages before deciding**

```bash
find src/reveng/pipeline src/reveng/pipelines -name '*.py' | wc -l
grep -rn "from reveng.pipeline import\|from reveng.pipeline\." src/ tests/ | wc -l
grep -rn "from reveng.pipelines import\|from reveng.pipelines\." src/ tests/ | wc -l
grep -rn "pipeline" .importlinter
```

Record all four numbers. A merge decision made without fan-in counts is a preference, not a decision.

- [ ] **Step 2: Confirm the architecture contracts currently pass**

```bash
lint-imports --no-cache; echo "rc=$?"
```

Record the result. If it fails on `main` before any change, say so — a pre-existing red is not caused by this decision.

- [ ] **Step 3: Write the decision doc**

Create `docs/architecture/decision-r-pipe-1-pipeline-packages.md`:

```markdown
# R-PIPE-1 — `reveng.pipeline` vs `reveng.pipelines` (2026-08-06)

## Measured state
| package | module count | import sites (src+tests) |
| --- | --- | --- |
| `reveng.pipeline` | <n> | <n> |
| `reveng.pipelines` | <n> | <n> |

Import-linter contracts referencing either package: <paste or "none">.
`lint-imports --no-cache` at plan time: <rc + summary>.

## Decision
**<MERGE | PERMANENT SPLIT>** — because <reason grounded in the numbers above>.

## Consequences
- If MERGE: the migration is a Wave B row. Mechanics: `sys.modules` alias shims at
  every old path (≤6 lines each), one independently-shippable slice at a time, an
  import-linter contract added to make the direction permanent. Not started in Wave A.
- If PERMANENT SPLIT: the responsibility boundary is <one sentence>, and an
  import-linter contract is added in Wave B to lock it so the split cannot silently rot.

## Exit criterion for M5-PIPE
Closes when the chosen path is implemented AND `lint-imports --no-cache` passes with
the new contract present. Wave A closes the *research* row R-PIPE-1 only; `M5-PIPE`
stays `partial` until then.
```

- [ ] **Step 4: Verify no placeholders remain**

```bash
grep -nE "<n>|<paste|TBD|TODO" docs/architecture/decision-r-pipe-1-pipeline-packages.md; echo "rc=$?"
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/decision-r-pipe-1-pipeline-packages.md
git commit -m "docs(r-pipe-1): decide pipeline package split from measured fan-in"
```

---

### Task 7: R-SEC-1 — sandbox class required before any exploit expansion (decision doc only)

**Files:**
- Create: `docs/architecture/decision-r-sec-1-sandbox-class.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the gate condition cited by `backlog.md` (Task 10) for the `R-SEC-1` row and by Phase 10 / Track J in `wave-b-exit-criteria.md`.

**Hard constraint for this task:** no code. No new exploit capability, no change to the `SEC-EXP-1` EXPERIMENTAL watermark, no relaxation of any existing guard. This task produces one document.

- [ ] **Step 1: Inventory the current exploit surface without changing it**

```bash
grep -rn "EXPERIMENTAL" src/reveng/exploits/ | head -20
ls src/reveng/exploits/
```

Record what exists and how it is currently gated.

- [ ] **Step 2: Write the decision doc**

Create `docs/architecture/decision-r-sec-1-sandbox-class.md`:

```markdown
# R-SEC-1 — Sandbox class required before exploit expansion (2026-08-06)

**Status: DECISION ONLY. No exploit capability is added, expanded, or ungated by
this document or by Wave A.**

## Current surface (measured, not changed)
<paste the inventory from Step 1: files + how each is watermarked EXPERIMENTAL>

## Required sandbox class
Before ANY exploit-surface expansion, the execution environment must provide, and a
test must PROVE for each:
1. **Process isolation** — untrusted payload execution cannot touch the host FS
   outside a scratch dir. Proof: a canary file outside the scratch dir survives a
   deliberate write attempt, AND the same attempt inside the scratch dir succeeds
   (bidirectional — a probe that reports DENIED for everything proves nothing).
2. **Network egress denial by default** — proof: an outbound connect fails with a
   specific errno, and a control connect from outside the sandbox succeeds.
3. **Wall-clock and memory caps** — proof: a deliberate infinite loop is killed at
   the stated budget, and a short job under the budget completes.
4. **No host credential inheritance** — proof: env/credential paths are absent
   inside, present outside.

Each proof must FAIL in the control arm. A check that passes in both arms is broken.

## Decision
Exploit surfaces remain **EXPERIMENTAL / non-GA** until all four proofs land as
tests. Phase 10 / Track J is gated on this document's criteria, not on a date.

## Explicitly out of scope for Wave A
Building the sandbox, expanding exploit generation, changing any watermark.
```

- [ ] **Step 3: Verify the exploit surface is genuinely unchanged**

```bash
git diff --name-only -- src/reveng/exploits/; echo "rc=$?"
```

Expected: empty output. Any file listed means this task violated its own constraint — revert it.

- [ ] **Step 4: Verify no placeholder remains**

```bash
grep -nE "<paste|TBD|TODO" docs/architecture/decision-r-sec-1-sandbox-class.md; echo "rc=$?"
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add docs/architecture/decision-r-sec-1-sandbox-class.md
git commit -m "docs(r-sec-1): define sandbox class gating any exploit expansion"
```

---

### Task 8: R-VRL-1 — minimum seeds + provider for an honest VRL LLM gate

**Files:**
- Create: `docs/architecture/decision-r-vrl-1-seeds-and-provider.md`
- Reads: `scripts/run_vrl.py`, `.reveng/benchmarks/corpus.yaml`

**Interfaces:**
- Consumes: nothing.
- Produces: a stated minimum seed count and a provider choice cited by `backlog.md` (Task 10) for Phase 4.

- [ ] **Step 1: Measure the current corpus and provider wiring**

```bash
/usr/bin/python3.9 scripts/run_vrl.py --help; echo "rc=$?"
grep -rn "REVENG_AI_PROVIDER" scripts/run_vrl.py src/reveng/ | head -20
/usr/bin/python3.9 - <<'PY'
import pathlib, yaml
p = pathlib.Path(".reveng/benchmarks/corpus.yaml")
print("exists:", p.exists())
if p.exists():
    d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    print("top-level keys:", list(d)[:10])
PY
```

Record the real flags, the providers actually wired, and whether the corpus file exists. If it does not exist, that is the finding — say so rather than describing a corpus that isn't there.

- [ ] **Step 2: Write the decision doc**

Create `docs/architecture/decision-r-vrl-1-seeds-and-provider.md`:

```markdown
# R-VRL-1 — Minimum seeds and provider for an honest VRL LLM gate (2026-08-06)

## Measured state
- `scripts/run_vrl.py` flags: <verbatim from --help>
- Providers wired via `REVENG_AI_PROVIDER`: <list, file:line for each>
- `.reveng/benchmarks/corpus.yaml`: <exists? top-level keys, seed count>

## Decision
- **Minimum seeds per case: <n>** — chosen because a single seed cannot separate a
  real convergence from a lucky draw; <n> is the smallest count that lets a
  disagreement between seeds be visible in the recorded `ValidationGrade`.
- **Provider for the gate: <ollama | anthropic | openai>** — because <reason:
  cost, determinism, availability on the dogfood host>. The oracle passes corpus
  seed tokens as **argv**, not stdin (existing contract — do not change it).

## What makes the gate HONEST
1. Every run records a real `ValidationGrade` into `.reveng/benchmarks/corpus.yaml`.
   A run that produced no grade is `could_not_measure`, never a pass.
2. A no-LLM control arm must FAIL the gate. If the gate passes with the provider
   disabled, the gate is measuring something else and must not be trusted.
3. Provider identity is recorded per run. A number attributed to the wrong provider
   is worse than no number.

## Exit criterion for Phase 4 (VRL half)
Phase 4's VRL half closes when <n> seeds × the tracked corpus produce recorded
grades under the chosen provider, with the no-LLM control arm failing. Not in Wave A.
```

- [ ] **Step 3: Verify no placeholder remains**

```bash
grep -nE "<n>|<verbatim|<list|TBD|TODO" docs/architecture/decision-r-vrl-1-seeds-and-provider.md; echo "rc=$?"
```

Expected: no matches.

- [ ] **Step 4: Commit**

```bash
git add docs/architecture/decision-r-vrl-1-seeds-and-provider.md
git commit -m "docs(r-vrl-1): fix minimum seeds and provider for an honest VRL gate"
```

---

### Task 9: DF-4 ops fix + M0 evidence-dir hygiene

Two small, independently testable ops closures in one task because they share the same deliverable surface (the reports tree): a scoped git-status script that cannot hang on DrvFS, and a test that stops `reports/native_analyze_probe/` from keeping a stamp that no longer matches `latest.json`.

**Files:**
- Create: `scripts/git_status_scoped.sh`
- Create: `tests/unit/test_git_status_scoped.py`
- Create: `tests/unit/test_evidence_dir_hygiene.py`

**Interfaces:**
- Consumes: `write_report` output layout from Tasks 1–3 (`latest.json` + `<stamp>.json` siblings).
- Produces: `scripts/git_status_scoped.sh` (no args; prints porcelain status excluding `reports/` and `analysis_*/`); two test modules cited by `backlog.md` (Task 10) for rows DF-4 and M0.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_git_status_scoped.py`:

```python
"""DF-4: a scoped status must never issue a bare `git status`."""

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "git_status_scoped.sh"


def test_script_exists():
    assert SCRIPT.is_file()


def test_script_excludes_reports_and_analysis_trees():
    text = SCRIPT.read_text(encoding="utf-8")
    assert ":(exclude)reports/" in text
    assert ":(exclude)analysis_*" in text


def test_script_never_runs_a_bare_git_status():
    lines = [
        ln.strip()
        for ln in SCRIPT.read_text(encoding="utf-8").splitlines()
        if ln.strip().startswith("git status")
    ]
    assert lines, "expected at least one git status invocation"
    for line in lines:
        assert "--" in line, f"unscoped git status would hang on DrvFS: {line}"
```

Create `tests/unit/test_evidence_dir_hygiene.py`:

```python
"""M0: an evidence dir must not keep a latest.json that no stamp corroborates."""

import json
from pathlib import Path

import pytest

PROBE_DIR = Path(__file__).resolve().parents[2] / "reports" / "native_analyze_probe"


def _stamps():
    return sorted(p for p in PROBE_DIR.glob("*.json") if p.name != "latest.json")


def test_probe_dir_exists():
    assert PROBE_DIR.is_dir()


def test_latest_json_is_byte_identical_to_a_stamped_sibling():
    latest = PROBE_DIR / "latest.json"
    if not latest.is_file():
        pytest.skip("no probe run recorded yet")
    stamps = _stamps()
    assert stamps, "latest.json with no stamped sibling is an orphan stamp"
    latest_text = latest.read_text(encoding="utf-8")
    assert any(
        s.read_text(encoding="utf-8") == latest_text for s in stamps
    ), "latest.json matches no stamped run — it is a lying stamp"


def test_every_result_carries_a_reason_when_not_completed():
    latest = PROBE_DIR / "latest.json"
    if not latest.is_file():
        pytest.skip("no probe run recorded yet")
    payload = json.loads(latest.read_text(encoding="utf-8"))
    for result in payload["results"]:
        if result["status"] != "completed":
            assert result["reason"], f"unlabelled non-completed status: {result}"
```

- [ ] **Step 2: Run both test modules to verify they fail**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_git_status_scoped.py tests/unit/test_evidence_dir_hygiene.py -v --no-cov
```

Expected: `test_git_status_scoped.py` FAILS at `test_script_exists`. `test_evidence_dir_hygiene.py` should PASS if Task 3 regenerated the reports correctly — if `test_latest_json_is_byte_identical_to_a_stamped_sibling` FAILS, the evidence dir is currently carrying a lying stamp; delete the orphan `latest.json` and re-run the Task 3 probe rather than editing the test.

- [ ] **Step 3: Write the script**

Create `scripts/git_status_scoped.sh`:

```bash
#!/usr/bin/env bash
# DF-4: a repo-wide `git status` hangs on the dirty reports/ tree over DrvFS.
# Always scope with pathspec exclusions; never run a bare status here.
set -euo pipefail

git status --porcelain -- \
  ':(exclude)reports/' \
  ':(exclude)analysis_*' \
  ':(exclude)external/ghidra*' \
  .
```

Then: `chmod +x scripts/git_status_scoped.sh`

- [ ] **Step 4: Run the tests and the script**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_git_status_scoped.py tests/unit/test_evidence_dir_hygiene.py -v --no-cov
bash scripts/git_status_scoped.sh | head -20; echo "rc=$?"
```

Expected: all tests PASS; the script returns promptly with a bounded list.

- [ ] **Step 5: Commit**

```bash
git add scripts/git_status_scoped.sh tests/unit/test_git_status_scoped.py tests/unit/test_evidence_dir_hygiene.py
git commit -m "fix(ops): scoped git status for DrvFS (DF-4) and evidence-dir hygiene tests (M0)"
```

---

### Task 10: Dogfood `verify_ga_readiness`, then reconcile `backlog.md` and publish Wave B exit criteria

The final task. A green gate is not proof — record the tracked evidence fields beside it, then update every row this wave touched.

**Files:**
- Create: `docs/architecture/dogfood-verify-ga-readiness-2026-08-06.md`
- Create: `docs/architecture/wave-b-exit-criteria.md`
- Modify: `backlog.md`

**Interfaces:**
- Consumes: every doc and test produced by Tasks 1–9, by exact filename.
- Produces: the reconciled backlog. No later task depends on it.

- [ ] **Step 1: Run the readiness gate under the dogfood interpreter and record the evidence fields**

```bash
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile baseline; echo "baseline_rc=$?"
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile ga; echo "ga_rc=$?"
/usr/bin/python3.9 -m pytest tests/unit/test_verify_ga_readiness.py -v --no-cov
```

Capture the exit code **and** the tracked report fields the gate consulted (which reports it read, which evidence fields it required, which were present). A gate that passes because it read nothing is a false green.

- [ ] **Step 2: Write the dogfood record**

Create `docs/architecture/dogfood-verify-ga-readiness-2026-08-06.md`:

```markdown
# Dogfood — `verify_ga_readiness` under Python 3.9 (2026-08-06)

- Baseline command: `/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile baseline`
- Baseline exit code: <rc>
- GA command: `/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile ga`
- GA exit code: <rc>
- Reports consulted (per profile): <paths>
- Evidence fields required and their observed values (per profile): <list>
- Unit gate: `tests/unit/test_verify_ga_readiness.py` → <passed/failed, counts>
- Neither profile proves native analyze capability.

## What this does and does not prove
A zero exit proves the gate's own conditions were met on the tracked reports listed
above. It does NOT prove native analyze capability, exploit safety, or any phase
completion. `M1-NATIVE-FAM` remains open; native fixtures remain `required: false`.
```

- [ ] **Step 3: Write the Wave B exit criteria**

Create `docs/architecture/wave-b-exit-criteria.md`:

```markdown
# Wave B — research-gated queue with exit criteria (post 2026-08-06)

Nothing below is started, scoped, or claimed in Wave A. Each row closes only on its
stated criterion, verified against a tracked artifact.

| id | criterion to close | gating doc |
| --- | --- | --- |
| M2 (hexyl) | hexyl obtained with recorded version+sha256; probe records `completed` or `timeout` at a stated budget in a tracked report | `research-r-hex-1-hexyl-frontier-measurement.md` |
| RALPH-2 | harness reports recall ≥ 0.8 on the tracked `cli.js` case, same command as the recorded baseline | `research-r-ralph-2-recall-baseline.md` |
| M5-PIPE | chosen path implemented AND `lint-imports --no-cache` green with the new contract present | `decision-r-pipe-1-pipeline-packages.md` |
| Phase 4 (VRL) | N seeds × tracked corpus produce recorded `ValidationGrade`s under the chosen provider, with the no-LLM control arm FAILING | `decision-r-vrl-1-seeds-and-provider.md` |
| Phase 10 / Track J | all four sandbox proofs land as tests, each failing in its control arm | `decision-r-sec-1-sandbox-class.md` |
| M1-NATIVE-FAM | probe status `completed` within 120s on ≥5 binaries across ≥3 families without Ghidra, then fixtures flipped to `required: true` | `diagnosis-hello-go-analyze-exit1.md` |
| Phases 5–13 | not scoped; each needs its own plan | — |

Parked (`T3-KERNEL`, `T3-PACKED`, `T3-JIT`, `T3-ANTI`, `T3-GUI`) stay parked and are
not Wave B candidates.
```

- [ ] **Step 4: Reconcile `backlog.md`**

Apply exactly these edits to `backlog.md`, each citing the artifact that justifies it:

1. **Section D, `R-HEX-1`** → status **`open` / `blocked`** (NOT done). Notes cite measurement doc + `tool_absent:hexyl` evidence path; hexyl timed run still required before any done claim.
2. **Section D:** add **`R-RALPH-2-BASELINE`** → `done` citing `research-r-ralph-2-recall-baseline.md`. Keep **`R-RALPH-2`** → `open` until smallest 0.8+ wedge is identified (research) and later implemented (Wave B).
3. **Section D, `R-PIPE-1`** → `done (decision recorded)`, cite `decision-r-pipe-1-pipeline-packages.md`. `M5-PIPE` in section C stays `partial`.
4. **Section D, `R-SEC-1`** → `done (decision recorded)`, cite `decision-r-sec-1-sandbox-class.md`. Add "no exploit expansion in this wave."
5. **Section D, `R-VRL-1`** → `done (decision recorded)`, cite `decision-r-vrl-1-seeds-and-provider.md`. Phase 4 stays `open`.
6. **Section H, `DF-4`** → `done (ops)`, cite `scripts/git_status_scoped.sh` + `tests/unit/test_git_status_scoped.py`.
7. **Section C, `M0`** → `partial`, notes cite `tests/unit/test_evidence_dir_hygiene.py` and probe v1.2 (`tool_absent` + `stderr_tail`). It is not `done`: CI enforcement of the hygiene tests is a Wave B item.
8. **Section C, `M1-NATIVE-FAM`** → stays `open`; replace the notes with the *diagnosed* blocking reason from `diagnosis-hello-go-analyze-exit1.md`. Do not flip `required`.
9. **Section C, `M2`** → stays `open`; note "blocked on hexyl availability, see Wave B exit criteria."
10. **Section E** → unchanged. Phases 4–13 stay `open`.
11. **Section G** → unchanged. All five T3 rows stay `parked`.
12. Add a **Section I** decision row: `| 2026-08-06 | Wave A closes research/ops/docs rows only; product wedges deferred to Wave B with exit criteria (docs/architecture/wave-b-exit-criteria.md) |`
13. Update the header links block to include `wave-b-exit-criteria.md`.

- [ ] **Step 5: Verify the reconciliation is honest, then commit**

```bash
grep -nE "M1-NATIVE-FAM|M2 \||T3-" backlog.md
grep -c "parked" backlog.md   # expect >= 5
/usr/bin/python3.9 -m pytest tests/unit/test_evidence_dir_hygiene.py tests/unit/test_git_status_scoped.py tests/unit/test_probe_native_analyze_timeout.py tests/unit/test_verify_ga_readiness.py -v --no-cov
bash scripts/git_status_scoped.sh
```

Expected: `M1-NATIVE-FAM` still `open`, `M2` still `open`, five `parked` rows intact, all four test modules PASS.

```bash
git add backlog.md \
        docs/architecture/dogfood-verify-ga-readiness-2026-08-06.md \
        docs/architecture/wave-b-exit-criteria.md
git commit -m "docs(backlog): reconcile Wave A closures and publish Wave B exit criteria"
```

---

## Wave B (not this plan — recorded so nothing is silently dropped)

Every row below is research-gated with its criterion in `docs/architecture/wave-b-exit-criteria.md`: RALPH-2 engine wedge, hexyl frontier hardening (M2), VRL LLM gate (Phase 4), `M1-NATIVE-FAM` closure, `M5-PIPE` migration, M4 CI corpus gates, phases 5–13. Each needs its own plan. None is scoped, started, or claimed here.

## Sol-mandated acceptance tests (Wave A gate)

Add (fail-first) before claiming Wave A complete:

1. `tests/unit/test_backlog_wave_a_invariants.py`
   - `M1-NATIVE-FAM` still `open`
   - ≥5 `parked` T3 rows
   - `R-HEX-1` line must NOT contain status `done` (blocked/open only until hexyl timed)
   - `R-RALPH-2-BASELINE` may be `done`; section C `RALPH-2` and section D `R-RALPH-2` (exact id, not substring of BASELINE) stay `open` until wedge identified+implemented
2. Probe report shape: every result has `probe_version`, three-valued `status`, `stderr_tail` key (may be null), and when `status=="completed"` also `stdout_tail` (bounded) plus diagnosis/dogfood recording whether analyze report / native fallback evidence was present or empty — process completion ≠ native GA. Unit test asserts these keys exist on completed fixtures.
3. Evidence hygiene: if `reports/native_analyze_probe/latest.json` exists, a stamped sibling with identical payload bytes (or identical results hash) must exist; FAIL if latest alone.
4. `git_status_scoped`: temp git repo with dirty `reports/huge.bin` must not list it; dirty tracked-path file must list it.
5. Probe README documents stderr/stdout tail redaction (no secrets in tracked reports).

