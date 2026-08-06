# Scope C Phase-Native-Fixtures Implementation Plan

## Goal

Land the **smallest honest slice** that moves M1-NATIVE-FAM from "inventory only" toward "measured", plus the R-HEX-1 timeout probe, without claiming any native GA capability we have not measured.

Concretely, after this phase:

1. Two hermetic native micro-CLI fixtures exist and build from source in-repo: one **C** (`hello_c`) and one **Go** (`hello_go`), each supporting `--help` and `--version` with byte-stable output.
2. Those fixtures are registered in the source↔binary benchmark manifest with `required: false` and an explicit `status` note recording *why* they are not gating (analyze path not proven hermetic without Ghidra).
3. A bounded-timeout probe script records, as tracked evidence JSON under `reports/`, whether `reveng analyze` on a native ELF (hexyl and/or our fixtures) completes or times out — **recording the timeout, not fixing it**.
4. `docs/BACKLOG.md` reflects the true state of M1-NATIVE-FAM, R-HEX-1, and M0 report discipline after this slice.

**Explicit non-goal:** no claim that native family analysis is GA, works, or is corpus-verified. If the probe times out, the evidence file says `status: "timeout"` and the manifest entry stays `required: false`. We ship the measurement, not a green light.

## Architecture

Three thin layers, each independently revertable:

```
test_samples/native/
  hello_c/      hello.c        + Makefile   -> build/hello_c        (cc, C99, no libs beyond libc)
  hello_go/     main.go        + go.mod     -> build/hello_go       (CGO_ENABLED=0, static)
  README.md                                  (what these are, what they are NOT)

src/reveng/... (unchanged this phase — fixtures are data, not product code)

scripts/probe_native_analyze_timeout.py
  -> subprocess reveng analyze <binary> with hard timeout
  -> writes reports/native_analyze_probe/<utc-stamp>.json  (+ latest.json symlink-free copy)
  -> exit 0 on MEASURED (either completed or timed out); exit 2 on COULD-NOT-MEASURE

.reveng/source_binary_benchmarks.ga.json
  -> two new entries, required=false, status="fixture_only", evidence_ref -> probe path
```

**Honesty seam.** The probe distinguishes three outcomes and never collapses them:

| outcome | meaning | JSON `status` |
|---|---|---|
| analyze returned 0 within budget | measured success | `"completed"` |
| analyze exceeded the wall budget | measured timeout — a real, reportable finding | `"timeout"` |
| binary missing / toolchain absent / exec failed | **did not measure** | `"could_not_measure"` |

The third case must never read as either of the first two. `could_not_measure` carries `reason` and exits **2** (integer, per the `SystemExit("2: …")` trap — always `raise SystemExit(2)`).

**Fixture build discipline.** Fixtures build via `make -C test_samples/native` and are **gitignored as artifacts** — only sources are tracked. Tests skip (not fail) when `cc`/`go` are absent, and the skip reason is asserted in a meta-test so a silently-skipped suite is distinguishable from a passing one.

## Tech Stack

- Python **3.9** (`/usr/bin/python3.9`) — dogfood target, per `.claude/rules/development.md`.
- pytest, no coverage for these runs (`--no-cov`).
- `cc` (any C99 compiler on PATH) and `go` (>= 1.20) — both optional at test time, required at fixture-build time.
- `subprocess.run(..., timeout=...)` for the bounded probe; no threads, no signals.
- `json` for evidence; UTC ISO-8601 timestamps passed in explicitly, never inferred mid-assert.
- black/isort at 100 cols; import-linter unaffected (no new `src/reveng` imports).

## Global Constraints

1. **No hollow GA claims.** No file added or edited in this phase may state that native analysis works, is supported, or is GA. Every new manifest entry carries `required: false` and a `status` string naming the gap.
2. **Bidirectional oracle on every check.** Every test asserting "the probe reports X" must have a sibling arm proving it reports **not-X** under the opposite input. A probe test with only a green arm is rejected in self-review.
3. **A zero is labelled.** Any count the probe emits (functions found, sections parsed) is accompanied by `measured: true|false`. An empty result from a run that never executed must be `could_not_measure`, never `0`.
4. **Python 3.9 syntax only.** No `match`, no `X | Y` type unions, no `dict[str, int]` in annotations evaluated at runtime — use `typing.Dict` / `Optional`.
5. **Named-path git commits.** `git add <explicit paths>` then commit; never `git add -A`, never `git stash` (parallel worktrees share the stash drawer).
6. **No repo-wide `git status`** over `reports/`; scope to the paths touched.
7. **Bounded time.** The probe's default budget is 120 s per binary and is a CLI flag; no unbounded Ghidra campaigns. Total added test wall-clock target: < 30 s with toolchains present.
8. **Excluded from this phase:** RALPH-2 engine work, exploit-surface expansion, full pipeline merge, any multi-hour Ghidra run, any change to `src/reveng/analysis/native/`.

---

## Tasks

### Task 1 — Hermetic C micro-CLI fixture

- [ ] **RED.** Create `tests/unit/test_native_fixtures.py` with `test_hello_c_help_and_version_are_byte_stable`, which builds nothing itself: it locates `test_samples/native/hello_c/build/hello_c`, and if absent **skips with a reason string containing `"run: make -C test_samples/native"`**. When present, it runs `--help` and `--version` and asserts exact expected stdout and exit 0. Run it now and confirm it **fails or skips for the stated reason** — a skip here is acceptable RED only if Task 1's meta-test (below) proves the skip path is reachable and labelled.

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py -k hello_c -v --no-cov
  ```

- [ ] Add `test_native_fixture_skip_reason_is_actionable`: monkeypatch the locator to return a nonexistent path and assert the skip reason names the make command. This is the **positive control that the skip branch exists and is labelled** — without it, an all-skipped suite reads as green.

- [ ] **GREEN.** Write `test_samples/native/hello_c/hello.c`:
  - `--help` prints a fixed 3-line usage block, exit 0.
  - `--version` prints exactly `hello_c 1.0.0\n`, exit 0.
  - Unknown arg prints usage to stderr, exit 2.
  - C99, `#include <stdio.h>` / `<string.h>` only. No timestamps, no `__DATE__`, no locale-dependent output — byte-stability is the point.

- [ ] Write `test_samples/native/Makefile` with targets `all`, `hello_c`, `hello_go`, `clean`. `hello_c` rule: `cc -std=c99 -O0 -g -o hello_c/build/hello_c hello_c/hello.c`. `-O0 -g` deliberately — this fixture exists to be *analyzed*, so keep symbols.

- [ ] Add `test_samples/native/*/build/` to `.gitignore` (append, do not rewrite the file).

- [ ] Build and re-run:

  ```bash
  make -C test_samples/native hello_c
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py -k hello_c -v --no-cov
  ```

- [ ] **Verify the control fails.** Temporarily change the expected version string in the test to `1.0.1`, re-run, confirm RED, revert, confirm GREEN and the file is byte-identical (`git diff --exit-code tests/unit/test_native_fixtures.py`).

- [ ] Commit: `git add test_samples/native/hello_c/hello.c test_samples/native/Makefile tests/unit/test_native_fixtures.py .gitignore && git commit -m "test(native): add hermetic C micro-CLI fixture with byte-stable --help/--version"`

### Task 2 — Hermetic Go micro-CLI fixture

- [ ] **RED.** Extend `tests/unit/test_native_fixtures.py` with `test_hello_go_help_and_version_are_byte_stable`, same shape as Task 1 (skip-with-actionable-reason when `test_samples/native/hello_go/build/hello_go` is absent).

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py -k hello_go -v --no-cov
  ```

- [ ] **GREEN.** Write `test_samples/native/hello_go/main.go` and `test_samples/native/hello_go/go.mod` (`module revengfixtures/hellogo`, `go 1.20`).
  - Same three behaviors as the C fixture, with `hello_go 1.0.0` as the version line.
  - Hand-rolled `os.Args` parsing, **not** `flag` — `flag`'s auto-generated usage is Go-version-dependent and would break byte-stability across toolchains.
  - No imports beyond `fmt` and `os`.

- [ ] Add the Makefile rule: `cd hello_go && CGO_ENABLED=0 go build -trimpath -o build/hello_go .` — `CGO_ENABLED=0` for a static binary, `-trimpath` so the build path does not leak into the binary and change its bytes per-machine.

- [ ] Build and re-run:

  ```bash
  make -C test_samples/native hello_go
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py -v --no-cov
  ```

- [ ] Write `test_samples/native/README.md`. It must state in plain text: *these are analysis fixtures, not a demonstration that REVENG analyzes native binaries; no GA claim attaches to their presence; the measured status lives in `reports/native_analyze_probe/`.* Enumerating that here is the artifact-side honesty record — a claim corrected only in a commit message is not corrected.

- [ ] Commit: `git add test_samples/native/hello_go/main.go test_samples/native/hello_go/go.mod test_samples/native/Makefile test_samples/native/README.md tests/unit/test_native_fixtures.py && git commit -m "test(native): add hermetic Go micro-CLI fixture (CGO_ENABLED=0, trimpath)"`

### Task 3 — Bounded-timeout native analyze probe (R-HEX-1)

- [ ] **RED.** Create `tests/unit/test_probe_native_analyze_timeout.py` with four arms, all against a **fake analyze command** injected via the probe's `analyze_cmd` parameter (no real `reveng analyze` in unit tests):
  - `test_probe_records_completed_when_command_exits_zero` — fake cmd `["true"]` → `status == "completed"`.
  - `test_probe_records_timeout_when_command_exceeds_budget` — fake cmd `[sys.executable, "-c", "import time; time.sleep(5)"]`, budget `0.5` → `status == "timeout"`, and `timeout_budget_s == 0.5` is recorded in the JSON.
  - `test_probe_records_could_not_measure_when_binary_absent` — target path does not exist → `status == "could_not_measure"`, `reason` contains the path.
  - `test_could_not_measure_exits_two` — assert the CLI wrapper `raise SystemExit(2)` yields returncode **2**, not 1. This tests the *premise* (a non-integer `SystemExit` argument exits 1), so the guard is not one Python release from decorative.

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -v --no-cov
  ```

- [ ] **GREEN.** Write `scripts/probe_native_analyze_timeout.py`:
  - `probe_one(binary_path, analyze_cmd, timeout_s, now_iso) -> Dict[str, Any]` — pure-ish, takes the clock in as a parameter so tests pin it.
  - Returned dict fields: `binary`, `binary_sha256`, `binary_size_bytes`, `analyze_cmd`, `timeout_budget_s`, `elapsed_s`, `status` (one of the three), `returncode` (nullable), `reason` (nullable), `measured` (bool), `probe_version`, `recorded_at_utc`.
  - `main(argv)` — argparse with `--binary` (repeatable), `--timeout-s` (default 120.0), `--out-dir` (default `reports/native_analyze_probe`), `--analyze-cmd` (default `["reveng", "analyze"]`).
  - Writes one JSON file per run: `reports/native_analyze_probe/<recorded_at_utc>.json` containing `{"probe_version": ..., "results": [...]}`, plus a copy at `reports/native_analyze_probe/latest.json` (a real copy, not a symlink — DrvFS).
  - Exit code: **0** if every target produced `completed` or `timeout` (i.e. we measured something, even a bad something); **2** if any target is `could_not_measure`. A timeout is a successful measurement and must not exit non-zero — conflating "the tool is slow" with "the probe broke" is the exact false-signal this phase exists to avoid.
  - Never writes into `src/`; never mutates the manifest.

- [ ] Re-run the unit suite to GREEN:

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_probe_native_analyze_timeout.py -v --no-cov
  ```

- [ ] **Dogfood it for real, once**, against the two new fixtures and hexyl if present, with a short budget so this cannot become a multi-hour run:

  ```bash
  /usr/bin/python3.9 scripts/probe_native_analyze_timeout.py \
    --binary test_samples/native/hello_c/build/hello_c \
    --binary test_samples/native/hello_go/build/hello_go \
    --timeout-s 120 ; echo "probe exit: $?"
  ```

  Record whatever it says. If every target times out, that is the finding — write it down, do **not** raise the budget (a fail-open deadline bought 4× wall-clock and zero verdicts the last time that was tried).

- [ ] Commit the script, tests, and the produced evidence JSON by name: `git add scripts/probe_native_analyze_timeout.py tests/unit/test_probe_native_analyze_timeout.py reports/native_analyze_probe/latest.json reports/native_analyze_probe/*.json && git commit -m "feat(probe): bounded-timeout native analyze probe writing tracked evidence JSON"`

### Task 4 — Register fixtures in the benchmark manifest as non-gating

- [ ] **RED.** Create `tests/unit/test_source_binary_benchmarks_manifest.py`:
  - `test_manifest_parses_and_every_entry_has_required_and_status` — walks all entries, asserts each has `required` (bool) and, when `required is False`, a non-empty `status` and `status_note`.
  - `test_native_fixture_entries_are_not_required` — the two new ids (`native_hello_c`, `native_hello_go`) exist, `required is False`, `status == "fixture_only"`.
  - `test_manifest_saw_at_least_n_entries` — **positive control**: assert the walk visited ≥ 3 entries, so an empty/misparsed manifest can never satisfy the loop above vacuously.
  - `test_fixture_entry_must_not_claim_ga` — assert no new entry's `status` is in `{"ga", "verified", "supported"}`. This is the machine-checked form of the honesty rule; a future edit flipping `fixture_only` → `ga` without evidence goes red here.

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_source_binary_benchmarks_manifest.py -v --no-cov
  ```

- [ ] **GREEN.** Edit `.reveng/source_binary_benchmarks.ga.json` — append two entries, do not reorder or reformat existing ones:

  ```json
  {
    "id": "native_hello_c",
    "language": "c",
    "source": "test_samples/native/hello_c/hello.c",
    "binary": "test_samples/native/hello_c/build/hello_c",
    "build": "make -C test_samples/native hello_c",
    "required": false,
    "status": "fixture_only",
    "status_note": "Fixture builds and its CLI surface is byte-stable-tested. REVENG analyze has NOT been shown to complete hermetically on this binary; see reports/native_analyze_probe/latest.json for the measured outcome. No GA or capability claim attaches to this entry.",
    "evidence_ref": "reports/native_analyze_probe/latest.json"
  }
  ```

  …and the parallel `native_hello_go` entry (`"language": "go"`, `CGO_ENABLED=0` noted in `build`).

- [ ] **Verify the guard bites.** Temporarily set `native_hello_c`'s `status` to `"ga"`, re-run, confirm `test_fixture_entry_must_not_claim_ga` goes RED, revert, confirm GREEN and `git diff --exit-code .reveng/source_binary_benchmarks.ga.json` is clean relative to the intended state.

- [ ] Confirm no gating surface changed. Run the readiness verifier and diff its verdict against the pre-change baseline — a `required: false` entry must not move the number:

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit -k "ga_readiness or benchmarks" -v --no-cov
  ```

- [ ] Commit: `git add .reveng/source_binary_benchmarks.ga.json tests/unit/test_source_binary_benchmarks_manifest.py && git commit -m "chore(benchmarks): register native fixtures as required=false with fixture_only status"`

### Task 5 — Backlog + lessons update

- [ ] Edit `docs/BACKLOG.md`:
  - **M1-NATIVE-FAM** — move from "inventory done" to "fixtures landed (C + Go, hermetic, byte-stable CLI); analyze-path status = *measured, see reports/native_analyze_probe/latest.json*". State explicitly that the item is **not** closed and what would close it: `reveng analyze` completing on both fixtures inside the 120 s budget without Ghidra, with the manifest entries flipped to `required: true` in the same change.
  - **R-HEX-1** — mark the probe as shipped and the hexyl timeout as *recorded, not fixed*, with the observed outcome from Task 3's real run written in as a number, not a word.
  - **M0 report discipline** — note the new `reports/native_analyze_probe/` convention (one timestamped JSON per run + `latest.json` copy, three-valued `status`).
  - **RALPH-2** — leave untouched; note only that it remains the long pole and is out of scope for this phase.

- [ ] Append one paragraph to `docs/architecture/lessons-learned-scope-c-2026-08.md`: *a fixture that builds is not a capability that works; the manifest records the gap in `status_note` and a test forbids flipping it to `ga` without evidence.*

- [ ] Full touched-area test sweep:

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py tests/unit/test_probe_native_analyze_timeout.py tests/unit/test_source_binary_benchmarks_manifest.py -v --no-cov
  ```

- [ ] Lint and format the two new Python files only:

  ```bash
  /usr/bin/python3.9 -m black --line-length=100 scripts/probe_native_analyze_timeout.py tests/unit/test_native_fixtures.py tests/unit/test_probe_native_analyze_timeout.py tests/unit/test_source_binary_benchmarks_manifest.py
  /usr/bin/python3.9 -m isort --profile=black --line-length=100 scripts/probe_native_analyze_timeout.py tests/unit/test_native_fixtures.py tests/unit/test_probe_native_analyze_timeout.py tests/unit/test_source_binary_benchmarks_manifest.py
  lint-imports --no-cache
  ```

- [ ] Commit: `git add docs/BACKLOG.md docs/architecture/lessons-learned-scope-c-2026-08.md && git commit -m "docs(scope-c): record native-fixture phase state and the fixture-vs-capability distinction"`

### Task 6 — Toolchain-absent CI honesty gate

- [ ] **RED.** Add `tests/unit/test_native_fixture_ci_visibility.py::test_absent_toolchain_is_reported_not_silent`: assert that when `cc` or `go` is absent, the fixture tests **skip** and a machine-readable marker is emitted — a line on stdout of the form `NATIVE_FIXTURE_SKIPPED: <name> reason=<...>`. Assert the marker text is produced by calling the helper directly with a forced-absent toolchain, and assert the opposite arm (toolchain present) produces **no** marker. Two arms, both required.

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixture_ci_visibility.py -v --no-cov
  ```

- [ ] **GREEN.** Factor the locator/skip logic from Tasks 1–2 into `tests/unit/_native_fixture_support.py` with `locate_fixture(name) -> Tuple[Optional[Path], Optional[str]]` and a `emit_skip_marker(name, reason)` helper. Update both fixture test modules to import it. Re-run all four new test modules.

- [ ] Add a short section to `test_samples/native/README.md` naming **who consumes the marker** and when — right now: nobody, it is emitted so a future CI job can count skips. Say that plainly. A default-OFF signal with no named consumer is a comment, and writing that down is what stops it being mistaken for coverage later.

- [ ] Final sweep, all five modules together:

  ```bash
  /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py tests/unit/test_probe_native_analyze_timeout.py tests/unit/test_source_binary_benchmarks_manifest.py tests/unit/test_native_fixture_ci_visibility.py -v --no-cov
  ```

- [ ] Commit: `git add tests/unit/_native_fixture_support.py tests/unit/test_native_fixture_ci_visibility.py tests/unit/test_native_fixtures.py test_samples/native/README.md && git commit -m "test(native): make absent-toolchain skips visible rather than silently green"`

---

## Self-Review

Run this list before declaring the phase done. Each line needs a command output or a file citation, not a recollection.

**Honesty**

- [ ] Grep the diff for GA-shaped words and read every hit: `git diff main...HEAD | grep -niE "\b(GA|generally available|supported|verified|production[- ]ready)\b"`. Every survivor must be a *negation* ("no GA claim attaches") or the phase is not honest. A hit count of zero here is itself suspicious — the README and status_note are *supposed* to contain the word in negated form, so zero means the grep is wrong, not that the diff is clean. Confirm the grep works by checking it finds the README's negation.
- [ ] No manifest entry added this phase has `required: true`.
- [ ] `reports/native_analyze_probe/latest.json` reflects a **real run**, not a fixture. Check `elapsed_s` is nonzero and `binary_sha256` matches `sha256sum` of the built fixture.

**Instrument integrity**

- [ ] Every new test has a proven-failing arm. For each of the four test modules, name the specific perturbation you ran and confirm the file is byte-identical after revert (`git status --porcelain tests/unit/`).
- [ ] The manifest walk asserts it saw ≥ 3 entries (a vacuous-loop control).
- [ ] The `could_not_measure` path exits **2**, verified by returncode, and the premise test (non-integer `SystemExit` → 1) passes.
- [ ] A timeout exits **0**. Confirm explicitly — if a timeout exits non-zero, CI will read a measured slowness as a broken probe.
- [ ] The skip path emits an actionable reason, proven by the forced-absent arm.

**Scope**

- [ ] `git diff --name-only main...HEAD` contains **no** file under `src/reveng/`. This phase adds fixtures, a script, tests, manifest data, and docs — nothing else.
- [ ] No RALPH-2, exploit, or pipeline-merge file touched.
- [ ] Total added test wall-clock measured and under 30 s with toolchains present: `time /usr/bin/python3.9 -m pytest tests/unit/test_native_fixtures.py tests/unit/test_probe_native_analyze_timeout.py tests/unit/test_source_binary_benchmarks_manifest.py tests/unit/test_native_fixture_ci_visibility.py --no-cov -q`

**Hygiene**

- [ ] black + isort clean on the four new Python files; `lint-imports --no-cache` green.
- [ ] Every commit used explicit named paths; `git diff --cached --name-status` was checked before each. No `git add -A`, no `git stash` (parallel worktrees share stash refs).
- [ ] `.gitignore` excludes `test_samples/native/*/build/`; confirm no built binary is tracked: `git ls-files test_samples/native | grep -c build/` returns 0 — and confirm the grep works by checking `git ls-files test_samples/native` is non-empty first.
- [ ] `docs/BACKLOG.md` states, for M1-NATIVE-FAM, the concrete condition that would close it. A backlog line that says "in progress" without a closing condition is the announce-then-stall shape and does not pass.

RECOMMENDED: WRITE_PLAN
