# REVENG Backlog Clearance — Wave A v2 (Thinktank-hardened)

> **For agentic workers:** Use superpowers:subagent-driven-development. Checkboxes track progress.
> **Prior:** v1 REJECTED twice by Codex Sol; this v2 is a full rewrite addressing must-fixes.

**Goal:** Ship honesty/ops/research artifacts that close only what measurement + decisions allow — without claiming native GA, exploit GA, or Scope C phases 4–13.

**Architecture:** Wave A changes `scripts/`, `tests/unit/`, `docs/architecture/`, `reports/native_analyze_probe/`, and `backlog.md` only. **Zero `src/reveng/**` edits.** Probe gains v1.2 fields; research/decision docs record measured baselines or labelled `could_not_measure`; backlog reclassified honestly.

**Tech Stack:** `/usr/bin/python3.9`, pytest, probe script, Markdown, git (named paths only).

## Thinktank status

| Round | Seat | Verdict |
| --- | --- | --- |
| R1 | Sol | REJECT (overclaim R-HEX/R-RALPH done; weak evidence) |
| R2–R3 | Sol | REJECT (v1 incomplete / semantic evidence missing) |
| R4 | Sol | REJECT (semantic attribution, outcome table, hexyl absent class, GA JSON open) |
| R5 | Sol | **APPROVE_WITH_NITS** — nits folded below |

## Global Constraints

- Python 3.9 dogfood; named-path `git add`; never repo-wide `git status` on dirty `reports/`.
- Fixture build ≠ analyze capability; no `required: true` flips; no exploit expansion; T3-* stay parked.
- Process status three-valued: `completed` | `timeout` | `could_not_measure`. Nonzero ≠ completed.
- Process `completed` ≠ native capability — semantic fields required on executed runs.
- Fail-first TDD for all code/script/tests. Docs: checklist + invariant tests. No blanket “everything is TDD.”
- Secrets: sanitize stdout/stderr tails before commit (strip lines matching `(?i)(api[_-]?key|token|authorization|password)\s*[:=]`).

## Explicit non-goals

M1-NATIVE-FAM closed; hexyl timed success; RALPH-2 0.8 engine; pipeline merge code; phases 4–13 done; any `src/reveng/**` change.

---

## File map

| Path | Action |
| --- | --- |
| `scripts/probe_native_analyze_timeout.py` | v1.2: `tool_absent`, `stderr_tail`, `stdout_tail`, `semantic` dict, sanitize |
| `tests/unit/test_probe_native_analyze_timeout.py` | fail-first for new fields |
| `tests/unit/test_evidence_dir_hygiene.py` | fail if missing/stale/orphan stamps |
| `tests/unit/test_git_status_scoped.py` | temp-repo behavioral test |
| `tests/unit/test_backlog_wave_a_invariants.py` | backlog honesty gates |
| `scripts/git_status_scoped.sh` | pathspec status excluding reports |
| `reports/native_analyze_probe/README.md` | contract + redaction |
| `docs/architecture/research-r-hex-1-*.md` | availability block (hexyl not timed) |
| `docs/architecture/diagnosis-hello-go-analyze-reconciliation.md` | exit-1 **and** exit-0 |
| `docs/architecture/research-r-ralph-2-baseline.md` | baseline only |
| `docs/architecture/decision-r-pipe-1-*.md` | permanent split |
| `docs/architecture/decision-r-sec-1-*.md` | sandbox class decision |
| `docs/architecture/decision-r-vrl-1-*.md` | seeds+provider decision |
| `docs/architecture/dogfood-verify-ga-readiness-2026-08-06.md` | baseline **and** ga profiles |
| `docs/architecture/wave-b-exit-criteria.md` | gated queue |
| `backlog.md` | reconcile |

---

### Task 1 — Probe v1.2 fields (TDD)

**Produce:** `PROBE_VERSION="1.2"`.

#### Normative outcome table (mandatory)

| Condition | `status` | `measured` | `reason` | `semantic.process_status` |
| --- | --- | --- | --- | --- |
| Child exit 0 within budget | `completed` | True | null or note | `completed` |
| Child exit ≠ 0 within budget | `could_not_measure` | True | `nonzero_exit:<code>` | `could_not_measure` |
| Wall timeout | `timeout` | True | `timeout` | `timeout` |
| Invoked executable missing (`shutil.which` + not a file path) | `could_not_measure` | False | `tool_absent:<name>` | `could_not_measure` |
| Subject `--binary` path missing | `could_not_measure` | False | `input_absent:<path>` | `could_not_measure` |
| OSError spawning child | `could_not_measure` | False | `os_error:<ExcName>` | `could_not_measure` |

**Hexyl arm in Wave A:** subject binary may be hello_go (present); analyze-cmd is `hexyl` → expect **`tool_absent:hexyl`** (missing invoked tool), NOT `input_absent`. If instead probing a missing hexyl binary path with `reveng analyze`, use `input_absent`. Job file must label which case.

**Tails:** sanitize **before** truncating to 2000 chars each (stdout and stderr independently). Sanitize regex case-insensitive for `api_key`, `token`, `authorization`, `password` key=value forms.

**Semantic object** (always present):

```python
semantic = {
  "process_status": <as table>,
  "analysis_report_present": bool | None,
  "native_fallback_empty": bool | None,
  "semantic_reason": str | None,
  "job_output_dir": str | None,
}
```

**Run-specific attribution (no stale scans):** each job result gets a fresh empty directory `job_output_dir = out_dir / "runs" / <result_id>` created immediately before spawn. Pass that dir to analyze via argv if the command supports `--output-dir` as a global flag **before** subcommand, else set env `REVENG_PROBE_OUT=<dir>` and record that Wave A may leave `analysis_report_present=None` when the CLI cannot take an out dir (document which). Snapshot dir mtimes/file set **before** and **after**; only files created after spawn count. Parse newly created JSON if any: set `analysis_report_present`; set `native_fallback_empty` only if a known field path is present in that new JSON (define path in code comment + test fixture); else `None`. `analysis_report_present=True` never implies native GA success.

- [ ] RED: outcome table cases + tool_absent vs input_absent + sanitize-before-truncate + version 1.2
- [ ] GREEN: implement
- [ ] Commit named paths

### Task 2 — Multi-result job file + write_report (TDD)

**Job schema** (`wave_a_job.json`):

```json
{
  "version": 1,
  "results": [
    {"id": "hello_go_analyze", "binary": "…/hello_go", "analyze_cmd": "/usr/bin/python3.9 -m reveng analyze", "timeout_s": 120},
    {"id": "hexyl_tool_absent", "binary": "…/hello_go", "analyze_cmd": "hexyl", "timeout_s": 30}
  ]
}
```

Validation: `version==1`; `results` non-empty; each has unique `id` matching `^[A-Za-z0-9][A-Za-z0-9_.-]*$` (no path separators), existing-or-absent binary path string, non-empty `analyze_cmd` string, `timeout_s>0`. Duplicate ids → CLI exit 2. `--job` and legacy `--binary` are mutually exclusive.

```bash
python3.9 scripts/probe_native_analyze_timeout.py \
  --job reports/native_analyze_probe/wave_a_job.json \
  --out-dir reports/native_analyze_probe
```

`write_report`: write both `latest.json` and stamped sibling to temp files and fsync; only after both temps exist successfully, delete obsolete `20*.json` stamps, then atomic replace both targets (same bytes). Keep README, `wave_a_job.json`, `runs/`. Before/after inventories for semantic attribution are **recursive** (analyzers may nest JSON).

- [ ] RED: schema validation tests; write_report exactly 1 stamp + latest; orphans removed
- [ ] GREEN
- [ ] Commit

### Task 3 — Evidence hygiene + README (TDD)

- [ ] RED: `test_evidence_dir_hygiene` **fails** if latest missing; fails if stamp missing; fails if extra stamp; fails if bytes differ
- [ ] GREEN: update README with multi-result contract, tool_absent, redaction rules
- [ ] Commit `latest` only after Task 4 real run

### Task 4 — Real measurement (hello_go + hexyl tool_absent)

Before deleting old stamps: `git show 029627d4:reports/native_analyze_probe/2026-08-06T035133Z.json > /tmp/hist-exit1.json` and copy into `docs/architecture/evidence-hello-go-hist-exit1-029627d4.json` (tracked historical anchor). Then run job.

- [ ] Build go fixture if needed; run one `--job`; record process exit code
- [ ] Commit **only** `latest.json` + its byte-identical stamp + README + job file + hist evidence json (explicit paths, no glob)
- [ ] Write `research-r-hex-1-hexyl-availability-block.md`: backlog status for R-HEX-1 = **`blocked`** (not done); tool_absent recorded
- [ ] Write `diagnosis-hello-go-analyze-reconciliation.md` with two observation tables (hist exit1 vs current); hypothesis only
- [ ] Doc invariant test: both docs exist; no `<placeholder>` tokens; R-HEX wording says `blocked`

### Task 5 — R-RALPH-2 baseline doc (checklist + placeholder scan)

- [ ] Measure current recall with existing harness if runnable under 3.9; on failure record `could_not_measure` with reason — **never write numeric 0 for a missing measurement**
- [ ] Doc: `research-r-ralph-2-baseline.md` — measured float **or** explicit null/`could_not_measure`; wedge candidates listed, none claimed done
- [ ] Test: no `<…>` placeholders; forbids a lone `0` / `0.0` presented as recall when status is could_not_measure
- [ ] Backlog: `R-RALPH-2-BASELINE=done`, `R-RALPH-2=open`

### Task 6 — Decision docs (PIPE / SEC / VRL)

- [ ] `decision-r-pipe-1-pipeline-packages.md` — Wave A decision: **keep permanent documented split**. Wave B may still implement a *future* merge only under M5-PIPE exit criteria (not a contradiction: A = freeze; B = optional later migration).
- [ ] `decision-r-sec-1-sandbox-class.md` — Docker-only minimum for preview; Firecracker/gVisor deferred; **no exploit expansion**
- [ ] `decision-r-vrl-1-seeds-and-provider.md` — **must** state concrete policy integers even if runtime unmeasured: `min_seeds: 3`, `provider: ollama`, plus separate `runtime_status: could_not_measure|measured`
- [ ] Placeholder scan over these three files; Wave B criteria must copy the integer `min_seeds`

### Task 7 — DF-4 scoped git status (behavioral TDD)

- [ ] RED: temp git repo with dirty `reports/huge.bin` and dirty `README.md`; script must list README change, must **not** list reports/huge.bin
- [ ] GREEN: `scripts/git_status_scoped.sh`
- [ ] Commit

### Task 8 — Backlog invariants test (fail-first against current backlog)

Protected exact IDs: `T3-KERNEL`, `T3-PACKED`, `T3-JIT`, `T3-ANTI`, `T3-GUI` each `parked`. Phases 4–13 each still `open` in section E. `M1-NATIVE-FAM` open. `R-HEX-1` must be `blocked` after reconcile (not `done`). `R-RALPH-2-BASELINE` done; `R-RALPH-2` open via exact column/id match.

- [ ] RED now (BASELINE missing; R-HEX-1 wording)
- [ ] Leave failing until Task 9

### Task 9 — Dogfood + backlog reconcile + Wave B criteria

Exact commands:

```bash
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile baseline
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile ga
```

Dogfood doc must list, per profile: exit code; **paths of tracked JSON reports the verifier referenced**; and for each path a table of evidence fields the verifier requires with **values read by opening the JSON** (not invented from stdout alone). If a report cannot be opened → record `could_not_measure` for that field.

- [ ] `wave-b-exit-criteria.md` copies `min_seeds: 3` from VRL decision; clarifies M5-PIPE Wave B merge is optional later migration, not required by Wave A split freeze
- [ ] Update `backlog.md`:

| Row | New status |
| --- | --- |
| R-HEX-1 | **blocked** |
| R-RALPH-2-BASELINE | done (new) |
| R-RALPH-2 | open |
| R-PIPE-1 | done (decision) |
| R-SEC-1 | done (decision; no exploit expansion) |
| R-VRL-1 | done (decision) |
| DF-4 | done (ops) |
| DF-1 | mitigated (convention) |
| M0 | partial |
| M3 | partial |
| M1-NATIVE-FAM, M2, RALPH-2, phases 4–13, T3-* | unchanged |

- [ ] GREEN invariants
- [ ] Commit

### Task 10 — Final gate

Record `WAVE_A_BASE=$(git rev-parse HEAD)` at Task 1 start in `.superpowers/sdd/wave-a-base-sha.txt`.

```bash
/usr/bin/python3.9 -m pytest --no-cov -q \
  tests/unit/test_probe_native_analyze_timeout.py \
  tests/unit/test_evidence_dir_hygiene.py \
  tests/unit/test_git_status_scoped.py \
  tests/unit/test_backlog_wave_a_invariants.py
git diff --name-only ${WAVE_A_BASE}..HEAD | tee /tmp/wave-a-files.txt
# FAIL if any path starts with src/reveng/
```

All pass.

---

## Wave B (not this plan)

RALPH-2 engine, hexyl timed run + M2, M1-NATIVE-FAM required:true, M4 CI blocking corpus, M5-PIPE code merge, VRL LLM gate, phases 5–13, SEC sandbox proofs.

## Self-check before Sol APPROVE

- [x] R-HEX-1 not marked done without hexyl timed binary
- [x] R-RALPH-2 split from BASELINE
- [x] No src/reveng authorization
- [x] Multi-result one JSON procedure
- [x] Evidence hygiene fail-closed
- [x] Behavioral git status test
- [x] Dual readiness profiles
- [x] Semantic fields on executed runs
- [x] Sanitization before commit
