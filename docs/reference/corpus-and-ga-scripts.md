# Reference: Corpus and GA scripts

> **Maturity:** process tooling is load-bearing · **does not** by itself make the product GA
>
> Prefer `/usr/bin/python3.9` on dogfood hosts. Always open tracked JSON evidence.

## `scripts/verify_ga_readiness.py`

Checks tracked reports + `docs/support_matrix.json` and writes a readiness report.

```bash
python3.9 scripts/verify_ga_readiness.py --profile baseline
python3.9 scripts/verify_ga_readiness.py --profile ga
```

Useful flags: `--source-report`, `--bun-report`, `--app-report`, `--support-matrix`, `--output` (default `reports/ga_readiness_report.json`).

**What not to claim:** a green exit code alone. Open the referenced report JSON and confirm evidence fields for **both** baseline and ga profiles. Hollow gates that pass on empty evidence are a bug, not readiness.

## `scripts/probe_native_analyze_timeout.py`

Bounded-timeout native `reveng analyze` probe (status contract v1.2+; code `PROBE_VERSION` may be newer).

```bash
python3.9 scripts/probe_native_analyze_timeout.py \
  --job reports/native_analyze_probe/wave_a_job.json

# Legacy single-binary form
python3.9 scripts/probe_native_analyze_timeout.py --binary path/to/sample.exe --timeout-s 120
```

**What not to claim:** process `completed` (returncode 0) ≠ native GA. Check semantic fields (DF-5). `tool_absent` / `input_absent` / timeout → `could_not_measure` — that is **not** “research done.” Fixtures under `test_samples/native/` remain **fixture_only** until analyze is measured green.

Evidence hygiene: exactly one stamp matching `latest.json` where that contract applies; scrub orphans after merges.

## `scripts/run_vrl.py`

Verified Recompilation Loop runner (decompile → compile → differentially verify → LLM refine).

```bash
REVENG_AI_PROVIDER=ollama python3.9 scripts/run_vrl.py --binary hexyl --max-iterations 3
```

`REVENG_AI_PROVIDER`: `ollama` (default, local) | `anthropic` | `openai`.

**What not to claim:** a single VRL run grade as broad binary↔source equivalence GA. Grades land in corpus/benchmark artifacts — read them.

## App reverse-engineering corpus

```bash
python3.9 scripts/run_app_reverse_engineering_corpus.py
python3.9 scripts/run_app_reverse_engineering_corpus.py --entry some_entry_name
```

Defaults: config `.reveng/app_reverse_engineering_corpus.json`, report `reports/app_reverse_engineering_corpus_report.json`. Also reachable via API `REVENGAPI.run_app_reverse_engineering_corpus` and MCP `run_app_corpus`.

App RE is a **supported** matrix workflow; corpus green still means “tracked entries met the gate,” not universal quality for every customer binary.

## Rules (short)

1. Never trust verifier green alone — open JSON.
2. Fixture ≠ capability.
3. No invented success percentages in docs or status updates.
4. Match claims to [`docs/support_matrix.json`](../support_matrix.json).

## Related

- Tutorial: [Unit & honesty gates](../tutorials/engineer/02-run-unit-and-honesty-gates.md)
- [Honesty rules](../support/honesty-rules.md)
- [Reading validation grades](../support/reading-validation-grades.md)
- Skill: `.cursor/skills/reveng-release-honesty/SKILL.md`
