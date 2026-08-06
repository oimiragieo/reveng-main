# Dogfood: `verify_ga_readiness.py` (2026-08-06)

Wave A Task 9 measurement. Commands run under `/usr/bin/python3.9` with `PYTHONPATH=src`.

**Neither profile proves native GA.** Gate pass here means the readiness script’s tracked-report floors were met. The source-vs-binary report used for those floors is managed JVM/Python rows, not hermetic native PE/ELF analyze success (see M1-NATIVE-FAM / R-HEX-1).

## Commands

```bash
export PYTHONPATH=src
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile baseline
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile ga
```

## Exit codes

| profile | exit code | overall_status (script stdout) | passed / failed gates |
| --- | --- | --- | --- |
| `baseline` | `0` | `pass` | 5 / 0 |
| `ga` | `0` | `pass` | 10 / 0 |

Output report path (written each run; not claimed as native GA proof): `reports/ga_readiness_report.json`.

## Tracked JSON inputs the verifier reads

Default paths from `scripts/verify_ga_readiness.py`:

| role | tracked path |
| --- | --- |
| source report | `reports/source_binary_benchmarks_report.json` |
| bun report | `reports/bun_sample_matrix.json` |
| app corpus report | `reports/app_reverse_engineering_corpus_report.json` |
| support matrix | `docs/support_matrix.json` |

Values below were read by opening each JSON on 2026-08-06 (not invented from stdout alone).

### `reports/source_binary_benchmarks_report.json`

| evidence field | value (opened JSON) |
| --- | --- |
| `config_path` | `.reveng/source_binary_benchmarks.ga.json` |
| `benchmark_count` | `4` |
| `benchmarks` length | `4` |
| `benchmarks[0].id` / `status` / `analyze_report_exists` | `java-helloworld-class` / `completed_without_behavior_checks` / `true` |
| `benchmarks[1].id` / `status` / `analyze_report_exists` | `java-helloworld-jar` / `completed_without_behavior_checks` / `true` |
| `benchmarks[2].id` / `status` / `analyze_report_exists` | `python-sample-bytecode` / `completed_without_behavior_checks` / `true` |
| `benchmarks[3].id` / `status` / `analyze_report_exists` | `python-sample-zipapp` / `completed_without_behavior_checks` / `true` |

Verifier uses: `benchmark_count` / `benchmarks`, `analyze_report_exists`, success-class `status`, and (GA) `config_path` match to `.reveng/source_binary_benchmarks.ga.json`.

### `reports/bun_sample_matrix.json`

| evidence field | value (opened JSON) |
| --- | --- |
| `config_path` | `.reveng\bun_sample_matrix.ga.json` (normalized to `.reveng/bun_sample_matrix.ga.json` by the verifier) |
| `matrix_status` | `pass` |
| `live_bun_sample_count` | `2` |
| `hard_failure_count` | `0` |

### `reports/app_reverse_engineering_corpus_report.json`

| evidence field | value (opened JSON) |
| --- | --- |
| `config_path` | `.reveng\app_reverse_engineering_corpus.ga.json` (normalized to `.reveng/app_reverse_engineering_corpus.ga.json`) |
| `summary.matrix_status` | `pass` |
| `summary.total_entries` | `7` |
| `rows` length | `7` |
| synthetic rows in `rows[].tags` | `false` (no `synthetic` tag) |
| example tags present | `bundle`, `bytecode`, `compiled`, `dotnet`, `javascript`, `jvm`, `managed`, `packaged`, `python`, `release`, `smoke`, `source` |

### `docs/support_matrix.json`

| evidence field | value (opened JSON) |
| --- | --- |
| `workflows` length | `6` |
| supported workflows (`status == "supported"`) | `3` (`cli_triage`, `app_reverse_engineering`, `source_binary_reconstruction`) |

## Gate interpretation (honesty)

- **baseline pass** — support matrix + app corpus (≥7) + ≥1 source benchmark + ≥1 analyze-evidence row + bun matrix with ≥1 live sample.
- **ga pass** — same plus strict `.ga.json` provenance, native-success floor (≥1 success-class row with analyze evidence), breadth floors, bun depth (≥2 live, 0 hard failures), non-synthetic app corpus.
- **Still not native GA** — success-class rows here are managed Java/Python fixtures. Hermetic native family coverage (M1-NATIVE-FAM) and hexyl timed analyze (R-HEX-1 / M2) remain open/blocked separately.
