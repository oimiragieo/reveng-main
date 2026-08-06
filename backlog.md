# REVENG Scope C Backlog

Ops index for the full roadmap clearance program. Update `status` and `last_verified` when work lands.

**Schema:** `id | title | phase | status | release_impact | source | validation | last_verified | notes`

Statuses: `open` · `in_progress` · `done` · `parked` · `blocked`

## Release blockers (Phase 1)

| id | title | phase | status | release_impact | source | validation | last_verified | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GA-HOLLOW-1 | Hollow native GA gate (pass without analyze evidence) | 1 | done | blocker | scripts/verify_ga_readiness.py | pytest tests/unit/test_verify_ga_readiness.py | 2026-08-06 | native-analyze-evidence + native-success-floor |
| GAP-OLLAMA-1 | Ollama analyzer tests skipped as known_gap | 1 | done | blocker | reports/skip_inventory.md | pytest …test_check_ollama_availability_* | 2026-08-06 | Patched real import paths; unskipped |
| GAP-ML-1 | Legacy MalwareClassification missing is_malware | 1 | done | blocker | src/reveng/security/ml_malware_classifier.py | pytest tests/unit/test_ml_malware_classification_api.py | 2026-08-06 | Alias → MLMalwareClassificationResult |
| SEC-EXP-1 | Exploit CLI without EXPERIMENTAL watermark | 1 | done | blocker | src/reveng/cli/__init__.py | reveng generate-exploit --help | 2026-08-06 | Watermarked non-GA |
| NATIVE-EVID-1 | Tracked native report 0/5 analyze_report_exists | 1 | done | blocker | reports/source_binary_benchmarks_report.json | verify_ga_readiness --profile ga | 2026-08-06 | 4× analyze_ok_recompile_failed; entrypoint fixed to python -m reveng |
| CLI-PY39-1 | CLI crash on Python 3.9 (`int \| None`) | 1 | done | blocker | src/reveng/cli/__init__.py | pytest tests/unit/test_cli_python39_import.py | 2026-08-06 | from __future__ import annotations |
| BENCH-LAUNCH-1 | Benchmarks called removed repo-root reveng.py | 1 | done | blocker | scripts/run_source_binary_benchmark.py, run_bun_sample_matrix.py | pytest test_build_reveng_command_* | 2026-08-06 | Use python -m reveng |

## Open follow-ons (post Phase-1 public preview)

| id | title | phase | status | release_impact | notes |
| --- | --- | --- | --- | --- | --- |
| RECOMPILE-1 | Managed-language recompile still fails (Ghidra wrongly required) | 2 | done | blocker | Fixed: app-adapter route; 4 hermetic benches completed_without_behavior_checks |
| PY39-FSTR-1 | spec_library f-string backslash SyntaxError on 3.9 | 1 | done | blocker | Blocks all app RE imports on Python 3.9 |
| CLI-OUTDIR-1 | Benchmark --output-dir lost on recompile subparser | 2 | done | blocker | Subcommand-specific argv order in runner |
| M1-NATIVE-FAM | Expand to ≥5 native / ≥3 families with hermetic fixtures | 2 | open | post-GA | opencode Windows binary not hermetic on Linux CI; managed benches already 4 |
| P3-BP-2 | npm pack/run probes | 6 | done | post-GA | Optional `run_javascript_npm_lifecycle_probe` (default off); dimension wired |
| P3-BP-3 | Behavior probe promotes validation.grade | 6 | done | post-GA | tier2+syntax_ok → evidence_backed; capability_report now attached in enrich |
| P3-BP-4 | Size-scaled JS probe timeouts | 6 | done | post-GA | resolve_javascript_probe_timeout_sec by file_count |
| RALPH-2 | cli.js 0.8+ recall | 6 | open | post-GA | |
| M5-PIPE | pipeline vs pipelines consolidation | 9 | open | post-GA | |
| DF-2 | Lazy conftest heavy imports | 3 | done | quality | Heavy deps imported inside fixtures only |
| LOG-PRINTF-1 | REVENGLogger.warning rejected %-args (sandbox arity crash) | 3 | done | quality | stdlib-compatible *args on debug/info/warning/error/critical |

## Phase index (Scope C)

| phase | focus | status |
| --- | --- | --- |
| 1 | Honesty + known_gaps + GA gate integrity | done |
| 2 | Managed recompile + GA report honesty | done (preview) |
| 3 | Behavior-backed JS validation (BP-2/3/4) | done (BP-1 partial: tsx optional) |
| 4–13 | See Scope C master plan / hardening plan | open |

## Parked (Tier 3 honesty non-goals)

| id | title | status | notes |
| --- | --- | --- | --- |
| T3-KERNEL | Kernel reverse engineering | parked | Do not claim |
| T3-PACKED | Packed/protected binaries depth | parked | Do not claim |
| T3-JIT | Self-modifying/JIT outside JS | parked | Do not claim |
| T3-ANTI | Malware anti-analysis depth | parked | Do not claim |
| T3-GUI | Large GUI-first without eval strategy | parked | Do not claim |

## Decisions / waivers

| date | decision | rationale |
| --- | --- | --- |
| 2026-08-06 | Scope C chosen over thinktank B | User override; Phase 1 honesty still first |
| 2026-08-06 | GA success floor accepts `analyze_ok_recompile_failed` | Honest analyze evidence; recompile tracked as RECOMPILE-1 |
| 2026-08-06 | Public preview claims: CLI + app RE supported; native reconstruction limited; exploits experimental | support_matrix.json |

## New findings (dogfood)

| id | finding | severity | disposition |
| --- | --- | --- | --- |
| DF-1 | System python3.13 stdlib incomplete (no shutil) on this host | medium | Use python3.9 for local gates |
| DF-2 | tests/conftest.py imports volatility3/sklearn — blocks default pytest without extra deps | medium | Fixed: lazy imports inside fixtures (2026-08-06) |
| DF-3 | Analyze writes `reports/unified_analysis_report.json` but runner looked for `analysis_report.json` | high | Fixed detector |
