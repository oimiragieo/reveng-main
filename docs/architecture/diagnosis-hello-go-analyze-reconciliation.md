# Diagnosis: hello_go analyze — historical exit-1 vs current probe

**Date:** 2026-08-06  
**Scope:** Observation tables only. Hypotheses are labelled; no claim of native GA or analyze success.

## Purpose

Reconcile the historical hello_go probe observation (git blob `029627d4`, exit 1) with the Wave A multi-result re-run (`hello_go_analyze` in `wave_a_job.json`).

## Observation A — historical (exit 1)

Source: `docs/architecture/evidence-hello-go-hist-exit1-029627d4.json`  
Origin: `git show 029627d4:reports/native_analyze_probe/2026-08-06T035133Z.json`

| Field | Observed value |
| --- | --- |
| probe_version | 1.1 |
| recorded_at_utc | 2026-08-06T03:51:33Z |
| binary | test_samples/native/hello_go/build/hello_go |
| binary_sha256 | 8a5084e6b0a86b39dab194d98dc195ec53e0dd06a69160942f7195c3314441aa |
| binary_size_bytes | 2250930 |
| analyze_cmd | /usr/bin/python3.9 -m reveng analyze \<binary\> |
| timeout_budget_s | 30.0 |
| elapsed_s | ~0.029 |
| status | could_not_measure |
| returncode | 1 |
| reason | nonzero_exit:1 |
| measured | true |
| semantic | absent (pre-v1.2) |

## Observation B — current Wave A job (`hello_go_analyze`)

Source: `reports/native_analyze_probe/latest.json` (result id `hello_go_analyze`)  
Companion stamp: `reports/native_analyze_probe/2026-08-06T134134Z.json` (byte-identical to `latest.json`).

| Field | Observed value |
| --- | --- |
| probe_version | 1.2 |
| recorded_at_utc | 2026-08-06T13:41:34Z |
| binary | test_samples/native/hello_go/build/hello_go |
| binary_sha256 | 8a5084e6b0a86b39dab194d98dc195ec53e0dd06a69160942f7195c3314441aa |
| binary_size_bytes | 2250930 |
| analyze_cmd | /usr/bin/python3.9 -m reveng --output-dir runs/hello_go_analyze analyze \<binary\> |
| timeout_budget_s | 120.0 |
| elapsed_s | ~8.33 |
| status | completed |
| returncode | 0 |
| reason | null |
| measured | true |
| semantic.process_status | completed |
| semantic.analysis_report_present | true |
| semantic.native_fallback_empty | null |
| semantic.job_output_dir | reports/native_analyze_probe/runs/hello_go_analyze |

Stdout noted pipeline `partial_success` and a unified report path; stderr included Ghidra-absent / native-fallback empty signals. Process `completed` does **not** mean native GA success.

## Hypotheses (not conclusions)

1. **Import / PYTHONPATH:** Historical ~0.03s exit 1 is consistent with a fast CLI failure (module path, argparse, or early guard) rather than a full analyze. Current run used `PYTHONPATH=src` and completed in ~8s.
2. **Fixture identity:** Same SHA256 as Observation A means binary drift does not explain the status change (exit 1 → exit 0).
3. **Probe contract change:** v1.2 adds semantic attribution and a longer budget; process `completed` still coexists with limited native analysis (Ghidra absent, `native_fallback_empty` unset/null).
4. **Environment:** Different `PYTHONPATH`, CWD, or installed entry points between hosts can flip exit 0 vs 1 without changing product capability claims.

## Non-claims

- Process `completed` ≠ native analyze capability.
- This note does not close M1-NATIVE-FAM, M2, or R-HEX-1.
