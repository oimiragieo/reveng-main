# Research: R-HEX-1 — hexyl availability block

**Date:** 2026-08-06  
**Backlog status for R-HEX-1:** `blocked`  
**Does not claim:** hexyl timed success, M2 closed, or native GA.

## Purpose

Record why Wave A cannot close R-HEX-1 with a fresh hexyl timed analyze run on this host, and what evidence was captured instead.

## Measurement

Job file: `reports/native_analyze_probe/wave_a_job.json`  
Result id: `hexyl_tool_absent`

| Field | Value |
| --- | --- |
| Subject binary | `test_samples/native/hello_go/build/hello_go` (present; not the hexyl binary) |
| Analyze command | `hexyl` (invoked tool) |
| Expected class | `tool_absent:hexyl` — missing analyze executable, **not** `input_absent` |
| Host check | `command -v hexyl` → absent |

This arm proves the probe classifies a missing **invoked tool** correctly. It is **not** a timed hexyl analyze of a hexyl binary.

## Status

R-HEX-1 remains **blocked** until:

1. A hexyl binary (or build recipe) is available on the measurement host, and
2. A bounded-timeout `reveng analyze` (or equivalent) run against that binary is recorded with honest process + semantic fields.

Wave A must not mark R-HEX-1 `done`.

## Related evidence

- Multi-result probe report: `reports/native_analyze_probe/latest.json`
- Historical hello_go exit-1 anchor: `docs/architecture/evidence-hello-go-hist-exit1-029627d4.json`
- Reconciliation notes: `docs/architecture/diagnosis-hello-go-analyze-reconciliation.md`
