# Mismatch control — Wave 6 tracked Ralph (W6-A wire)

**Date:** 2026-08-09
**Interpreter:** `/usr/bin/python3.9`

## Arms

| Arm | Input | Oracle | `best_project_file_recall` | Notes |
| --- | --- | --- | --- | --- |
| Treatment | `test_samples/js_tracked_bundle_artifact/bundle.js` | `test_samples/js_tracked_bundle_source` | `0.4` | `source_map`; fingerprint artifact present; confirmed=0 on micro-bundle |
| Mismatch | same bundle | `test_samples/native/hello_go` | `0.0` | fingerprint confirmed=0 |

## Interpretation

W6-A product-path wire is live. Tracked recall **unchanged at 0.4** vs Wave 4 — fingerprint did not add files on this micro-bundle (no qualifying unique signals). Operator-local Claude dogfood remains the stronger fingerprint signal (232 confirms) and is **not** the ship gate. R-RALPH-2 stays open.
