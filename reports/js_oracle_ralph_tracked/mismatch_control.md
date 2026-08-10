# Wave 4 mismatch control — recovered-root materialization

| Arm | Input | Oracle | Recall | Notes |
| --- | --- | --- | --- | --- |
| Treatment | `test_samples/js_tracked_bundle_artifact/bundle.js` | `test_samples/js_tracked_bundle_source` | `0.4` | `materialization_mode:source_map`, `sourcemap:bundle.js.map` — **no** `no_recovered_root` |
| Mismatch | same bundle | `test_samples/native/hello_go` | `0.0` | same materialization mode; filename-set match fails against native oracle |

## Interpretation

This pair **discriminates**: treatment recovers `src/index.ts` + `src/lib/greet.ts` from sibling `bundle.js.map` `sourcesContent` (2/5 oracle files = 0.4). Mismatch keeps recovered TS files but scores 0.0 against an unrelated native tree.

Ship gate tokens: treatment recall **> 0**, mismatch recall **<** treatment, mode `source_map`.

Does **not** close `R-RALPH-2` / Phase 6 (target 0.8 not reached; product `cli.js` surface still obsolete).

Commands:

```bash
/usr/bin/python3.9 scripts/ralph_js_oracle_loop.py \
  --input test_samples/js_tracked_bundle_artifact/bundle.js \
  --oracle test_samples/js_tracked_bundle_source \
  --output-dir /tmp/ralph_w4_raw \
  --target-recall 0.80 --max-attempts 1 --no-plateau --no-js-behavior-probe

/usr/bin/python3.9 scripts/ralph_js_oracle_loop.py \
  --input test_samples/js_tracked_bundle_artifact/bundle.js \
  --oracle test_samples/native/hello_go \
  --output-dir /tmp/ralph_w4_mismatch \
  --target-recall 0.80 --max-attempts 1 --no-plateau --no-js-behavior-probe
```

Wave 3 frozen baseline (pre-materialize): `wave3_ralph_report.json` (recall `0.0`, `no_recovered_root`).
