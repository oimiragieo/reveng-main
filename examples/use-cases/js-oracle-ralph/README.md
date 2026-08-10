# JS oracle Ralph loop

Automates **execute → measure `project_file_recall` → retry with a different tool profile** for JavaScript bundle reverse-engineering against a source oracle.

## Why variants matter

Running the **same** pipeline repeatedly does not increase oracle recall. This project **cycles** built-in profiles (baseline → webcrack → combined passes) so each attempt can change the artifact surface that promotion rules consume.

Reaching **0.80+ recall** on a real minified `cli.js` still depends on **engine improvements** in `bundle_reverse_engineer.py` (and/or exact build + source maps). The loop gives you a **repeatable harness** and a **JSON audit trail** (`ralph_report.json`) for agents or humans iterating on code.

## Quick start

From repository root (after `pip install -e .` or `PYTHONPATH=src`):

**Wave 3 note (2026-08-09):** current npm `@anthropic-ai/claude-code` ships a native `claude.exe` and **does not** publish `cli.js`. Prefer the checked-in interim surface until a legitimate large JS bundle input exists again (see `docs/architecture/research-r-ralph-2.md`).

**Wave 4 note:** sibling `bundle.js.map` materializes `output_dir/project/` (`source_map`); tracked recall is **0.4** (not 0.8). Operator-local Claude dogfood: `docs/architecture/operator_local_claude.md` + `operator_local_provenance.example.json` (never commit Anthropic trees).

```bash
# Interim tracked micro-bundle (repo-local; not "cli.js GA")
python scripts/ralph_js_oracle_loop.py \
  --input test_samples/js_tracked_bundle_artifact/bundle.js \
  --oracle test_samples/js_tracked_bundle_source \
  --output-dir reports/js_oracle_ralph_tracked \
  --target-recall 0.80 \
  --max-attempts 1 \
  --no-plateau \
  --no-js-behavior-probe
```

Historical large-bundle shape (obsolete on current npm packaging — keep only if you still have a real `cli.js`):

```bash
python scripts/ralph_js_oracle_loop.py \
  --input "C:/Users/you/AppData/Roaming/npm/node_modules/@anthropic-ai/claude-code/cli.js" \
  --oracle "C:/dev/projects/claude-code-main" \
  --output-dir reports/js_oracle_ralph_cli \
  --target-recall 0.80 \
  --max-attempts 100 \
  --no-plateau
```

Use **`--max-attempts N`** as the **iteration budget** (hard cap). With **`--no-plateau`**, the loop keeps going until it hits **N** attempts or **`--target-recall`** — it will not stop early just because scores stopped improving. Without `--no-plateau`, **`--plateau-attempts`** can end the run sooner.

- **Exit 0** — best recall ≥ `--target-recall`
- **Exit 1** — bad paths / errors
- **Exit 2** — finished without hitting target (still writes `ralph_report.json`)

### Variant schedule flags

| Flag | Effect |
|------|--------|
| `--variants-json PATH` | Append profiles from a JSON array (see `variants.example.json`). |
| `--variants-json-only` | Use **only** JSON profiles (requires `--variants-json`). |
| `--no-default-variants` | Skip built-in profiles; combine with JSON and/or heavy flags. |
| `--append-wakaru` | Append a `webcrack+wakaru` profile (slow; tool must be installed). |
| `--append-js-deobfuscator` | Append a `webcrack+js-deobfuscator` profile (slow). |
| `--no-js-behavior-probe` | Skip `node <entry> --help` on the reconstructed tree (faster; weaker tie-breaks). |
| `--no-plateau` | Only **`--max-attempts`** or **`--target-recall`** stops the loop (no early exit when scores plateau). |
| `--until-target` | Long-horizon preset: raises **`--max-attempts`** (≥5000) and plateau budget; add **`--no-plateau`** if you want that budget without plateau early-exit. |

When **Node** is available, each attempt runs a **behavior probe** (`capability_report.dimensions.javascript_behavior_probe`). The loop uses probe **tier** as a tie-breaker after oracle recall/precision (`js_behavior_probe_tier` on each attempt row).

`ralph_report.json` includes `variant_schedule` (resolved paths, labels, counts) for reproducibility.

## Outputs

Under `--output-dir`:

- `attempt_NNN_<label>/` — full analysis tree per attempt
- `ralph_report.json` — best recall, completion reason (`target_recall_reached`, `plateau_after`, `max_attempts_reached`), per-attempt metrics

## Tests

```bash
pytest tests/unit/test_ralph_js_loop.py -q
```

## Implementation

- Core loop: `src/reveng/app_reverse_engineering/ralph_js_loop.py`
- CLI: `scripts/ralph_js_oracle_loop.py`
