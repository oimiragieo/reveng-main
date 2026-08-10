# Research + toolkit — JS recovery climb (Wave 7, 2026-08-09)

Exa MCP research + in-tree toolkit. **Not** exe decode / R-RALPH-2 close / enterprise GA.

## Exa-found code we can use / import (optional CLIs)

| Tool | URL | Role in toolkit |
|------|-----|-----------------|
| **bun-demincer** | https://github.com/vicnaum/bun-demincer | Bun extract → split modules → vendor fingerprint → wakaru/rename (Node). Reference pipeline; not vendored. |
| **unbun** (cc-friend) | https://github.com/cc-friend/unbun | Bun SEA module graph extract (list/extract). |
| **unbun** (skelpo / can1357) | https://github.com/skelpo/unbun , https://github.com/can1357/unbun | Bun/Node SEA/Deno extract; Python variant. |
| **debun** | https://github.com/iivankin/debun | BunFS carve + pack + rename. |
| **bun-unpack** | https://github.com/xpcmdshell/bun-unpack | Reconstruct sources from Bun compile. |
| **wakaru** | https://github.com/pionxzh/wakaru | Unpack/unminify (webpack/esbuild/Bun). Wired via `npx @wakaru/cli`. |
| **webcrack** | https://github.com/j4k0xb/webcrack | Deobfuscate + unpack. Wired via `npx webcrack`. |
| **humanify** | https://github.com/jehna/humanify | LLM rename (optional, non-hermetic). |
| **astdiff** | https://github.com/shcv/astdiff | Structural MinHash matching across minified versions. |
| **mozilla/source-map** | https://github.com/mozilla/source-map | VLQ/`sourcesContent` consumer (JS). We use JSON `sourcesContent` directly in Python. |
| **bundle-breaker** | https://github.com/awphi/bundle-breaker | Debundle + module graph (graphology). |
| Prior art notes | wakaru#74 / 0xdevalias gists; CASCADE arXiv 2507.17691; jsNaughty | AST fingerprint / LLM+IR ideas — not shipped as deps. |

**In-tree (already importable):** `reveng.tools.anti_analysis.bun_extractor` (Bun `.bun` / trailer extract).

## Toolkit package

`src/reveng/app_reverse_engineering/js_recovery_toolkit/`

| Stage | Module | Hermetic? |
|-------|--------|-----------|
| Tool probe | `external_tools.probe_external_tools` | yes |
| Bun extract | `external_tools.try_bun_extract_in_tree` | yes (in-tree) |
| Materialize | `js_project_materialize` | yes |
| Fingerprint v5 | `js_stale_map_transfer` | yes |
| Ensemble signals | `ensemble_signals` + `ensemble_index` | yes |
| Graph complete | `graph_complete` | yes |
| Behavior overlap | `behavior_probe` | yes |
| webcrack / wakaru | `external_tools.try_*` | optional (`--run-external`) |

CLI: `scripts/js_recovery_toolkit.py`

## Measured results (2026-08-09)

### Hermetic fixture (`test_samples/js_recovery_toolkit/`)

- Ensemble confirms **3** first-party paths on positive remix; **0** on mismatch.
- Behavior token recall **~0.82** vs oracle on positive.
- `npx webcrack` / `@wakaru/cli`: **available and exit 0** on fixture (dogfood).

### Operator-local Claude (stale map → Bun `stable/cli.js`)

| Method | first-party confirms | vs ~1902 oracle `src/` |
|--------|---------------------:|-----------------------:|
| Wave 5 fingerprint | **232** | ~12% |
| Wave 7 ensemble | **553** | **~29%** |

`decoded_exe_claim=false`. Still not 100%. Still not R-RALPH-2 close.

## How to run

```bash
export PYTHONPATH=src
python3.9 scripts/js_recovery_toolkit.py \
  --bundle path/to/bundle.js \
  --map path/to/stale.map \
  --oracle path/to/oracle \
  --output-dir /tmp/toolkit_out

# optional externals:
python3.9 scripts/js_recovery_toolkit.py ... --run-external

# Bun SEA:
python3.9 scripts/js_recovery_toolkit.py \
  --bun-binary /path/to/claude.exe \
  --map /path/to/stale.map \
  --output-dir /tmp/toolkit_bun
```

## Honesty

- Fixture ≠ Claude capability; operator-local counts stay out of git (receipt only).
- Optional CLIs are **adapters**, not guarantors of 100%.
- Next climb: Bun multi-module unpack quality + astdiff-style structural matching + mid-size CI corpus hill-climb.
