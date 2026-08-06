# Research: R-NATIVE-1 — Linux-hermetic native GA candidates

**Date:** 2026-08-06  
**Status:** researched (does **not** claim native GA)

## Purpose

Identify candidate CLIs for expanding the source-binary corpus to ≥5 benchmarks across ≥3 implementation families **on Linux CI**, without treating Windows-only assets as hermetic.

## Candidate table

| name | family / language | in `external/ga_sources` | Linux hermetic? | Notes |
| --- | --- | --- | --- | --- |
| hexyl | Rust CLI | yes | **conditional** | Primary native frontier; historically timeout-prone on analyze/recompile. Needs fresh timed dogfood (R-HEX-1) before GA row. |
| fd | Rust CLI | yes | **conditional** | Good `--version`/`--help` behavior target; build from source or pin release binary for Linux. |
| ripgrep (`rg`) | Rust CLI | yes | **conditional** | Strong hermetic candidate if Linux binary/build recipe pinned. |
| hyperfine | Rust CLI | yes | **conditional** | Benchmarking CLI; deterministic `--help`/`--version`. |
| bat | Rust CLI | yes | **conditional** | Same family as above (Rust); counts toward benches but **not** a new family. |
| winsw | Windows service wrapper | yes | **no** | Windows-oriented; not Linux CI hermetic. |
| opencode | Product binary (often Windows in matrix) | yes | **no** (for Linux CI) | Tracked elsewhere; not a hermetic Linux native family expander. |

**Family count today among Linux-plausible sources:** effectively **one family (Rust)** until a C/C++/Go fixture is added.

## Gap to ≥3 families

To close **M1-NATIVE-FAM** honestly, add at least two non-Rust hermetic fixtures, for example:

1. Small **C** CLI (hand-written under `test_samples/` or vendored) with `--help`/`--version`
2. Small **Go** or **C++** CLI similarly

Do **not** count Windows-only `winsw`/`opencode` toward the Linux hermetic gate.

## Non-goals

- Declaring native GA or raising marketing claims
- Running full Ghidra reconstruct loops in this research note
- Replacing managed-language hermetic benches (Java/Python) already green

## Recommendation

1. Keep managed-language hermetic rows as the GA preview backbone.
2. Treat Rust sources (hexyl/fd/rg/hyperfine) as the first native family once Linux build/binary recipes are pinned and R-HEX-1 clears timeout honesty.
3. Add C + Go (or C++) micro-CLIs before claiming ≥3 families.
4. Leave **M1-NATIVE-FAM** open until fixtures + tracked report rows exist.

## Acceptance for this research item

- [x] ≥5 named candidates inventoried with hermeticity notes  
- [x] Explicit non-claim of native GA  
- [x] Pointer recorded in `backlog.md`
