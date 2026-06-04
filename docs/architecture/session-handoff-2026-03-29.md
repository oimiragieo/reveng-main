# Session Handoff 2026-03-29

## Current State

- Claude Code is the active JavaScript benchmark target.
- Droid (`C:\dev\droid.exe`) is the next native benchmark target.
- Codex/Cursor-style packaged agent runtimes are the next packaged-app benchmark class after Droid.

## What Was Completed

### Claude benchmark pipeline

- Live Claude bundle analyzed from:
  - `C:\Users\oimir\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`
- Current installed Claude Code version observed:
  - `2.1.87`

### JS workflow improvements

- `reveng-js reverse-engineer-bundle` now supports:
  - `--oracle-dir`
  - `--run-webcrack`
- Output now includes:
  - `SPECS`
  - reconstructed source tree
  - benchmark scorecard
  - optional `webcrack` output
  - shared IR artifact

### Claude benchmark artifacts

- Scored Claude run:
  - `analysis_claude_code_2026_03_29_scored`
- Webcrack-enabled Claude run:
  - `analysis_claude_code_2026_03_29_webcrack`
- Claude IR run:
  - `analysis_claude_code_ir`

### Claude benchmark result

- Oracle used:
  - `C:\dev\projects\Claude_Code_Reverse_Engineered`
- Current benchmark scorecard on the scored run:
  - `domain_recall = 1.0`
  - `domain_precision = 1.0`
  - `token_signal_score = 1.0`
  - `overall_score = 1.0`

Important:
- This means the generated domain tree matches the August oracle structure.
- It does **not** mean literal upstream source-equivalent recovery.

## Shared IR

- Shared IR model added at:
  - `src/reveng/ir.py`
- JS bundle workflow now emits:
  - `artifacts/project_ir.json`
- IR plan doc:
  - `docs/architecture/reveng-ir-plan.md`

## Next Step

Use Droid as the next benchmark target:

- Target:
  - `C:\dev\droid.exe`
- Goal:
  - add native/Ghidra IR export using the existing analyzer and Ghidra integration
- Then:
  - benchmark Droid on the same shared IR path
  - after Droid, move to Codex/Cursor-style packaged runtime targets

## Suggested Resume Prompt

Continue from `docs/architecture/session-handoff-2026-03-29.md`.

Current state:
- Claude JS benchmark is working and emits `SPECS`, reconstructed source tree, oracle scorecard, optional `webcrack` output, and `project_ir.json`
- next target is `C:\dev\droid.exe`
- next implementation task is native/Ghidra IR export into the shared IR contract in `src/reveng/ir.py`
