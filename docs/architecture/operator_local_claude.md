# Operator-local Claude / Bun dogfood (Wave 4)

**Do not commit** Anthropic recovered trees, extracted Bun VFS dumps, or full `cli.js` / `claude.exe` payloads into `reveng-main`.

## Provenance template (local only)

Record these fields in an **untracked** operator note (e.g. `/tmp/claude_dogfood_provenance.json`):

```json
{
  "package": "@anthropic-ai/claude-code",
  "version": "REPLACE_ME",
  "artifact_sha256": "REPLACE_ME",
  "extract_tool": "reveng.tools.anti_analysis.bun_extractor",
  "extract_root": "/tmp/claude_bun_extract/...",
  "materialization_mode": "bun_vfs|source_map|absent",
  "oracle_tree": "operator-local-only",
  "ralph_report": "/tmp/.../ralph_report.json",
  "notes": "Not ship-gating. Tracked micro-bundle is the Wave 4 gate."
}
```

## Suggested local flow

1. Extract Bun PE with the in-repo Bun extractor to a temp directory.
2. Point app-RE / Ralph at the recovered JS entry with `--oracle` set to an operator-local tree if you have one.
3. Prefer `output_dir/bunfs` (or `bun_vfs_dir=`) so Wave 4 materialization can copy VFS `root/**` into `project/`.
4. Keep scores out of git unless they are the **tracked micro-bundle** surface.

## Legal / honesty

Historical npm source-map disclosure is context only. Map-era name tables may not transfer to current Bun builds (`sourcemap_size=0` on dogfood). Do not claim “any `claude.exe` → full codebase.”
