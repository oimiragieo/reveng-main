# How to: Reverse a Bun single-executable

> **Maturity:** preview / limited depending on sample and rebuild path
>
> Bun-aware `analyze` / `recompile` / `build-bun-sea` are specialized PE routes — not the same as claiming native Ghidra recompile GA. Deep guide: [Bun executable reversing](../../user-guide/bun-reversing.md).

## Goal

Detect a Bun-packed Windows PE, extract the embedded JavaScript / BunFS payload, review Bun analysis reports, and optionally rebuild via the Node SEA path documented in the user guide.

## Prerequisites

- Working `reveng` CLI — [Install and triage](../../tutorials/analyst/01-install-and-triage.md)
- A Bun single-file executable (not every `.exe` is Bun)
- For SEA rebuild: Node/npm toolchain as described in the user guide
- Read [When Ghidra is required](when-ghidra-is-required.md) so you do not escalate to Ghidra unnecessarily for JS recovery

## Steps

1. Confirm packer / Bun signals:

```bash
reveng detect-packer path/to/sample.exe
```

2. Run analyze (Bun-aware routing kicks in when markers match):

```bash
reveng analyze path/to/sample.exe --output-dir analysis_bun_sample
```

3. Review the deep field list and interpretation in:

→ **[Bun executable reversing (user guide)](../../user-guide/bun-reversing.md)**

Key report surfaces include `bun_analysis.json`, recovered `*_bundle.js`, optional `*_bunfs/`, and `normalized_project` metadata.

4. Optional rebuild via Node SEA:

```bash
reveng recompile path/to/sample.exe --output-dir analysis_bun_sample
# or dedicated:
reveng build-bun-sea path/to/sample.exe --output-dir analysis_bun_sample
```

5. If you have a recovered `.js` bundle (not only the PE), also run the supported app RE path:

```bash
reveng reverse-engineer-app path/to/recovered_bundle.js \
  --language javascript \
  --output-dir analysis_bun_app_re
```

See [App RE JavaScript](app-re-javascript.md).

## Expected outputs

| Artifact | Meaning |
| --- | --- |
| `bun_analysis.json` | Bun detection, recovery, normalization, escalation guidance |
| `*_bundle.js` / bunfs tree | Extracted JS / virtual FS when recovery works |
| `normalized_project/` | Node-oriented workspace for cleanup / SEA |
| `bun_sea_build.json` / `bun-sea.exe` | SEA rebuild evidence when rebuild succeeds |
| App RE `SPECS/` + `analysis.json` | Validation/evidence if you also ran `reverse-engineer-app` |

Equivalence language in Bun rebuild reports (`equivalence_validation`, `report_severity`) is rebuild-risk framing — not malware verdict and not native GA.

## Failure modes

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| No Bun route | Not a Bun PE / weak markers | Stay on generic triage/analyze; do not force Bun claims |
| Empty bunfs | Recovery mode limited | Read `recovery_mode` / warnings in `bun_analysis.json` |
| SEA build fails | Missing Node/npm or bad normalization | Follow user guide prerequisites; check `sea_build.verification` |
| Treating Bun success as native GA | Wrong maturity frame | [Support matrix](../../support/support-matrix.md) · [Honesty rules](../../support/honesty-rules.md) |

## Related

- [Bun executable reversing](../../user-guide/bun-reversing.md)
- [Bun escalation paths](../../architecture/bun-escalation-paths.md)
- [App RE JavaScript](app-re-javascript.md)
- [Maturity badges](../../support/maturity-badges.md)
