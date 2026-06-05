# Bun Executable Reversing

REVENG has a specialized workflow for Bun single-file executables embedded in Windows PE binaries. Instead of treating them as generic packed binaries, the toolkit extracts the bundled JavaScript payload, attempts Bun virtual filesystem recovery, normalizes the recovered source into a Node-compatible workspace, and can rebuild that workspace through the Node SEA path.

## What REVENG Detects

The Bun-aware path looks for strong, additive indicators such as:

- a `.bun` PE section
- the Bun trailer marker
- `// @bun` JavaScript markers
- Bun virtual paths like `B:/~BUN/...`
- startup flow that reaches `.bun`-backed targets

When those signals are present, `analyze`, `decompile`, `unpack`, and `recompile` switch to Bun-specific handling.

## Recommended CLI Workflow

### 1. Confirm the target is Bun-aware

```bash
reveng detect-packer sample.exe
reveng analyze sample.exe --output-dir analysis_sample
```

Primary outputs:

- `analysis_sample\bun_analysis.json`
- `analysis_sample\<binary>_bundle.js`
- `analysis_sample\<binary>_bunfs\...` when virtual files are recovered

### 2. Review the recovered source and startup triage

Start with these Bun analysis report sections:

- `canonical_recompilation_input`
- `normalized_project`
- `runtime_escalation`
- `native_stub.startup_targets`
- `native_stub.startup_graph`
- `native_stub.handoff_signals`
- `native_stub.runtime_readiness`
- `native_stub.dump_guidance`
- `report_severity`

These surfaces tell you:

- which recovered artifact is the cleanest source candidate
- whether Bun handoff is strongly evidenced
- whether startup looks static enough to keep analyzing offline
- when to escalate to breakpoints, dumping, or import reconstruction

### 3. Normalize for source recovery and manual cleanup

`analyze` and `recompile` both create a normalized workspace when a canonical Bun input is available.

Key normalized outputs:

- `normalized_project.entrypoint_path`
- `normalized_project.semantic_checks`
- `normalized_project.postprocessing_hooks`
- `normalized_project.warnings`

Interpretation:

- `semantic_checks` explains dependency/runtime concerns explicitly
- `postprocessing_hooks` recommends additive cleanup tools such as `webcrack`, `wakaru`, `tsmap-extract`, or `recover-source`
- `warnings` is the human-readable subset of warning-severity semantic checks

### 4. Rebuild through Node SEA

```bash
reveng recompile sample.exe --output-dir analysis_sample
```

Primary rebuild outputs:

- `analysis_sample\bun_sea_build.json`
- `analysis_sample\normalized_project\`
- `analysis_sample\normalized_project\bun-sea.exe`

Key rebuild report sections:

- `runtime_escalation`
- `equivalence_validation`
- `differential_validation`
- `sea_build.verification`
- `report_severity`

`differential_validation` compares the canonical Bun input against the normalized entrypoint and records:

- artifact hashes and sizes
- whether the content changed
- preserved, added, and missing runtime features
- expected Bun-specific rewrites such as `import.meta.require -> createRequire(import.meta.url)`

`sea_build.verification` checks the rebuilt workspace itself:

- normalized entrypoint presence
- SEA blob generation
- output executable generation
- dependency-manifest alignment
- Bun marker continuity
- shim continuity

## Interpreting `equivalence_validation`

`equivalence_validation` is the build-side summary that turns low-level differential and verification checks into an explicit equivalence claim.

Key fields:

- `status`
- `equivalence_level`
- `confidence`
- `reasons`
- `recommended_validations`
- `evidence`

Typical equivalence levels:

- `artifact_identity_candidate`: the normalized entrypoint matches the canonical input exactly and rebuild verification is clean
- `semantic_candidate`: the normalized source changed, but only within a verification-clean path, so semantic equivalence is the strongest supported claim
- `structural_candidate`: no hard failures were found, but warnings still limit confidence
- `not_equivalent`: differential or verification failures materially undermine the current rebuild
- `insufficient_evidence`: a full equivalence claim is not justified yet

`recommended_validations` is intentionally practical and TDD-friendly: it points you toward black-box characterization checks, structural diff review, or direct runtime comparison before raising confidence further.

## Interpreting `report_severity`

Both Bun analysis and Bun rebuild reports now emit `report_severity`.

This is a compact `reconstruction_risk` summary, not a malware verdict. It rolls up attention factors from:

- native startup complexity
- dump/import-reconstruction guidance
- semantic warnings
- differential validation failures or warnings
- SEA build verification failures or warnings

Practical guidance:

- `low`: static recovery and rebuild look straightforward
- `medium`: expect manual review or targeted cleanup
- `high`: static-only recovery may be incomplete; plan for runtime observation or verification
- `critical`: rebuild verification failed in a way that undermines trust in the current artifact

## Interpreting `runtime_escalation`

Both Bun analysis and Bun rebuild reports now emit `runtime_escalation`.

This is an analyst-facing contract that summarizes whether static recovery is still sufficient and, if not, what to do next in priority order.

Key fields:

- `recommended`
- `status`
- `confidence`
- `reasons`
- `next_steps`
- `evidence`

Typical statuses:

- `static_sufficient`: stay in static mode and keep working from the normalized workspace
- `targeted_runtime_observation`: set breakpoints before claiming stronger fidelity
- `runtime_dump_recommended`: capture memory near Bun handoff because runtime materialization is likely
- `manual_review_required`: report-side warnings outpace the currently available runtime evidence

`next_steps` is intentionally additive. It points you toward targeted breakpointing, memory dumping, import reconstruction, or diff/verification review without silently mutating recovered artifacts.

## MCP Parity

Enterprise MCP Bun recompilation responses keep the full nested `bun_build_report` and also lift the most useful report surfaces to first-class payload keys:

- `bun_report_severity`
- `bun_differential_validation`
- `bun_runtime_escalation`
- `bun_equivalence_validation`
- `bun_build_verification`

This lets agent consumers reason over Bun rebuild quality without re-parsing the full report structure.

## Known Limits

The current Bun workflow is intentionally conservative:

- static recovery depends on recognizable Bun layouts, markers, and suffix-aware artifact validation
- some real samples expose only partial module metadata
- normalized source is evidence-preserving, not guaranteed source-identical
- SEA rebuild verification is structural and semantic, not full runtime equivalence

When static recovery stalls, use the escalation guidance in [Bun Escalation Paths](../architecture/bun-escalation-paths.md).
