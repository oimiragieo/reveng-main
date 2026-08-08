# Phase 4 — Track A hexyl honesty attribution exit (2026-08-07)

**Status:** Phase 4 Track A **honesty attribution exit** evidenced (probe v1.3 +
re-stamp). This does **not** close world-class **M2** (hexyl frontier hardening).
M2 stays **partial** / open until analyze/recompile artifacts and behavior checks
meet `reveng-world-class-execution-backlog.md` M2 acceptance.

Does **not** close M1-NATIVE-FAM. Does **not** flip any native fixture
`required: true`. Process `completed` ≠ native GA (DF-5).

## What this closes (honesty only)

R-HEX-1 proved a bounded `reveng analyze` on the hexyl **subject** ELF can finish
inside the 120s budget (`status=completed`, ~4–5s). That alone did not close M2.

This Phase 4 Track A slice adds **semantic stream attribution** (probe **v1.3**)
and a live re-stamp so DF-5 markers in stdout/stderr are recorded in evidence
fields instead of left null — a **frontier honesty** slice, not engine
reconstruction closeout:

| Field | Wave B stamp (v1.2) | Phase 4 stamp (v1.3) |
| --- | --- | --- |
| `probe_version` | `1.2` | `1.3` |
| `semantic.native_fallback_empty` | `null` (missed) | `true` when streams show empty native fallback |
| `semantic.semantic_reason` | `null` | `native_fallback_empty` / `pipeline_partial_success` |
| Honesty | process green looked “clean” | process green + empty fallback is explicit |

Streams on this host still show `Pipeline status: partial_success` and
`Native fallback analysis returned no analysis_data` while the process exits 0 —
exactly the DF-5 shape. v1.3 attributes that into `semantic` so a green process
status cannot be mistaken for native GA.

## What remains open (world-class M2)

Per `docs/architecture/reveng-world-class-execution-backlog.md` §M2, still
required before marking M2 `done`:

* tracked `run_source_binary_benchmark.py --benchmark hexyl` analyze **and**
  recompile report artifacts (not timeout-only / analyze_failed forever)
* original-behavior checks for hexyl remaining passing
* behavior comparisons present when a rebuilt binary is produced
* hardening slices from `HARDENING_PRIORITIES.md` with regression tests

Probe v1.3 attribution does **not** satisfy those gates.

## Evidence paths

| Artifact | Role |
| --- | --- |
| `reports/native_analyze_probe/latest.json` | Canonical multi-result report (`probe_version: "1.3"`) |
| `reports/native_analyze_probe/2026-08-07T191850Z.json` | Sole stamp; byte-identical to `latest.json` |
| `reports/native_analyze_probe/wave_b_job.json` | Job: `hello_go_analyze` + `hexyl_subject`; analyze_cmd = `/usr/bin/python3.9 -m reveng analyze` |
| `scripts/probe_native_analyze_timeout.py` | Probe implementation (`PROBE_VERSION = "1.3"`) |
| `tests/unit/test_probe_native_analyze_timeout.py` | Unit coverage for stream attribution |

### Phase 4 dogfood result (this host)

| id | status | elapsed (approx) | semantic_reason | native_fallback_empty |
| --- | --- | --- | --- | --- |
| `hello_go_analyze` | `completed` | ~8s class | `native_fallback_empty` | `true` |
| `hexyl_subject` | `completed` | ~5s class | `native_fallback_empty` | `true` |

Analyze command for both arms: `/usr/bin/python3.9 -m reveng analyze` (not
`tool_absent` on a hexyl CLI).

## Hexyl subject rebuild

| Item | Value |
| --- | --- |
| Recipe | `scripts/build_hexyl_fixture.sh` |
| Sources | `external/hexyl-benchmark/hexyl` (sharkdp/hexyl tag `v0.17.0`; cloned when missing) |
| Cargo | present (`~/.cargo/bin/cargo`) |
| Installed ELF | `test_samples/native/hexyl/build/hexyl` (gitignored) |
| Phase 4 rebuild sha256 | `3d26048bbbaee5e87a4613b4e21e898185e15b43cf43bd4fe74cc5d2dbaa5dba` |
| Wave B historical sha256 | `e2040b5deda5900a152ac28a7444ba565b2b0d46861a3efefafaf074f1a16dfc` |

Cargo release builds are not bit-identical across hosts/toolchains; the Phase 4
pin matches this rebuild. Fixture presence still ≠ analyze capability.

## Negative / control (must remain true)

* No native GA manifest entry flipped to `required: true` from process `completed`.
* `M1-NATIVE-FAM` stays **open**.
* World-class **M2** stays **partial** (this doc is honesty attribution only).
* Exploits / R-SEC-1 unchanged (no expansion).

## Disposition

Phase 4 Track A **honesty attribution exit** (v1.3 attribution + re-stamp + this
doc) is **evidenced**. Do **not** claim M2 `done`. Deeper hexyl
analyze/recompile/behavior hardening remains open; M1-NATIVE-FAM is the separate
`required: true` flip gate.
