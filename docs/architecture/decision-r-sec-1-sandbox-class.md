# R-SEC-1 — Sandbox class before exploit expansion (2026-08-06)

**Status: DECISION ONLY.** No exploit capability is added, expanded, or ungated by this document or by Wave A. No change to `SEC-EXP-1` EXPERIMENTAL / non-GA watermark.

## Current surface (measured, not changed)

Modules under `src/reveng/exploits/` (inventory only):

- `exploit_chain_generator.py`
- `heap_exploit_engine.py`
- `rop_chain_builder.py`
- `shellcode_generator.py`
- `__init__.py`

CLI gating (unchanged): `src/reveng/cli/__init__.py` advertises exploit generation as **EXPERIMENTAL (non-GA)** (help/description around the exploit subcommand; runtime banner `REVENG Exploit Generation — EXPERIMENTAL (non-GA)`).

Existing Docker isolation for malware behavioral tracing (preview class, not an exploit expander): `src/reveng/malware/docker_sandbox.py` — `DockerSandbox` class.

## Decision

**Docker-only minimum for preview.** Before any exploit-surface expansion:

1. Preview / dogfood isolation class is **Docker** (`DockerSandbox` or equivalent container isolation with proven FS/network/time caps).
2. **Firecracker** and **gVisor** are deferred — research/ops options for a later hardening wave, not Wave A requirements.
3. **No exploit expansion** in Wave A: no new generators, no watermark relaxation, no GA claim, no new CLI paths that execute exploit payloads.

Exploit surfaces remain **EXPERIMENTAL / non-GA** until a later phase proves stronger isolation if expansion is ever authorized. Phase 10 / Track J remains gated on honesty about sandbox class, not on a calendar date.

## Explicitly out of scope for Wave A

- Building Firecracker/gVisor proofs
- Expanding exploit generation or chaining
- Changing any EXPERIMENTAL watermark
- Editing `src/reveng/exploits/**`
