# CEO update — REVENG (2026-08-06)

Plain-language status after Scope C Phases 1–3 (preview + behavior probes). **Last CEO update:** none on file; this is the first dated briefing.

**Superseded for “what’s next” by:** [`ceo-update-2026-08-06-wave2.md`](ceo-update-2026-08-06-wave2.md) (native fixtures + probe + Sol APPROVE). Keep this file as the Phase 1–3 snapshot.

## Bottom line (one sentence)

We made the “ready to ship” lights honest, fixed managed-language rebuild without Ghidra, and wired real JS behavior into grades — **public preview can be claimed carefully**; full Scope C is still a multi-month program.

## What worked

1. **Honesty gates** — GA verifier no longer passes when analyze evidence is missing (`native-analyze-evidence`, `native-success-floor`).
2. **Managed rebuild** — Java/Python fixtures recompile via app adapters; four hermetic benches show `completed_without_behavior_checks` with analyze + recompile evidence.
3. **Python 3.9 survival** — CLI annotations + `spec_library` f-string fix so app RE imports on 3.9.
4. **JS behavior → grade** — `capability_report` actually attached on enrich; tier-2 `--help` + clean syntax can promote grade to `evidence_backed` (without claiming oracle magic).
5. **Optional npm pack dry-run** + **size-scaled probe timeouts**.
6. **Logger crash** — `REVENGLogger` now accepts stdlib-style `%-` args (sandbox warnings no longer explode).
7. **Test collection** — heavy conftest imports deferred into fixtures.
8. **Dogfood** — `verify_ga_readiness --profile ga` = **pass** (10/10) after the above.

## What “ship” means today (honest)

| Surface | Claim |
| --- | --- |
| CLI + app reverse-engineering (JS/JVM/Python managed) | Supported preview |
| Native PE/ELF deep rebuild | Limited — needs Ghidra / not hermetic on Linux CI for Windows binaries |
| Exploits | Experimental / non-GA (watermarked) |
| Full Scope C (phases 4–13) | **Not done** |

## Needs research (before big builds)

| ID | Question | Why it matters |
| --- | --- | --- |
| R-NATIVE-1 | Which **Linux-hermetic** native CLIs (Rust/C/Go) can replace Windows-only fixtures for ≥5 benches / ≥3 families? | Blocks **M1-NATIVE-FAM** |
| R-RALPH-2 | What’s the smallest engine change that moves tracked `cli.js` recall toward **0.8+** (measure baseline first)? | Blocks **RALPH-2** — harness ready, engine not |
| R-HEX-1 | Is hexyl still timeout-only on this host with current Ghidra/tooling? Fresh timed run + artifact check. | Blocks **M2** / Phase 4 |
| R-TSX-1 | Is `tsx`/`npx` worth productizing vs keeping `reveng_behavior_smoke.cjs` stub? | Closes **P3-BP-1** residual |
| R-PIPE-1 | Merge `pipeline/` + `pipelines/` vs keep documented split forever? | **M5-PIPE** full merge |
| R-SEC-1 | Sandbox class (Docker-only vs gVisor/Firecracker) before any exploit expansion | Phase 10 gate |
| R-VRL-1 | Minimum seeds + provider for honest VRL LLM round-trip gate | Phase 4 |

## Lessons (retain — see also skill + AGENTS)

See [`lessons-learned-scope-c-2026-08.md`](lessons-learned-scope-c-2026-08.md) and project skill `reveng-release-honesty`.

## Pointers

- Living ops index: repo-root [`backlog.md`](../../backlog.md)
- GA definition: [`reveng-ga-master-plan.md`](reveng-ga-master-plan.md)
- Capability / Ralph thread: [`reveng-capability-hardening-plan.md`](reveng-capability-hardening-plan.md)
- Native/Bun milestones: [`reveng-world-class-execution-backlog.md`](reveng-world-class-execution-backlog.md)
