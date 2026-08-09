# CEO update — 2026-08-08 (post tg-audit merge + CI honesty)

Plain-language status after merging PR **#119** (`5a71ad65`) and a follow-up tg audit of wiring / CI.

## One sentence

We shipped honesty wiring for JS oracles / MCP / AI gates, cleaned a pile of broken CI, and **GA baseline is green** — but **honesty CI still cannot install the fat dependency set**, and most of the product roadmap is still open.

## What worked

- **Merged Scope C history + tg-audit P0/P1** onto `origin/main` (was ~75 commits ahead locally).
- **Baseline GA gate green** on the merge tip (app corpus paths fixed for Linux; Windows `\` no longer breaks every row).
- **Code quality / lint** green on the honesty path (black/isort/import-linter).
- **Product honesty wiring** (already in #119): JS `oracle_dir` scorecard through framework→adapter; MCP knobs not silently dropped; binary `detect_malware` explicitly unsupported; deobfuscator placeholders not claimed as applied; `enable_ai=False` really turns AI off.
- **Closed Dependabot floods** twice (pre- and post-merge) instead of blind-merging risky bumps (`secrets` package, transformers major, etc.).
- **Follow-up fixes (this update):** slim `requirements-honesty.txt` for Wave B/C CI; remove fake `ghidramcp>=0.1.0` PyPI pins; backlog tests accept Phase 5 **partial** thin honesty.

## What is broken / not wired (tg audit snapshot)

| Item | Status |
| --- | --- |
| Wave B / Phase 5 honesty jobs | Were red: pip **`resolution-too-deep`** on full `requirements.txt` (fix: slim honesty requirements — land with this update) |
| Integration CI | Red: **`ghidramcp>=0.1.0` not on PyPI** (fix: comment out pin — land with this update) |
| Docs linkcheck | Red: `docs.reveng-toolkit.org` DNS + bad `#L` links (soft-fail; content debt) |
| Docker Hub push on `main` | Red: missing `DOCKER_USERNAME`/`PASSWORD` secrets (ops, not code) |
| Full unit matrix | Soft-fail / noisy: platform angr/unicorn builds, backlog invariants (phase 5), optional fixtures |
| **D1–D6 deferred** from tg-audit | Still deferred: LibAFL, mega splits, full CFG/fold/DCE, DnSpy installer, java AI cloud NI, hollow native rows |
| Issue **#101** | Open: rich local Capstone pseudocode (36 xfails) |

## Research still needed

| ID | Question |
| --- | --- |
| **R-RALPH-2** | Smallest engine wedge for cli.js 0.8+ recall (baseline already measured) |
| *(no new research for CI)* | Honesty slim-install is an engineering fix, not research |
| Optional later | Whether to resurrect a real Ghidra MCP package or keep fallback forever |

Closed research (do not re-open): R-NATIVE-1, R-RALPH-2-BASELINE, R-HEX-1, R-TSX-1, R-PIPE-1, R-SEC-1, R-VRL-1.

## Lessons learned since last CEO update (wave3 / charter) — L25+

See `docs/architecture/lessons-learned-scope-c-2026-08.md` **L25–L32**. Short list:

1. **Unpushed local `main` ≠ shipped** — ~75 Scope C commits sat local until a feature PR carried them.
2. **Black/pytest “security” bumps that need py≥3.10 break the py3.9 floor.**
3. **Windows path separators in `.reveng` JSON break Linux corpus (baseline hollow-red).**
4. **Full `requirements.txt` in honesty CI → `resolution-too-deep`** — thin gates need thin installs.
5. **`ghidramcp>=0.1.0` is a fiction on PyPI** — pinning it fails integration by construction.
6. **Alive CI watchers ≠ merge authority** — branch unprotected; merge landed while honesty still installing.
7. **Dependabot recreates the flood the day you merge** — close again; batch review later.
8. **Phase 5 `partial` is honest** — tests that demand `open` for all of 5–13 fight authorized thin honesty.

## Full backlog pointer

**Living index:** root [`backlog.md`](../../backlog.md) — sections A–K (shipped Phase 1–3, open product M*, research queue, phases 1–13, capability leftovers, parked T3, dogfood, decisions, **full roadmap index J**).

Do not duplicate every row here; CEO reads `backlog.md` for ALL ids. Snapshot of still-open poles: M1 / M1-NATIVE-FAM, M2 (world-class), M4 residual, M5, RALPH-2, phases 6–13 (await Sol), EPIC/FEAT/REV/V6 open rows in section J, issue #101, D1–D6.

## Ask of the CEO

1. Approve landing the honesty slim-install + ghidramcp pin fix on `main` (this PR/commit).
2. Decide whether Docker Hub / docs DNS are ops priorities this week or stay soft-fail.
3. Sol stop/go still required before product work on phases **6–13**.
