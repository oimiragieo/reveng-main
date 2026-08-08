# TG-audit fixups receipt (2026-08-08)

Plan: `docs/superpowers/plans/2026-08-08-reveng-tg-audit-fixups.md`  
Thinktank plan: Sol **APPROVE_WITH_NITS** (R9).  
Thinktank impl: Sol **APPROVE_WITH_NITS** (`docs/architecture/thinktank-tg-audit-impl-verdict-r1.md`); schema honesty nits + expanded behavioral tests closed on follow-up.

## Shipped this wave

- JS `oracle_dir` / filename-set `benchmark_scorecard` wiring through framework → JS adapter
- Enterprise MCP knobs applied or explicitly unsupported (no silent F841 drops)
- Binary MCP `detect_malware` → explicit `unsupported`
- Deobfuscator placeholder stages excluded from `stages_applied`; fail-closed success
- `enable_ai=False` whole-analyzer AI off (steps 1/3 + enhanced + preflight)
- Focused suite: 33 green (+ tracked capability xfail lifted)

## Deferred (D1–D6)

| ID | Item |
| --- | --- |
| D1 | LibAFL `fuzz_until_divergence` |
| D2 | Mega-file splits |
| D3 | Full CFG/fold/DCE engines |
| D4 | DnSpy installer TODO |
| D5 | java_ai_analyzer cloud NotImplemented |
| D6 | Hollow native analyze_report_exists rows (measured, not gate-flipped) |
