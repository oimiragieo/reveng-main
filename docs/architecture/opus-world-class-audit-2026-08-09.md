# Opus-class world-class audit — 2026-08-09

**Status:** Cursor Task Opus quota exhausted; CLI Opus 1m seat used for synthesis. Evidence from adversarial wiring scan + prior tg-audit/docs wave.  
**Product:** beta `4.0.0` / public preview — not full Scope C GA.  
**SoT:** `docs/support_matrix.json`, `docs/support/*`, `backlog.md`, `.cursor/skills/reveng-release-honesty/SKILL.md`.

## P0 — breaks designed E2E / honesty lies (fix now)

| ID | Title | Evidence | Impact | Fix shape | Effort |
| --- | --- | --- | --- | --- | --- |
| W-01 | Enterprise MCP advertises knobs it ignores (`unbundle_webpack`) | `reveng_enterprise_server.py` schema ~758–761 vs handler ~2256–2301 | Agents think unbundling ran; silent no-op | Wire or reject as `unsupported` with warning in tool result; test both arms | S |
| W-02 | `find_vulnerabilities` ignores `vulnerability_types` / `use_ai_analysis`; hollow clean result | Schema ~628–654; handler ~1941; false arm ~1987–1990 returns “No vulnerabilities found” | Looks secure when measurement never ran | Return explicit `could_not_measure` / unsupported when AI/types paths not executed; never “none found” on skipped path | M |
| W-03 | Brochure accuracy % in live MCP tool descriptions | `find_vulnerabilities` “90%+” ~623; `use_ml_renaming` “60-80%” ~748 | Honesty lie in agent-facing surface | Strip % claims; point at support matrix / experimental | S |
| W-04 | `NativeAppAdapter` exists but unwired from default framework + MCP language enum | `adapters/native.py`; missing from `adapters/__init__.py` / `create_default_framework()`; MCP enum omits `native` | Dead code looks like a feature | Either register + matrix+tests **or** document fixture_only/unwired and quarantine from docs as CUJ | S (doc) / L (register for real) |
| W-05 | CLI `analyze` cannot pass `enable_ai=False` though analyzer gate exists | `analyzer.py` gate ~148–158; `handle_analyze_command` ~921–926 no flag; basic MCP also omits | Operators cannot disable AI on main surface; docs teach the gate | Add CLI flag + MCP core param; test enable_ai False skips AI | S |

## P1 — world-class integration gaps

| ID | Title | Evidence | Impact | Fix | Effort |
| --- | --- | --- | --- | --- | --- |
| W-06 | Enterprise health checker dead imports + abstract NI | `enhanced_health_monitor.py` ~74, ~93–98 | Health lies or crashes | Fix import paths or mark unsupported; implement or remove | M |
| W-07 | `java_ai_analyzer` OpenAI/Anthropic NI | `java_ai_analyzer.py` ~233–237 | Cloud path marketed, local only works | Explicit unsupported providers in API/docs; don’t raise mid-flight as surprise | S |
| W-08 | Dual grade ladders still easy to conflate in API payloads | app `contracts.py` vs `verification/models.py` | Juniors misread trust | Namespace fields (`app_validation_grade` vs `vrl_grade`) or docs+schema discriminators | M |
| W-09 | Off-nav changelogs / system paper still teach dead paths + 95% | `docs/changelogs/v4–v6`, `reveng-system-paper.md` | Searchable lies | Banner “historical / not support claims” + fix entry paths | S |
| W-10 | Basic vs enterprise MCP capability parity unclear | `reveng_server.py` vs `reveng_enterprise_server.py` | Agents pick wrong server | Docs matrix of tools×server + shared honesty helpers | M |

## P2 — polish later

- Expand thin language how-tos further with sample oracle expectations
- Line-anchor engineer how-tos to stable symbols
- Quarantine aspirational v5/v6 from any “shipped” framing in search landing
- MCP “Enterprise” branding ≠ maturity (rename or badge)

## Explicitly NOT in scope this wave (research / product phases)

- **R-RALPH-2** engine wedge for cli.js 0.8+ recall
- M1-NATIVE-FAM hermetic analyze `required: true`
- M2 world-class hexyl beyond timed probe
- LibAFL / `fuzz_until_divergence` implementation (D1)
- Exploit expansion beyond Docker-only preview (R-SEC-1)
- Full nightly corpus blocking (M4 residual)
- Phases 6–13 product work (await Sol stop/go)
- Registering NativeAppAdapter as **supported** without corpus proof

## Clean / already fixed (do not re-open)

- Wave B/C honesty slim `requirements-honesty.txt`
- `ghidramcp>=0.1.0` commented out
- Core MCP binary `detect_malware` explicit unsupported
- Diátaxis dual-door docs + mkdocs nav (Wave A docs)

## Top 8 recommended fix wave

1. **W-03** Strip MCP brochure % from tool descriptions + unit/string tests  
2. **W-01** `unbundle_webpack` unsupported-or-wire + bidirectional test  
3. **W-02** Hollow vuln-scan honesty (no “none found” on skipped path) + tests  
4. **W-05** CLI `--no-ai` / `--enable-ai` + core MCP mirror + tests + docs  
5. **W-04** Doc/quarantine NativeAppAdapter as unwired (do **not** claim supported)  
6. **W-07** java_ai cloud providers → explicit unsupported responses  
7. **W-09** Historical changelog/system-paper honesty banners + path fixes  
8. **W-06** Health monitor: fail closed with real package checks or delete dead path  

Each item: code + pytest (prefer bidirectional) + update `docs/reference/mcp-tools.md` / tutorials as touched.
