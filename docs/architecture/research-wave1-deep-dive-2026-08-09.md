# Research — Wave 1 deep-dive inputs (2026-08-09)

**Exa MCP:** unavailable this session (`GetMcpTools` pattern Exa → 0 servers). Fresh research via **WebSearch/WebFetch** (labeled). Re-run with Exa MCP when authenticated.

## Competitive landscape (fresh web, 2026)

| Competitor / trend | Edge-case idea for REVENG | Honesty note |
| --- | --- | --- |
| **Sleuthre** (Rust RE + native MCP, recompile-diff) | Competitors ship **recompile→diff** as a first-class tool; REVENG VRL is the analogue — must not claim parity without measured corpus | VRL-LLM-1 done for micro; hexyl still toolchain-broken |
| **Glaurung** (AI-native RE) | Agent-first pipelines; pressure to overclaim AI when `enable_ai=False` | Wave 0 wired `--no-ai`; keep bidirectional tests |
| **Ghidra-MCP** (200+ tools) | Tool-count arms race ≠ capability; prefer **honest unsupported** over hollow tools | REVENG should shrink or watermark experimental MCP surface |
| **Reversecore MCP** (r2/YARA/angr) | Security-first MCP; dangerous tools need labels | Align with actlint-style declaration honesty |
| **actlint / mcp-trust / mcpgrade** | **Declared vs derived risk** for MCP tools; under-declared is worst | New Wave-1+ research/epic: MCP annotation honesty gate (not product GA) |

### Pinned sources (accessed 2026-08-09; Exa MCP unavailable → WebSearch/WebFetch)

| Topic | URL |
| --- | --- |
| Sleuthre (recompile-diff + MCP) | https://github.com/kidoz/sleuthre |
| actlint (declared-vs-derived MCP honesty) | https://github.com/formael/actlint |
| actlint DEV writeup (31-server study) | https://dev.to/formael/are-your-mcp-servers-safety-labels-honest-a-one-command-check-and-what-it-found-on-31-popular-1ml3 |
| Unicorn cmake &lt;3.5 removal / macos-15 | https://github.com/unicorn-engine/unicorn/issues/2263 |
| reccmp (related recompile-compare toolchain) | https://github.com/isledecomp/reccmp |

Also noted (not Wave-1 blockers): Glaurung, Ghidra-MCP, Reversecore MCP — names only until measured against REVENG corpus.

## CI research — unicorn/angr (CI-UNICORN-BUILD-1)

- Root cause class (verified unicorn#2263, accessed 2026-08-09): modern CMake removed compatibility with `cmake_minimum_required` **&lt; 3.5**; old unicorn source builds fail on GHA macOS-15 when building from source.
- Community workaround: `macos-15-intel` or ensure **binary wheels** / newer unicorn matching angr.
- REVENG posture for Wave 1: **do not claim fixed native angr** — soft-fail or exclude angr-heavy matrix legs; document measured status; backlog row stays **`partial`**.

## tg-led code smells (this session)

- Installer stubs: `dependency_manager.py` maps `dnspy`/`uncompyle6`/`exeinfo_pe`/`x64dbg`/`imhex`/`lordpe` → `None` with TODO (REV-P0-INSTALLERS).
- `tg prepare` primary for “honesty stubs” → `ghidra_mcp_connector.ai_analyze_function` (confidence 0.94) — review for hollow AI claims when Ghidra/MCP absent.
- Many workflows already `continue-on-error: true` for docs-link / matrix noise — soft-red ≠ merge blocker but still confuses operators (L39).

## Edge-case ideas (competitive → backlog candidates)

1. **MCP annotation honesty** — under-declared destructive tools (actlint pattern).
2. **Recompile-diff competitor parity research** — measure VRL vs Sleuthre-style claim without marketing.
3. **AI-off bidirectional** — already Wave 0; extend to Ghidra MCP connector path.
4. **Installer None ≠ silent success** — callers must get `unsupported` not pretend install.
5. **Tool-count vanity** — refuse adding MCP tools without validation_grade/evidence contract.

## Explicit non-goals this wave (L33)

RALPH-2 engine, native `required:true`, #101 full renderer, phases 6–13 product, exploit expansion, “all backlog done.”
