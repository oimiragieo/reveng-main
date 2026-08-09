# Support matrix (human-readable)

> **Maturity:** supported (as the customer-facing boundary document)
>
> Machine source of truth: [`../support_matrix.json`](../support_matrix.json)

This page mirrors the JSON workflows. If Markdown and JSON disagree, **fix Markdown** (or update JSON via the engineer how-to) — release gates read the JSON.

## Supported

### CLI threat triage (`cli_triage`)

| Field | Value |
| --- | --- |
| Surfaces | CLI |
| Platforms | Windows, Linux, macOS |
| Scope | Core triage / reporting without deep reconstruction |
| Notes | Does not imply native recompile GA |

### App reverse engineering (`app_reverse_engineering`)

| Field | Value |
| --- | --- |
| Surfaces | CLI, API, MCP |
| Languages | JavaScript, JVM, Python, .NET |
| Scope | Adapter-driven `reverse-engineer-app` with SPECS / analysis.json / validation / evidence / provenance |
| Notes | Quality varies by input shape and optional tools (`ilspycmd`, `pyi-archive_viewer`, …). Tracked by app RE corpus. |

### Source-backed binary reconstruction (`source_binary_reconstruction`)

| Field | Value |
| --- | --- |
| Surfaces | CLI, API |
| Status | **supported** for **managed-language** paths |
| Managed | Java / Python / .NET-class inputs use **app adapters** — **do not require Ghidra** |
| Native | PE / ELF / Mach-O recompile still needs a healthy **Ghidra Analysis Server** → treat native recompile as **limited**, not GA-equivalent |
| Notes | Hermetic GA benches may report analyze+recompile evidence without full behavior checks — read the report |

## Limited

### Ghidra-backed native analysis (`ghidra_backed_native_analysis`)

| Field | Value |
| --- | --- |
| Surfaces | CLI, API, MCP |
| Platforms | primarily Windows, Linux |
| Notes | Requires external Ghidra; not all paths meet GA evidence/performance gates |

## Experimental

### Exploit generation (`exploit_generation`)

- Surfaces: CLI (`generate-exploit`)
- Watermarked **EXPERIMENTAL / non-GA**
- Not production-ready; Docker-only preview policy (R-SEC-1)

### Symbolic execution (`symbolic_execution`)

- Surfaces: CLI, API
- Coverage and operational depth uneven

## Doc-only honesty badges (not always in JSON)

| Badge | When |
| --- | --- |
| unsupported | MCP/API explicitly refuses (e.g. binary `detect_malware` on core MCP) |
| fixture_only | Native micro-fixtures without hermetic analyze GA |

## Related

- [Maturity badges](maturity-badges.md)
- [Honesty rules](honesty-rules.md)
- Analyst tutorial: [First app reverse-engineer](../tutorials/analyst/02-app-reverse-engineer.md)
