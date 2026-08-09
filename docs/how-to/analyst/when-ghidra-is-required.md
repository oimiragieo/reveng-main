# How to: Know when Ghidra is required

> **Maturity:** limited (`ghidra_backed_native_analysis`)
>
> Ghidra-backed native analysis is usable with known gaps — **not** GA-equivalent. Managed-language app RE does **not** require Ghidra. See [Support matrix](../../support/support-matrix.md).

## Goal

Decide whether your workflow needs a healthy Ghidra Analysis Server, or whether you should stay on the supported app reverse-engineering / triage paths.

## Prerequisites

- Familiarity with the matrix workflows: [Support matrix](../../support/support-matrix.md)
- Optional: ability to install/run the repo’s Ghidra server scripts if you escalate

## Decision table

| You want… | Ghidra needed? | Prefer |
| --- | --- | --- |
| Triage / first-pass IR on a PE | Usually **no** | `reveng triage` / light `analyze` |
| App RE on JS / JVM / Python / .NET | **No** | `reveng reverse-engineer-app` |
| Managed-language recompile via app adapters | **No** | App adapters (matrix: `source_binary_reconstruction` managed path) |
| Bun JS recovery from a Bun PE | **No** for extraction | [Bun executable](bun-executable.md) |
| Deep native PE/ELF/Mach-O decompile | **Yes** | Ghidra Analysis Server + `analyze` / `decompile` |
| Native PE/ELF/Mach-O **recompile** | **Yes** | Healthy Ghidra server (`recompile --ghidra-url …`) |

`NativeAppAdapter` may exist in the codebase for experiments, but the **default app RE registry** is the managed languages — do not market native app RE as the GA path.

## Steps (when you do need Ghidra)

1. Install / provision Ghidra per project scripts (commonly):

```bash
python scripts/install_ghidra.py
python external/ghidra-server/ghidra_http_server.py
```

Default URL is often `http://127.0.0.1:13370`.

2. Point native recompile / decompile at the server:

```bash
reveng recompile path/to/native.exe \
  --output-dir analysis_native \
  --ghidra-url http://127.0.0.1:13370 \
  --ghidra-timeout 900

reveng decompile path/to/native.exe --timeout 120
```

3. For analyze-stage Ghidra timing:

```bash
reveng analyze path/to/native.exe \
  --ghidra-timeout 900 \
  --ghidra-retries 0 \
  --output-dir analysis_native
```

4. Still open evidence JSON — process completion is not native GA (**DF-5**).

## Expected outputs

- Decompile / recompile artifacts under your `--output-dir`
- Connection errors if the server is down (fail closed rather than inventing success)

## Failure modes

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Connection refused / timeout | Server not running | Start `ghidra_http_server.py`; check URL/port |
| Empty / stub native recovery | Unhealthy server or unsupported input | Do not claim GA; file evidence honestly |
| Used Ghidra for a `.jar` / `.pyc` | Wrong path | Switch to [app RE](../../tutorials/analyst/02-app-reverse-engineer.md) |
| Fixture PE “works” in CLI | `fixture_only` | [Honesty rules](../../support/honesty-rules.md) · native README |

## Related

- [Ghidra boundary (explanation)](../../explanation/ghidra-boundary.md)
- [Triage a PE](triage-pe.md)
- [Maturity badges](../../support/maturity-badges.md)
- [Reading validation grades](../../support/reading-validation-grades.md)
