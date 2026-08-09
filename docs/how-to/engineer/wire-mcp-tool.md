# How to: wire an MCP tool

> **Maturity:** MCP is a first-class surface for supported workflows (e.g. app RE) · individual tools may return **unsupported**
>
> Explicit refusal beats a silent success. See [maturity badges](../../support/maturity-badges.md), [Result contracts](../../explanation/result-contracts.md), [honesty rules](../../support/honesty-rules.md).

## Where MCP servers live

| Server module | Path |
| --- | --- |
| Core | `src/reveng/agent_sdk/mcp/servers/reveng_server.py` |
| Enterprise | `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py` |

Package root: `src/reveng/agent_sdk/`. Breadcrumbs under `src/reveng/agent_sdk/mcp/`.

## Always use `build_mcp_tool_response`

Import from `reveng.core.result_contracts`:

```python
from reveng.core.result_contracts import build_mcp_tool_response, make_evidence_item
```

Required discipline:

- Set `tool_name` to the public tool id.
- Put human text in `text=` (becomes `content`).
- Put structured fields in `payload=` — they are **merged at top level**.
- On failure / refusal, set `status=` and `error=` appropriately.
- Preserve provenance (default stages include `mcp_tool_execution`).

Schema version is `RESULT_SCHEMA_VERSION` (`"1.0"`).

## Never silently drop knobs

Tool arguments that change behavior (examples already in enterprise analyze: `enable_ai`, `quick_mode`, find-vulns style flags) must either:

1. Be forwarded into the underlying API (`REVENGAnalyzer(..., enable_ai=...)`), or
2. Be reflected in the response as ignored/unsupported with an explicit reason.

Regression coverage: `tests/unit/test_mcp_enterprise_knobs.py`. Adding a schema property without wiring it is a honesty bug.

## Unsupported must be explicit

When a capability is out of scope for that MCP path, return `status="unsupported"` (and a stable `error` / `reason` code). Example: binary malware detection on the core MCP server (`reveng_server.py`) builds a response with `status="unsupported"` and `error="binary_malware_mcp_unsupported"` instead of pretending to scan.

Tests: `tests/unit/test_mcp_binary_detect_malware_unsupported.py`, `tests/unit/test_mcp_contracts.py`.

Docs and matrix language should say **unsupported**, not “coming soon” as if it works.

## Suggested implementation steps

1. Define the tool schema / handler on the appropriate server class.
2. Call real domain APIs (`create_default_framework`, `REVENGAnalyzer`, …) — not test-only helpers.
3. Wrap every exit path (success, error, unsupported) in `build_mcp_tool_response`.
4. Echo or apply every advertised knob.
5. Add a unit test that fails if the knob is dropped or unsupported becomes success.
6. If the tool claims a supported workflow, align with [support matrix](../../support/support-matrix.md) / [Update support matrix](update-support-matrix.md).

## Related

- [Result contracts](../../explanation/result-contracts.md)
- [AI providers](../../explanation/ai-providers.md) (`enable_ai` gating)
- [Architecture overview](../../explanation/architecture-overview.md)
- [Support matrix](../../support/support-matrix.md)
