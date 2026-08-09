# Result contracts

> **Maturity:** **supported** as the serialization contract for public MCP / app RE payloads · product overall **preview**
>
> Grades on a payload still need correct ladder interpretation — see [Reading validation grades](../support/reading-validation-grades.md). Honesty: [honesty rules](../support/honesty-rules.md).

Public analyzer, API, app RE, and MCP outputs share a small versioned vocabulary in `src/reveng/core/result_contracts.py`. Juniors extending surfaces should **reuse** these builders instead of inventing parallel JSON shapes.

## Schema version

```python
RESULT_SCHEMA_VERSION = "1.0"
```

Responses typically include:

- `schema_version` — currently `"1.0"`
- `result_type` — e.g. `mcp_tool_result`, `mcp_resource_result`, or app-analysis types set by enrich helpers
- `provenance` — inputs / artifacts / stages / references / tools
- Optional `evidence` items via `make_evidence_item` / `make_trace_reference`

Dataclass helpers: `ResultContract`, `AnalysisResultContract`, and siblings in the same module.

> Note: VRL IR uses a **different** schema constant (`SCHEMA_VERSION` / `IR_SCHEMA_VERSION` in `src/reveng/core/ir.py`). Do not conflate IR schema with result-contract schema.

## MCP builders

| Function | Purpose |
| --- | --- |
| `build_mcp_tool_response(...)` | Versioned tool reply; merges `payload` at top level; sets `content`, `status`, optional `error` |
| `build_mcp_resource_result(...)` | Versioned resource-read payload |

Example shape from `build_mcp_tool_response`:

- Always sets `schema_version`, `result_type="mcp_tool_result"`, `tool_name`, `status`, `content`, `provenance`
- `payload` keys are merged onto the response (so knobs/results stay visible — do not strip them)
- Failures / refusals should set `status` (including explicit `"unsupported"`) and `error` when appropriate

Used by:

- `src/reveng/agent_sdk/mcp/servers/reveng_server.py`
- `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`

See [Wire MCP tool](../how-to/engineer/wire-mcp-tool.md) for the engineer checklist (never silently drop knobs; unsupported must be explicit).

## App RE enrichment

`src/reveng/app_reverse_engineering/contracts.py` imports `RESULT_SCHEMA_VERSION` and attaches validation / evidence / provenance via `enrich_app_analysis_payload`. Models in `models.py` / corpus rollups also pin the same schema version.

Validation **grades** for app RE are Ladder A (`build_validation_summary`) — documented in [Reading validation grades](../support/reading-validation-grades.md).

## Dual grades (do not mix)

| Ladder | Where | Doc |
| --- | --- | --- |
| A — App RE | `app_reverse_engineering/contracts.py` | [Reading validation grades](../support/reading-validation-grades.md) |
| B — VRL | `verification/models.py` `VALIDATION_GRADE_LADDER` | [VRL and verification](vrl-and-verification.md) |

Both may appear in reposide JSON, but they answer different questions. An app RE `evidence_backed` does **not** mean VRL converged, and vice versa.

## Tests

- `tests/unit/test_result_contracts.py`
- `tests/unit/test_mcp_contracts.py`
- `tests/unit/test_mcp_binary_detect_malware_unsupported.py` — explicit `status="unsupported"`

## Related

- [Architecture overview](architecture-overview.md)
- [App RE dispatch](app-re-dispatch.md)
- [Maturity badges](../support/maturity-badges.md)
- [Support matrix](../support/support-matrix.md)
