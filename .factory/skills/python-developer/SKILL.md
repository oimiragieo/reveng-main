---
name: python-developer
description: Core python developer for the REVENG upgrade mission.
---

# Python Developer

NOTE: Startup and cleanup are handled by `worker-base`. This skill defines the WORK PROCEDURE.

## When to Use This Skill

Use this skill to implement the core python features, including the asynchronous pipeline, compiler-in-the-loop, ML forensics, and MCP integration.

## Work Procedure

1. Read the feature description and constraints from `mission.md` and `AGENTS.md`.
2. Run the scoped baseline (`pytest tests/unit/ tests/integration/ -n 4 --ignore=tests/performance --ignore=tests/poc`). If it fails due to pre-existing issues documented in `AGENTS.md`, document the failure and continue — do NOT stop just because the baseline is red from pre-existing issues. **Scrutiny note:** If validator exit codes are non-zero but all failures are identical to prior scrutiny rounds (pre-existing), classify them as passing and proceed to feature review.
3. Write tests first (red). Locate the appropriate test file in `tests/unit/` or `tests/integration/` and add the test cases. Run `pytest` targeted at your test file to confirm they fail. **TDD exception**: if the feature's implementation already exists (e.g., landed in a prior session), skip straight to verification and lint cleanup — no need to manufacture a red state.
4. Implement the feature in the source codebase (`src/reveng/...`) to make the tests pass (green). Ensure type hints and proper error handling.
5. Run `pytest` targeted at your feature's tests again to verify your implementation.
6. Run `flake8 src/reveng/<modified-files> --extend-ignore=E501,F811,E203` on your changed files to catch new lint issues (ignore pre-existing violations with `--extend-ignore`).
7. If the feature touches CLI output or behavior, run manual verification using `python src/reveng/cli/reveng.py` (ensure `PYTHONIOENCODING=utf8` is set if on Windows).
8. When adding module-level test skips for optional dependency files, use `pytestmark = pytest.mark.skip(reason="...")` after importing pytest at the top of the test file rather than a `sys.exit(1)` fallback.
9. Provide a thorough handoff.

## Example Handoff

```json
{
  "salientSummary": "Implemented asynchronous execution in pipeline_engine.py using asyncio.gather. Wrote tests in test_pipeline_engine.py which failed initially, then passed after implementation. Verified execution speed improvements on mock tasks.",
  "whatWasImplemented": "Refactored the `execute` method in `pipeline_engine.py` to be an async function. Added error isolation blocks around each node's execution.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {
        "command": "pytest tests/unit/test_pipeline_engine.py",
        "exitCode": 0,
        "observation": "All 4 new tests passed, verifying async concurrency and error isolation."
      }
    ],
    "interactiveChecks": [
      {
        "action": "Ran `python src/reveng/cli/reveng.py analyze dummy.exe` manually",
        "observed": "Pipeline executed successfully and outputted the summary report without blocking on sleep intervals."
      }
    ]
  },
  "tests": {
    "added": [
      {
        "file": "tests/unit/test_pipeline_engine.py",
        "cases": [
          {"name": "test_async_execution_time", "verifies": "Total execution time is less than sequential sum"},
          {"name": "test_error_isolation", "verifies": "One node failure does not crash the DAG"}
        ]
      }
    ]
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- If you encounter a fundamental architectural issue that prevents implementing the feature as requested.
- If existing Ghidra or MCP integrations are fundamentally broken and require external resolution.
