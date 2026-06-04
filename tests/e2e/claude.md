# `claude.md` — `e2e`

**Repository path:** `tests/e2e/`

Pytest layout: markers and heavy tools are gated in `pytest.ini`. **Parent index:** [`../claude.md`](../claude.md).

## Python files

### `__init__.py`
- **Summary:** End-to-End Tests

### `test_cli_workflow.py`
- **Summary:** End-to-end smoke tests for the direct src wrapper.
- **Tests (6):**
  - `TestCLIWorkflow.test_cli_analyze_binary_not_found`
  - `TestCLIWorkflow.test_cli_help_command`
  - `TestCLIWorkflow.test_cli_invalid_command`
  - `TestCLIWorkflow.test_cli_reverse_engineer_app_python_sample`
  - `TestCLIWorkflow.test_cli_serve_web_interface_or_dependency_error`
  - `TestCLIWorkflow.test_cli_version_command`

### `test_cli_workflows.py`
- **Summary:** End-to-end smoke tests for the supported REVENG CLI wrappers.
- **Tests (8):**
  - `TestCLIWorkflows.test_analyze_binary_not_found`
  - `TestCLIWorkflows.test_analyze_help_command`
  - `TestCLIWorkflows.test_help_command`
  - `TestCLIWorkflows.test_invalid_command`
  - `TestCLIWorkflows.test_reverse_engineer_app_help_command`
  - `TestCLIWorkflows.test_reverse_engineer_app_java_sample`
  - `TestCLIWorkflows.test_serve_command_dependency_or_running_server`
  - `TestCLIWorkflows.test_version_command`

### `test_complete_workflow.py`
- **Summary:** End-to-end tests for supported complete REVENG workflows.
- **Tests (8):**
  - `TestCompleteWorkflow.test_complete_app_corpus_workflow`
  - `TestCompleteWorkflow.test_complete_baseline_ga_readiness_workflow`
  - `TestCompleteWorkflow.test_complete_bun_sample_matrix_report_contract`
  - `TestCompleteWorkflow.test_complete_dotnet_reverse_engineering_workflow`
  - `TestCompleteWorkflow.test_complete_javascript_reverse_engineering_workflow`
  - `TestCompleteWorkflow.test_complete_jvm_reverse_engineering_workflow`
  - `TestCompleteWorkflow.test_complete_python_reverse_engineering_workflow`
  - `TestCompleteWorkflow.test_complete_strict_ga_readiness_workflow`

---
*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*
