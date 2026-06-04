# `claude.md` — `integration`

**Repository path:** `tests/integration/`

Pytest layout: markers and heavy tools are gated in `pytest.ini`. **Parent index:** [`../claude.md`](../claude.md).

## Python files

### `__init__.py`
- **Summary:** Integration Tests

### `test_app_reverse_engineering_external_tools.py`
- **Tests (2):**
  - `test_dotnet_adapter_ilspy_normalization_executes_when_available`
  - `test_python_adapter_archive_viewer_executes_on_checked_in_fixture`

### `test_app_reverse_engineering_surfaces.py`
- **Tests (3):**
  - `test_api_runs_selected_app_corpus_entries`
  - `test_enterprise_mcp_runs_selected_app_corpus_entries`
  - `test_simple_mcp_runs_selected_app_corpus_entries`

### `test_automated_pipeline.py`
- **Summary:** Integration tests for the current automated analysis pipeline API.
- **Tests (8):**
  - `TestAutomatedAnalysisPipeline.test_execute_step_returns_timeout_error`
  - `TestAutomatedAnalysisPipeline.test_init_loads_prebuilt_templates`
  - `TestAutomatedAnalysisPipeline.test_missing_binary_raises_analysis_failure`
  - `TestAutomatedAnalysisPipeline.test_optional_step_failure_is_recorded_as_warning`
  - `TestAutomatedAnalysisPipeline.test_required_step_failure_marks_pipeline_unsuccessful`
  - `TestAutomatedAnalysisPipeline.test_run_pipeline_executes_custom_steps_and_writes_reports`
  - `TestAutomatedAnalysisPipeline.test_template_definitions_use_expected_stage_layout`
  - `TestAutomatedAnalysisPipeline.test_unknown_template_raises_analysis_failure`

### `test_cli.py`
- **Summary:** Integration tests for the current REVENG CLI entrypoints.
- **Tests (21):**
  - `TestBootstrapScripts.test_linux_bootstrap`
  - `TestBootstrapScripts.test_windows_bootstrap`
  - `TestCLI.test_analyze_bun_report_matches_golden_subset`
  - `TestCLI.test_analyze_routes_bun_executable_to_bundle_extraction`
  - `TestCLI.test_build_bun_sea_missing_binary_reports_path_error`
  - `TestCLI.test_decompile_missing_binary_reports_path_error`
  - `TestCLI.test_decompile_routes_bun_executable_to_bundle_extraction`
  - `TestCLI.test_help_command`
  - `TestCLI.test_invalid_binary`
  - `TestCLI.test_java_sample_analysis`
  - `TestCLI.test_recompile_missing_binary_does_not_fail_on_import`
  - `TestCLI.test_recompile_routes_bun_executable_to_node_sea`
  - `TestCLI.test_reverse_engineer_app_dotnet_like_sample`
  - `TestCLI.test_reverse_engineer_app_help_command`
  - `TestCLI.test_reverse_engineer_app_java_sample`
  - `TestCLI.test_reverse_engineer_app_pyinstaller_like_sample`
  - `TestCLI.test_reverse_engineer_app_python_source_sample`
  - `TestCLI.test_verbose_output`
  - `TestCLI.test_version_command`
  - `TestToolCLI.test_language_detector_cli`
  - `TestUtilityScripts.test_cleanup_script`

### `test_documentation.py`
- **Summary:** Integration tests for the current REVENG documentation layout.
- **Tests (8):**
  - `TestDocumentationContent.test_docs_index_highlights_current_sections`
  - `TestDocumentationContent.test_examples_readme_matches_current_headings`
  - `TestDocumentationFiles.test_core_documents_exist_and_have_expected_sections`
  - `TestDocumentationFiles.test_docs_directory_contains_key_guides`
  - `TestDocumentationFormatting.test_markdown_syntax`
  - `TestDocumentationFormatting.test_readme_has_code_blocks`
  - `TestDocumentationLinks.test_core_external_links_resolve`
  - `TestDocumentationLinks.test_readme_references_current_core_docs`

### `test_e2e_cli.py`
- **Summary:** End-to-end CLI integration coverage for the native sample pipeline.
- **Tests (1):**
  - `test_analyze_sample_produces_yara_enriched_report`

### `test_examples.py`
- **Summary:** Test REVENG Examples
- **Tests (10):**
  - `TestExampleDocumentation.test_example_docstrings`
  - `TestExampleDocumentation.test_examples_readme_content`
  - `TestExampleExecution.test_analysis_template_with_sample`
  - `TestExampleExecution.test_basic_analysis_example`
  - `TestExampleOutputs.test_example_outputs_directory`
  - `TestExampleOutputs.test_output_file_formats`
  - `TestExamples.test_advanced_examples`
  - `TestExamples.test_analysis_template`
  - `TestExamples.test_basic_examples`
  - `TestExamples.test_examples_readme`

### `test_llm4decompile_integration.py`
- **Summary:** Deterministic integration tests for the LLM4Decompile integration layer.
- **Tests (4):**
  - `test_llm4decompile_extracts_code_from_fenced_output`
  - `test_llm4decompile_formats_optimization_aware_prompt`
  - `test_multimodel_ensemble_combines_successful_functions`
  - `test_multimodel_ensemble_initializes_lazy_members`

### `test_mcp_integration.py`
- **Summary:** Integration Tests for REVENG MCP Integration
- **Tests (33):**
  - `test_ai_code_reconstruction_returns_cfg_aware_structured_code (async)`
  - `test_ai_code_reconstruction_returns_timeout_error_json (async)`
  - `test_analyze_memory_dump_tool_returns_structured_analysis (async)`
  - `test_ask_ai_about_binary_returns_structured_ollama_answer (async)`
  - `test_ask_ai_about_binary_returns_timeout_error_json (async)`
  - `test_ask_ai_about_binary_timeout_without_context_returns_safe_fallback (async)`
  - `test_audit_logger`
  - `test_classify_malware_tool_returns_structured_result (async)`
  - `test_decompile_binary_tool_returns_descriptive_error (async)`
  - `test_decompile_binary_tool_returns_structured_json (async)`
  - `test_detect_js_malware_tool_rejects_non_utf8_file (async)`
  - `test_diff_binaries_tool_returns_structured_diff (async)`
  - `test_enterprise_server_with_rate_limiting (async)`
  - `test_get_prompt (async)`
  - `test_initialize_message (async)`
  - `test_list_recent_analyses_tool (async)`
  - `test_mcp_server_initialization`
  - `test_prompts_list_message (async)`
  - `test_rate_limiter (async)`
  - `test_read_resource (async)`
  - `test_recompile_binary_tool_returns_structured_failure (async)`
  - `test_recompile_binary_tool_returns_structured_success (async)`
  - `test_recompile_binary_tool_skips_decompile_when_source_is_provided (async)`
  - `test_resources_list_message (async)`
  - `test_scan_yara_tool_rejects_non_rule_files (async)`
  - `test_scan_yara_tool_returns_structured_matches (async)`
  - `test_tool_execution_error_handling (async)`
  - `test_tool_registration`
  - `test_tool_schemas`
  - `test_tools_list_includes_decompile_binary_schema_and_descriptions (async)`
  - `test_tools_list_includes_forensic_tools (async)`
  - `test_tools_list_includes_recompile_binary_schema (async)`
  - `test_tools_list_message (async)`

### `test_ml_enhancements.py`
- **Summary:** Test ML Enhancements
- **Tests (4):**
  - `test_malware_classifier`
  - `test_ml_pipeline`
  - `test_nlp_analyzer`
  - `test_vulnerability_predictor`

### `test_ml_workflow.py`
- **Summary:** Integration tests for the current ML workflow API.
- **Tests (8):**
  - `TestMLWorkflow.test_analysis_can_skip_saving_results`
  - `TestMLWorkflow.test_disabled_components_are_skipped`
  - `TestMLWorkflow.test_extract_code_fragments_combines_disassembly_and_functions`
  - `TestMLWorkflow.test_full_ml_analysis_workflow`
  - `TestMLWorkflow.test_get_model_status_reports_loaded_models`
  - `TestMLWorkflow.test_get_model_status_returns_error_payload_on_failure`
  - `TestMLWorkflow.test_update_config_can_enable_components_after_startup`
  - `TestMLWorkflow.test_update_config_returns_false_when_component_init_fails`

### `test_pipeline.py`
- **Summary:** Basic Pipeline Test Harness
- **Tests (14):**
  - `TestCTypeParser.test_array_parameters`
  - `TestCTypeParser.test_const_char_pointer`
  - `TestCTypeParser.test_function_address_decimal`
  - `TestCTypeParser.test_function_address_missing`
  - `TestCTypeParser.test_function_address_preserved`
  - `TestCTypeParser.test_function_pointer_params`
  - `TestCTypeParser.test_pointer_param_with_const`
  - `TestCTypeParser.test_unsigned_long_long`
  - `TestGeneratedCode.test_generated_functions_have_return_statements`
  - `TestGeneratedCode.test_no_windows_headers_in_generated_code`
  - `TestPlatformAwareCompilation.test_fpic_not_on_windows`
  - `TestValidationDefaults.test_default_mode_is_checksum`
  - `TestValidationDefaults.test_no_smoke_tests_in_checksum_mode`
  - `TestValidationDefaults.test_smoke_tests_only_in_smoke_mode`

### `test_symbolic_execution_integration.py`
- **Summary:** Integration tests for the symbolic execution engine.
- **Tests (3):**
  - `test_analysis_depth_configurations`
  - `test_symbolic_execution_basic`
  - `test_vulnerability_type_coverage`

---
*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*
