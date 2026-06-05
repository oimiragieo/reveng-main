# `claude.md` — `unit`

**Repository path:** `tests/unit/`

Pytest layout: markers and heavy tools are gated in `pytest.ini`. **Parent index:** [`../claude.md`](../claude.md).

## Python files

### `__init__.py`
- **Summary:** Unit Tests

### `test_agent_sdk_fixes.py`
- **Summary:** Regression tests for agent_sdk bug fixes (Tasks 1.9, 1.10, 1.11).
- **Tests (9):**
  - `test_binary_analysis_tool_calls_analyze_binary`
  - `test_execute_tool_not_found_raises_toolerror`
  - `test_execute_tool_permission_denied_raises_toolerror`
  - `test_get_available_tools_filters_missing_without_raising`
  - `test_get_still_raises_on_miss`
  - `test_security_audit_uses_content_not_data`
  - `test_toolresult_has_no_data_attribute`
  - `test_try_get_returns_none_on_miss`
  - `test_try_get_returns_tool_when_present`

### `test_analyzer.py`
- **Summary:** Unit Tests for REVENG Analyzer
- **Tests (21):**
  - `TestEnhancedAnalysisFeatures.test_enhanced_features_default`
  - `TestEnhancedAnalysisFeatures.test_enhanced_features_from_config`
  - `TestEnhancedAnalysisFeatures.test_is_any_enhanced_enabled_false`
  - `TestEnhancedAnalysisFeatures.test_is_any_enhanced_enabled_partial`
  - `TestEnhancedAnalysisFeatures.test_is_any_enhanced_enabled_true`
  - `TestREVENGAnalyzer.test_analyzer_initialization`
  - `TestREVENGAnalyzer.test_analyzer_with_enhanced_features`
  - `TestREVENGAnalyzer.test_check_ollama_availability_failure`
  - `TestREVENGAnalyzer.test_check_ollama_availability_success`
  - `TestREVENGAnalyzer.test_count_enabled_modules`
  - `TestREVENGAnalyzer.test_count_enabled_modules_none`
  - `TestREVENGAnalyzer.test_detect_file_type`
  - `TestREVENGAnalyzer.test_detect_file_type_import_error`
  - `TestREVENGAnalyzer.test_find_binary_auto_detection`
  - `TestREVENGAnalyzer.test_find_binary_no_files`
  - `TestREVENGAnalyzer.test_generate_final_report`
  - `TestREVENGAnalyzer.test_step1_ai_analysis_failure`
  - `TestREVENGAnalyzer.test_step1_ai_analysis_success`
  - `TestREVENGAnalyzer.test_step1_ai_analysis_timeout`
  - `TestREVENGAnalyzer.test_step4_specifications_exists`
  - `TestREVENGAnalyzer.test_step4_specifications_not_exists`

### `test_angr_cfg_preprocessor.py`
- **Summary:** Tests for angr-based CFG preprocessing in the recompilation pipeline.
- **Tests (6):**
  - `test_extract_cfg_payload_from_sample_pe`
  - `test_extract_cfg_payload_raises_for_missing_binary`
  - `test_extract_cfg_payload_rejects_empty_cfg`
  - `test_extract_cfg_payload_wraps_angr_failures`
  - `test_gemini_prompt_includes_cfg_context`
  - `test_phase1_decompilation_writes_cfg_artifacts (async)`

### `test_app_reverse_engineering.py`
- **Summary:** Tests for the generic app reverse-engineering framework.
- **Tests (14):**
  - `test_csharp_il_analyzer_records_external_tooling_status`
  - `test_dotnet_detector_recognizes_checked_in_managed_pe_fixture`
  - `test_framework_auto_detects_pyinstaller_frozen_python_sample`
  - `test_framework_dotnet_adapter_emits_fallback_report_without_external_tools`
  - `test_framework_extracts_python_entries_from_pyi_archive_viewer`
  - `test_framework_recovers_sources_from_simple_jar`
  - `test_framework_reverse_engineers_dotnet_sample_with_mocked_analyzers`
  - `test_framework_reverse_engineers_java_source_sample`
  - `test_framework_reverse_engineers_python_bytecode_sample`
  - `test_framework_reverse_engineers_python_source_sample`
  - `test_framework_reverse_engineers_python_zipapp_sample`
  - `test_framework_uses_pyi_archive_viewer_when_available`
  - `test_java_bytecode_analyzer_uses_split_java_commands`
  - `test_python_bytecode_detector_recognizes_current_interpreter_magic`

### `test_app_reverse_engineering_corpus.py`
- **Summary:** Tests for app reverse-engineering corpus execution.
- **Tests (2):**
  - `test_app_corpus_report_preserves_row_metadata`
  - `test_app_corpus_required_failure_flips_matrix_status`

### `test_app_reverse_engineering_corpus_script.py`
- **Tests (4):**
  - `test_build_report_runs_selected_entries_only`
  - `test_checked_in_corpus_config_can_run_dotnet_entry`
  - `test_checked_in_corpus_config_can_run_packaged_entries`
  - `test_load_app_corpus_config_resolves_relative_paths`

### `test_automated_analysis_pipeline.py`
- **Summary:** Tests for the current async DAG-based AnalysisPipeline API.
- **Tests (21):**
  - `test_add_stage_appends_pipeline_stage`
  - `test_aggregate_stage_outputs_only_includes_completed_results`
  - `test_binary`
  - `test_build_stage_report_writes_utf8_json`
  - `test_create_pipeline_registers_pipeline_with_description`
  - `test_dispatch_stage_execution_exposes_dependency_context_and_clears_afterwards`
  - `test_execute_dynamic_analysis_stage_returns_placeholder_message`
  - `test_execute_pipeline_async_runs_independent_stages_concurrently (async)`
  - `test_execute_pipeline_empty_pipeline_returns_completed`
  - `test_execute_pipeline_isolates_failed_branch_and_skips_dependents`
  - `test_execute_pipeline_marks_circular_dependencies_as_failed`
  - `test_execute_pipeline_marks_missing_dependencies_as_failed`
  - `test_execute_pipeline_preserves_pipeline_stage_order`
  - `test_execute_stage_async_retries_until_success (async)`
  - `test_execute_stage_async_returns_failed_after_timeout (async)`
  - `test_get_prebuilt_pipeline_returns_expected_templates`
  - `test_init_loads_templates_dir_and_prebuilt_pipelines`
  - `test_list_pipelines_includes_newly_created_pipeline`
  - `test_resolve_output_dir_uses_configured_parent_directory`
  - `test_save_and_load_pipeline_roundtrip_preserves_stage_fields`
  - `test_select_analysis_target_prefers_recompiled_binary`

### `test_babel_transformer_replace_accessors.py`
- **Summary:** Regression tests for BabelTransformer._replace_accessors re.sub injection.
- **Tests (3):**
  - `test_replace_accessors_combined_escapes`
  - `test_replace_accessors_group_ref_does_not_raise`
  - `test_replace_accessors_hex_escape_not_mangled`

### `test_bun_extractor.py`
- **Tests (49):**
  - `test_bun_differential_validation_tracks_bun_global_bootstrap`
  - `test_bun_differential_validation_tracks_expected_rewrites`
  - `test_bun_equivalence_validation_summary_reports_divergence`
  - `test_bun_equivalence_validation_summary_reports_semantic_candidate`
  - `test_bun_extractor_analyzes_dependency_roles`
  - `test_bun_extractor_bootstraps_bun_global_usage`
  - `test_bun_extractor_builds_bounded_startup_graph`
  - `test_bun_extractor_builds_dump_guidance`
  - `test_bun_extractor_builds_node_sea_from_normalized_workspace`
  - `test_bun_extractor_builds_node_sea_from_relative_workspace`
  - `test_bun_extractor_builds_runtime_readiness_surface`
  - `test_bun_extractor_builds_symbolic_label_without_section`
  - `test_bun_extractor_classifies_runtime_bootstrap_profile`
  - `test_bun_extractor_collects_cross_references`
  - `test_bun_extractor_collects_indirect_import_startup_targets`
  - `test_bun_extractor_collects_startup_targets`
  - `test_bun_extractor_detects_bun_handoff_signals`
  - `test_bun_extractor_detects_bun_pe_section`
  - `test_bun_extractor_extracts_javascript_from_pe_bundle`
  - `test_bun_extractor_ignores_embedded_manifest_and_diff_noise_in_dependency_analysis`
  - `test_bun_extractor_includes_instruction_previews`
  - `test_bun_extractor_includes_rip_relative_preview_hints`
  - `test_bun_extractor_normalizes_recovered_project_workspace`
  - `test_bun_extractor_parses_extended_short_module_graph_layout`
  - `test_bun_extractor_parses_module_graph_and_recovers_virtual_files`
  - `test_bun_extractor_parses_short_module_graph_layout`
  - `test_bun_extractor_prefers_code_path_for_sparse_mixed_path_scan`
  - `test_bun_extractor_recommends_postprocessing_hooks`
  - `test_bun_extractor_recovers_external_sourcemap_during_path_scan_fallback`
  - `test_bun_extractor_recovers_inline_sourcemap_during_path_scan_fallback`
  - `test_bun_extractor_recovers_metadata_when_module_graph_layout_is_unknown`
  - `test_bun_extractor_recovers_metadata_with_invalid_offsets_path_scan`
  - `test_bun_extractor_recovers_supporting_json_artifacts_during_path_scan_fallback`
  - `test_bun_extractor_recovers_supporting_text_artifacts_during_path_scan_fallback`
  - `test_bun_extractor_recovers_supporting_wasm_artifact_during_path_scan_fallback`
  - `test_bun_extractor_recovers_supporting_web_and_config_artifacts_during_path_scan_fallback`
  - `test_bun_extractor_resolves_tls_callback_metadata`
  - `test_bun_extractor_rewrites_minified_bun_ffi_imports`
  - `test_bun_extractor_summarizes_native_pe_stub`
  - `test_bun_extractor_tracks_aliased_create_require_dependencies`
  - `test_bun_fixture_matrix_characterization`
  - `test_bun_report_severity_summary_rolls_up_attention_factors`
  - `test_bun_runtime_escalation_summary_prioritizes_runtime_steps`
  - `test_bun_sea_workflow_reports_differential_validation`
  - `test_bun_sea_workflow_reports_equivalence_validation`
  - `test_bun_sea_workflow_reports_runtime_escalation`
  - `test_packer_detector_identifies_bun_executable`
  - `test_probe_standalone_output_cleans_up_temp_dir`
  - `test_universal_unpacker_extracts_bun_javascript`

### `test_bun_sample_matrix.py`
- **Tests (10):**
  - `test_build_smoke_parity_requires_output_and_timeout_match`
  - `test_evaluate_expectations_checks_rebuild_equivalence_level`
  - `test_evaluate_expectations_checks_smoke_parity`
  - `test_evaluate_expectations_handles_missing_nested_rebuild_sections`
  - `test_load_matrix_config_resolves_relative_paths`
  - `test_normalize_smoke_output_strips_ansi_and_normalizes_newlines`
  - `test_rollup_matrix_status_counts_pass_with_warnings_as_success`
  - `test_rollup_matrix_status_reports_fail_for_required_sample_failure`
  - `test_rollup_matrix_status_reports_pass_with_limitations`
  - `test_run_smoke_test_captures_timeout_output_and_marks_timeout`

### `test_business_logic_extractor.py`
- **Summary:** Unit tests for the current BusinessLogicExtractor API.
- **Tests (5):**
  - `test_analyze_application_domain_extracts_real_business_signals`
  - `test_analyze_application_domain_returns_unknown_for_missing_binary`
  - `test_calculate_confidence_score_tracks_available_evidence`
  - `test_extract_strings_keeps_printable_sequences_of_length_four_or_more`
  - `test_supporting_extractors_and_loaders_expose_current_patterns`

### `test_capability_report.py`
- **Summary:** Unit tests for app reverse-engineering capability reporting.
- **Tests (7):**
  - `test_analyze_js_reconstructed_project_package_and_syntax`
  - `test_analyze_js_reconstructed_project_skips_when_no_node`
  - `test_build_capability_report_includes_behavior_dimension`
  - `test_build_capability_report_includes_oracle_slice`
  - `test_run_javascript_behavior_probe_cli_help_exit_zero`
  - `test_run_javascript_behavior_probe_disabled`
  - `test_run_javascript_behavior_probe_uses_reveng_behavior_probe_main`

### `test_claude_cli_analyzer.py`
- **Summary:** Unit tests for ClaudeCodeCLIAnalyzer.
- **Tests (8):**
  - `test_analyze_extracts_result_and_usage_fields`
  - `test_analyze_invokes_subprocess_with_shell_false`
  - `test_analyze_raises_on_nonzero_returncode`
  - `test_analyze_raises_on_timeout`
  - `test_analyze_raises_when_is_error_true`
  - `test_analyze_returns_refined_source_on_success`
  - `test_get_analyzer_claude_cli_returns_cli_analyzer`
  - `test_get_analyzer_claude_code_alias_works`

### `test_cli.py`
- **Summary:** Unit tests for the current REVENG CLI surface.
- **Tests (24):**
  - `TestCLIHandlers.test_create_enhanced_features_applies_cli_flags`
  - `TestCLIHandlers.test_create_enhanced_features_loads_json_config`
  - `TestCLIHandlers.test_handle_analyze_command_failure`
  - `TestCLIHandlers.test_handle_analyze_command_missing_binary`
  - `TestCLIHandlers.test_handle_analyze_command_success`
  - `TestCLIHandlers.test_handle_reverse_engineer_app_command_success`
  - `TestCLIHandlers.test_handle_serve_command_import_error`
  - `TestCLIIntegration.test_analyze_command_missing_binary`
  - `TestCLIIntegration.test_analyze_help_command`
  - `TestCLIIntegration.test_help_command`
  - `TestCLIIntegration.test_version_command`
  - `TestCLIMain.test_main_no_command`
  - `TestCLIMain.test_main_routes_analyze_command`
  - `TestCLIMain.test_main_routes_reverse_engineer_app_command`
  - `TestCLIMain.test_main_routes_serve_command`
  - `TestCLIMain.test_main_unknown_command`
  - `TestCLIParser.test_create_parser`
  - `TestCLIParser.test_parser_analyze_command_accepts_current_global_flags`
  - `TestCLIParser.test_parser_decompile_command`
  - `TestCLIParser.test_parser_help_lists_current_commands`
  - `TestCLIParser.test_parser_reverse_engineer_app_command`
  - `TestCLIParser.test_parser_reverse_engineer_app_command_accepts_dotnet_language`
  - `TestCLIParser.test_parser_reverse_engineer_app_command_accepts_python_language`
  - `TestCLIParser.test_parser_serve_command`

### `test_code_gen.py`
- **Summary:** Unit tests for the functional code generator.
- **Tests (2):**
  - `test_generator_initialises_without_ai`
  - `test_generator_writes_output`

### `test_compile_adapter.py`
- **Summary:** Unit tests for reveng.verification.refinement.compile_adapter.
- **Tests (12):**
  - `test_compile_fn_binary_has_exe_suffix_on_windows`
  - `test_compile_fn_creates_workspace_dir_if_missing`
  - `test_compile_fn_different_source_different_filename`
  - `test_compile_fn_falls_back_to_clang_when_gcc_not_found`
  - `test_compile_fn_propagates_runtime_error_when_all_compilers_fail`
  - `test_compile_fn_returns_path_object`
  - `test_compile_fn_same_source_same_filename`
  - `test_compile_fn_source_file_content_matches_input`
  - `test_compile_fn_uses_given_workspace_dir`
  - `test_compile_fn_uses_system_temp_when_workspace_dir_is_none`
  - `test_compile_fn_writes_source_file_and_calls_compiler`
  - `test_make_compile_fn_returns_callable`

### `test_config_tunables.py`
- **Summary:** Tests for moving configuration into the new package layout.
- **Tests (2):**
  - `test_config_manager_returns_expected_ai_settings`
  - `test_ollama_analyzer_uses_config_values`

### `test_critical_bugs.py`
- **Summary:** Regression tests for the foundation critical bug fixes.
- **Tests (6):**
  - `test_behavioral_monitor_entropy_uses_log2_without_attribute_errors`
  - `test_ghidra_engine_decompile_calls_decompile_endpoint`
  - `test_ghidra_engine_defaults_to_long_running_native_timeout`
  - `test_init_script_installs_yara_python_and_ollama`
  - `test_requirements_include_yara_python_and_ollama`
  - `test_runtime_dependency_imports`

### `test_deobfuscator_temp_cleanup.py`
- **Summary:** Regression test for _rename_variables_ml temp-file cleanup.
- **Tests (2):**
  - `test_rename_variables_ml_finally_no_nameerror_on_raw_propagation`
  - `test_rename_variables_ml_tempfile_creation_failure_does_not_mask_error`

### `test_dependency_manager.py`
- **Summary:** Unit tests for DependencyManager
- **Tests (14):**
  - `TestDependencyManager.test_check_all_dependencies`
  - `TestDependencyManager.test_cleanup_failed_installations`
  - `TestDependencyManager.test_export_configuration`
  - `TestDependencyManager.test_get_fallback_analyzer`
  - `TestDependencyManager.test_get_installation_status`
  - `TestDependencyManager.test_get_tool_path`
  - `TestDependencyManager.test_ghidra_installer_detects_repo_bundled_distribution`
  - `TestDependencyManager.test_ghidra_installer_detects_versioned_distribution_in_install_dir`
  - `TestDependencyManager.test_import_configuration`
  - `TestDependencyManager.test_import_configuration_invalid_file`
  - `TestDependencyManager.test_import_configuration_invalid_json`
  - `TestDependencyManager.test_init`
  - `TestDependencyManager.test_install_missing_tools`
  - `TestDependencyManager.test_install_missing_tools_no_auto_install`

### `test_docker_sandbox.py`
- **Summary:** Unit tests for Docker-based malware behavioral sandboxing.
- **Tests (4):**
  - `test_behavioral_monitor_parses_trace_output_into_behavioral_events`
  - `test_behavioral_monitor_skip_sandbox_returns_static_only_profile`
  - `test_behavioral_monitor_uses_docker_sandbox_and_never_enumerates_host_processes`
  - `test_docker_sandbox_executes_python_slim_container_with_strace`

### `test_documentation.py`
- **Summary:** Regression tests for UTF-8 documentation reads on Windows.
- **Tests (2):**
  - `TestDocumentationEncoding.test_examples_readme_can_be_read_with_utf8`
  - `TestDocumentationEncoding.test_main_docs_can_be_read_with_utf8`

### `test_dotnet_analyzer.py`
- **Summary:** Tests for the .NET analyzer module.
- **Tests (4):**
  - `test_analyze_assembly_returns_result`
  - `test_analyze_obfuscation_categories`
  - `test_calculate_analysis_confidence`
  - `test_detect_gui_framework_uses_string_indicators`

### `test_e2e_pipeline_integration.py`
- **Summary:** Focused tests for the end-to-end CLI pipeline integration flow.
- **Tests (8):**
  - `test_analysis_pipeline_generates_unified_report`
  - `test_handle_analyze_command_passes_ghidra_stage_overrides`
  - `test_handle_analyze_command_reports_unified_pipeline_result`
  - `test_runner_build_pipeline_skips_forensics_when_disabled`
  - `test_runner_build_pipeline_uses_configured_ghidra_timeout_and_retry_count`
  - `test_runner_marks_all_stages_failing_as_failed`
  - `test_runner_preserves_graceful_recompilation_failure`
  - `test_runner_resolves_invalid_binary_path_before_execution`

### `test_educational_generator.py`
- **Summary:** Tests for the educational content generator.
- **Tests (1):**
  - `test_generator_creates_output_directories`

### `test_exploit_generation.py`
- **Tests (4):**
  - `test_generate_exploit_on_sample_binary_returns_structured_response (async)`
  - `test_generate_exploit_returns_timeout_note (async)`
  - `test_generate_exploit_tool_schema_only_requires_binary_path`
  - `test_generate_exploit_uses_cfgfast_and_returns_structured_candidates (async)`

### `test_filesystem_mcp_path_containment.py`
- **Summary:** Regression tests for FilesystemMCPServer path containment.
- **Tests (2):**
  - `test_path_inside_root_is_accepted`
  - `test_sibling_prefix_path_is_rejected`

### `test_generate_release_report.py`
- **Tests (3):**
  - `test_generate_release_report_main_resolves_relative_paths_from_repo_root`
  - `test_generate_release_report_marks_not_ready_when_strict_ga_fails`
  - `test_generate_release_report_writes_json_and_markdown`

### `test_generate_skip_inventory.py`
- **Tests (3):**
  - `test_generate_skip_inventory_can_exclude_internal_report_tests`
  - `test_generate_skip_inventory_categorizes_skip_patterns`
  - `test_generate_skip_inventory_main_writes_json_and_markdown`

### `test_ghidra_install.py`
- **Summary:** Tests for installing the Ghidra binary distribution.
- **Tests (6):**
  - `test_install_ghidra_extracts_downloaded_distribution`
  - `test_install_ghidra_is_idempotent_for_existing_install`
  - `test_resolve_ghidra_path_falls_back_to_legacy_source_tree`
  - `test_resolve_ghidra_path_prefers_binary_distribution`
  - `test_verify_archive_checksum_accepts_expected_hash`
  - `test_verify_archive_checksum_removes_archive_on_mismatch`

### `test_ghidra_scripting_engine.py`
- **Summary:** Unit tests for the Ghidra scripting engine integration.
- **Tests (3):**
  - `test_execute_java_script_failure`
  - `test_execute_python_script_handles_timeout`
  - `test_execute_python_script_success`

### `test_ghidra_server.py`
- **Tests (6):**
  - `test_analyze_endpoint_passes_requested_timeout_to_headless_runner`
  - `test_analyze_endpoint_timeout_response_uses_requested_timeout`
  - `test_build_headless_command_preserves_windows_paths_with_spaces`
  - `test_decompile_endpoint_returns_503_without_mock_data_when_unavailable`
  - `test_health_endpoint_reports_ghidra_availability`
  - `test_run_ghidra_analysis_uses_default_timeout_and_returns_source`

### `test_gpu_batching_integration.py`
- **Summary:** Unit tests for memory forensics GPU batching integration.
- **Tests (5):**
  - `test_dispatch_ready_memory_forensics_tasks_flushes_on_wait_window`
  - `test_gpu_accelerator_defaults_to_cpu_without_device_metadata`
  - `test_memory_forensics_dispatch_history_is_capped`
  - `test_memory_forensics_extract_artifacts_uses_batched_gpu_dispatch`
  - `test_process_memory_forensics_tasks_batches_by_batch_size`

### `test_hex_editor.py`
- **Summary:** Unit tests for the refactored HexEditor module.
- **Tests (6):**
  - `test_entropy_analysis_returns_regions`
  - `test_extract_region_bounds_checked`
  - `test_extract_strings_advanced`
  - `test_find_embedded_executables_identifies_pe`
  - `test_open_binary_returns_hex_view`
  - `test_search_pattern_finds_offsets`

### `test_import_analyzer.py`
- **Summary:** Unit tests for ImportAnalyzer
- **Tests (30):**
  - `TestImportAnalyzer.test_analyze_imports_failure`
  - `TestImportAnalyzer.test_analyze_imports_success`
  - `TestImportAnalyzer.test_assess_api_suspiciousness_critical`
  - `TestImportAnalyzer.test_assess_api_suspiciousness_high`
  - `TestImportAnalyzer.test_assess_api_suspiciousness_low`
  - `TestImportAnalyzer.test_assess_api_suspiciousness_medium`
  - `TestImportAnalyzer.test_assess_api_suspiciousness_safe`
  - `TestImportAnalyzer.test_calculate_analysis_confidence`
  - `TestImportAnalyzer.test_calculate_analysis_confidence_empty`
  - `TestImportAnalyzer.test_calculate_risk_score`
  - `TestImportAnalyzer.test_calculate_risk_score_safe`
  - `TestImportAnalyzer.test_create_api_info_known`
  - `TestImportAnalyzer.test_create_api_info_unknown`
  - `TestImportAnalyzer.test_determine_api_category_crypto`
  - `TestImportAnalyzer.test_determine_api_category_file_io`
  - `TestImportAnalyzer.test_determine_api_category_gui`
  - `TestImportAnalyzer.test_determine_api_category_memory`
  - `TestImportAnalyzer.test_determine_api_category_network`
  - `TestImportAnalyzer.test_determine_api_category_process`
  - `TestImportAnalyzer.test_determine_api_category_registry`
  - `TestImportAnalyzer.test_determine_api_category_system`
  - `TestImportAnalyzer.test_determine_api_category_unknown`
  - `TestImportAnalyzer.test_find_import_table`
  - `TestImportAnalyzer.test_init`
  - `TestImportAnalyzer.test_load_api_database`
  - `TestImportAnalyzer.test_load_behavioral_indicators`
  - `TestImportAnalyzer.test_load_suspicious_patterns`
  - `TestImportAnalyzer.test_parse_import_descriptors`
  - `TestImportAnalyzer.test_parse_pe_header_invalid`
  - `TestImportAnalyzer.test_parse_pe_header_valid`

### `test_import_contracts.py`
- **Summary:** Import-direction / architecture contracts (enforced).
- **Tests (2):**
  - `test_import_contracts_are_enforced`
  - `test_importlinter_contract_config_exists`

### `test_imports.py`
- **Summary:** Sanity checks for AI enhanced data model imports.
- **Tests (3):**
  - `test_confidence_level_enum_contains_expected_members`
  - `test_evidence_tracker_records_items`
  - `test_mitre_mapping_serialises_round_trip`

### `test_installation.py`
- **Summary:** Test REVENG Installation
- **Tests (17):**
  - `TestDependencies.test_capstone_version`
  - `TestDependencies.test_keystone_version`
  - `TestDependencies.test_lief_version`
  - `TestDependencies.test_networkx_version`
  - `TestDependencies.test_requests_version`
  - `TestFileStructure.test_directories_exist`
  - `TestFileStructure.test_main_files_exist`
  - `TestFileStructure.test_tools_directory`
  - `TestInstallation.test_analysis_pipeline`
  - `TestInstallation.test_compiler_availability`
  - `TestInstallation.test_core_imports`
  - `TestInstallation.test_ghidra_availability`
  - `TestInstallation.test_java_availability`
  - `TestInstallation.test_python_version`
  - `TestInstallation.test_reveng_analyzer_import`
  - `TestInstallation.test_tool_chain_check`
  - `TestInstallation.test_tools_import`

### `test_ir.py`
- **Summary:** Unit tests for reveng.ir -- v2 IR data model.
- **Tests (39):**
  - `TestBackwardsCompatAliases.test_ir_schema_version_constant`
  - `TestBackwardsCompatAliases.test_reedge_construction_keyword`
  - `TestBackwardsCompatAliases.test_reedge_is_ireedge`
  - `TestBackwardsCompatAliases.test_renode_construction_keyword`
  - `TestBackwardsCompatAliases.test_renode_is_irnode`
  - `TestBackwardsCompatAliases.test_reprojectir_is_irprogram_instance`
  - `TestBackwardsCompatAliases.test_reprojectir_is_subclass`
  - `TestBackwardsCompatAliases.test_reprojectir_keyword_construction`
  - `TestBackwardsCompatAliases.test_reprojectir_legacy_properties`
  - `TestIREdge.test_basic_creation`
  - `TestIREdge.test_from_dict_round_trip`
  - `TestIREdge.test_to_dict`
  - `TestIRNode.test_basic_creation`
  - `TestIRNode.test_confidence_default`
  - `TestIRNode.test_confidence_explicit`
  - `TestIRNode.test_from_dict_round_trip`
  - `TestIRNode.test_raw_string_kind_accepted`
  - `TestIRNode.test_to_dict_keys`
  - `TestIRProgramMutation.test_add_edge_valid`
  - `TestIRProgramMutation.test_add_edge_validates_source`
  - `TestIRProgramMutation.test_add_edge_validates_target`
  - `TestIRProgramMutation.test_add_node`
  - `TestIRProgramMutation.test_duplicate_node_raises`
  - `TestIRProgramQueries.test_incoming`
  - `TestIRProgramQueries.test_neighbors_kind_filter`
  - `TestIRProgramQueries.test_neighbors_kind_filter_string`
  - `TestIRProgramQueries.test_neighbors_no_filter`
  - `TestIRProgramQueries.test_nodes_of_kind`
  - `TestIRProgramQueries.test_nodes_of_kind_string`
  - `TestIRProgramQueries.test_outgoing`
  - `TestIRProgramSerialization.test_from_dict`
  - `TestIRProgramSerialization.test_from_json_path`
  - `TestIRProgramSerialization.test_full_json_round_trip`
  - `TestIRProgramSerialization.test_schema_version_stamped`
  - `TestIRProgramSerialization.test_to_json_returns_string`
  - `TestProvenance.test_defaults_are_none`
  - `TestProvenance.test_partial_provenance_round_trip`
  - `TestProvenance.test_to_dict_round_trip`
  - `TestProvenanceInIR.test_provenance_survives_json_round_trip`

### `test_iterative_refiner.py`
- **Summary:** Unit tests for reveng.verification.refinement.
- **Tests (18):**
  - `test_build_refinement_prompt_includes_all_placeholders`
  - `test_extract_code_block_handles_c_fence`
  - `test_extract_code_block_returns_raw_when_no_fence_present`
  - `test_refiner_budget_exhausted_reflects_iterations_count`
  - `test_refiner_budget_exhausted_when_compile_always_fails`
  - `test_refiner_calls_llm_on_divergence_and_applies_response`
  - `test_refiner_handles_empty_string_llm_response`
  - `test_refiner_handles_garbage_llm_response`
  - `test_refiner_handles_json_llm_response`
  - `test_refiner_handles_oracle_runtime_error_gracefully`
  - `test_refiner_handles_oracle_timeout_gracefully`
  - `test_refiner_no_progress_when_llm_returns_identical_code`
  - `test_refiner_records_each_round_with_tokens_and_elapsed`
  - `test_refiner_respects_wall_clock_budget`
  - `test_refiner_returns_budget_exhausted_when_max_iterations_hit`
  - `test_refiner_returns_converged_when_initial_source_already_equivalent`
  - `test_refiner_returns_llm_error_when_analyzer_raises`
  - `test_refiner_returns_no_progress_when_llm_echoes_source`

### `test_javascript_bundle_reverse_engineer.py`
- **Summary:** Tests for the JavaScript bundle reverse-engineering workflow.
- **Tests (2):**
  - `test_cli_parser_accepts_reverse_engineer_bundle_command`
  - `test_reverse_engineer_bundle_generates_specs_and_filters_skipped_patterns`

### `test_llm_providers.py`
- **Summary:** Unit tests for LLM provider integrations.
- **Tests (33):**
  - `TestAnthropicAnalyzer.test_analyze_function_connection_error_retries`
  - `TestAnthropicAnalyzer.test_analyze_function_falls_back_on_api_error`
  - `TestAnthropicAnalyzer.test_analyze_function_passes_model_id`
  - `TestAnthropicAnalyzer.test_analyze_function_rate_limit_retries_then_fails`
  - `TestAnthropicAnalyzer.test_analyze_function_returns_result`
  - `TestAnthropicAnalyzer.test_api_key_from_env`
  - `TestAnthropicAnalyzer.test_generate_implementation_fallback_stub`
  - `TestAnthropicAnalyzer.test_generate_implementation_returns_string`
  - `TestAnthropicAnalyzer.test_init_custom_model`
  - `TestAnthropicAnalyzer.test_init_defaults`
  - `TestAnthropicAnalyzer.test_missing_anthropic_package_raises_import_error`
  - `TestAnthropicAnalyzer.test_parse_invalid_json_falls_back_to_text_extraction`
  - `TestAnthropicAnalyzer.test_parse_json_with_code_fence`
  - `TestGetAnalyzer.test_get_analyzer_anthropic_returns_instance`
  - `TestGetAnalyzer.test_get_analyzer_case_insensitive`
  - `TestGetAnalyzer.test_get_analyzer_explicit_arg_overrides_env`
  - `TestGetAnalyzer.test_get_analyzer_openai_returns_instance`
  - `TestGetAnalyzer.test_get_analyzer_reads_env_var`
  - `TestGetAnalyzer.test_get_analyzer_unknown_provider_raises_value_error`
  - `TestOpenAIAnalyzer.test_analyze_function_connection_error_retries`
  - `TestOpenAIAnalyzer.test_analyze_function_falls_back_on_api_error`
  - `TestOpenAIAnalyzer.test_analyze_function_passes_model_id`
  - `TestOpenAIAnalyzer.test_analyze_function_rate_limit_retries_then_fails`
  - `TestOpenAIAnalyzer.test_analyze_function_returns_result`
  - `TestOpenAIAnalyzer.test_api_key_from_env`
  - `TestOpenAIAnalyzer.test_generate_implementation_fallback_stub`
  - `TestOpenAIAnalyzer.test_generate_implementation_returns_string`
  - `TestOpenAIAnalyzer.test_init_custom_model`
  - `TestOpenAIAnalyzer.test_init_defaults`
  - `TestOpenAIAnalyzer.test_missing_openai_package_raises_import_error`
  - `TestOpenAIAnalyzer.test_none_content_raises_value_error`
  - `TestOpenAIAnalyzer.test_parse_invalid_json_falls_back_to_text_extraction`
  - `TestOpenAIAnalyzer.test_parse_json_with_code_fence`

### `test_local_disassembler.py`
- **Summary:** Tests for local disassembler fallback output.
- **Tests (44):**
  - `test_bounded_section_data_uses_wider_but_still_bounded_window`
  - `test_collect_behavioral_seed_targets_includes_local_callers_of_behavior_regions`
  - `test_collect_behavioral_seed_targets_includes_multi_hop_pe_wide_callers`
  - `test_collect_behavioral_seed_targets_includes_neighbor_windows_for_behavior_regions`
  - `test_collect_behavioral_seed_targets_includes_pe_wide_callers_of_behavior_regions`
  - `test_collect_behavioral_seed_targets_prefers_import_referencing_regions`
  - `test_collect_behavioral_seed_targets_prioritizes_output_regions_over_handle_setup`
  - `test_collect_behavioral_seed_targets_prioritizes_pe_scan_output_imports_when_scan_order_is_noisy`
  - `test_collect_behavioral_seed_targets_uses_pe_scan_for_out_of_slice_import_calls`
  - `test_collect_register_behavioral_call_targets_finds_register_loaded_import_calls`
  - `test_expand_behavioral_predecessor_targets_walks_multiple_local_hops`
  - `test_find_pe_behavioral_call_targets_promotes_direct_thunk_calls_to_enclosing_start`
  - `test_instruction_to_pseudocode_resolves_rip_relative_import_calls`
  - `test_instruction_to_pseudocode_resolves_rip_relative_local_code_calls`
  - `test_render_pseudocode_function_clears_volatile_arg_state_after_call`
  - `test_render_pseudocode_function_does_not_double_add_rbp_to_frame_pointers`
  - `test_render_pseudocode_function_emits_local_cmp_jump_labels_and_gotos`
  - `test_render_pseudocode_function_emits_local_test_jump_labels_and_gotos`
  - `test_render_pseudocode_function_emits_setcc_assignments_from_cmp_state`
  - `test_render_pseudocode_function_materializes_indexed_frame_pointers_for_lea`
  - `test_render_pseudocode_function_materializes_indexed_frame_reads`
  - `test_render_pseudocode_function_materializes_rbp_relative_local_buffers`
  - `test_render_pseudocode_function_materializes_register_relative_lea`
  - `test_render_pseudocode_function_materializes_register_relative_reads_and_stores`
  - `test_render_pseudocode_function_materializes_rip_relative_addressed_strings`
  - `test_render_pseudocode_function_materializes_scaled_register_relative_lea`
  - `test_render_pseudocode_function_preserves_arithmetic_state_updates`
  - `test_render_pseudocode_function_preserves_multibytetowidechar_arguments`
  - `test_render_pseudocode_function_preserves_register_aliases_as_live_runtime_vars`
  - `test_render_pseudocode_function_preserves_shadow_space_args_for_windows_x64_calls`
  - `test_render_pseudocode_function_preserves_windows_x64_register_args_for_import_calls`
  - `test_render_pseudocode_function_resolves_register_loaded_import_calls`
  - `test_render_pseudocode_function_resolves_register_loaded_local_code_calls`
  - `test_render_pseudocode_function_uses_live_register_vars_for_overwritten_args`
  - `test_resolve_call_target_prefers_indirect_local_code_targets`
  - `test_resolve_call_target_uses_sub_prefix_for_local_targets`
  - `test_to_ghidra_format_includes_local_pseudocode_functions`
  - `test_to_ghidra_format_only_emits_continuations_for_generated_functions`
  - `test_to_ghidra_format_prioritizes_behavioral_import_regions_over_chunk_sweep`
  - `test_to_ghidra_format_prioritizes_direct_call_targets_from_entry_point`
  - `test_to_ghidra_format_prioritizes_indirect_local_targets_from_entry_point`
  - `test_to_ghidra_format_records_orphan_behavioral_seed_reachability_metadata`
  - `test_to_ghidra_format_stitches_bounded_fallthrough_continuations`
  - `test_to_ghidra_format_uses_on_demand_window_for_out_of_slice_local_targets`

### `test_malware_forensics_anomaly_detection.py`
- **Summary:** Focused tests for ML-driven malware forensics anomaly detection.
- **Tests (5):**
  - `test_behavioral_profile_flags_high_anomaly_score`
  - `test_behavioral_profile_leaves_benign_activity_below_threshold`
  - `test_forensics_models_train_once_per_model_class`
  - `test_memory_analysis_uses_ml_scores_for_flags_and_risk`
  - `test_memory_artifact_marks_ml_anomaly_when_threshold_exceeded`

### `test_mcp_contracts.py`
- **Summary:** Contract tests for MCP-facing REVENG server responses.
- **Tests (41):**
  - `test_enterprise_ai_code_reconstruction_returns_contract`
  - `test_enterprise_ai_code_reconstruction_timeout_returns_contract`
  - `test_enterprise_analyze_memory_dump_returns_contract`
  - `test_enterprise_ask_ai_about_binary_returns_contract`
  - `test_enterprise_ask_ai_about_binary_timeout_returns_contract`
  - `test_enterprise_ask_ai_about_binary_timeout_without_context_returns_safe_fallback`
  - `test_enterprise_coerce_optional_int_invalid_values_return_none`
  - `test_enterprise_deobfuscate_javascript_non_utf8_file_returns_contract`
  - `test_enterprise_detect_js_malware_non_utf8_file_returns_contract`
  - `test_enterprise_detect_js_malware_returns_contract`
  - `test_enterprise_diff_binaries_returns_contract`
  - `test_enterprise_execute_with_audit_allows_acknowledged_high_risk_tools`
  - `test_enterprise_execute_with_audit_denies_unacknowledged_high_risk_tools`
  - `test_enterprise_execute_with_audit_logs_policy_denial`
  - `test_enterprise_execute_with_audit_rate_limit_logs_audit_event`
  - `test_enterprise_execute_with_audit_rate_limit_returns_contract`
  - `test_enterprise_find_vulnerabilities_returns_contract`
  - `test_enterprise_generate_exploit_returns_contract`
  - `test_enterprise_get_analysis_report_missing_returns_contract`
  - `test_enterprise_get_analysis_report_returns_contract`
  - `test_enterprise_get_prompt_returns_versioned_prompt_message`
  - `test_enterprise_list_recent_analyses_returns_contract`
  - `test_enterprise_mcp_analyze_binary_wraps_analysis_result`
  - `test_enterprise_mcp_classify_malware_returns_contract`
  - `test_enterprise_mcp_decompile_binary_returns_contract`
  - `test_enterprise_mcp_recent_analyses_resource_is_versioned`
  - `test_enterprise_mcp_reverse_engineer_app_returns_contract`
  - `test_enterprise_mcp_run_app_corpus_returns_versioned_contract`
  - `test_enterprise_missing_resource_is_versioned`
  - `test_enterprise_recompile_binary_error_returns_contract`
  - `test_enterprise_recompile_binary_routes_bun_to_node_sea`
  - `test_enterprise_require_existing_file_rejects_directories`
  - `test_enterprise_scan_yara_error_returns_contract`
  - `test_enterprise_scan_yara_rejects_non_rule_files`
  - `test_enterprise_server_env_overrides_ollama_routing`
  - `test_enterprise_server_resolves_ollama_routing_from_config`
  - `test_enterprise_tools_list_exposes_risk_annotations`
  - `test_simple_mcp_analyze_binary_returns_versioned_contract`
  - `test_simple_mcp_deobfuscate_js_returns_versioned_contract`
  - `test_simple_mcp_reverse_engineer_app_returns_versioned_contract`
  - `test_simple_mcp_run_app_corpus_returns_versioned_contract`

### `test_mitre_simple.py`

### `test_ml_anomaly_detection.py`
- **Summary:** Unit tests for the current malware-forensics anomaly APIs.
- **Tests (5):**
  - `test_behavioral_anomaly_model_flags_high_risk_event_stream`
  - `test_behavioral_anomaly_model_leaves_benign_event_stream_below_threshold`
  - `test_behavioral_monitor_creates_static_only_profile_when_sandbox_unavailable`
  - `test_behavioral_monitor_parses_trace_output_and_adds_timeout_event`
  - `test_forensics_anomaly_model_distinguishes_suspicious_and_benign_profiles`

### `test_ml_code_reconstruction.py`
- **Summary:** Unit tests for the current ML code reconstruction and recompilation APIs.
- **Tests (6):**
  - `test_binary_recompilation_engine_feedback_prompt_includes_cfg_context_and_history`
  - `test_generate_threat_intelligence_uses_current_analysis_inputs`
  - `test_ml_code_reconstruction_loads_current_local_models`
  - `test_reconstruct_code_returns_structured_result_for_function_task`
  - `test_save_reconstruction_and_threat_results_write_current_json_shapes`
  - `test_select_best_model_prefers_current_available_fallbacks`

### `test_ml_integration.py`
- **Summary:** Characterization tests for the ML integration subsystem.
- **Tests (6):**
  - `test_analyze_binary_returns_expected_sections`
  - `test_extract_code_fragments_combines_disassembly_and_functions`
  - `test_get_model_status_serializes_available_models`
  - `test_ml_integration_initialises_enabled_components`
  - `test_ml_integration_skips_disabled_components`
  - `test_perform_anomaly_detection_handles_errors`

### `test_native_ghidra_workflow.py`
- **Summary:** Unit tests for native Ghidra workflow helpers.
- **Tests (2):**
  - `test_analyze_with_lock_retry_retries_once_on_temp_project_lock`
  - `test_candidate_ghidra_urls_prefers_current_server_port`

### `test_oracle_adapter.py`
- **Summary:** Unit tests for reveng.verification.refinement.oracle_adapter.
- **Tests (9):**
  - `test_factory_accepts_str_original_binary`
  - `test_factory_accepts_str_recompiled_binary`
  - `test_factory_creates_fresh_oracle_each_call`
  - `test_factory_passes_original_binary_to_oracle`
  - `test_factory_passes_timeout_to_oracle`
  - `test_factory_returns_differential_oracle`
  - `test_make_oracle_factory_returns_callable`
  - `test_raises_file_not_found_for_missing_original`
  - `test_raises_value_error_for_non_positive_timeout`

### `test_parser_fixes.py`
- **Summary:** Regression tests for the C type parser.
- **Tests (3):**
  - `test_address_field_parses_hex_and_decimal`
  - `test_array_parameter_preserves_name`
  - `test_pointer_parsing_extracts_parameter_details`

### `test_pe_resource_extractor.py`
- **Summary:** Unit tests for PEResourceExtractor
- **Tests (19):**
  - `TestPEResourceExtractor.test_detect_embedded_files`
  - `TestPEResourceExtractor.test_extract_all_resources_failure`
  - `TestPEResourceExtractor.test_extract_all_resources_success`
  - `TestPEResourceExtractor.test_extract_icons_manual`
  - `TestPEResourceExtractor.test_extract_icons_with_rh`
  - `TestPEResourceExtractor.test_extract_manifests_manual`
  - `TestPEResourceExtractor.test_extract_manifests_with_rh`
  - `TestPEResourceExtractor.test_extract_strings_manual`
  - `TestPEResourceExtractor.test_extract_strings_with_rh`
  - `TestPEResourceExtractor.test_extract_version_info_manual`
  - `TestPEResourceExtractor.test_extract_version_info_with_rh`
  - `TestPEResourceExtractor.test_find_resource_section`
  - `TestPEResourceExtractor.test_find_resource_section_not_found`
  - `TestPEResourceExtractor.test_init`
  - `TestPEResourceExtractor.test_parse_custom_resources`
  - `TestPEResourceExtractor.test_parse_icon_resources`
  - `TestPEResourceExtractor.test_parse_manifest_resources`
  - `TestPEResourceExtractor.test_parse_string_resources`
  - `TestPEResourceExtractor.test_parse_version_resources`

### `test_pipeline_engine_async.py`
- **Summary:** Tests for asynchronous pipeline execution and failure isolation.
- **Tests (6):**
  - `test_binary`
  - `test_execute_pipeline_async_runs_stages_concurrently (async)`
  - `test_execute_pipeline_isolates_failed_branch`
  - `test_execute_pipeline_supports_dynamic_analysis_stage`
  - `test_optional_stage_defaults_return_skipped_payloads`
  - `test_run_coroutine_sync_times_out_when_thread_hangs`

### `test_provision_ga_assets.py`
- **Tests (2):**
  - `test_extract_members_flattens_requested_files`
  - `test_load_manifest_resolves_relative_destinations`

### `test_python_bytecode_version_routing.py`
- **Summary:** Regression tests for Python bytecode decompiler version routing.
- **Tests (5):**
  - `test_310_does_not_route_to_decompyle3`
  - `test_310_does_not_route_to_uncompyle6`
  - `test_310_routes_to_pycdc`
  - `test_38_still_routes_to_uncompyle6`
  - `test_39_routes_to_decompyle3_not_uncompyle6`

### `test_ralph_js_loop.py`
- **Summary:** Unit tests for Ralph-style JS oracle loop (pure logic + injected runner).
- **Tests (21):**
  - `test_compose_empty_raises`
  - `test_compose_merges_defaults_json_and_heavy`
  - `test_compose_no_defaults_wakaru_only`
  - `test_default_variants_have_labels`
  - `test_heavy_js_ralph_variants_both_flags`
  - `test_js_behavior_probe_tier_reads_capability_report`
  - `test_load_js_ralph_variants_from_json`
  - `test_load_js_ralph_variants_rejects_unknown_key`
  - `test_load_js_ralph_variants_requires_non_empty_array`
  - `test_oracle_recall_precision_missing`
  - `test_oracle_recall_precision_reads_scorecard`
  - `test_ralph_cli_help_exits_zero`
  - `test_ralph_cli_missing_input_exits_one`
  - `test_ralph_cli_variants_json_only_without_json_exits_one`
  - `test_ralph_effective_plateau_at_least_variant_count`
  - `test_ralph_loop_runs_max_attempts_when_plateau_disabled`
  - `test_ralph_loop_stops_at_target_recall`
  - `test_ralph_loop_stops_on_plateau`
  - `test_ralph_score_key_behavior_tiebreak`
  - `test_ralph_score_key_orders_recall_first`
  - `test_ralph_score_key_recall_dominates_behavior`

### `test_recompilation_engine_feedback_loop.py`
- **Summary:** Tests for compiler-in-the-loop retry behavior in the recompilation engine.
- **Tests (250):**
  - `test_align_conflicting_function_prototypes_prefers_definition_return_type`
  - `test_build_c_type_prelude_declares_swi_stub`
  - `test_build_c_type_prelude_uses_value_context_aliases_on_windows`
  - `test_build_compile_command_uses_windows_linker_flags_for_clang`
  - `test_build_generated_helper_prelude_adds_forward_declarations_for_later_helper_definitions`
  - `test_build_generated_helper_prelude_calls_entry_point_for_fallback_native_sources`
  - `test_build_generated_helper_prelude_declares_runtime_stubs`
  - `test_build_generated_helper_prelude_defines_fallback_sub_stubs`
  - `test_build_generated_helper_prelude_injects_main_for_fallback_native_sources`
  - `test_build_generated_helper_prelude_injects_main_for_sanitized_fallback_marker`
  - `test_build_generated_helper_prelude_keeps_indented_calls_as_macros`
  - `test_build_generated_helper_prelude_skips_multiline_function_definitions`
  - `test_build_generated_helper_prelude_skips_same_line_sub_function_definitions`
  - `test_build_generated_helper_prelude_stubs_declared_import_like_calls_after_stripping`
  - `test_build_generated_helper_prelude_stubs_resolved_import_calls_for_fallback_sources`
  - `test_build_generated_helper_prelude_stubs_undeclared_sub_targets_for_fallback_sources`
  - `test_build_generated_helper_prelude_uses_runtime_helpers_for_critical_output_imports`
  - `test_build_generated_helper_prelude_uses_runtime_helpers_for_declared_import_like_output_calls`
  - `test_build_generated_helper_prelude_uses_stub_function_when_helper_is_called_and_referenced`
  - `test_build_generated_symbol_prelude_declares_discovered_synthetic_symbols`
  - `test_build_generated_symbol_prelude_declares_ptr_and_string_symbols`
  - `test_build_generated_symbol_prelude_declares_ram_pseudo_symbols`
  - `test_build_generated_symbol_prelude_declares_stack_pseudo_symbols`
  - `test_build_generated_symbol_prelude_declares_switchdata_symbols`
  - `test_build_generated_symbol_prelude_declares_unresolved_lab_symbols`
  - `test_build_generated_symbol_prelude_infers_globals_from_pointer_return_and_param_contexts`
  - `test_build_generated_symbol_prelude_infers_windows_pointer_like_global_types`
  - `test_build_generated_symbol_prelude_keeps_integerish_globals_scalar_without_explicit_handle_cues`
  - `test_build_generated_symbol_prelude_keeps_split_fragments_scalar_even_in_handle_context`
  - `test_build_generated_symbol_prelude_skips_called_helper_names`
  - `test_build_generated_symbol_prelude_skips_function_names`
  - `test_build_helper_call_summary_counts_helper_managed_calls`
  - `test_build_helper_reachability_summary_scopes_helpers_to_entry_reachable_functions`
  - `test_collect_calls_for_names_skips_declarations_and_keeps_real_calls`
  - `test_collect_calls_for_names_skips_multiline_declarations_and_keeps_real_calls`
  - `test_compile_with_feedback_loop_handles_empty_llm_response (async)`
  - `test_compile_with_feedback_loop_retries_and_includes_stderr (async)`
  - `test_compile_with_feedback_loop_stops_at_retry_limit (async)`
  - `test_compile_with_feedback_loop_stops_on_non_retryable_failure (async)`
  - `test_compile_with_feedback_loop_zero_retries_stops_after_first_failure (async)`
  - `test_extract_declared_function_names_ignores_indented_calls`
  - `test_find_nearest_declared_variable_type_falls_back_to_current_function_params`
  - `test_find_nearest_declared_variable_type_ignores_control_flow_continuations`
  - `test_full_pipeline_returns_graceful_failure_report_when_compilation_fails (async)`
  - `test_full_pipeline_surfaces_differential_validation (async)`
  - `test_get_function_boundary_indices_detects_commented_and_multiline_functions`
  - `test_inject_fallback_function_entry_traces_preserves_comment_and_adds_trace`
  - `test_inject_missing_import_like_stub_macros_backfills_final_source`
  - `test_inject_missing_import_like_stub_macros_skips_helper_managed_output_apis`
  - `test_join_wrapped_sanitized_call_identifiers_repairs_split_function_signatures`
  - `test_normalize_bare_returns_for_scalar_functions`
  - `test_normalize_bare_returns_for_scalar_functions_ignores_warning_comments`
  - `test_normalize_bare_returns_for_scalar_functions_recovers_local_boundary_when_cache_misses`
  - `test_normalize_bare_returns_for_scalar_functions_uses_forward_boundary_collection_when_cache_is_stale`
  - `test_normalize_code_pointer_byte_uses_rewrites_parenthesized_code_pointer_indexing`
  - `test_normalize_data_symbol_arguments_for_pointer_params_keeps_adjacent_calls_intact`
  - `test_normalize_generated_c_semantics_balances_unclosed_ghidra_u64_lines`
  - `test_normalize_generated_c_semantics_bridges_float_backed_pointer_casts`
  - `test_normalize_generated_c_semantics_bridges_scalar_float_backed_pointer_casts`
  - `test_normalize_generated_c_semantics_can_skip_pointer_assignment_rewrite`
  - `test_normalize_generated_c_semantics_casts_data_symbols_for_pointer_params`
  - `test_normalize_generated_c_semantics_casts_integer_expressions_for_pointer_params`
  - `test_normalize_generated_c_semantics_casts_pointer_values_via_uintptr_for_double_comparisons`
  - `test_normalize_generated_c_semantics_casts_wake_by_address_single_large_integer_args`
  - `test_normalize_generated_c_semantics_declares_bare_alias_for_fragment_locals`
  - `test_normalize_generated_c_semantics_declares_missing_split_local_symbols`
  - `test_normalize_generated_c_semantics_fixes_large_integer_call_casts_and_pointer_aliases`
  - `test_normalize_generated_c_semantics_fixes_malformed_vec64_cast_rewrite`
  - `test_normalize_generated_c_semantics_generalizes_non_auvar_128bit_arrays`
  - `test_normalize_generated_c_semantics_keeps_ghidra_u64_calls_balanced_with_string_parens`
  - `test_normalize_generated_c_semantics_preserves_indexed_vector_masks`
  - `test_normalize_generated_c_semantics_preserves_large_integer_aggregate_copies`
  - `test_normalize_generated_c_semantics_relaxes_readonly_local_wide_pointers_when_written`
  - `test_normalize_generated_c_semantics_repairs_default_and_switch_labels`
  - `test_normalize_generated_c_semantics_repairs_struct_cast_large_integer_returns`
  - `test_normalize_generated_c_semantics_repairs_top_level_comma_in_ghidra_u64`
  - `test_normalize_generated_c_semantics_restores_large_integer_split_aliases`
  - `test_normalize_generated_c_semantics_restores_malformed_case_labels`
  - `test_normalize_generated_c_semantics_restores_prefixed_local_aliases`
  - `test_normalize_generated_c_semantics_retargets_non_code_pointer_cast_assignments`
  - … *170 more*

### `test_recompilation_engine_hardening.py`
- **Summary:** Unit tests for HARDENING_PRIORITIES methods in BinaryRecompilationEngine.
- **Tests (12):**
  - `TestNormalizeUndeclaredSplitLocals.test_drops_leading_underscore_when_declared`
  - `TestNormalizeUndeclaredSplitLocals.test_injects_declaration_when_undeclared`
  - `TestNormalizeUndeclaredSplitLocals.test_multiple_distinct_undeclared_vars_each_injected_once`
  - `TestNormalizeUndeclaredSplitLocals.test_no_match_returns_source_unchanged`
  - `TestUnifyFragmentLocals.test_does_not_inject_when_base_already_declared`
  - `TestUnifyFragmentLocals.test_injects_volatile_declaration_for_fragment`
  - `TestUnifyFragmentLocals.test_local_fragment_family_also_handled`
  - `TestUnifyFragmentLocals.test_no_fragment_returns_source_unchanged`
  - `TestWidenUndefined8ParamPrototypes.test_delegates_to_relax_mismatched`
  - `TestWidenUndefined8ParamPrototypes.test_no_undefined8_params_unchanged`
  - `TestWidenUndefined8ParamPrototypes.test_undefined8_star_param_rewritten_to_void_star_when_callsite_passes_pointer`
  - `test_pipeline_methods_exist_and_are_callable`

### `test_recompile_command.py`
- **Tests (2):**
  - `test_console_safe_text_replaces_unencodable_characters`
  - `test_run_recompile_command_forwards_ghidra_timeout`

### `test_result_contracts.py`
- **Tests (6):**
  - `test_ai_api_analysis_result_is_versioned`
  - `test_analyzer_capabilities_are_versioned`
  - `test_reveng_api_analysis_result_is_versioned`
  - `test_reveng_api_app_corpus_report_is_versioned`
  - `test_reveng_api_app_reverse_engineering_result_is_versioned`
  - `test_reveng_api_reconstruction_and_malware_results_are_versioned`

### `test_reverse_engineering_ir.py`
- **Summary:** Tests for the shared reverse-engineering IR and JS IR export.
- **Tests (2):**
  - `test_js_bundle_workflow_emits_ir_artifact`
  - `test_re_project_ir_serializes_nodes_edges_and_metadata`

### `test_run_vrl.py`
- **Summary:** Unit tests for scripts/run_vrl.py.
- **Tests (6):**
  - `test_binary_arg_selects_correct_corpus_entry`
  - `test_binary_not_in_corpus_returns_error`
  - `test_json_log_fields_are_correct`
  - `test_main_happy_path_produces_json_log`
  - `test_missing_corpus_yaml_returns_error`
  - `test_result_grade_recorded_in_corpus_update`

### `test_security_utils.py`
- **Summary:** Tests for REVENG security utilities
- **Tests (14):**
  - `TestPathTraversalScenarios.test_various_traversal_patterns`
  - `TestSafeExtractArchive.test_auto_detect_tar`
  - `TestSafeExtractArchive.test_auto_detect_tar_gz`
  - `TestSafeExtractArchive.test_auto_detect_zip`
  - `TestSafeExtractArchive.test_unsupported_format_raises_error`
  - `TestSafeExtractTar.test_safe_tar_extraction_normal_files`
  - `TestSafeExtractTar.test_safe_tar_extraction_prevents_absolute_paths`
  - `TestSafeExtractTar.test_safe_tar_extraction_prevents_parent_traversal`
  - `TestSafeExtractZip.test_safe_zip_extraction_deep_nested_ok`
  - `TestSafeExtractZip.test_safe_zip_extraction_normal_files`
  - `TestSafeExtractZip.test_safe_zip_extraction_prevents_absolute_paths`
  - `TestSafeExtractZip.test_safe_zip_extraction_prevents_parent_traversal`
  - `TestSecurityUtilsIntegration.test_extraction_with_symlinks_blocked`
  - `TestSecurityUtilsIntegration.test_multiple_archives_sequential`

### `test_source_binary_benchmark.py`
- **Tests (6):**
  - `test_build_reveng_command_appends_ghidra_timeout`
  - `test_compare_behavior_results_honors_output_and_exit_code_flags`
  - `test_load_benchmark_config_resolves_relative_paths`
  - `test_normalize_output_strips_ansi_and_normalizes_newlines`
  - `test_rollup_status_reports_rebuilt_binary_missing`
  - `test_run_behavior_case_uses_full_output_for_expectation_checks`

### `test_source_map_recoverer.py`
- **Summary:** Tests for JavaScript source-map recovery helpers.
- **Tests (4):**
  - `test_find_sourcemaps_local_returns_inline_data_url`
  - `test_find_sourcemaps_local_tolerates_non_utf8_bundle_bytes`
  - `test_recover_decodes_inline_data_url_and_normalizes_duplicate_src_root`
  - `test_save_directory_writes_normalized_source_map_tree`

### `test_tracked_js_bundle_manifest.py`
- **Summary:** TDD: tracked JS bundle artifact integrity (manifest + SHA-256 proof).
- **Tests (8):**
  - `test_benchmark_tracked_js_bundle_script_writes_combined_report`
  - `test_build_tracked_js_bundle_script_verify_only_exits_zero`
  - `test_committed_artifact_matches_manifest`
  - `test_corpus_configs_reference_tracked_bundle_row`
  - `test_manifest_lists_required_outputs`
  - `test_manifest_schema_constant`
  - `test_tracked_bundle_corpus_benchmark_includes_capability`
  - `test_verify_detects_tampering`

### `test_unified_cli.py`
- **Summary:** Tests for the unified CLI entry point.
- **Tests (4):**
  - `test_create_parser_includes_core_commands`
  - `test_main_routes_to_analyze_handler`
  - `test_main_routes_to_serve_handler_with_defaults`
  - `test_main_without_command_shows_help`

### `test_validation_contracts.py`
- **Tests (4):**
  - `test_binary_validator_returns_versioned_result_dict`
  - `test_validation_config_round_trip_preserves_schema_and_smoke_tests`
  - `test_validation_manifest_loader_builds_versioned_binary_specific_config`
  - `test_validation_result_round_trip_preserves_details`

### `test_verification_oracle_scaffold.py`
- **Summary:** Phase 1 scaffold tests for reveng.verification oracle interfaces.
- **Tests (30):**
  - `TestDifferentialOracleFuzz.test_fuzz_until_divergence_raises_not_implemented`
  - `TestDifferentialOracleVerify.test_diverging_outputs_gives_divergent`
  - `TestDifferentialOracleVerify.test_empty_corpus_returns_zero_iterations`
  - `TestDifferentialOracleVerify.test_empty_corpus_verdict_is_equivalent`
  - `TestDifferentialOracleVerify.test_harness_error_gives_error_verdict`
  - `TestDifferentialOracleVerify.test_matching_outputs_gives_equivalent`
  - `TestDivergenceReport.test_default_construction`
  - `TestDivergenceReport.test_divergence_rate_with_data`
  - `TestDivergenceReport.test_divergence_rate_zero_iterations`
  - `TestDivergenceReport.test_repr_contains_verdict`
  - `TestEquivalenceResult.test_default_construction`
  - `TestEquivalenceResult.test_repr_contains_verdict`
  - `TestExecutionHarness.test_construction`
  - `TestExecutionHarness.test_missing_file_raises_harness_error`
  - `TestExecutionHarness.test_permission_error_raises_harness_error`
  - `TestExecutionHarness.test_run_with_sys_executable_construction`
  - `TestExecutionHarness.test_timeout_returns_timed_out_result`
  - `TestSymbolicOracle.test_construction`
  - `TestSymbolicOracle.test_error_verdict_notes_installation_hint`
  - `TestSymbolicOracle.test_notes_mention_phase_15`
  - `TestSymbolicOracle.test_verify_with_angr_present_returns_undetermined`
  - `TestSymbolicOracle.test_verify_with_none_returns_undetermined_when_angr_missing`
  - `TestVerificationVerdict.test_all_members_present`
  - `TestVerificationVerdict.test_has_divergent`
  - `TestVerificationVerdict.test_has_equivalent`
  - `TestVerificationVerdict.test_has_error`
  - `TestVerificationVerdict.test_has_timed_out`
  - `TestVerificationVerdict.test_has_undetermined`
  - `test_subpackage_imports`
  - `test_top_level_imports`

### `test_verify_ga_readiness.py`
- **Tests (5):**
  - `test_baseline_profile_fails_without_supported_workflows`
  - `test_baseline_profile_passes_with_current_minimum_shapes`
  - `test_ga_profile_fails_when_ga_thresholds_are_not_met`
  - `test_ga_profile_fails_when_reports_are_not_generated_from_strict_ga_configs`
  - `test_main_writes_readiness_report_and_returns_zero_for_baseline`

### `test_virustotal_connector.py`
- **Summary:** Regression tests for VirusTotalConnector.enrich_analysis.
- **Tests (1):**
  - `test_enrich_analysis_not_found_without_threat_intel_key`

### `test_volatility_integration.py`
- **Summary:** Tests for Volatility3-backed memory dump analysis.
- **Tests (5):**
  - `test_analyze_memory_dump_mcp_tool_supports_skip_volatility (async)`
  - `test_memory_dump_uses_volatility_analyzer_instead_of_wmic`
  - `test_volatility_analyzer_requires_existing_dump`
  - `test_volatility_analyzer_skip_env_returns_mock_results`
  - `test_volatility_analyzer_uses_timezone_aware_timestamp`

### `test_vrl_grade.py`
- **Summary:** Regression tests for ValidationGrade vs RefinementStatus handling (VRL Task 1.8).
- **Tests (4):**
  - `test_converged_result_yields_ladder_grade`
  - `test_grade_for_result_never_writes_none`
  - `test_llm_error_with_none_divergence_falls_back`
  - `test_update_corpus_grade_exact_name_not_substring`

### `test_vrl_harness_argv.py`
- **Summary:** Regression tests for ExecutionHarness ARGV-vs-STDIN handling (VRL Task 1.7).
- **Tests (3):**
  - `test_run_without_argv_defaults_to_empty`
  - `test_seed_tokens_reach_process_argv`
  - `test_stdin_payload_remains_distinct_from_argv`

### `test_yara_scanner.py`
- **Summary:** Unit tests for built-in YARA malware classification support.
- **Tests (4):**
  - `test_builtin_ruleset_contains_at_least_twenty_rules`
  - `test_classify_file_returns_family_confidence_and_matched_rules`
  - `test_mcp_classify_malware_returns_structured_response (async)`
  - `test_scan_pe_with_eicar_string_returns_a_builtin_match`

---
*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*
