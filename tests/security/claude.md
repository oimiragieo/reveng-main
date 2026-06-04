# `claude.md` — `security`

**Repository path:** `tests/security/`

Pytest layout: markers and heavy tools are gated in `pytest.ini`. **Parent index:** [`../claude.md`](../claude.md).

## Python files

### `__init__.py`
- **Summary:** Security Tests

### `test_advanced_malware_classifier.py`
- **Summary:** Test script for Advanced Malware Classification System
- **Tests (4):**
  - `test_basic_classification`
  - `test_deep_learning_features`
  - `test_similarity_analysis`
  - `test_training_simulation`

### `test_input_validation.py`
- **Summary:** Security tests for input validation.
- **Tests (27):**
  - `TestAnalysisConfigValidation.test_default_configuration`
  - `TestAnalysisConfigValidation.test_invalid_ai_provider`
  - `TestAnalysisConfigValidation.test_invalid_file_size`
  - `TestAnalysisConfigValidation.test_invalid_timeout`
  - `TestAnalysisConfigValidation.test_system_directory_output`
  - `TestAnalysisConfigValidation.test_valid_configuration`
  - `TestBinaryContentValidation.test_high_entropy_detection`
  - `TestBinaryContentValidation.test_pe_executable_validation`
  - `TestBinaryContentValidation.test_text_file_validation`
  - `TestFilePathValidation.test_allowed_extensions`
  - `TestFilePathValidation.test_file_size_limit`
  - `TestFilePathValidation.test_nonexistent_file`
  - `TestFilePathValidation.test_path_traversal_prevention`
  - `TestFilePathValidation.test_suspicious_path_patterns`
  - `TestFilePathValidation.test_valid_file_path`
  - `TestFilenameSanitization.test_sanitize_control_characters`
  - `TestFilenameSanitization.test_sanitize_dangerous_characters`
  - `TestFilenameSanitization.test_sanitize_empty_name`
  - `TestFilenameSanitization.test_sanitize_length_limit`
  - `TestSecureHashing.test_nonexistent_file_hash`
  - `TestSecureHashing.test_secure_hash_file`
  - `TestSecureHashing.test_unsafe_hash_algorithm`
  - `TestSecureTempFile.test_secure_temp_file_creation`
  - `TestSecureTempFile.test_secure_temp_file_in_allowed_directory`
  - `TestSecureTempFile.test_secure_temp_file_in_disallowed_directory`
  - `TestSecurityIntegration.test_end_to_end_validation`
  - `TestSecurityIntegration.test_security_error_propagation`

---
*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*
