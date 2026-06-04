# `claude.md` — `performance`

**Repository path:** `tests/performance/`

Pytest layout: markers and heavy tools are gated in `pytest.ini`. **Parent index:** [`../claude.md`](../claude.md).

## Python files

### `__init__.py`
- **Summary:** Performance Tests

### `test_analysis_speed.py`
- **Summary:** Performance Tests for REVENG Analysis Speed
- **Tests (14):**
  - `TestAnalysisSpeed.test_analysis_speed_cpu_usage`
  - `TestAnalysisSpeed.test_analysis_speed_io_operations`
  - `TestAnalysisSpeed.test_analysis_speed_memory_usage`
  - `TestAnalysisSpeed.test_analysis_speed_regression`
  - `TestAnalysisSpeed.test_analysis_speed_with_timeout`
  - `TestAnalysisSpeed.test_concurrent_analysis_speed`
  - `TestAnalysisSpeed.test_csharp_analysis_speed`
  - `TestAnalysisSpeed.test_enhanced_analysis_speed`
  - `TestAnalysisSpeed.test_java_analysis_speed`
  - `TestAnalysisSpeed.test_large_binary_analysis_speed`
  - `TestAnalysisSpeed.test_medium_binary_analysis_speed`
  - `TestAnalysisSpeed.test_native_analysis_speed`
  - `TestAnalysisSpeed.test_python_analysis_speed`
  - `TestAnalysisSpeed.test_small_binary_analysis_speed`

### `test_incremental_compilation.py`
- **Summary:** Performance tests for the incremental compilation system.
- **Tests (5):**
  - `test_cache_hit_rate_accumulation`
  - `test_cache_statistics`
  - `test_incremental_compilation_speedup`
  - `test_incremental_compiler_basic`
  - `test_multiple_optimization_levels`

### `test_memory_usage.py`
- **Summary:** Performance Tests for REVENG Memory Usage
- **Tests (12):**
  - `TestMemoryUsage.test_basic_memory_usage`
  - `TestMemoryUsage.test_concurrent_analysis_memory_usage`
  - `TestMemoryUsage.test_enhanced_analysis_memory_usage`
  - `TestMemoryUsage.test_large_binary_memory_usage`
  - `TestMemoryUsage.test_memory_cleanup_after_analysis`
  - `TestMemoryUsage.test_memory_usage_regression`
  - `TestMemoryUsage.test_memory_usage_with_ai_analysis`
  - `TestMemoryUsage.test_memory_usage_with_audit_logging`
  - `TestMemoryUsage.test_memory_usage_with_error_handling`
  - `TestMemoryUsage.test_memory_usage_with_file_operations`
  - `TestMemoryUsage.test_memory_usage_with_ml_models`
  - `TestMemoryUsage.test_memory_usage_with_timeout`

---
*Generated for AI navigation. Regenerate: `python scripts/generate_claude_md_index.py`.*
