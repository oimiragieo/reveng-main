# `claude.md` — `tools/config`

**Repository path:** `src/reveng/tools/config/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Configuration package exports.

### `config_manager.py`
- **Summary:** REVENG Configuration Manager
- **Classes:**
  - `AIConfig` — AI/LLM configuration
  - `GhidraConfig` — Ghidra MCP configuration
  - `ValidationConfig` — Validation configuration
  - `CompilationConfig` — Compilation configuration
  - `SecurityConfig` — Security configuration
  - `ConfigManager` — Manage REVENG configuration
- **Functions / coroutines:**
  - `def get_config()` — Get global configuration instance

### `enhanced_config_manager.py`
- **Summary:** Enhanced Configuration Manager
- **Classes:**
  - `AIServiceConfig` — Configuration for AI services
  - `AnalysisModuleConfig` — Configuration for individual analysis modules
  - `DeploymentConfig` — Configuration for deployment and infrastructure
  - `SecurityConfig` — Security configuration for enhanced analysis
  - `EnhancedAnalysisConfiguration` — Complete configuration for enhanced analysis system
  - `EnhancedConfigManager` — Configuration manager for AI-Enhanced Universal Analysis Engine
- **Functions / coroutines:**
  - `def get_enhanced_config()` — Get enhanced analysis configuration
  - `def main()` — Main function for configuration management

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
