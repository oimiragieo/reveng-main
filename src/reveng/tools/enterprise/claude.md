# `claude.md` — `tools/enterprise`

**Repository path:** `src/reveng/tools/enterprise/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Enterprise feature modules and canonical GPU accelerator exports.

### `audit_trail.py`
- **Summary:** REVENG Audit Trail System
- **Classes:**
  - `EventType` — Types of audit events
  - `Severity` — Event severity levels
  - `AuditEvent` — Single audit event
  - `AnalysisSession` — Represents a complete analysis session
  - `AuditLogger` — Main audit logging system
- **Functions / coroutines:**
  - `def main()` — CLI interface for audit trail system

### `enhanced_health_monitor.py`
- **Summary:** Enhanced Analysis Health Monitor
- **Classes:**
  - `HealthMetric` — Individual health metric
  - `ComponentHealth` — Health status for a component
  - `SystemHealth` — Overall system health status
  - `HealthChecker` — Base class for health checkers
  - `CoreREVENGHealthChecker` — Health checker for core REVENG components
  - `EnhancedModulesHealthChecker` — Health checker for enhanced analysis modules
  - `AIServiceHealthChecker` — Health checker for AI services
  - `SystemResourcesHealthChecker` — Health checker for system resources
  - `EnhancedHealthMonitor` — Comprehensive health monitor for AI-Enhanced Universal Analysis Engine
- **Functions / coroutines:**
  - `def main()` — Main function for health monitoring

### `plugin_system.py`
- **Summary:** REVENG Plugin System
- **Classes:**
  - `PluginType` — Types of plugins
  - `PluginHook` — Plugin execution hooks
  - `PluginMetadata` — Metadata for a plugin
  - `PluginInfo` — Runtime plugin information
  - `PluginBase` — Base class for all plugins
  - `AnalyzerPlugin` — Base class for analyzer plugins
  - `DecompilerPlugin` — Base class for decompiler plugins
  - `ExporterPlugin` — Base class for exporter plugins
  - `PluginManager` — Manages plugin discovery, loading, and execution
- **Functions / coroutines:**
  - `def main()` — CLI interface for plugin system

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
