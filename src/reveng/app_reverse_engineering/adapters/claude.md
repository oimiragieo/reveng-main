# `claude.md` — `app_reverse_engineering/adapters`

**Repository path:** `src/reveng/app_reverse_engineering/adapters/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Language-specific app reverse-engineering adapters.

### `dotnet.py`
- **Summary:** .NET adapter for the shared app reverse-engineering framework.
- **Classes:**
  - `DotNetAppAdapter` — Adapter for .NET assemblies using the repo's IL and metadata analyzers.

### `javascript.py`
- **Summary:** JavaScript adapter for the shared app reverse-engineering framework.
- **Classes:**
  - `JavaScriptAppAdapter` — Adapter that wraps the existing JavaScript bundle workflow.

### `jvm.py`
- **Summary:** JVM adapter for the shared app reverse-engineering framework.
- **Classes:**
  - `JVMAppAdapter` — Adapter for Java/JVM source and bytecode applications.

### `native.py`
- **Summary:** Native adapter for the shared app reverse-engineering framework.
- **Classes:**
  - `NativeAppAdapter` — Adapter for native executable and shared-library inputs.

### `python.py`
- **Summary:** Python adapter for the shared app reverse-engineering framework.
- **Classes:**
  - `_PythonMetadataVisitor` — Collect summary metadata from Python ASTs.
  - `PythonAppAdapter` — Adapter for Python source, bytecode, and zipapp-style inputs.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
